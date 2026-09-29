"""Offline contract checks for GUG-432's closed AWS transport."""
from __future__ import annotations

import base64
from dataclasses import dataclass, replace
from hashlib import sha256
import json
import traceback
from types import SimpleNamespace

import pytest
from botocore.exceptions import ClientError
from botocore.loaders import Loader
from botocore.model import ServiceModel

from tooling import platform_authority_gug376_upstream_live_provider as provider


@dataclass(frozen=True)
class Readback:
    service: str
    method: str
    request: dict
    expected_projection: dict
    projection: str


@dataclass(frozen=True)
class Operation:
    operation_id: str
    phase: str
    account_id: str
    region: str
    request: dict
    request_digest: str
    before_state_digest: str
    target_state_digest: str
    before_readbacks: tuple
    readbacks: tuple


class Client:
    def __init__(self, service, calls, responses, errors=None):
        self.service = service
        self.calls = calls
        self.responses = responses
        self.errors = errors or {}

    def __getattr__(self, method):
        def call(**request):
            self.calls.append((self.service, method, request))
            if (self.service, method) in self.errors:
                raise self.errors[self.service, method]
            return self.responses.get((self.service, method), {})
        return call


def _value(shape):
    if shape.type_name == "structure":
        if shape.metadata.get("union"):
            name = next(iter(shape.members))
            return {name: _value(shape.members[name])}
        return {name: _value(shape.members[name]) for name in shape.required_members}
    if shape.type_name == "list":
        return [_value(shape.member)]
    if shape.type_name == "map":
        return {"fixture": _value(shape.value)}
    if shape.type_name == "boolean":
        return False
    if shape.type_name in {"integer", "long"}:
        return max(shape.metadata.get("min", 1), 1)
    if shape.type_name in {"float", "double"}:
        return 1.0
    if shape.type_name == "blob":
        return b"synthetic package"
    if shape.type_name == "timestamp":
        return "2026-09-23T12:00:00Z"
    if shape.enum:
        return shape.enum[0]
    return "x" * max(shape.metadata.get("min", 1), 1)


def _model(service, api):
    return ServiceModel(provider._packaged_model_loader().load_service_model(service, "service-2")).operation_model(api)


def _set(response, path, value):
    parts = path.split(".")
    for part in parts[:-1]:
        response = response.setdefault(part, {})
    response[parts[-1]] = value


def _setup(identifier="GUG377_OP_16_ENABLE_KMS_KEY_ROTATION"):
    route = provider.OPERATION_ROUTES[identifier]
    account = "839393571433" if route.service == "sso-admin" else "042360977644"
    caller = f"arn:aws:sts::{account}:assumed-role/AWSReservedSSO_Test_0123456789abcdef/operator"
    shape = _model(route.service, route.api_name).input_shape
    request = {name: _value(shape.members[name]) for name in route.request_keys if name != "BodySha256"}
    if route.method in {"create_account_assignment", "provision_permission_set"}:
        request.update(TargetId="042360977644", TargetType="AWS_ACCOUNT")
    if route.method == "start_signing_job":
        request["profileOwner"] = "042360977644"
    artifacts = {}
    if route.method == "put_object":
        content = b"synthetic package"
        content_digest = "sha256:" + sha256(content).hexdigest()
        request.update(BodySha256=sha256(content).hexdigest(), ContentLength=len(content), ChecksumSHA256=base64.b64encode(sha256(content).digest()).decode())
        artifacts[content_digest] = content
    name = provider._REQUIRED_AFTER[route.method]
    projection = provider.READBACK_PROJECTIONS[name]
    read_shape = _model(projection.service, projection.api_name).input_shape
    read_request = {key: _value(read_shape.members[key]) for key in read_shape.required_members}
    if "AccountId" in read_request:
        read_request["AccountId"] = "042360977644"
    if projection.service == "s3":
        read_request["ExpectedBucketOwner"] = provider.AUTHORITY_ACCOUNT_ID
    response = {}
    _set(response, projection.fields[0], "fixture")
    if projection.terminal_field:
        _set(response, projection.terminal_field, "SUCCEEDED")
    expected = {field: provider._field(response, field) for field in projection.fields}
    readback = Readback(projection.service, projection.method, read_request, expected, name)
    operation = Operation(identifier, route.phase, account, provider.REGION, request,
                          provider.digest(request), provider.digest("before"), provider.digest("target"),
                          (readback,), (readback,))
    calls = []
    responses = {("sts", "get_caller_identity"): {"Account": account, "Arn": caller},
                 (projection.service, projection.method): response}
    clients = {service: Client(service, calls, responses) for service in provider._ENDPOINTS}
    transport = provider.UpstreamLiveProvider.from_injected_clients(
        clients=clients, expected_account_id=account, expected_caller_arn=caller,
        region=provider.REGION, artifact_bytes=artifacts,
    )
    return transport, operation, calls, responses, clients


@pytest.mark.parametrize("identifier", list(provider.OPERATION_ROUTES))
def test_each_catalog_operation_has_exact_sdk_route_and_one_write(identifier):
    transport, operation, calls, _responses, _clients = _setup(identifier)
    route = provider.OPERATION_ROUTES[identifier]
    assert calls[0][:2] == ("sts", "get_caller_identity")
    outcome = transport.dispatch_once(operation)
    assert outcome.status == "SUCCEEDED"
    assert outcome.mode == "SYNTHETIC"
    writes = [call for call in calls if call[:2] == (route.service, route.method)]
    assert len(writes) == 1
    sdk_keys = route.request_keys - {"BodySha256"} | ({"Body"} if route.method == "put_object" else set())
    if route.service == "s3" and route.method != "create_bucket":
        sdk_keys |= {"ExpectedBucketOwner"}
        assert writes[0][2]["ExpectedBucketOwner"] == provider.AUTHORITY_ACCOUNT_ID
    assert set(writes[0][2]) == sdk_keys
    with pytest.raises(provider.UpstreamProviderError, match="OPERATION_ATTEMPT_CONSUMED"):
        transport.dispatch_once(operation)
    assert len([call for call in calls if call[:2] == (route.service, route.method)]) == 1


def test_all_closed_request_fields_exist_in_native_sdk_models():
    for route in provider.OPERATION_ROUTES.values():
        model = _model(route.service, route.api_name)
        assert route.request_keys - {"BodySha256"} <= model.input_shape.members.keys()
        if route.service == "s3" and route.method != "create_bucket":
            assert "ExpectedBucketOwner" in model.input_shape.members
    for projection in provider.READBACK_PROJECTIONS.values():
        model = _model(projection.service, projection.api_name)
        assert projection.request_keys <= model.input_shape.members.keys()


@pytest.mark.parametrize("field,value", [
    ("operation_id", "DELETE_EVERYTHING"), ("phase", "ACTIVATOR"),
    ("account_id", "905418363887"), ("region", "eu-west-1"),
    ("request_digest", "sha256:" + "0" * 64),
])
def test_operation_binding_rejected_before_any_mutation(field, value):
    transport, operation, calls, _responses, _clients = _setup()
    with pytest.raises(provider.UpstreamProviderError):
        transport.dispatch_once(replace(operation, **{field: value}))
    assert len(calls) == 1


def test_unknown_request_field_rejected_even_with_rehashed_digest():
    transport, operation, calls, _responses, _clients = _setup()
    request = {**operation.request, "EndpointUrl": "https://untrusted.invalid"}
    with pytest.raises(provider.UpstreamProviderError, match="OPERATION_REQUEST_FIELDS_INVALID"):
        transport.dispatch_once(replace(operation, request=request, request_digest=provider.digest(request)))
    assert len(calls) == 1


@pytest.mark.parametrize("change", [
    {"method": "delete_key"}, {"projection": "arbitrary.jmespath"},
    {"request": {"KeyId": "x", "extra": "bad"}},
    {"expected_projection": {}},
])
def test_readback_escape_rejected_before_write(change):
    transport, operation, calls, _responses, _clients = _setup()
    with pytest.raises(provider.UpstreamProviderError):
        transport.dispatch_once(replace(operation, readbacks=(replace(operation.readbacks[0], **change),)))
    assert len(calls) == 1


def test_absence_is_read_only_and_distinct_from_access_denied():
    transport, operation, calls, _responses, clients = _setup()
    readback = replace(operation.before_readbacks[0], expected_projection={"absence": "NotFoundException"})
    clients["kms"].errors["kms", "get_key_rotation_status"] = ClientError({"Error": {"Code": "NotFoundException", "Message": "never expose"}}, "GetKeyRotationStatus")
    result = transport.observe(replace(operation, before_readbacks=(readback,)))
    assert result.status == "OBSERVED"
    assert len(calls) == 2
    clients["kms"].errors["kms", "get_key_rotation_status"] = ClientError({"Error": {"Code": "AccessDeniedException", "Message": "secret marker"}}, "GetKeyRotationStatus")
    with pytest.raises(provider.UpstreamProviderError, match="READBACK_FAILED") as failure:
        transport.observe(operation)
    assert "secret marker" not in str(failure.value)


def test_timeout_consumes_attempt_and_never_retries_or_exposes_message():
    transport, operation, calls, _responses, clients = _setup()
    clients["kms"].errors["kms", "enable_key_rotation"] = TimeoutError("secret marker")
    result = transport.dispatch_once(operation)
    assert result.status == "AMBIGUOUS"
    assert "secret marker" not in repr(result)
    with pytest.raises(provider.UpstreamProviderError, match="OPERATION_ATTEMPT_CONSUMED"):
        transport.dispatch_once(operation)
    assert sum(call[1] == "enable_key_rotation" for call in calls) == 1


def test_async_ack_without_terminal_readback_is_ambiguous():
    transport, operation, calls, responses, _clients = _setup("GUG377_OP_28_BROKER_START_SIGNING_JOB")
    responses["signer", "start_signing_job"] = {"jobId": "a" * 36}
    responses["signer", "describe_signing_job"] = {"jobId": "a" * 36, "status": "UNRECOGNIZED"}
    assert transport.dispatch_once(operation).status == "AMBIGUOUS"
    assert sum(call[1] == "start_signing_job" for call in calls) == 1


def test_async_pending_can_only_poll_bounded_exact_readbacks():
    transport, operation, calls, responses, _clients = _setup("GUG377_OP_28_BROKER_START_SIGNING_JOB")
    responses["signer", "describe_signing_job"]["status"] = "InProgress"
    assert transport.dispatch_once(operation).status == "PENDING"
    changed = replace(operation, target_state_digest=provider.digest("substitute"))
    with pytest.raises(provider.UpstreamProviderError, match="READBACK_ATTEMPT_BINDING_MISMATCH"):
        transport.poll_readbacks(changed)
    for _ in range(provider._MAX_POLLS):
        assert transport.poll_readbacks(operation).status == "PENDING"
    with pytest.raises(provider.UpstreamProviderError, match="READBACK_POLL_LIMIT"):
        transport.poll_readbacks(operation)
    assert sum(call[1] == "start_signing_job" for call in calls) == 1


def test_after_readback_pagination_never_certifies_partial_result():
    transport, operation, _calls, responses, _clients = _setup()
    responses["kms", "get_key_rotation_status"]["NextToken"] = "private-cursor"
    assert transport.dispatch_once(operation).status == "AMBIGUOUS"


def test_missing_readback_anchor_never_succeeds_even_expected_none():
    transport, operation, _calls, responses, _clients = _setup()
    responses["kms", "get_key_rotation_status"] = {}
    readback = replace(operation.readbacks[0], expected_projection={field: None for field in operation.readbacks[0].expected_projection})
    assert transport.dispatch_once(replace(operation, readbacks=(readback,))).status == "AMBIGUOUS"


def test_generated_output_is_bound_into_exact_readback_and_expected_value():
    transport, operation, calls, responses, _clients = _setup("GUG377_OP_15_CREATE_KMS_KEY")
    key_id = "755700ab-1cd4-472f-8642-3ba9cb35dadb"
    arn = "arn:aws:kms:us-east-1:042360977644:key/" + key_id
    responses["kms", "create_key"] = {"KeyMetadata": {"KeyId": key_id, "Arn": arn}}
    responses["kms", "describe_key"]["KeyMetadata"].update(KeyId=key_id, Arn=arn)
    original = operation.readbacks[0]
    after = replace(original, request={"KeyId": {"response_field": "KeyMetadata.KeyId"}},
                    expected_projection={**original.expected_projection, "KeyMetadata.KeyId": {"response_field": "KeyMetadata.KeyId"}, "KeyMetadata.Arn": {"response_field": "KeyMetadata.Arn"}})
    result = transport.dispatch_once(replace(operation, readbacks=(after,)))
    assert result.status == "SUCCEEDED"
    assert calls[-1][2]["KeyId"] == key_id
    evidence = transport.private_evidence(operation.operation_id)
    evidence["response"].clear()
    assert transport.private_evidence(operation.operation_id)["response"]


def test_initial_identity_mismatch_stops_before_other_api():
    transport, _operation, calls, responses, clients = _setup()
    responses["sts", "get_caller_identity"]["Account"] = "905418363887"
    calls.clear()
    with pytest.raises(provider.UpstreamProviderError, match="PROVIDER_IDENTITY_MISMATCH"):
        provider.UpstreamLiveProvider(clients=clients, expected_account_id=transport._account,
                                     expected_caller_arn=transport._caller, region=provider.REGION)
    assert [call[1] for call in calls] == ["get_caller_identity"]


def test_identity_is_revalidated_immediately_before_each_write():
    transport, operation, calls, responses, _clients = _setup()
    responses["sts", "get_caller_identity"]["Arn"] += "changed"
    with pytest.raises(provider.UpstreamProviderError, match="PROVIDER_IDENTITY_MISMATCH"):
        transport.dispatch_once(operation)
    assert all(call[1] == "get_caller_identity" for call in calls)


@pytest.mark.parametrize("invalid,code", [
    ({"endpoint": "http://kms.us-east-1.amazonaws.com"}, "PROVIDER_ENDPOINT_INVALID"),
    ({"endpoint": "https://untrusted.invalid"}, "PROVIDER_ENDPOINT_INVALID"),
    ({"retries": {"total_max_attempts": 2}}, "PROVIDER_RETRIES_INVALID"),
    ({"verify": False}, "PROVIDER_TLS_INVALID"),
])
def test_client_security_settings_fail_closed(invalid, code):
    transport, *_ = _setup()
    client = SimpleNamespace(meta=SimpleNamespace(
        endpoint_url=invalid.get("endpoint", "https://kms.us-east-1.amazonaws.com"),
        region_name=provider.REGION,
        config=SimpleNamespace(retries=invalid.get("retries", {"total_max_attempts": 1})),
        events=SimpleNamespace(register_first=lambda *_: None)),
        _endpoint=SimpleNamespace(http_session=SimpleNamespace(_verify=invalid.get("verify", True))))
    with pytest.raises(provider.UpstreamProviderError, match=code):
        transport._validate_client("kms", client)


def test_second_wire_request_is_rejected_including_redirect_retries():
    transport, *_ = _setup()
    transport._current_wire_service = "s3"
    request = SimpleNamespace(url="https://s3.us-east-1.amazonaws.com/bucket/key")
    transport._before_send(request)
    with pytest.raises(provider.UpstreamProviderError, match="PROVIDER_RETRY_FORBIDDEN"):
        transport._before_send(request)


def test_injected_transport_never_claims_live_provider_certification():
    transport, *_ = _setup()
    assert transport.identity()["mode"] == "SYNTHETIC"
    assert transport.identity()["live_provider_evidence"] is False


def test_executor_gate_runs_after_sts_and_directly_before_write():
    transport, operation, calls, _responses, _clients = _setup()
    def gate():
        assert calls[-1][1] == "get_caller_identity"
        calls.append(("executor", "external_gate", {}))
    assert transport.dispatch_once(operation, before_mutation=gate).status == "SUCCEEDED"
    index = next(index for index, call in enumerate(calls) if call[1] == "external_gate")
    assert calls[index + 1][1] == "enable_key_rotation"


def test_gate_rejection_consumes_local_attempt_without_write():
    transport, operation, calls, _responses, _clients = _setup()
    def gate():
        raise ValueError("private authorization details")
    with pytest.raises(provider.UpstreamProviderError, match="PRE_MUTATION_GATE_REJECTED") as failure:
        transport.dispatch_once(operation, before_mutation=gate)
    assert "private authorization" not in str(failure.value)
    assert all(call[1] == "get_caller_identity" for call in calls)
    with pytest.raises(provider.UpstreamProviderError, match="OPERATION_ATTEMPT_CONSUMED"):
        transport.dispatch_once(operation)


def test_invalid_native_nested_request_fails_before_provider_call():
    transport, operation, calls, _responses, _clients = _setup()
    request = {**operation.request, "RotationPeriodInDays": "wrong-type"}
    with pytest.raises(provider.UpstreamProviderError, match="SDK_REQUEST_INVALID"):
        transport.dispatch_once(replace(operation, request=request, request_digest=provider.digest(request)))
    assert len(calls) == 1


def test_artifact_bytes_must_match_digest_length_and_checksum():
    transport, operation, calls, _responses, _clients = _setup("GUG377_OP_27_BROKER_PUT_UNSIGNED_OBJECT")
    transport._artifacts["sha256:" + operation.request["BodySha256"]] = b"substitute"
    with pytest.raises(provider.UpstreamProviderError, match="ARTIFACT_CONTENT_MISMATCH"):
        transport.dispatch_once(operation)
    assert len(calls) == 1


def test_async_request_id_binding_is_compatible_with_native_sdk_shape():
    transport, operation, calls, responses, _clients = _setup("GUG377_OP_10_CLASSIFIER_CREATE_ACCOUNT_ASSIGNMENT")
    request_id = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
    responses["sso-admin", "create_account_assignment"] = {"AccountAssignmentCreationStatus": {"RequestId": request_id}}
    responses["sso-admin", "describe_account_assignment_creation_status"]["AccountAssignmentCreationStatus"]["RequestId"] = request_id
    original = operation.readbacks[0]
    after = replace(original, request={**original.request, "AccountAssignmentCreationRequestId": {"response_field": "AccountAssignmentCreationStatus.RequestId"}},
                    expected_projection={**original.expected_projection, "AccountAssignmentCreationStatus.RequestId": {"response_field": "AccountAssignmentCreationStatus.RequestId"}})
    assert transport.dispatch_once(replace(operation, readbacks=(after,))).status == "SUCCEEDED"
    assert calls[-1][2]["AccountAssignmentCreationRequestId"] == request_id


def test_source_policy_object_serializes_only_at_sdk_boundary():
    transport, operation, calls, _responses, _clients = _setup("GUG377_OP_08_CLASSIFIER_PUT_INLINE_POLICY")
    document = {"Version": "2012-10-17", "Statement": []}
    request = {**operation.request, "InlinePolicy": document}
    operation = replace(operation, request=request, request_digest=provider.digest(request))
    assert transport.dispatch_once(operation).status == "SUCCEEDED"
    mutation = next(call for call in calls if call[1] == "put_inline_policy_to_permission_set")
    assert mutation[2]["InlinePolicy"] == provider._json(document)
    assert operation.request["InlinePolicy"] == document


def test_caller_mutation_during_gate_cannot_change_write_or_readback():
    transport, operation, calls, _responses, _clients = _setup()
    expected_key = operation.request["KeyId"]
    def gate():
        operation.request["KeyId"] = "changed"
        operation.readbacks[0].request["KeyId"] = "changed"
    assert transport.dispatch_once(operation, before_mutation=gate).status == "SUCCEEDED"
    assert next(call for call in calls if call[1] == "enable_key_rotation")[2]["KeyId"] == expected_key
    assert calls[-1][2]["KeyId"] != "changed"


@pytest.mark.parametrize("identifier,field", [
    ("GUG377_OP_10_CLASSIFIER_CREATE_ACCOUNT_ASSIGNMENT", "TargetId"),
    ("GUG377_OP_12_CLASSIFIER_PROVISION_PERMISSION_SET", "TargetId"),
    ("GUG377_OP_28_BROKER_START_SIGNING_JOB", "profileOwner"),
])
def test_management_session_cannot_redirect_authority_operations_to_production(identifier, field):
    transport, operation, calls, _responses, _clients = _setup(identifier)
    request = {**operation.request, field: "905418363887"}
    with pytest.raises(provider.UpstreamProviderError, match="OPERATION_TARGET_ACCOUNT_INVALID"):
        transport.dispatch_once(replace(operation, request=request, request_digest=provider.digest(request)))
    assert len(calls) == 1


@pytest.mark.parametrize("boundary", ["identity", "readback", "gate"])
def test_sanitized_exception_traceback_never_exposes_provider_or_gate_message(boundary):
    transport, operation, calls, _responses, clients = _setup()
    marker = "synthetic-" + "private-message-" + boundary
    private_error = ValueError(marker)
    def rejected_gate():
        raise private_error
    if boundary == "identity":
        clients["sts"].errors["sts", "get_caller_identity"] = private_error
        invoke = lambda: transport.dispatch_once(operation)
    elif boundary == "readback":
        clients["kms"].errors["kms", "get_key_rotation_status"] = private_error
        invoke = lambda: transport.observe(operation)
    else:
        invoke = lambda: transport.dispatch_once(operation, before_mutation=rejected_gate)
    with pytest.raises(provider.UpstreamProviderError) as failure:
        invoke()
    rendered = "".join(traceback.format_exception(failure.value))
    assert marker not in rendered
    assert failure.value.__suppress_context__ is True
    assert not any(call[1] == "enable_key_rotation" for call in calls)


@pytest.mark.parametrize("identifier", list(provider.OPERATION_ROUTES))
def test_public_preclaim_validation_is_offline_and_has_no_side_effects(identifier):
    transport, operation, calls, _responses, _clients = _setup(identifier)
    before = list(calls)
    transport.validate_operation(operation)
    assert calls == before
    assert transport._attempts == {}
    assert transport._evidence == {}


@pytest.mark.parametrize("location", ["request", "expected_projection"])
@pytest.mark.parametrize("field", ["VersionId", "PermissionSet.PermissionSetArn", "KeyMetadata.Missing"])
def test_impossible_generated_binding_is_rejected_before_claim_gate_or_mutation(location, field):
    transport, operation, calls, _responses, _clients = _setup("GUG377_OP_15_CREATE_KMS_KEY")
    after = operation.readbacks[0]
    if location == "request":
        after = replace(after, request={"KeyId": {"response_field": field}})
    else:
        after = replace(after, expected_projection={**after.expected_projection, "KeyMetadata.KeyId": {"response_field": field}})
    operation = replace(operation, readbacks=(after,))
    gates = []
    with pytest.raises(provider.UpstreamProviderError, match="READBACK_RESPONSE_BINDING_INVALID"):
        transport.validate_operation(operation)
    with pytest.raises(provider.UpstreamProviderError, match="READBACK_RESPONSE_BINDING_INVALID"):
        transport.dispatch_once(operation, before_mutation=lambda: gates.append(True))
    assert gates == []
    assert transport._attempts == {}
    assert len(calls) == 1


@pytest.mark.parametrize("stage", ["before_readbacks", "readbacks"])
@pytest.mark.parametrize("owner", [None, "905418363887"])
def test_s3_readbacks_require_exact_authority_owner_before_write(stage, owner):
    transport, operation, calls, _responses, _clients = _setup("GUG377_OP_27_BROKER_PUT_UNSIGNED_OBJECT")
    readback = getattr(operation, stage)[0]
    request = dict(readback.request)
    if owner is None:
        request.pop("ExpectedBucketOwner")
    else:
        request["ExpectedBucketOwner"] = owner
    operation = replace(operation, **{stage: (replace(readback, request=request),)})
    with pytest.raises(provider.UpstreamProviderError, match="READBACK_TARGET_ACCOUNT_INVALID"):
        transport.validate_operation(operation)
    with pytest.raises(provider.UpstreamProviderError, match="READBACK_TARGET_ACCOUNT_INVALID"):
        transport.dispatch_once(operation)
    assert len(calls) == 1


def test_s3_write_without_native_owner_guard_fails_before_mutation(monkeypatch):
    transport, operation, calls, _responses, _clients = _setup("GUG377_OP_27_BROKER_PUT_UNSIGNED_OBJECT")
    original = provider._sdk_operation_model
    def model_without_guard(service, api):
        model = original(service, api)
        if service == "s3" and api == "PutObject":
            return SimpleNamespace(input_shape=SimpleNamespace(members={key: value for key, value in model.input_shape.members.items() if key != "ExpectedBucketOwner"}))
        return model
    monkeypatch.setattr(provider, "_sdk_operation_model", model_without_guard)
    with pytest.raises(provider.UpstreamProviderError, match="S3_OWNER_GUARD_UNAVAILABLE"):
        transport.dispatch_once(operation)
    assert len(calls) == 1


def test_open_pins_packaged_models_before_credentials_and_client_creation(monkeypatch, tmp_path):
    import boto3
    import botocore.client
    import botocore.session

    # The override is synthetic and temporary. No real AWS config, credentials,
    # user model directories, SSO cache, or network transport is read here.
    override = tmp_path / "models"
    model = provider._packaged_model_loader().load_service_model("sts", "service-2")
    model["operations"]["GetCallerIdentity"]["http"]["requestUri"] = "/fixture-override"
    model_path = override / "sts" / model["metadata"]["apiVersion"] / "service-2.json"
    model_path.parent.mkdir(parents=True)
    model_path.write_text(json.dumps(model), encoding="utf-8")
    monkeypatch.setattr(Loader, "CUSTOMER_DATA_PATH", str(override))
    assert Loader().load_service_model("sts", "service-2")["operations"]["GetCallerIdentity"]["http"]["requestUri"] == "/fixture-override"
    monkeypatch.setattr(provider.os, "environ", {})
    account = provider.AUTHORITY_ACCOUNT_ID
    caller = f"arn:aws:sts::{account}:assumed-role/AWSReservedSSO_Test_0123456789abcdef/operator"
    events = []
    original_core = botocore.session.Session
    original_boto_session = boto3.Session

    def core_session():
        core = original_core()
        core.set_config_variable("config_file", str(tmp_path / "no-config"))
        core.set_config_variable("credentials_file", str(tmp_path / "no-credentials"))
        core._config = {"profiles": {"fixture": {"sso_account_id": account, "sso_role_name": "Test", "sso_start_url": "https://fixture.invalid/start", "sso_region": provider.REGION}}}
        return core

    def pinned_boto_session(**kwargs):
        core = kwargs["botocore_session"]
        loader = core.get_component("data_loader")
        assert str(override) not in loader.search_paths
        assert loader.load_service_model("sts", "service-2")["operations"]["GetCallerIdentity"]["http"]["requestUri"] == "/"
        events.append("loader-pinned")
        session = original_boto_session(**kwargs)
        def fixture_credentials():
            events.append("credentials")
            return SimpleNamespace(method="sso", get_frozen_credentials=lambda: SimpleNamespace(access_key="synthetic-access", secret_key="synthetic-secret", token="synthetic-token"))
        monkeypatch.setattr(session, "get_credentials", fixture_credentials)
        return session

    def fixture_api_call(client, operation_name, api_params):
        events.append("client-call")
        assert client.meta.service_model.operation_model(operation_name).http["requestUri"] == "/"
        assert operation_name == "GetCallerIdentity" and api_params == {}
        return {"Account": account, "Arn": caller}

    monkeypatch.setattr(botocore.session, "Session", core_session)
    monkeypatch.setattr(boto3, "Session", pinned_boto_session)
    monkeypatch.setattr(botocore.client.BaseClient, "_make_api_call", fixture_api_call)
    transport = provider.UpstreamLiveProvider.open(profile="fixture", expected_account_id=account, expected_caller_arn=caller)
    try:
        assert events == ["loader-pinned", "credentials", "client-call"]
        assert transport.mode == "AWS_TRANSPORT"
        assert transport.identity()["live_provider_evidence"] is False
    finally:
        transport.close()
