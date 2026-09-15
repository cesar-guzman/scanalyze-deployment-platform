"""Real registry/ACCOUNT_READY gates with an in-memory, no-network DDB port."""
from copy import deepcopy
from datetime import timedelta
from types import SimpleNamespace

import pytest

from tests.test_deployment import test_gug122_backend_authorization as fixture
from tooling.authorize_deployment_backend import AuthorizationError, authorize_backendless_gate, canonical_digest
from tooling.deployment_registry_io import (
    RegistryConflict, RegistryOutcomeUncertain,
    publish_registry_create, publish_registry_update, retrieve_registry_anchor,
)


TABLE = "arn:aws:dynamodb:us-east-1:999888777666:table/scanalyze-deployment-registry"
METADATA = {"HTTPStatusCode": 200, "RetryAttempts": 0}
NOW = fixture.NOW


def av(value):
    if isinstance(value, dict):
        return {"M": {key: av(item) for key, item in value.items()}}
    if type(value) is int:
        return {"N": str(value)}
    return {"S": value}


class ConditionalFailure(Exception):
    response = {"Error": {"Code": "ConditionalCheckFailedException"},
                "ResponseMetadata": {"HTTPStatusCode": 400, "RetryAttempts": 0}}


class Client:
    def __init__(self, record=None):
        self.item = av(record)["M"] if record else None
        self.calls = []
        self.before_put = lambda client: None
        self.after_put = lambda client: None
        self.on_get = lambda client: None
        self.put_response = None
        self.get_response = None
        self.meta = SimpleNamespace(
            region_name="us-east-1", endpoint_url="https://dynamodb.us-east-1.amazonaws.com",
            config=SimpleNamespace(retries={"total_max_attempts": 1}),
            service_model=SimpleNamespace(service_name="dynamodb"),
        )

    def get_item(self, **request):
        self.calls.append(("get_item", deepcopy(request)))
        assert request["TableName"] == TABLE
        assert request["ConsistentRead"] is True
        assert request["Key"] == {"deployment_id": {"S": fixture.DEPLOYMENT_ID}}
        assert set(request) == {"TableName", "Key", "ConsistentRead"}
        self.on_get(self)
        if self.get_response is not None:
            return deepcopy(self.get_response)
        return {"ResponseMetadata": deepcopy(METADATA), **({"Item": deepcopy(self.item)} if self.item else {})}

    def put_item(self, **request):
        self.calls.append(("put_item", deepcopy(request)))
        assert request["TableName"] == TABLE
        assert request["ReturnValues"] == "ALL_OLD"
        assert request["ReturnValuesOnConditionCheckFailure"] == "NONE"
        self.before_put(self)
        # Evaluate the actual emitted condition, including each equality, instead
        # of mocking prepare_registry_update or trusting only a success flag.
        condition = request["ConditionExpression"]
        if condition == "attribute_not_exists(deployment_id)":
            if self.item is not None:
                raise ConditionalFailure
            assert "ExpressionAttributeValues" not in request
            assert "ExpressionAttributeNames" not in request
        else:
            for clause in condition.split(" AND "):
                field, token = clause.split(" = ")
                field = request.get("ExpressionAttributeNames", {}).get(field, field)
                if self.item is None or self.item.get(field) != request["ExpressionAttributeValues"][token]:
                    raise ConditionalFailure
        old = deepcopy(self.item)
        self.item = deepcopy(request["Item"])
        self.after_put(self)
        if self.put_response is not None:
            return deepcopy(self.put_response)
        return {"ResponseMetadata": deepcopy(METADATA), **({"Attributes": old} if old else {})}


def baseline_and_target(version=1):
    baseline = fixture._account_ready()
    target = fixture._target_v2(baseline)
    target["registry_version"] = version
    redigest(target)
    return baseline, target


def redigest(target):
    target["record_digest"] = fixture._digest(target, "record_digest")


def operation(target, baseline, action="create", previous=None):
    return {
        "schema_version": "deployment-registry-operation.v1", "operation": action,
        "authority_account_id": "999888777666", "authority_region": "us-east-1",
        "registry_table_arn": TABLE,
        "valid_from": "2026-07-14T17:55:00Z", "expires_at": "2026-07-14T18:05:00Z",
        "expected_anchor": fixture._anchor(target),
        "previous_anchor": fixture._anchor(previous) if previous else None,
        "account_ready_anchor": {
            **{field: baseline[field] for field in ("customer_id", "deployment_id", "account_id", "region", "environment", "baseline_version")},
            "expected_contract_digest": baseline["contract_digest"],
        },
    }


def arguments(client, authority, baseline, target=None):
    result = dict(client=client, authority=authority, account_ready=baseline,
                  expected_authority_digest=canonical_digest(authority), clock=lambda: NOW)
    if target is not None:
        result["record"] = target
    return result


def test_create_and_independent_read_return_only_existing_anchor_schema():
    baseline, target = baseline_and_target()
    client = Client()
    expected = fixture._anchor(target)
    anchor = publish_registry_create(**arguments(client, operation(target, baseline), baseline, target))
    assert anchor == expected
    assert [call[0] for call in client.calls] == ["put_item", "get_item"]
    assert client.item == av(target)["M"]
    # A consumer uses the real backendless gate after receiving the anchor over
    # its separately authenticated channel; the adapter adds no status override.
    result = authorize_backendless_gate(manifest=fixture._manifest(), target=target,
                                       anchor=anchor, account_ready=baseline)
    assert result["expected_contract_digest"] == baseline["contract_digest"]
    read_op = operation(target, baseline, "read")
    assert retrieve_registry_anchor(**arguments(client, read_op, baseline)) == expected
    assert client.calls[-1][0] == "get_item"


@pytest.mark.parametrize("schema_version", ["1", "2"])
def test_update_preserves_real_cas_and_replay_fails_without_another_write(schema_version):
    baseline, current = baseline_and_target(7)
    if schema_version == "1":
        current["schema_version"] = "1"
        current.pop("runtime_origin")
        redigest(current)
    target = deepcopy(current)
    target.update(registry_version=8, status="ACTIVE")
    redigest(target)
    client = Client(current)
    args = arguments(client, operation(target, baseline, "update", current), baseline, target)
    assert publish_registry_update(**args) == fixture._anchor(target)
    assert [call[0] for call in client.calls] == ["get_item", "put_item", "get_item"]
    write = client.calls[1][1]
    assert write["ExpressionAttributeValues"][":expected_version"] == {"N": "7"}
    assert write["ExpressionAttributeValues"][":expected_digest"] == {"S": current["record_digest"]}
    with pytest.raises(AuthorizationError, match="approved anchor"):
        publish_registry_update(**args)
    assert len([call for call in client.calls if call[0] == "put_item"]) == 1


def test_create_replay_is_conflict_even_if_identical():
    baseline, target = baseline_and_target()
    client = Client(target)
    with pytest.raises(RegistryConflict):
        publish_registry_create(**arguments(client, operation(target, baseline), baseline, target))
    assert [call[0] for call in client.calls] == ["put_item"]
    assert client.item == av(target)["M"]


def test_only_same_status_v1_to_v2_migration_is_supported():
    baseline, current = baseline_and_target(7)
    target = deepcopy(current)
    current["schema_version"] = "1"
    current.pop("runtime_origin")
    redigest(current)
    target["registry_version"] = 8
    redigest(target)
    client = Client(current)
    assert publish_registry_update(**arguments(client, operation(target, baseline, "update", current), baseline, target)) == fixture._anchor(target)
    assert client.calls[1][1]["ExpressionAttributeValues"][":expected_schema_version"] == {"S": "1"}


@pytest.mark.parametrize("mutation", ["target", "authority", "table", "new_pin_in_operation", "baseline", "missing_pin", "request_hash"])
def test_untrusted_mutations_fail_before_any_io(mutation):
    baseline, target = baseline_and_target()
    client = Client()
    auth = operation(target, baseline)
    args = arguments(client, auth, baseline, target)
    if mutation == "target":
        target["runtime_origin"]["domain_name"] = "substituted.synthetic.example"
        redigest(target)
    elif mutation == "authority":
        auth["expected_anchor"]["record_digest"] = "sha256:" + "f" * 64
    elif mutation == "table":
        auth["registry_table_arn"] = TABLE.replace("999888777666", "555666777888")
    elif mutation == "new_pin_in_operation":
        auth["expected_authority_digest"] = canonical_digest(auth)
    elif mutation == "baseline":
        baseline["controls"]["state_public_access_blocked"] = False
        baseline["contract_digest"] = fixture._digest(baseline, "contract_digest")
    elif mutation == "request_hash":
        args["expected_authority_digest"] = target["record_digest"]
    else:
        args["expected_authority_digest"] = None
    with pytest.raises(AuthorizationError):
        publish_registry_create(**args)
    assert client.calls == []


@pytest.mark.parametrize("mutation", ["control", "role", "tuple", "state", "runtime_origin", "transition", "version", "unknown_record", "migration_status"])
def test_real_gates_reject_even_when_proposed_change_was_pinned(mutation):
    baseline, current = baseline_and_target(7)
    target = deepcopy(current)
    target.update(registry_version=8, status="ACTIVE")
    if mutation == "control":
        baseline["controls"]["native_lockfile_enabled"] = False
        baseline["contract_digest"] = fixture._digest(baseline, "contract_digest")
    elif mutation == "role":
        baseline["roles"]["apply"]["account_id_tag"] = "555666777888"
        baseline["contract_digest"] = fixture._digest(baseline, "contract_digest")
    elif mutation == "tuple":
        target["customer_id"] = target["customer_id"][:-1] + "2"
    elif mutation == "state":
        target["state_binding"]["state_bucket"] = "arn:aws:s3:::substituted-state-bucket"
    elif mutation == "runtime_origin":
        target["runtime_origin"]["domain_name"] = "substituted.synthetic.example"
    elif mutation == "transition":
        target["status"] = "ARCHIVED"
    elif mutation == "version":
        target["registry_version"] = 9
    elif mutation == "unknown_record":
        target["execution_lock"] = "unexpected-sidecar"
    else:
        current["schema_version"] = "1"
        current.pop("runtime_origin")
        redigest(current)
    redigest(target)
    client = Client(current)
    with pytest.raises(AuthorizationError):
        publish_registry_update(**arguments(client, operation(target, baseline, "update", current), baseline, target))
    assert not any(call[0] == "put_item" for call in client.calls)


@pytest.mark.parametrize("fault", ["timeout_before_write", "timeout_after_write", "bad_http", "sdk_retry", "bool_retry", "ambiguous_conflict", "readback_missing", "readback_digest", "readback_same_digest", "readback_version", "readback_number", "unknown_attribute", "old_response"])
def test_ambiguous_or_substituted_outcome_never_returns_anchor_or_retries(fault):
    baseline, target = baseline_and_target()
    client = Client()

    def timeout(_client):
        raise TimeoutError("synthetic sensitive backend body must not escape")

    if fault == "timeout_before_write":
        client.before_put = timeout
    elif fault == "timeout_after_write":
        client.after_put = timeout
    elif fault == "ambiguous_conflict":
        def uncertain_conflict(c):
            error = ConditionalFailure()
            error.response = {"Error": {"Code": "ConditionalCheckFailedException"},
                              "ResponseMetadata": {"HTTPStatusCode": 400, "RetryAttempts": 1}}
            raise error
        client.after_put = uncertain_conflict
    elif fault in {"bad_http", "sdk_retry", "bool_retry", "old_response"}:
        client.put_response = {"ResponseMetadata": dict(METADATA)}
        if fault == "bad_http":
            client.put_response["ResponseMetadata"]["HTTPStatusCode"] = 500
        elif fault == "sdk_retry":
            client.put_response["ResponseMetadata"]["RetryAttempts"] = 1
        elif fault == "bool_retry":
            client.put_response["ResponseMetadata"]["RetryAttempts"] = False
        else:
            client.put_response["Attributes"] = av(target)["M"]
    else:
        def corrupt(c):
            if fault == "readback_missing":
                c.item = None
            elif fault == "readback_digest":
                c.item["record_digest"] = {"S": "sha256:" + "e" * 64}
            elif fault == "readback_same_digest":
                c.item["status"] = {"S": "ACTIVE"}
            elif fault == "readback_version":
                c.item["registry_version"] = {"N": "2"}
            elif fault == "readback_number":
                c.item["registry_version"] = {"N": "1.0"}
            else:
                c.item["unknown"] = {"S": "extra"}
        client.on_get = corrupt
    with pytest.raises(RegistryOutcomeUncertain) as error:
        publish_registry_create(**arguments(client, operation(target, baseline), baseline, target))
    assert "sensitive" not in str(error.value)
    assert error.value.__cause__ is None
    assert len([call for call in client.calls if call[0] == "put_item"]) == 1


def test_competing_cas_between_read_and_write_conflicts():
    baseline, current = baseline_and_target(7)
    target = deepcopy(current)
    target.update(registry_version=8, status="ACTIVE")
    redigest(target)
    client = Client(current)
    client.before_put = lambda c: c.item.update(registry_version={"N": "8"})
    with pytest.raises(RegistryConflict):
        publish_registry_update(**arguments(client, operation(target, baseline, "update", current), baseline, target))
    assert [call[0] for call in client.calls] == ["get_item", "put_item"]


@pytest.mark.parametrize("fault", ["retry", "region", "endpoint", "service", "table_partition", "table_account", "table_region", "same_account"])
def test_client_and_table_bindings_are_not_defaults(fault):
    baseline, target = baseline_and_target()
    auth = operation(target, baseline)
    client = Client()
    if fault == "retry":
        client.meta.config.retries = {"max_attempts": 3}
    elif fault == "region":
        client.meta.region_name = "us-west-2"
    elif fault == "endpoint":
        client.meta.endpoint_url = "https://substituted.invalid"
    elif fault == "service":
        client.meta.service_model.service_name = "s3"
    elif fault == "table_partition":
        auth["registry_table_arn"] = TABLE.replace("arn:aws:", "arn:aws-cn:")
    elif fault == "table_account":
        auth["authority_account_id"] = "555666777888"
    elif fault == "table_region":
        auth["authority_region"] = "us-west-2"
    else:
        auth["authority_account_id"] = baseline["account_id"]
        auth["registry_table_arn"] = TABLE.replace("999888777666", baseline["account_id"])
    with pytest.raises(AuthorizationError):
        publish_registry_create(**arguments(client, auth, baseline, target))
    assert client.calls == []


@pytest.mark.parametrize("phase", ["before_read", "before_put", "after_read"])
def test_expiration_is_checked_before_effect_and_after_readback(phase):
    baseline, current = baseline_and_target(7)
    target = deepcopy(current)
    target.update(registry_version=8, status="ACTIVE")
    redigest(target)
    client = Client(current)
    now = [NOW]
    if phase == "before_read":
        now[0] = NOW + timedelta(minutes=6)
    elif phase == "before_put":
        client.on_get = lambda c: now.__setitem__(0, NOW + timedelta(minutes=6))
    else:
        client.after_put = lambda c: now.__setitem__(0, NOW + timedelta(minutes=6))
    args = arguments(client, operation(target, baseline, "update", current), baseline, target)
    args["clock"] = lambda: now[0]
    expected = RegistryOutcomeUncertain if phase == "after_read" else AuthorizationError
    with pytest.raises(expected):
        publish_registry_update(**args)
    writes = [call for call in client.calls if call[0] == "put_item"]
    assert len(writes) == (1 if phase == "after_read" else 0)


def test_caller_callback_cannot_substitute_snapshotted_authority_or_record():
    baseline, current = baseline_and_target(7)
    target = deepcopy(current)
    target.update(registry_version=8, status="ACTIVE")
    redigest(target)
    auth = operation(target, baseline, "update", current)
    expected = fixture._anchor(target)
    original = deepcopy(target)
    client = Client(current)

    def mutate_inputs(c):
        target["runtime_origin"]["domain_name"] = "substituted.synthetic.example"
        auth["registry_table_arn"] = "untrusted-table"
        auth["expected_anchor"]["record_digest"] = "sha256:" + "f" * 64
        baseline["controls"].clear()

    client.on_get = mutate_inputs
    assert publish_registry_update(**arguments(client, auth, baseline, target)) == expected
    assert client.item == av(original)["M"]


@pytest.mark.parametrize("fault", ["missing", "version", "digest", "expired", "metadata"])
def test_anchor_retrieval_is_exact_read_only_and_fails_closed(fault):
    baseline, target = baseline_and_target()
    client = Client(target)
    args = arguments(client, operation(target, baseline, "read"), baseline)
    if fault == "missing":
        client.item = None
    elif fault == "version":
        client.item["registry_version"] = {"N": "2"}
    elif fault == "digest":
        client.item["record_digest"] = {"S": "sha256:" + "e" * 64}
    elif fault == "expired":
        times = iter([NOW, NOW + timedelta(minutes=6)])
        args["clock"] = lambda: next(times)
    else:
        client.get_response = {"Item": av(target)["M"]}
    with pytest.raises(AuthorizationError):
        retrieve_registry_anchor(**args)
    assert [call[0] for call in client.calls] == ["get_item"]


def test_create_version_must_be_one_before_io():
    baseline, target = baseline_and_target(7)
    client = Client()
    with pytest.raises(AuthorizationError, match="version one"):
        publish_registry_create(**arguments(client, operation(target, baseline), baseline, target))
    assert client.calls == []


def test_production_registration_does_not_invent_environment_or_bypass_baseline():
    baseline, target = baseline_and_target()
    baseline["environment"] = target["environment"] = "production"
    for role in baseline["roles"].values():
        role["environment_tag"] = "production"
    baseline["contract_digest"] = fixture._digest(baseline, "contract_digest")
    target["account_ready"]["contract_digest"] = baseline["contract_digest"]
    redigest(target)
    client = Client()
    assert publish_registry_create(**arguments(client, operation(target, baseline), baseline, target)) == fixture._anchor(target)


def test_non_executable_lifecycle_transition_does_not_grant_execution():
    baseline, current = baseline_and_target(7)
    target = deepcopy(current)
    target.update(registry_version=8, status="SUSPENDED")
    redigest(target)
    client = Client(current)
    anchor = publish_registry_update(**arguments(client, operation(target, baseline, "update", current), baseline, target))
    with pytest.raises(AuthorizationError, match="not executable"):
        authorize_backendless_gate(manifest=fixture._manifest(), target=target,
                                   anchor=anchor, account_ready=baseline)
