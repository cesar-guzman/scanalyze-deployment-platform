from __future__ import annotations

import copy
import hashlib
import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

import pytest

from identity_control_plane.aws_adapters import (
    AdapterContractError,
    CognitoExistingUserProvider,
    CognitoSecretsM2MClientProvider,
    DynamoBootstrapRequestStore,
    DynamoM2MBindingStore,
    DynamoMembershipReader,
)
from identity_control_plane.config import (
    ControlRuntimeConfig,
    PreTokenRuntimeConfig,
    RuntimeConfigError,
)
from identity_control_plane.entrypoints import (
    RuntimeUnavailable,
    _ControlDispatcher,
    build_control_processor_entrypoint,
    build_pre_token_entrypoint,
)
from identity_control_plane.pre_token import PreTokenDenied


CUSTOMER_ID = "cust_01HZX3YQ8J4F6A2B7C9D0E1G5K"
DEPLOYMENT_ID = "dep_01HZX3YQ8J4F6A2B7C9D0E1G5K"
SUBJECT = "00000000-0000-4000-8000-000000000001"
USER_POOL_ID = "us-east-1_SYNTHETIC"
CLIENT_ID = "syntheticspaclient"
IDEMPOTENCY_KEY = "idem_01HZX3YQ8J4F6A2B7C9D0E1G5K"
POLICY_DIGEST = f"sha256:{'a' * 64}"
QUEUE_ARN = (
    "arn:aws:sqs:us-east-1:111111111111:"
    "dep_01HZX3YQ8J4F6A2B7C9D0E1G5K-identity-bootstrap.fifo"
)
KMS_ARN = "arn:aws:kms:us-east-1:111111111111:key/00000000-0000-4000-8000-000000000001"
RAW_SECRET_CANARY = "SENSITIVE_CANARY_GENERATED_CLIENT_SECRET"
BODY_CANARY = "SENSITIVE_CANARY_CONTROL_BODY"
NOW = datetime(2026, 7, 13, 12, 0, tzinfo=timezone.utc)


def _env(**overrides: str) -> dict[str, str]:
    env = {
        "AWS_REGION": "us-east-1",
        "CUSTOMER_ID": CUSTOMER_ID,
        "DEPLOYMENT_ID": DEPLOYMENT_ID,
        "USER_POOL_ID": USER_POOL_ID,
        "ALLOWED_CLIENT_IDS": json.dumps([CLIENT_ID]),
        "ALLOWED_ROLE_IDS": json.dumps(
            [
                "auditor",
                "customer_admin",
                "document_operator",
                "document_reviewer",
            ]
        ),
        "AUTHZ_SCHEMA_VERSION": "enterprise-authorization.v1",
        "SCOPE_CATALOG_VERSION": "scanalyze.api.v1",
        "ROLE_CATALOG_VERSION": "enterprise-roles.v1",
        "POLICY_VERSION": "1.0.0",
        "POLICY_DIGEST": POLICY_DIGEST,
        "HUMAN_RUNTIME_ENABLED": "false",
        "MEMBERSHIP_TABLE": "synthetic-memberships",
        "AUTHORIZATION_AUDIT_TABLE": "synthetic-audit",
        "BOOTSTRAP_REQUEST_TABLE": "synthetic-bootstrap",
        "M2M_BINDING_TABLE": "synthetic-m2m",
        "CONTROL_QUEUE_ARN": QUEUE_ARN,
        "IDENTITY_KMS_KEY_ARN": KMS_ARN,
        "SECRET_NAME_PREFIX": f"{DEPLOYMENT_ID}-identity-m2m-",
        "RESOURCE_SERVER_ID": "scanalyze.api.v1",
        "M2M_RUNTIME_ENABLED": "true",
    }
    env.update(overrides)
    return env


class AwsError(RuntimeError):
    def __init__(self, code: str) -> None:
        self.response = {"Error": {"Code": code}}
        super().__init__("synthetic AWS error")


@dataclass
class FakeTable:
    get_response: dict[str, Any] = field(default_factory=dict)
    calls: list[tuple[str, dict[str, Any]]] = field(default_factory=list)

    def get_item(self, **request: Any) -> dict[str, Any]:
        self.calls.append(("get_item", copy.deepcopy(request)))
        return copy.deepcopy(self.get_response)

    def put_item(self, **request: Any) -> dict[str, Any]:
        self.calls.append(("put_item", copy.deepcopy(request)))
        return {}

    def update_item(self, **request: Any) -> dict[str, Any]:
        self.calls.append(("update_item", copy.deepcopy(request)))
        return {}


@dataclass
class FakeDynamoResource:
    tables: dict[str, FakeTable]
    requested: list[str] = field(default_factory=list)

    def Table(self, name: str) -> FakeTable:
        self.requested.append(name)
        return self.tables[name]


@pytest.mark.parametrize(
    ("missing", "legacy_name", "legacy_value"),
    [
        ("CUSTOMER_ID", "X_TENANT_ID", CUSTOMER_ID),
        ("DEPLOYMENT_ID", "TENANT_ID", DEPLOYMENT_ID),
        ("USER_POOL_ID", "COGNITO_POOL", USER_POOL_ID),
        ("ALLOWED_CLIENT_IDS", "CLIENT_ID", CLIENT_ID),
        ("ALLOWED_ROLE_IDS", "ROLE_IDS", "customer_admin"),
    ],
)
def test_required_identity_env_never_uses_legacy_fallback(
    missing: str,
    legacy_name: str,
    legacy_value: str,
) -> None:
    env = _env(**{legacy_name: legacy_value})
    del env[missing]

    with pytest.raises(RuntimeConfigError):
        PreTokenRuntimeConfig.from_env(env)


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("ALLOWED_CLIENT_IDS", CLIENT_ID),
        ("ALLOWED_CLIENT_IDS", json.dumps([CLIENT_ID, CLIENT_ID])),
        ("ALLOWED_ROLE_IDS", json.dumps(["customer_admin"])),
        (
            "ALLOWED_ROLE_IDS",
            json.dumps(
                [
                    "auditor",
                    "customer_admin",
                    "document_operator",
                    "document_reviewer",
                    "superuser",
                ]
            ),
        ),
        ("HUMAN_RUNTIME_ENABLED", "False"),
    ],
)
def test_identity_env_lists_and_flags_are_strict(name: str, value: str) -> None:
    with pytest.raises(RuntimeConfigError):
        PreTokenRuntimeConfig.from_env(_env(**{name: value}))


def test_disabled_human_runtime_accepts_only_explicit_unbound_bootstrap() -> None:
    config = PreTokenRuntimeConfig.from_env(
        _env(USER_POOL_ID="UNBOUND", ALLOWED_CLIENT_IDS="[]")
    )

    assert config.human_runtime_enabled is False
    assert config.user_pool_id == "UNBOUND"
    assert config.allowed_client_ids == ()

    with pytest.raises(RuntimeConfigError):
        PreTokenRuntimeConfig.from_env(
            _env(
                USER_POOL_ID="UNBOUND",
                ALLOWED_CLIENT_IDS="[]",
                HUMAN_RUNTIME_ENABLED="true",
            )
        )


def test_control_runtime_rejects_unbound_pool_but_allows_empty_client_registry() -> None:
    config = ControlRuntimeConfig.from_env(_env(ALLOWED_CLIENT_IDS="[]"))
    assert config.base.allowed_client_ids == ()

    with pytest.raises(RuntimeConfigError):
        ControlRuntimeConfig.from_env(
            _env(USER_POOL_ID="UNBOUND", ALLOWED_CLIENT_IDS="[]")
        )


def test_control_env_requires_exact_source_and_provider_configuration() -> None:
    config = ControlRuntimeConfig.from_env(_env())

    assert config.base.user_pool_id == USER_POOL_ID
    assert config.base.allowed_client_ids == (CLIENT_ID,)
    assert frozenset(config.base.allowed_role_ids) == {
        "auditor",
        "customer_admin",
        "document_operator",
        "document_reviewer",
    }
    assert config.control_queue_arn == QUEUE_ARN
    assert config.action_scopes == {
        "read": "scanalyze.api.v1/read",
        "write": "scanalyze.api.v1/write",
        "admin": "scanalyze.api.v1/admin",
    }

    with pytest.raises(RuntimeConfigError):
        ControlRuntimeConfig.from_env(_env(CONTROL_QUEUE_ARN=""))
    with pytest.raises(RuntimeConfigError):
        ControlRuntimeConfig.from_env(_env(RESOURCE_SERVER_ID="legacy.api"))


def test_malformed_control_env_fails_before_constructing_aws_dependencies() -> None:
    class ExplodingDependency:
        def __getattr__(self, name: str) -> Any:
            raise AssertionError(f"dependency must not be used: {name}")

    env = _env()
    del env["USER_POOL_ID"]
    env["LEGACY_USER_POOL_ID"] = USER_POOL_ID

    with pytest.raises(RuntimeConfigError):
        build_control_processor_entrypoint(
            env,
            ExplodingDependency(),
            ExplodingDependency(),
            ExplodingDependency(),
        )


def _pre_token_event() -> dict[str, Any]:
    return {
        "version": "2",
        "triggerSource": "TokenGeneration_Authentication",
        "userPoolId": USER_POOL_ID,
        "callerContext": {"clientId": CLIENT_ID},
        "request": {
            "userAttributes": {
                "sub": SUBJECT,
                "custom:customerId": CUSTOMER_ID,
                "custom:deployment_id": DEPLOYMENT_ID,
            }
        },
        "response": {},
    }


def test_disabled_human_runtime_entrypoint_denies_before_membership_read() -> None:
    membership = FakeTable()
    audit = FakeTable()
    resource = FakeDynamoResource(
        {
            "synthetic-memberships": membership,
            "synthetic-audit": audit,
        }
    )
    handler = build_pre_token_entrypoint(_env(), resource)

    with pytest.raises(PreTokenDenied) as exc_info:
        handler(_pre_token_event(), None)

    assert exc_info.value.reason_code == "human_runtime_disabled"
    assert membership.calls == []
    assert audit.calls[0][0] == "put_item"
    assert audit.calls[0][1]["ConditionExpression"] == (
        "attribute_not_exists(pk) AND attribute_not_exists(sk)"
    )


def test_membership_reader_uses_one_exact_consistent_get() -> None:
    table = FakeTable(get_response={"Item": {"membership_state": "active"}})
    reader = DynamoMembershipReader(table)

    result = reader.get_membership(
        subject=SUBJECT,
        customer_id=CUSTOMER_ID,
        deployment_id=DEPLOYMENT_ID,
    )

    assert result == {"membership_state": "active"}
    assert table.calls == [
        (
            "get_item",
            {
                "Key": {
                    "pk": f"MEMBERSHIP#{DEPLOYMENT_ID}#{CUSTOMER_ID}",
                    "sk": f"SUBJECT#{SUBJECT}",
                },
                "ConsistentRead": True,
            },
        )
    ]


def test_bootstrap_store_claim_and_consume_use_conditional_exact_state() -> None:
    table = FakeTable()
    store = DynamoBootstrapRequestStore(table)

    claim = store.claim(
        request_id="boot_synthetic",
        expected_state="approved",
        expected_version=7,
        idempotency_key=IDEMPOTENCY_KEY,
        claimed_at=NOW,
    )
    assert isinstance(claim, str) and claim
    assert store.consume(
        request_id="boot_synthetic",
        claim_token=claim,
        expected_version=7,
        consumed_at=NOW,
        result_reference="bootstrap_request_completed",
    )

    claim_request = table.calls[0][1]
    consume_request = table.calls[1][1]
    assert "#state = :approved" in claim_request["ConditionExpression"]
    assert "idempotency_key = :idempotency_key" in claim_request[
        "ConditionExpression"
    ]
    assert "claim_token = :claim_token" in consume_request["ConditionExpression"]


def test_m2m_binding_store_binds_partition_and_completion_conditions() -> None:
    table = FakeTable()
    store = DynamoM2MBindingStore(
        table,
        customer_id=CUSTOMER_ID,
        deployment_id=DEPLOYMENT_ID,
    )
    claim = store.claim(
        idempotency_key=IDEMPOTENCY_KEY,
        workload_id="ingest-api",
        environment="production",
        customer_id=CUSTOMER_ID,
        deployment_id=DEPLOYMENT_ID,
        actions=["read", "write"],
        claimed_at=NOW,
    )
    assert isinstance(claim, str) and claim
    reacquired = store.reacquire(
        idempotency_key=IDEMPOTENCY_KEY,
        expected_claim_token=claim,
        expected_claimed_at="2026-07-13T11:54:59Z",
        workload_id="ingest-api",
        environment="production",
        customer_id=CUSTOMER_ID,
        deployment_id=DEPLOYMENT_ID,
        actions=["read", "write"],
        claimed_at=NOW,
    )
    assert isinstance(reacquired, str) and reacquired != claim
    assert store.complete(
        idempotency_key=IDEMPOTENCY_KEY,
        claim_token=reacquired,
        client_id="syntheticclient",
        secret_reference="synthetic-secret-reference",
        workload_id="ingest-api",
        environment="production",
        customer_id=CUSTOMER_ID,
        deployment_id=DEPLOYMENT_ID,
        actions=["read", "write"],
        grant_version="1",
        completed_at=NOW,
    )

    item = table.calls[0][1]["Item"]
    assert item["pk"] == f"M2M#{DEPLOYMENT_ID}#{CUSTOMER_ID}"
    assert item["sk"] == f"IDEMPOTENCY#{IDEMPOTENCY_KEY}"
    reacquire_request = table.calls[1][1]
    complete_request = table.calls[2][1]
    assert "claim_token = :expected_claim_token" in reacquire_request[
        "ConditionExpression"
    ]
    assert "claimed_at = :expected_claimed_at" in reacquire_request[
        "ConditionExpression"
    ]
    assert "customer_id = :customer_id" in complete_request[
        "ConditionExpression"
    ]
    assert "deployment_id = :deployment_id" in complete_request[
        "ConditionExpression"
    ]


@dataclass
class FakeProcessor:
    fail: bool = False
    commands: list[dict[str, Any]] = field(default_factory=list)

    def process(self, command: dict[str, Any]) -> None:
        self.commands.append(command)
        if self.fail:
            raise RuntimeError(BODY_CANARY)

    def provision(self, command: dict[str, Any]) -> None:
        self.commands.append(command)
        if self.fail:
            raise RuntimeError(BODY_CANARY)


def _record(message_id: str, body: dict[str, Any], **overrides: Any) -> dict[str, Any]:
    record = {
        "messageId": message_id,
        "body": json.dumps(body),
        "eventSource": "aws:sqs",
        "eventSourceARN": QUEUE_ARN,
        "awsRegion": "us-east-1",
    }
    record.update(overrides)
    return record


def test_dispatcher_routes_explicit_commands_and_reports_partial_failures(
    caplog: pytest.LogCaptureFixture,
) -> None:
    bootstrap = FakeProcessor()
    m2m = FakeProcessor(fail=True)
    logger = logging.getLogger("scanalyze.identity.dispatcher.test")
    caplog.set_level(logging.INFO, logger=logger.name)
    dispatcher = _ControlDispatcher(
        bootstrap=bootstrap,  # type: ignore[arg-type]
        m2m=m2m,  # type: ignore[arg-type]
        queue_arn=QUEUE_ARN,
        region="us-east-1",
        logger=logger,
    )

    result = dispatcher(
        {
            "Records": [
                _record(
                    "message-bootstrap",
                    {
                        "command_type": "bootstrap",
                        "schema_version": "identity-bootstrap-command.v1",
                    },
                ),
                _record(
                    "message-m2m",
                    {
                        "command_type": "m2m.provision",
                        "schema_version": "identity-m2m-provisioning.v1",
                        "payload": BODY_CANARY,
                    },
                ),
                _record(
                    "message-not-processed",
                    {
                        "command_type": "bootstrap",
                        "schema_version": "identity-bootstrap-command.v1",
                    },
                ),
            ]
        },
        None,
    )

    assert result == {
        "batchItemFailures": [
            {"itemIdentifier": "message-m2m"},
            {"itemIdentifier": "message-not-processed"},
        ]
    }
    assert len(bootstrap.commands) == 1
    assert len(m2m.commands) == 1
    assert BODY_CANARY not in caplog.text
    assert "message-m2m" not in caplog.text


@pytest.mark.parametrize(
    "body",
    [
        {"command_type": "legacy", "schema_version": "legacy.v1"},
        {
            "command_type": "bootstrap",
            "schema_version": "identity-m2m-provisioning.v1",
        },
        {
            "command_type": "m2m.provision",
            "schema_version": "identity-bootstrap-command.v1",
        },
    ],
)
def test_dispatcher_rejects_unknown_or_conflicting_command_contract(
    body: dict[str, Any],
) -> None:
    bootstrap = FakeProcessor()
    m2m = FakeProcessor()
    dispatcher = _ControlDispatcher(
        bootstrap=bootstrap,  # type: ignore[arg-type]
        m2m=m2m,  # type: ignore[arg-type]
        queue_arn=QUEUE_ARN,
        region="us-east-1",
        logger=logging.getLogger("scanalyze.identity.dispatcher.contract.test"),
    )

    assert dispatcher({"Records": [_record("message-invalid", body)]}, None) == {
        "batchItemFailures": [{"itemIdentifier": "message-invalid"}]
    }
    assert bootstrap.commands == []
    assert m2m.commands == []


def test_dispatcher_rejects_foreign_source_before_any_effect() -> None:
    bootstrap = FakeProcessor()
    m2m = FakeProcessor()
    dispatcher = _ControlDispatcher(
        bootstrap=bootstrap,  # type: ignore[arg-type]
        m2m=m2m,  # type: ignore[arg-type]
        queue_arn=QUEUE_ARN,
        region="us-east-1",
        logger=logging.getLogger("scanalyze.identity.dispatcher.foreign.test"),
    )

    with pytest.raises(RuntimeUnavailable):
        dispatcher(
            {
                "Records": [
                    _record(
                        "message-foreign",
                        {
                            "command_type": "bootstrap",
                            "schema_version": "identity-bootstrap-command.v1",
                        },
                        eventSourceARN=QUEUE_ARN.replace("111111111111", "222222222222"),
                    )
                ]
            },
            None,
        )

    assert bootstrap.commands == []
    assert m2m.commands == []


def _client_config(name: str, client_id: str, secret: str) -> dict[str, Any]:
    return {
        "ClientName": name,
        "ClientId": client_id,
        "ClientSecret": secret,
        "ExplicitAuthFlows": ["ALLOW_REFRESH_TOKEN_AUTH"],
        "SupportedIdentityProviders": ["COGNITO"],
        "AllowedOAuthFlows": ["client_credentials"],
        "AllowedOAuthScopes": [
            "scanalyze.api.v1/read",
            "scanalyze.api.v1/write",
        ],
        "AllowedOAuthFlowsUserPoolClient": True,
        "AccessTokenValidity": 15,
        "IdTokenValidity": 5,
        "RefreshTokenValidity": 1,
        "TokenValidityUnits": {
            "AccessToken": "minutes",
            "IdToken": "minutes",
            "RefreshToken": "days",
        },
        "EnableTokenRevocation": True,
        "PreventUserExistenceErrors": "ENABLED",
    }


@dataclass
class FakeCognito:
    clients: dict[str, dict[str, Any]] = field(default_factory=dict)
    calls: list[tuple[str, dict[str, Any]]] = field(default_factory=list)

    def list_user_pool_clients(self, **request: Any) -> dict[str, Any]:
        self.calls.append(("list", copy.deepcopy(request)))
        return {
            "UserPoolClients": [
                {"ClientName": item["ClientName"], "ClientId": item["ClientId"]}
                for item in self.clients.values()
            ]
        }

    def create_user_pool_client(self, **request: Any) -> dict[str, Any]:
        self.calls.append(("create", copy.deepcopy(request)))
        client = _client_config(
            request["ClientName"],
            "syntheticm2mclient",
            RAW_SECRET_CANARY,
        )
        client["AllowedOAuthScopes"] = list(request["AllowedOAuthScopes"])
        self.clients[client["ClientId"]] = client
        return {"UserPoolClient": copy.deepcopy(client)}

    def describe_user_pool_client(self, **request: Any) -> dict[str, Any]:
        self.calls.append(("describe", copy.deepcopy(request)))
        return {"UserPoolClient": copy.deepcopy(self.clients[request["ClientId"]])}

    def delete_user_pool_client(self, **request: Any) -> None:
        self.calls.append(("delete", copy.deepcopy(request)))
        self.clients.pop(request["ClientId"], None)


@dataclass
class FakeSecrets:
    descriptions: dict[str, dict[str, Any]] = field(default_factory=dict)
    calls: list[tuple[str, dict[str, Any]]] = field(default_factory=list)

    def describe_secret(self, **request: Any) -> dict[str, Any]:
        self.calls.append(("describe", copy.deepcopy(request)))
        if request["SecretId"] not in self.descriptions:
            raise AwsError("ResourceNotFoundException")
        return copy.deepcopy(self.descriptions[request["SecretId"]])

    def create_secret(self, **request: Any) -> dict[str, Any]:
        self.calls.append(("create", copy.deepcopy(request)))
        name = request["Name"]
        token = request["ClientRequestToken"]
        arn = (
            "arn:aws:secretsmanager:us-east-1:111111111111:"
            f"secret:{name}-ABC123"
        )
        self.descriptions[name] = {
            "ARN": arn,
            "Name": name,
            "KmsKeyId": request["KmsKeyId"],
            "Tags": copy.deepcopy(request["Tags"]),
            "VersionIdsToStages": {token: ["AWSCURRENT"]},
        }
        return {"ARN": arn, "VersionId": token}

    def put_secret_value(self, **request: Any) -> dict[str, Any]:
        self.calls.append(("put", copy.deepcopy(request)))
        token = request["ClientRequestToken"]
        description = self.descriptions[request["SecretId"]]
        description["VersionIdsToStages"] = {token: ["AWSCURRENT"]}
        return {"ARN": description["ARN"], "VersionId": token}


def _provider(
    cognito: FakeCognito,
    secrets: FakeSecrets,
) -> CognitoSecretsM2MClientProvider:
    return CognitoSecretsM2MClientProvider(
        cognito,
        secrets,
        user_pool_id=USER_POOL_ID,
        customer_id=CUSTOMER_ID,
        deployment_id=DEPLOYMENT_ID,
        secret_name_prefix=f"{DEPLOYMENT_ID}-identity-m2m-",
        kms_key_id=KMS_ARN,
        allowed_scopes=(
            "scanalyze.api.v1/read",
            "scanalyze.api.v1/write",
            "scanalyze.api.v1/admin",
        ),
    )


def _provider_request() -> dict[str, Any]:
    return {
        "workload_id": "ingest-api",
        "environment": "production",
        "customer_id": CUSTOMER_ID,
        "deployment_id": DEPLOYMENT_ID,
        "idempotency_key": IDEMPOTENCY_KEY,
        "scopes": ["scanalyze.api.v1/read", "scanalyze.api.v1/write"],
    }


def test_m2m_adapter_escrows_generated_value_with_deterministic_token(
    caplog: pytest.LogCaptureFixture,
) -> None:
    cognito = FakeCognito()
    secrets = FakeSecrets()
    caplog.set_level(logging.INFO)

    result = _provider(cognito, secrets).ensure_client(**_provider_request())

    expected_token = hashlib.sha256(IDEMPOTENCY_KEY.encode()).hexdigest()
    secret_create = next(request for name, request in secrets.calls if name == "create")
    assert secret_create["SecretString"] == RAW_SECRET_CANARY
    assert secret_create["ClientRequestToken"] == expected_token
    assert secret_create["KmsKeyId"] == KMS_ARN
    assert result["client_id"] == "syntheticm2mclient"
    assert set(result) == {"client_id", "secret_reference"}
    assert RAW_SECRET_CANARY not in repr(result)
    assert RAW_SECRET_CANARY not in caplog.text
    assert all(name != "get_secret_value" for name, _ in secrets.calls)


def test_m2m_adapter_replay_validates_list_describe_and_never_recreates() -> None:
    cognito = FakeCognito()
    secrets = FakeSecrets()
    provider = _provider(cognito, secrets)
    first = provider.ensure_client(**_provider_request())
    cognito.calls.clear()
    secrets.calls.clear()

    second = provider.ensure_client(**_provider_request())

    assert second == first
    assert [name for name, _ in cognito.calls].count("create") == 0
    assert [name for name, _ in cognito.calls] == ["list", "describe"]
    assert [name for name, _ in secrets.calls] == ["describe"]


def test_m2m_adapter_rejects_conflicting_metadata_without_mutation() -> None:
    cognito = FakeCognito()
    secrets = FakeSecrets()
    provider = _provider(cognito, secrets)
    provider.ensure_client(**_provider_request())
    secret_name = next(iter(secrets.descriptions))
    tags = secrets.descriptions[secret_name]["Tags"]
    next(item for item in tags if item["Key"] == "scanalyze:scope-digest")[
        "Value"
    ] = "conflicting"
    cognito.calls.clear()
    secrets.calls.clear()

    with pytest.raises(AdapterContractError):
        provider.ensure_client(**_provider_request())

    assert [name for name, _ in secrets.calls] == ["describe"]
    assert cognito.calls == []


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("KmsKeyId", "arn:aws:kms:us-east-1:111111111111:key/foreign"),
        ("KmsKeyId", None),
        ("Name", "foreign-secret-name"),
        ("ARN", "arn:aws:secretsmanager:us-east-1:111111111111:secret:foreign-ABC123"),
        ("DeletedDate", NOW),
    ],
)
def test_m2m_adapter_rejects_drifted_credential_custody(
    field: str,
    value: object,
) -> None:
    cognito = FakeCognito()
    secrets = FakeSecrets()
    provider = _provider(cognito, secrets)
    provider.ensure_client(**_provider_request())
    secret_name = next(iter(secrets.descriptions))
    secrets.descriptions[secret_name][field] = value
    cognito.calls.clear()
    secrets.calls.clear()

    with pytest.raises(AdapterContractError):
        provider.ensure_client(**_provider_request())

    assert [name for name, _ in secrets.calls] == ["describe"]
    assert cognito.calls == []


def test_m2m_adapter_rejects_foreign_binding_before_provider_calls() -> None:
    cognito = FakeCognito()
    secrets = FakeSecrets()
    request = _provider_request()
    request["customer_id"] = "cust_01HZX3YQ8J4F6A2B7C9D0E1G5M"

    with pytest.raises(AdapterContractError):
        _provider(cognito, secrets).ensure_client(**request)

    assert cognito.calls == []
    assert secrets.calls == []


def test_m2m_adapter_recovers_missing_version_with_put_and_no_secret_read() -> None:
    cognito = FakeCognito()
    secrets = FakeSecrets()
    provider = _provider(cognito, secrets)
    provider.ensure_client(**_provider_request())
    secret_name = next(iter(secrets.descriptions))
    secrets.descriptions[secret_name]["VersionIdsToStages"] = {}
    secrets.calls.clear()

    result = provider.ensure_client(**_provider_request())

    put_request = next(request for name, request in secrets.calls if name == "put")
    assert put_request["ClientRequestToken"] == hashlib.sha256(
        IDEMPOTENCY_KEY.encode()
    ).hexdigest()
    assert put_request["SecretString"] == RAW_SECRET_CANARY
    assert RAW_SECRET_CANARY not in repr(result)


def test_existing_user_adapter_requires_exact_immutable_binding() -> None:
    class Cognito:
        def admin_get_user(self, **request: Any) -> dict[str, Any]:
            assert request == {"UserPoolId": USER_POOL_ID, "Username": SUBJECT}
            return {
                "Username": SUBJECT,
                "UserAttributes": [
                    {"Name": "sub", "Value": SUBJECT},
                    {"Name": "custom:customerId", "Value": CUSTOMER_ID},
                    {"Name": "custom:deployment_id", "Value": DEPLOYMENT_ID},
                ],
            }

    provider = CognitoExistingUserProvider(Cognito(), user_pool_id=USER_POOL_ID)

    result = provider.ensure_user(
        subject=SUBJECT,
        immutable_attributes={
            "custom:customerId": CUSTOMER_ID,
            "custom:deployment_id": DEPLOYMENT_ID,
        },
        idempotency_key=IDEMPOTENCY_KEY,
    )

    assert set(result) == {"user_reference"}
    assert CUSTOMER_ID not in repr(result)
    assert DEPLOYMENT_ID not in repr(result)
