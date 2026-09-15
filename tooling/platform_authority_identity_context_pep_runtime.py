"""Lambda Function URL entrypoint for the GUG-217 proof-only PEP."""
from __future__ import annotations

import json
import os
import base64
import re
import zlib
import time
from threading import Lock
from contextlib import contextmanager
from datetime import UTC, datetime
from typing import Any, Callable, Mapping

from tooling.platform_authority_change_set_retirement_broker import (
    BotoClients,
    BrokerConfig,
    BrokerError,
    RetirementBroker,
    WorkforceRetirementBroker,
    WorkforceRetirementConfig,
    WorkforceRetirementRequest,
    WORKFORCE_RETIREMENT_MODE,
    WORKFORCE_RETIREMENT_OPERATIONS,
    WORKFORCE_READER_ARN,
    canonical_digest,
    _workforce_require,
    _alias_from_context,
)
from tooling.platform_authority_identity_context_pep import (
    IdentityContextPep,
    IdentityContextPepBinding,
    IdentityContextProofVerifier,
    ProofBoundaryError,
)


def _required(env: Mapping[str, str], name: str) -> str:
    value = env.get(name)
    if not isinstance(value, str) or not value:
        raise ProofBoundaryError("CONFIGURATION_INCOMPLETE")
    return value


def binding_from_environment(
    broker_config: BrokerConfig,
    env: Mapping[str, str] | None = None,
) -> IdentityContextPepBinding:
    source = os.environ if env is None else env
    redirect_uri = _required(source, "IDENTITY_CENTER_REDIRECT_URI")
    if redirect_uri != broker_config.identity_center_redirect_uri:
        raise ProofBoundaryError("CONFIGURATION_BINDING_MISMATCH")
    return IdentityContextPepBinding(
        authority_account_id=broker_config.authority_account_id,
        region=broker_config.region,
        identity_center_application_arn=broker_config.identity_center_application_arn,
        identity_center_instance_arn=broker_config.identity_center_instance_arn,
        identity_store_arn=broker_config.identity_store_arn,
        redirect_uri=redirect_uri,
        broker_execution_role_arn=broker_config.execution_role_arn,
        classifier_user_id=broker_config.classifier_identity_store_user_id,
        approver_user_id=broker_config.approver_identity_store_user_id,
        classifier_proof_role_arn=broker_config.classifier_proof_role_arn,
        approver_proof_role_arn=broker_config.approver_proof_role_arn,
        authorization_mode=getattr(
            broker_config,
            "authorization_mode",
            "TWO_HUMAN",
        ),
        single_operator_authorization_sha256=(
            getattr(
                broker_config,
                "single_operator_authorization_sha256",
                None,
            )
            or ""
        ),
    )


def _response(status_code: int, value: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "statusCode": status_code,
        "headers": {
            "cache-control": "no-store",
            "content-type": "application/json",
            "pragma": "no-cache",
            "x-content-type-options": "nosniff",
        },
        "isBase64Encoded": False,
        "body": json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ),
    }


def handler(event: object, context: object) -> dict[str, Any]:
    """Verify one human proof and execute one synchronous broker operation."""

    try:
        mode = os.environ.get("GUG215_IDENTITY_MODE")
        if mode is not None:
            if mode != WORKFORCE_RETIREMENT_MODE:
                raise BrokerError("WORKFORCE_MODE_INVALID")
            return _workforce_handler(event, context)
        config = BrokerConfig.from_environment()
        binding = binding_from_environment(config)
        clients = BotoClients.create(config.region)
        pep = IdentityContextPep(
            verifier=IdentityContextProofVerifier(
                oidc_client=clients.sso_oidc,
                sts_client=clients.sts,
                clock=lambda: datetime.now(tz=UTC),
            ),
            broker=RetirementBroker(config=config, clients=clients),
        )
        result = pep.execute(
            alias=_alias_from_context(context),
            event=event,
            binding=binding,
            now=datetime.now(tz=UTC),
        )
        return _response(200, result)
    except (ProofBoundaryError, BrokerError) as exc:
        return _response(403, {"status": "DENY", "reason_code": exc.code})
    except Exception:
        return _response(
            500,
            {"status": "DENY", "reason_code": "IDENTITY_CONTEXT_PEP_INTERNAL_ERROR"},
        )


def _workforce_json(raw: str) -> dict[str, Any]:
    def pairs(items: list) -> dict:
        result = {}
        for key, value in items:
            _workforce_require(key not in result, "WORKFORCE_JSON_INVALID")
            result[key] = value
        return result
    def constant(_value: str) -> None:
        raise BrokerError("WORKFORCE_JSON_INVALID")
    try:
        value = json.loads(raw, object_pairs_hook=pairs, parse_constant=constant)
        _workforce_require(type(value) is dict, "WORKFORCE_JSON_INVALID")
        return value
    except Exception:
        raise BrokerError("WORKFORCE_JSON_INVALID") from None


def workforce_config_from_environment(source: Mapping[str, str]) -> WorkforceRetirementConfig:
    """The installer must protect BOTH environment values; a self-hash is not authority."""
    try:
        _workforce_require(source.get("GUG215_IDENTITY_MODE") == WORKFORCE_RETIREMENT_MODE)
        encoded = source.get("GUG215_WORKFORCE_CONFIG_B64Z")
        _workforce_require(type(encoded) is str and 1 <= len(encoded) <= 12288)
        decompressor = zlib.decompressobj()
        raw = decompressor.decompress(base64.b64decode(encoded, validate=True), 16385)
        _workforce_require(len(raw) <= 16384 and decompressor.eof and not decompressor.unused_data
                           and not decompressor.unconsumed_tail)
        config = WorkforceRetirementConfig(_workforce_json(raw.decode("utf-8", "strict")),
                                           source.get("GUG215_WORKFORCE_CONFIG_DIGEST"))
        # A canonical byte encoding avoids multiple environment representations.
        _workforce_require(config.runtime_environment()["GUG215_WORKFORCE_CONFIG_B64Z"] == encoded)
        return config
    except Exception:
        raise BrokerError("WORKFORCE_CONFIGURATION_INVALID") from None


def workforce_request(event: object, context: object, config: WorkforceRetirementConfig,
                      now: datetime) -> WorkforceRetirementRequest:
    """Validate provider-owned context only after the version's ingress policy is pinned.

    This parser cannot authenticate a fabricated event sent directly to Lambda;
    the broker verifies the exact service-only resource policy before any CAS.
    It does not manufacture an IdC token or assert independent human approval.
    """
    try:
        _workforce_require(type(event) is dict)
        request = event.get("requestContext")
        _workforce_require(type(request) is dict)
        operation = event.get("routeKey", "").removeprefix("POST /")
        _workforce_require(operation in WORKFORCE_RETIREMENT_OPERATIONS)
        config.require_time(now, reconcile=operation == "reconcile")
        route, path = "POST /" + operation, "/retirement/" + operation
        http, authorizer = request.get("http"), request.get("authorizer")
        _workforce_require(event.get("version") == "2.0" and event.get("routeKey") == route
            and event.get("rawPath") == path and event.get("rawQueryString") == ""
            and event.get("queryStringParameters") in (None, {})
            and request.get("accountId") == "042360977644" and request.get("apiId") == config.api_id
            and request.get("stage") == "retirement" and request.get("routeKey") == route
            and request.get("domainName") == config.api_id + ".execute-api.us-east-1.amazonaws.com"
            and type(http) is dict and http.get("method") == "POST" and http.get("path") == path
            and type(authorizer) is dict and set(authorizer) == {"iam"}, "WORKFORCE_INGRESS_INVALID")
        _workforce_require(getattr(context, "invoked_function_arn", None) == config.version_arn, "WORKFORCE_VERSION_INVALID")
        if config.schema_version == "2":
            _workforce_require(getattr(context, "function_version", None) == config.function_version,
                               "WORKFORCE_VERSION_INVALID")
        epoch = request.get("timeEpoch")
        _workforce_require(type(epoch) is int and 0 <= epoch <= 253402300799999)
        requested_at = datetime.fromtimestamp(epoch / 1000, UTC)
        _workforce_require(0 <= (now - requested_at).total_seconds() < 300
                           and requested_at >= config.parse_time(config.not_before), "WORKFORCE_REQUEST_EXPIRED")
        iam = authorizer["iam"]
        _workforce_require(type(iam) is dict and iam.get("accountId") == "042360977644")
        role = config.roles["classify" if operation == "classify" else "retire"]
        prefix = "arn:aws:sts::042360977644:assumed-role/" + role["role_arn"].rsplit("/", 1)[1] + "/"
        caller = iam.get("userArn")
        _workforce_require(type(caller) is str and caller.startswith(prefix))
        session = caller[len(prefix):]
        _workforce_require(re.fullmatch(r"[A-Za-z0-9+=,.@_-]{2,64}", session) is not None
            and iam.get("userId") == role["role_id"] + ":" + session
            and iam.get("callerId") in (None, "", iam["userId"]) and iam.get("cognitoIdentity") in (None, {}), "WORKFORCE_CALLER_INVALID")
        request_id = request.get("requestId")
        _workforce_require(type(request_id) is str and re.fullmatch(r"[A-Za-z0-9+=_/-]{1,128}", request_id) is not None)
        body = event.get("body")
        _workforce_require(type(body) is str and len(body) <= 1024 and type(event.get("isBase64Encoded")) is bool)
        raw = base64.b64decode(body, validate=True) if event["isBase64Encoded"] else body.encode("utf-8", "strict")
        _workforce_require(0 < len(raw) <= 256 and _workforce_json(raw.decode("utf-8", "strict")) == {}, "REQUEST_AUTHORITY_FORBIDDEN")
        return WorkforceRetirementRequest(operation, caller, role["role_id"], requested_at, now,
            canonical_digest({"request_id": request_id}), config.expected_digest)
    except BrokerError:
        raise
    except Exception:
        raise BrokerError("WORKFORCE_REQUEST_INVALID") from None


class _OnePhysicalDelete:
    """Reserve the sole SDK invocation and reject any second HTTP send hook."""
    def __init__(self, client: Any, *, before_send=None) -> None:
        self._client = client
        self._used = False
        self._lock = Lock()
        self._before_send = before_send

    def __getattr__(self, name: str) -> Any:
        return getattr(self._client, name)

    def delete_change_set(self, **kwargs: Any) -> Any:
        with self._lock:
            _workforce_require(not self._used, "WORKFORCE_DELETE_ALREADY_SENT")
            self._used = True
        sends = 0
        def guard(**_kwargs: Any) -> None:
            nonlocal sends
            sends += 1
            _workforce_require(sends == 1, "WORKFORCE_DELETE_ALREADY_SENT")
            if self._before_send is not None:
                self._before_send()
        event = "before-send.cloudformation.DeleteChangeSet"
        unique = "gug215-workforce-single-delete"
        self._client.meta.events.register(event, guard, unique_id=unique)
        try:
            return self._client.delete_change_set(**kwargs)
        finally:
            self._client.meta.events.unregister(event, unique_id=unique)


class WorkforceBotoClients:
    """Private Lambda SDK sessions; no profile, endpoint, or credentials from a request."""

    def __init__(self, config: WorkforceRetirementConfig, *, deadline: float, operation: str,
                 request_guard: Callable[[], datetime]) -> None:
        import boto3
        from botocore.config import Config
        self._boto3 = boto3
        self._config = Config(region_name="us-east-1", signature_version="v4", connect_timeout=1,
            read_timeout=2, retries={"total_max_attempts": 1, "mode": "standard"},
            proxies={}, ignore_configured_endpoint_urls=True)
        self._session = boto3.Session(region_name="us-east-1")
        self._binding = config
        self._deadline = deadline
        self._operation = operation
        self._request_guard = request_guard
        for attr, service, endpoint in (
            ("sts", "sts", "sts.us-east-1.amazonaws.com"), ("iam", "iam", "iam.amazonaws.com"),
            ("dynamodb", "dynamodb", "dynamodb.us-east-1.amazonaws.com"),
            ("cloudformation", "cloudformation", "cloudformation.us-east-1.amazonaws.com"),
            ("kms", "kms", "kms.us-east-1.amazonaws.com"), ("lambda_client", "lambda", "lambda.us-east-1.amazonaws.com"),
            ("s3control", "s3control", "s3-control.us-east-1.amazonaws.com"),
        ):
            setattr(self, attr, self._client(self._session, service, endpoint))
        if config.schema_version == "2":
            self.apigatewayv2 = self._client(self._session, "apigatewayv2", "apigateway.us-east-1.amazonaws.com")
        self.cloudformation = _OnePhysicalDelete(self.cloudformation, before_send=self._before_delete_send)

    def _require_budget(self, **_kwargs: Any) -> None:
        # The broker's SAME stateful validator preserves the ingress timestamp,
        # last observed UTC, request age and common monotonic deadline. A second
        # window-only clock here would permit a rollback during signing.
        self._request_guard()

    def _before_delete_send(self) -> None:
        _workforce_require(self._operation == "retire", "WORKFORCE_DELETE_NOT_AUTHORIZED")
        self._require_budget()

    def _client(self, session: Any, service: str, endpoint: str) -> Any:
        client = session.client(service, region_name="us-east-1", config=self._config, endpoint_url="https://" + endpoint)
        # Bounds both signing delays and provider response delays. A timed-out
        # conditional write is uncertain, never reconstructed as permission.
        for event in ("before-call.*.*", "before-send.*.*", "after-call.*.*"):
            client.meta.events.register(event, self._require_budget)
        return client

    @classmethod
    def create(cls, config: WorkforceRetirementConfig, *, deadline: float, operation: str,
               request_guard: Callable[[], datetime]) -> "WorkforceBotoClients":
        return cls(config, deadline=deadline, operation=operation, request_guard=request_guard)

    @contextmanager
    def assignment_reader(self):
        response, values, session, sso, sts = None, None, None, None, None
        try:
            response = self.sts.assume_role(RoleArn=WORKFORCE_READER_ARN,
                RoleSessionName="gug215-workforce-reader", DurationSeconds=900)
            expected = "arn:aws:sts::839393571433:assumed-role/ScanalyzeGug215WorkforceAssignmentReader/gug215-workforce-reader"
            _workforce_require(response.get("AssumedRoleUser", {}).get("Arn") == expected, "WORKFORCE_READER_INVALID")
            values = response.get("Credentials")
            _workforce_require(type(values) is dict, "WORKFORCE_READER_INVALID")
            session = self._boto3.Session(region_name="us-east-1", aws_access_key_id=values["AccessKeyId"],
                aws_secret_access_key=values["SecretAccessKey"], aws_session_token=values["SessionToken"])
            sts = self._client(session, "sts", "sts.us-east-1.amazonaws.com")
            actual = sts.get_caller_identity()
            _workforce_require(actual.get("Account") == "839393571433" and actual.get("Arn") == expected, "WORKFORCE_READER_INVALID")
            sso = self._client(session, "sso-admin", "sso.us-east-1.amazonaws.com")
            yield sso
        except Exception:
            raise BrokerError("WORKFORCE_ASSIGNMENT_READ_FAILED") from None
        finally:
            if isinstance(values, dict):
                values.clear()
            if isinstance(response, dict):
                response.clear()
            for client in (sso, sts):
                if client is not None:
                    try:
                        client.close()
                    except Exception:
                        pass
            session = None


def _workforce_now() -> datetime:
    return datetime.now(UTC)


def _workforce_handler(event: object, context: object) -> dict[str, Any]:
    deadline = time.monotonic() + 25
    config = workforce_config_from_environment(os.environ).bind_lambda_context(context)
    request = workforce_request(event, context, config, _workforce_now())
    broker = WorkforceRetirementBroker(config=config, clients=None, request=request, now=_workforce_now, deadline=deadline)
    request_guard = lambda: broker._time(reconcile=request.operation == "reconcile")
    request_guard()
    broker.clients = WorkforceBotoClients.create(config, deadline=deadline, operation=request.operation,
                                                request_guard=request_guard)
    evidence = canonical_digest({"operation": request.operation, "caller_arn": request.caller_arn,
        "request_id_digest": request.request_id_digest, "request_epoch": int(request.requested_at.timestamp() * 1000),
        "binding_digest": request.binding_digest})
    result = broker.handle(alias=request.operation, event={}, identity_proof_sha256=evidence)
    broker._time(reconcile=request.operation == "reconcile")
    return _response(200, result)
