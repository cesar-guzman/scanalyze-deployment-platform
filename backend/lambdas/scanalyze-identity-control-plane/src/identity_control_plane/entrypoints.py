from __future__ import annotations

import json
import logging
import os
import threading
from collections.abc import Callable, Mapping, Sequence
from datetime import datetime, timezone
from typing import Any

from .aws_adapters import (
    CognitoExistingUserProvider,
    CognitoSecretsM2MClientProvider,
    DynamoAuditSink,
    DynamoBootstrapRequestStore,
    DynamoM2MBindingStore,
    DynamoMembershipReader,
    DynamoMembershipStore,
)
from .bootstrap import BootstrapProcessor
from .config import ControlRuntimeConfig, PreTokenRuntimeConfig, RuntimeConfigError
from .handlers import build_pre_token_handler
from .m2m import M2MProvisioner
from .pre_token import PreTokenProcessor


class RuntimeUnavailable(RuntimeError):
    def __init__(self) -> None:
        super().__init__("identity runtime unavailable")


def _clock() -> datetime:
    return datetime.now(timezone.utc)


def _table(resource: Any, name: str) -> Any:
    table = resource.Table(name)
    if table is None:
        raise RuntimeConfigError()
    return table


def _compose_pre_token(
    config: PreTokenRuntimeConfig,
    dynamodb_resource: Any,
    logger: logging.Logger,
) -> Callable[[Mapping[str, Any], object], dict[str, Any]]:
    processor = PreTokenProcessor(
        config=config.processor_config(),
        membership_reader=DynamoMembershipReader(
            _table(dynamodb_resource, config.membership_table)
        ),
        audit_sink=DynamoAuditSink(
            _table(dynamodb_resource, config.authorization_audit_table)
        ),
        clock=_clock,
        logger=logger,
    )
    return build_pre_token_handler(processor, logger=logger)


def build_pre_token_entrypoint(
    env: Mapping[str, str],
    dynamodb_resource: Any,
    *,
    logger: logging.Logger | None = None,
) -> Callable[[Mapping[str, Any], object], dict[str, Any]]:
    """Compose the pre-token runtime from explicit, validated dependencies."""

    safe_logger = logger or logging.getLogger("scanalyze.identity.pre_token")
    config = PreTokenRuntimeConfig.from_env(env)
    return _compose_pre_token(config, dynamodb_resource, safe_logger)


class _ControlDispatcher:
    def __init__(
        self,
        *,
        bootstrap: BootstrapProcessor,
        m2m: M2MProvisioner,
        queue_arn: str,
        region: str,
        logger: logging.Logger,
    ) -> None:
        self.bootstrap = bootstrap
        self.m2m = m2m
        self.queue_arn = queue_arn
        self.region = region
        self.logger = logger

    def __call__(
        self,
        event: Mapping[str, Any],
        context: object,
    ) -> dict[str, list[dict[str, str]]]:
        del context
        records = self._validated_records(event)
        failures: list[dict[str, str]] = []
        for index, record in enumerate(records):
            message_id = str(record["messageId"])
            try:
                body = json.loads(str(record["body"]))
                if not isinstance(body, Mapping):
                    raise ValueError("invalid body")
                command_type = body.get("command_type")
                schema_version = body.get("schema_version")
                if (
                    command_type == "bootstrap"
                    and schema_version == "identity-bootstrap-command.v1"
                ):
                    self.bootstrap.process(body)
                elif (
                    command_type == "m2m.provision"
                    and schema_version == "identity-m2m-provisioning.v1"
                ):
                    self.m2m.provision(body)
                else:
                    raise ValueError("unsupported command")
            except Exception:
                # Never log a body, identifier, dependency exception, provider
                # response, or credential value. SQS needs only the identifier.
                self.logger.warning("identity_control_record_failed")
                # This queue is FIFO. Stop after the first failure and return
                # the failed identifier plus every unprocessed identifier so
                # Lambda cannot acknowledge later messages out of order if a
                # future configuration raises batch_size above one.
                failures.extend(
                    {"itemIdentifier": str(pending["messageId"])}
                    for pending in records[index:]
                )
                break
        return {"batchItemFailures": failures}

    def _validated_records(
        self,
        event: Mapping[str, Any],
    ) -> tuple[Mapping[str, Any], ...]:
        if not isinstance(event, Mapping):
            self._reject_batch()
        records = event.get("Records")
        if (
            not isinstance(records, Sequence)
            or isinstance(records, (str, bytes))
            or not records
        ):
            self._reject_batch()
        validated: list[Mapping[str, Any]] = []
        seen_ids: set[str] = set()
        for record in records:
            if not isinstance(record, Mapping):
                self._reject_batch()
            message_id = record.get("messageId")
            body = record.get("body")
            if (
                not isinstance(message_id, str)
                or not message_id
                or message_id != message_id.strip()
                or len(message_id) > 128
                or message_id in seen_ids
                or not isinstance(body, str)
                or not body
                or record.get("eventSource") != "aws:sqs"
                or record.get("eventSourceARN") != self.queue_arn
                or record.get("awsRegion") != self.region
            ):
                self._reject_batch()
            seen_ids.add(message_id)
            validated.append(record)
        return tuple(validated)

    def _reject_batch(self) -> None:
        self.logger.error("identity_control_batch_rejected")
        raise RuntimeUnavailable() from None


def _compose_control(
    config: ControlRuntimeConfig,
    dynamodb_resource: Any,
    cognito_client: Any,
    secrets_client: Any,
    logger: logging.Logger,
) -> Callable[
    [Mapping[str, Any], object],
    dict[str, list[dict[str, str]]],
]:
    membership_table = _table(dynamodb_resource, config.base.membership_table)
    audit_table = _table(dynamodb_resource, config.base.authorization_audit_table)
    bootstrap = BootstrapProcessor(
        config=config.bootstrap_processor_config(),
        request_store=DynamoBootstrapRequestStore(
            _table(dynamodb_resource, config.bootstrap_request_table)
        ),
        identity_provider=CognitoExistingUserProvider(
            cognito_client,
            user_pool_id=config.base.user_pool_id,
        ),
        membership_store=DynamoMembershipStore(membership_table),
        audit_sink=DynamoAuditSink(audit_table),
        clock=_clock,
        logger=logger,
    )
    m2m = M2MProvisioner(
        config=config.m2m_processor_config(),
        client_provider=CognitoSecretsM2MClientProvider(
            cognito_client,
            secrets_client,
            user_pool_id=config.base.user_pool_id,
            customer_id=config.base.customer_id,
            deployment_id=config.base.deployment_id,
            secret_name_prefix=config.secret_name_prefix,
            kms_key_id=config.identity_kms_key_arn,
            allowed_scopes=tuple(config.action_scopes.values()),
        ),
        binding_store=DynamoM2MBindingStore(
            _table(dynamodb_resource, config.m2m_binding_table),
            customer_id=config.base.customer_id,
            deployment_id=config.base.deployment_id,
        ),
        audit_sink=DynamoAuditSink(audit_table),
        clock=_clock,
        logger=logger,
    )
    return _ControlDispatcher(
        bootstrap=bootstrap,
        m2m=m2m,
        queue_arn=config.control_queue_arn,
        region=config.base.region,
        logger=logger,
    )


def build_control_processor_entrypoint(
    env: Mapping[str, str],
    dynamodb_resource: Any,
    cognito_client: Any,
    secrets_client: Any,
    *,
    logger: logging.Logger | None = None,
) -> Callable[
    [Mapping[str, Any], object],
    dict[str, list[dict[str, str]]],
]:
    """Compose the SQS bootstrap/M2M dispatcher without performing live calls."""

    safe_logger = logger or logging.getLogger("scanalyze.identity.control")
    config = ControlRuntimeConfig.from_env(env)
    return _compose_control(
        config,
        dynamodb_resource,
        cognito_client,
        secrets_client,
        safe_logger,
    )


_runtime_lock = threading.Lock()
_pre_token_runtime: Callable[[Mapping[str, Any], object], dict[str, Any]] | None = None
_control_runtime: (
    Callable[
        [Mapping[str, Any], object],
        dict[str, list[dict[str, str]]],
    ]
    | None
) = None


def _load_pre_token_runtime() -> Callable[[Mapping[str, Any], object], dict[str, Any]]:
    global _pre_token_runtime
    if _pre_token_runtime is None:
        with _runtime_lock:
            if _pre_token_runtime is None:
                try:
                    config = PreTokenRuntimeConfig.from_env(os.environ)
                    import boto3  # type: ignore[import-not-found]

                    resource = boto3.resource("dynamodb", region_name=config.region)
                    _pre_token_runtime = _compose_pre_token(
                        config,
                        resource,
                        logging.getLogger("scanalyze.identity.pre_token"),
                    )
                except Exception:
                    logging.getLogger("scanalyze.identity.pre_token").error(
                        "pre_token_runtime_initialization_failed"
                    )
                    raise RuntimeUnavailable() from None
    return _pre_token_runtime


def _load_control_runtime() -> Callable[
    [Mapping[str, Any], object],
    dict[str, list[dict[str, str]]],
]:
    global _control_runtime
    if _control_runtime is None:
        with _runtime_lock:
            if _control_runtime is None:
                try:
                    config = ControlRuntimeConfig.from_env(os.environ)
                    import boto3  # type: ignore[import-not-found]

                    resource = boto3.resource(
                        "dynamodb",
                        region_name=config.base.region,
                    )
                    cognito = boto3.client(
                        "cognito-idp",
                        region_name=config.base.region,
                    )
                    secrets = boto3.client(
                        "secretsmanager",
                        region_name=config.base.region,
                    )
                    _control_runtime = _compose_control(
                        config,
                        resource,
                        cognito,
                        secrets,
                        logging.getLogger("scanalyze.identity.control"),
                    )
                except Exception:
                    logging.getLogger("scanalyze.identity.control").error(
                        "identity_control_runtime_initialization_failed"
                    )
                    raise RuntimeUnavailable() from None
    return _control_runtime


def pre_token_handler(event: Mapping[str, Any], context: object) -> dict[str, Any]:
    """AWS Lambda entrypoint for the fail-closed Cognito V2 pre-token hook."""

    return _load_pre_token_runtime()(event, context)


def control_processor_handler(
    event: Mapping[str, Any],
    context: object,
) -> dict[str, list[dict[str, str]]]:
    """AWS Lambda entrypoint for ReportBatchItemFailures SQS processing."""

    return _load_control_runtime()(event, context)
