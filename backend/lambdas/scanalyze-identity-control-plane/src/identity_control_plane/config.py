from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any, Mapping

from .common import CUSTOMER_ID_PATTERN, DEPLOYMENT_ID_PATTERN, POLICY_DIGEST_PATTERN


CANONICAL_ROLE_IDS = frozenset(
    {
        "customer_admin",
        "document_operator",
        "document_reviewer",
        "auditor",
    }
)
CANONICAL_ACTION_IDS = ("read", "write", "admin")
AUTHZ_SCHEMA_VERSION = "enterprise-authorization.v1"
SCOPE_CATALOG_VERSION = "scanalyze.api.v1"
ROLE_CATALOG_VERSION = "enterprise-roles.v1"

_REGION_PATTERN = re.compile(r"^[a-z]{2}(?:-[a-z0-9]+)+-[0-9]+$")
_USER_POOL_ID_PATTERN = re.compile(r"^[A-Za-z0-9-]+_[A-Za-z0-9]+$")
_CLIENT_ID_PATTERN = re.compile(r"^[A-Za-z0-9]{1,128}$")
_TABLE_NAME_PATTERN = re.compile(r"^[A-Za-z0-9_.-]{3,255}$")
_POLICY_VERSION_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_SECRET_PREFIX_PATTERN = re.compile(r"^[A-Za-z0-9/_+=.@-]{1,400}-$")


class RuntimeConfigError(RuntimeError):
    """Sanitized fail-closed runtime configuration error."""

    def __init__(self, reason_code: str = "runtime_configuration_invalid") -> None:
        self.reason_code = reason_code
        super().__init__("identity runtime configuration rejected")


def _required(env: Mapping[str, str], name: str) -> str:
    value = env.get(name)
    if not isinstance(value, str) or not value or value != value.strip():
        raise RuntimeConfigError()
    return value


def _matches(env: Mapping[str, str], name: str, pattern: re.Pattern[str]) -> str:
    value = _required(env, name)
    if pattern.fullmatch(value) is None:
        raise RuntimeConfigError()
    return value


def _exact(env: Mapping[str, str], name: str, expected: str) -> str:
    value = _required(env, name)
    if value != expected:
        raise RuntimeConfigError()
    return value


def _boolean(env: Mapping[str, str], name: str) -> bool:
    value = _required(env, name)
    if value == "true":
        return True
    if value == "false":
        return False
    raise RuntimeConfigError()


def _json_string_list(
    env: Mapping[str, str],
    name: str,
    *,
    allow_empty: bool = False,
) -> tuple[str, ...]:
    raw = _required(env, name)
    try:
        value = json.loads(raw)
    except (TypeError, ValueError):
        raise RuntimeConfigError() from None
    if (
        not isinstance(value, list)
        or (not value and not allow_empty)
        or any(not isinstance(item, str) or not item for item in value)
        or len(set(value)) != len(value)
    ):
        raise RuntimeConfigError()
    return tuple(value)


@dataclass(frozen=True)
class PreTokenRuntimeConfig:
    region: str
    customer_id: str
    deployment_id: str
    user_pool_id: str
    allowed_client_ids: tuple[str, ...]
    allowed_role_ids: tuple[str, ...]
    membership_table: str
    authorization_audit_table: str
    policy_version: str
    policy_digest: str
    human_runtime_enabled: bool

    @classmethod
    def from_env(cls, env: Mapping[str, str]) -> PreTokenRuntimeConfig:
        region = _matches(env, "AWS_REGION", _REGION_PATTERN)
        customer_id = _matches(env, "CUSTOMER_ID", CUSTOMER_ID_PATTERN)
        deployment_id = _matches(env, "DEPLOYMENT_ID", DEPLOYMENT_ID_PATTERN)
        human_runtime_enabled = _boolean(env, "HUMAN_RUNTIME_ENABLED")
        user_pool_id = _required(env, "USER_POOL_ID")
        allowed_client_ids = _json_string_list(
            env,
            "ALLOWED_CLIENT_IDS",
            allow_empty=not human_runtime_enabled,
        )
        if human_runtime_enabled:
            if _USER_POOL_ID_PATTERN.fullmatch(user_pool_id) is None:
                raise RuntimeConfigError()
        elif user_pool_id != "UNBOUND" and _USER_POOL_ID_PATTERN.fullmatch(user_pool_id) is None:
            raise RuntimeConfigError()
        if any(_CLIENT_ID_PATTERN.fullmatch(value) is None for value in allowed_client_ids):
            raise RuntimeConfigError()
        allowed_role_ids = _json_string_list(env, "ALLOWED_ROLE_IDS")
        if frozenset(allowed_role_ids) != CANONICAL_ROLE_IDS:
            raise RuntimeConfigError()

        _exact(env, "AUTHZ_SCHEMA_VERSION", AUTHZ_SCHEMA_VERSION)
        _exact(env, "SCOPE_CATALOG_VERSION", SCOPE_CATALOG_VERSION)
        _exact(env, "ROLE_CATALOG_VERSION", ROLE_CATALOG_VERSION)
        policy_version = _matches(env, "POLICY_VERSION", _POLICY_VERSION_PATTERN)
        policy_digest = _matches(env, "POLICY_DIGEST", POLICY_DIGEST_PATTERN)

        return cls(
            region=region,
            customer_id=customer_id,
            deployment_id=deployment_id,
            user_pool_id=user_pool_id,
            allowed_client_ids=allowed_client_ids,
            allowed_role_ids=allowed_role_ids,
            membership_table=_matches(env, "MEMBERSHIP_TABLE", _TABLE_NAME_PATTERN),
            authorization_audit_table=_matches(
                env,
                "AUTHORIZATION_AUDIT_TABLE",
                _TABLE_NAME_PATTERN,
            ),
            policy_version=policy_version,
            policy_digest=policy_digest,
            human_runtime_enabled=human_runtime_enabled,
        )

    def processor_config(self) -> dict[str, Any]:
        return {
            "human_runtime_enabled": self.human_runtime_enabled,
            "expected_customer_id": self.customer_id,
            "expected_deployment_id": self.deployment_id,
            "expected_user_pool_id": self.user_pool_id,
            "allowed_client_ids": list(self.allowed_client_ids),
            "allowed_role_ids": list(self.allowed_role_ids),
            "authz_schema_version": AUTHZ_SCHEMA_VERSION,
            "scope_catalog_version": SCOPE_CATALOG_VERSION,
            "role_catalog_version": ROLE_CATALOG_VERSION,
            "policy_version": self.policy_version,
            "policy_digest": self.policy_digest,
        }


@dataclass(frozen=True)
class ControlRuntimeConfig:
    base: PreTokenRuntimeConfig
    bootstrap_request_table: str
    m2m_binding_table: str
    control_queue_arn: str
    identity_kms_key_arn: str
    secret_name_prefix: str
    resource_server_id: str

    @classmethod
    def from_env(cls, env: Mapping[str, str]) -> ControlRuntimeConfig:
        base = PreTokenRuntimeConfig.from_env(env)
        if base.human_runtime_enabled is not False:
            raise RuntimeConfigError()
        if _USER_POOL_ID_PATTERN.fullmatch(base.user_pool_id) is None:
            raise RuntimeConfigError()
        if _boolean(env, "M2M_RUNTIME_ENABLED") is not True:
            raise RuntimeConfigError()

        resource_server_id = _exact(
            env,
            "RESOURCE_SERVER_ID",
            SCOPE_CATALOG_VERSION,
        )
        queue_arn = _required(env, "CONTROL_QUEUE_ARN")
        queue_pattern = re.compile(
            r"^arn:(aws|aws-us-gov|aws-cn):sqs:"
            + re.escape(base.region)
            + r":[0-9]{12}:[A-Za-z0-9_-]{1,75}\.fifo$"
        )
        if queue_pattern.fullmatch(queue_arn) is None:
            raise RuntimeConfigError()

        kms_arn = _required(env, "IDENTITY_KMS_KEY_ARN")
        kms_pattern = re.compile(
            r"^arn:(aws|aws-us-gov|aws-cn):kms:"
            + re.escape(base.region)
            + r":[0-9]{12}:key/[A-Za-z0-9-]{1,128}$"
        )
        if kms_pattern.fullmatch(kms_arn) is None:
            raise RuntimeConfigError()

        return cls(
            base=base,
            bootstrap_request_table=_matches(
                env,
                "BOOTSTRAP_REQUEST_TABLE",
                _TABLE_NAME_PATTERN,
            ),
            m2m_binding_table=_matches(env, "M2M_BINDING_TABLE", _TABLE_NAME_PATTERN),
            control_queue_arn=queue_arn,
            identity_kms_key_arn=kms_arn,
            secret_name_prefix=_matches(
                env,
                "SECRET_NAME_PREFIX",
                _SECRET_PREFIX_PATTERN,
            ),
            resource_server_id=resource_server_id,
        )

    @property
    def action_scopes(self) -> dict[str, str]:
        return {
            action: f"{self.resource_server_id}/{action}"
            for action in CANONICAL_ACTION_IDS
        }

    def bootstrap_processor_config(self) -> dict[str, Any]:
        result = self.base.processor_config()
        result.update(
            {
                "max_ttl_seconds": 900,
                "max_auth_age_seconds": 300,
                "max_recovery_seconds": 3600,
            }
        )
        return result

    def m2m_processor_config(self) -> dict[str, Any]:
        return {
            "expected_customer_id": self.base.customer_id,
            "expected_deployment_id": self.base.deployment_id,
            "action_scopes": self.action_scopes,
            "policy_version": self.base.policy_version,
            "policy_digest": self.base.policy_digest,
        }
