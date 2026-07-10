from __future__ import annotations

import json
import os
from functools import lru_cache
from typing import Any, Dict, Optional

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    """
    Configuración 100% por environment variables.
    - Direct env vars (A)
    - JSON env vars (B): BUCKETS_JSON, SQS_QUEUE_URLS_JSON

    Nota: mantenemos settings "tolerante" para que /health funcione aunque falten dependencias,
    pero las rutas de documentos validan en runtime los valores requeridos.
    """

    model_config = SettingsConfigDict(env_prefix="", case_sensitive=False)

    service_name: str = Field(default="scanalyze-ingest-api", alias="SERVICE_NAME")
    env: str = Field(default="dev", alias="APP_ENV")

    log_level: str = Field(default="INFO", alias="LOG_LEVEL")

    # DynamoDB
    documents_table_name: Optional[str] = Field(default=None, alias="DOCUMENTS_TABLE_NAME")
    batches_table_name: Optional[str] = Field(default=None, alias="BATCHES_TABLE_NAME")

    # Buckets direct (A)
    raw_bucket: Optional[str] = Field(default=None, alias="RAW_BUCKET")
    ocr_bucket: Optional[str] = Field(default=None, alias="OCR_BUCKET")
    structured_bucket: Optional[str] = Field(default=None, alias="STRUCTURED_BUCKET")
    errors_bucket: Optional[str] = Field(default=None, alias="ERRORS_BUCKET")

    # Buckets JSON (B)
    buckets_json: Optional[Dict[str, str]] = Field(default=None, alias="BUCKETS_JSON")

    # SQS URLs JSON (B)
    sqs_queue_urls_json: Optional[Dict[str, str]] = Field(default=None, alias="SQS_QUEUE_URLS_JSON")

    # Timeouts presigned
    upload_url_ttl_seconds: int = Field(default=900, alias="UPLOAD_URL_TTL_SECONDS")
    download_url_ttl_seconds: int = Field(default=600, alias="DOWNLOAD_URL_TTL_SECONDS")

    # Primer stage a encolar en /submit
    first_stage: str = Field(default="ingest", alias="FIRST_STAGE")

    # S3 key prefix convention
    s3_key_prefix_template: str = Field(default="{tenant}/{document_id}/", alias="S3_KEY_PREFIX_TEMPLATE")

    # ── Auth handling (P0-001: verified auth context, P0-002: deployment customer binding) ──
    auth_mode: str = Field(default="cognito_jwt", alias="AUTH_MODE")
    # ^ "cognito_jwt" (default, production) or "local_mock" (local/test/ci only)

    # P0-002: Expected customer identity for this dedicated deployment.
    # Required in every non-local deployment.
    # The backend validates that verified JWT custom:customerId matches this value.
    scanalyze_deployment_customer_id: Optional[str] = Field(
        default=None,
        alias="SCANALYZE_DEPLOYMENT_CUSTOMER_ID",
    )

    # Cognito JWT verification
    cognito_user_pool_id: Optional[str] = Field(default=None, alias="COGNITO_USER_POOL_ID")
    cognito_region: str = Field(default="", alias="COGNITO_REGION")
    cognito_allowed_token_uses: str = Field(default="access", alias="COGNITO_ALLOWED_TOKEN_USES")
    # ^ Comma-separated: "access" or "access,id". Default: access only.
    cognito_allowed_client_ids: str = Field(default="", alias="COGNITO_ALLOWED_CLIENT_IDS")
    # ^ Comma-separated Cognito app client IDs. Empty = skip client_id validation.

    # Customer/tenant claim configuration
    # NOTE: TENANT_CLAIM_NAME is a legacy env var name. Semantically, this claim
    # carries the SaaS customer_id (e.g. custom:customerId = customer-example),
    # NOT a document processing route (platform/personal/gov/bank).
    # See ADR: 05_ADR_Modelo_SaaS_Multi_Account.
    tenant_claim_name: str = Field(default="custom:customerId", alias="TENANT_CLAIM_NAME")
    # ^ Must be a legitimate customer/tenant claim (custom:customerId, custom:tenantId, org_id).
    #   MUST NOT be set to sub, client_id, email, username, scope, etc.

    # M2M (client_credentials) tenant resolution
    m2m_tenant_resolution: str = Field(default="disabled", alias="M2M_TENANT_RESOLUTION")
    # ^ "disabled" (default, fail-closed) or "client_id_map"
    m2m_client_tenant_map: Optional[Dict[str, str]] = Field(default=None, alias="M2M_CLIENT_TENANT_MAP")
    # ^ JSON map: {"cognito_client_id": "tenant_id", ...}

    # Local/test/ci mock auth (only works with AUTH_MODE=local_mock AND APP_ENV∈{local,test,ci})
    # Legacy name retained for compatibility. Semantics are customer_id, not tenant header.
    # LOCAL_MOCK_TENANT_ID is local/test/ci-only and never read in customer deployments.
    local_mock_tenant_id: Optional[str] = Field(default=None, alias="LOCAL_MOCK_TENANT_ID")
    local_mock_subject: str = Field(default="local-dev-user", alias="LOCAL_MOCK_SUBJECT")

    # DEPRECATED — kept for backwards-compatible env var parsing but IGNORED at runtime.
    # P0-001: X-Tenant-Id is no longer trusted. ENFORCE_AUTH_HEADER replaced by AUTH_MODE.
    # P0-002: ENFORCE_AUTH_HEADER=false is FATAL in non-local deployments.
    enforce_auth_header: Optional[bool] = Field(default=None, alias="ENFORCE_AUTH_HEADER", exclude=True)
    tenant_header_name: Optional[str] = Field(default=None, alias="TENANT_HEADER_NAME", exclude=True)

    # boto3 timeouts/retries
    aws_connect_timeout_seconds: float = Field(default=3.0, alias="AWS_CONNECT_TIMEOUT_SECONDS")
    aws_read_timeout_seconds: float = Field(default=20.0, alias="AWS_READ_TIMEOUT_SECONDS")
    aws_max_attempts: int = Field(default=3, alias="AWS_MAX_ATTEMPTS")

    # Artifacts listing limits
    list_max_keys: int = Field(default=200, alias="LIST_MAX_KEYS")

    # ── Employee Profiles Add-on ──
    employee_profiles_enabled: bool = Field(default=False, alias="EMPLOYEE_PROFILES_ENABLED")
    employee_profiles_enabled_tenants: str = Field(default="", alias="EMPLOYEE_PROFILES_ENABLED_TENANTS")
    employee_profiles_mode: str = Field(default="sync", alias="EMPLOYEE_PROFILES_MODE")
    employee_profiles_max_docs_per_batch: int = Field(default=200, alias="EMPLOYEE_PROFILES_MAX_DOCUMENTS_PER_BATCH")

    # CORS (normalmente APIGW maneja CORS, pero lo dejamos configurable)
    cors_allow_origins: str = Field(default="*", alias="CORS_ALLOW_ORIGINS")

    @field_validator("buckets_json", "sqs_queue_urls_json", "m2m_client_tenant_map", mode="before")
    @classmethod
    def _parse_optional_json(cls, v: Any) -> Any:
        if v is None:
            return None
        if isinstance(v, dict):
            return v
        if isinstance(v, str) and v.strip() == "":
            return None
        if isinstance(v, str):
            try:
                parsed = json.loads(v)
            except Exception as e:
                raise ValueError("Invalid JSON configuration") from e
            if not isinstance(parsed, dict):
                raise ValueError("JSON must be an object/dict")
            return parsed
        raise ValueError("Invalid value type for JSON field")

    def get_bucket(self, alias: str) -> Optional[str]:
        """
        alias in {"raw","ocr","structured","errors"}
        Prefer JSON BUCKETS_JSON, fallback to direct env vars.
        """
        key = alias.lower().strip()

        if self.buckets_json:
            v = self.buckets_json.get(key)
            if v:
                return v

        if key == "raw":
            return self.raw_bucket
        if key == "ocr":
            return self.ocr_bucket
        if key == "structured":
            return self.structured_bucket
        if key == "errors":
            return self.errors_bucket

        return None

    def get_queue_url(self, stage: str) -> Optional[str]:
        """
        stage: por ejemplo "ocr", "classify", etc.
        Prefer JSON mapping SQS_QUEUE_URLS_JSON, fallback a env var {STAGE}_QUEUE_URL
        y también contempla nombres comunes como OCR_QUEUE_URL, CLASSIFY_QUEUE_URL, etc.
        """
        s = stage.lower().strip()

        if self.sqs_queue_urls_json:
            v = self.sqs_queue_urls_json.get(s)
            if v:
                return v

        # Fallback dinámico: {STAGE}_QUEUE_URL
        env_key = f"{s.upper()}_QUEUE_URL"
        v = os.getenv(env_key)
        if v:
            return v

        # Fallback de compatibilidad (si stage ya es ocr/classify no hace falta, pero cubre casos)
        common = {
            "ocr": os.getenv("OCR_QUEUE_URL"),
            "classify": os.getenv("CLASSIFY_QUEUE_URL"),
            "structured": os.getenv("STRUCTURED_QUEUE_URL"),
        }
        return common.get(s)

    def s3_prefix_for(self, tenant: str, document_id: str) -> str:
        prefix = self.s3_key_prefix_template.format(tenant=tenant, document_id=document_id)
        if not prefix.endswith("/"):
            prefix += "/"
        return prefix

    def cors_origins_list(self) -> list[str]:
        v = (self.cors_allow_origins or "*").strip()
        if v == "*":
            return ["*"]
        # comma-separated
        return [x.strip() for x in v.split(",") if x.strip()]

@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()


# ── Auth Config Startup Validation (P0-001 + P0-002 hardening) ──────

# P0-002: Allowed AUTH_MODE values. Unknown values are rejected at startup
# in ALL environments (local, test, ci, dev, staging, prod, etc.).
_VALID_AUTH_MODES = frozenset({"cognito_jwt", "local_mock"})

# P0-002: Environments where auth bypass (local_mock) is permitted.
# ANY env NOT in this set is treated as a customer deployment and requires full
# auth configuration.
# NOTE: "dev" is NOT here — it is a cloud deployment with real Cognito/ECS.
_LOCAL_TEST_ENVS = frozenset({"local", "test", "ci"})


def validate_auth_config(settings: Settings | None = None) -> None:
    """Fail-fast startup validation for auth configuration.

    Called during app creation (before accepting traffic).

    P0-002 rules:
      1. Unknown AUTH_MODE → RuntimeError in ALL environments.
      2. AUTH_MODE=local_mock outside local/test/ci → RuntimeError.
      3. SCANALYZE_DEPLOYMENT_CUSTOMER_ID required in non-local deployments.
      4. Cognito config required in non-local deployments.
      5. ENFORCE_AUTH_HEADER=false in non-local → RuntimeError (blocking).
      6. ENFORCE_AUTH_HEADER set in local/test/ci → warning only.
      7. TENANT_CLAIM_NAME must be custom:customerId in non-local.
    """
    if settings is None:
        settings = get_settings()

    env = (settings.env or "").lower().strip()
    auth_mode = (settings.auth_mode or "").lower().strip()
    is_local_test = env in _LOCAL_TEST_ENVS
    is_customer_deployment = not is_local_test

    # ── P0-002 Rule 1: Reject unknown AUTH_MODE in ALL environments ──
    if auth_mode not in _VALID_AUTH_MODES:
        raise RuntimeError(
            f"Invalid AUTH_MODE='{auth_mode}'. "
            f"Allowed values: {sorted(_VALID_AUTH_MODES)}"
        )

    # ── P0-002 Rule 2: local_mock only in local/test/ci ──
    if auth_mode == "local_mock" and is_customer_deployment:
        raise RuntimeError(
            f"AUTH_MODE=local_mock is FORBIDDEN in APP_ENV='{env}'. "
            f"Only allowed in: {sorted(_LOCAL_TEST_ENVS)}"
        )

    # ── P0-002 Rule 5: ENFORCE_AUTH_HEADER in non-local is fatal ──
    enforce_auth_env = os.getenv("ENFORCE_AUTH_HEADER")
    if enforce_auth_env is not None:
        if is_customer_deployment:
            raise RuntimeError(
                f"Deprecated env var ENFORCE_AUTH_HEADER is set in APP_ENV='{env}'. "
                "This variable is no longer used. Remove it from the task definition. "
                "Auth is controlled by AUTH_MODE=cognito_jwt."
            )
        else:
            import logging
            logging.getLogger("scanalyze.config").warning(
                "Deprecated env var ENFORCE_AUTH_HEADER is set but IGNORED. "
                "Auth is controlled by AUTH_MODE. Remove ENFORCE_AUTH_HEADER."
            )

    # ── P0-002 Rule 6: TENANT_HEADER_NAME deprecation warning ──
    if os.getenv("TENANT_HEADER_NAME") is not None:
        if is_customer_deployment:
            import logging
            logging.getLogger("scanalyze.config").warning(
                "Deprecated env var TENANT_HEADER_NAME is set but IGNORED. "
                "Customer identity comes from verified JWT claims, not headers."
            )
        else:
            import logging
            logging.getLogger("scanalyze.config").warning(
                "Deprecated env var TENANT_HEADER_NAME is set but IGNORED."
            )

    # ── For local_mock, no further config validation needed ──
    if auth_mode != "cognito_jwt":
        return

    errors: list[str] = []

    # ── P0-002 Rule 3: SCANALYZE_DEPLOYMENT_CUSTOMER_ID in non-local ──
    if is_customer_deployment:
        deployment_customer = (settings.scanalyze_deployment_customer_id or "").strip()
        if not deployment_customer:
            errors.append(
                "SCANALYZE_DEPLOYMENT_CUSTOMER_ID is required in non-local deployments "
                f"(APP_ENV='{env}'). Set it to the expected customer identity "
                "for this dedicated deployment (e.g. customer-example)."
            )

    # ── Cognito config validation ──
    if not settings.cognito_user_pool_id:
        errors.append(
            "COGNITO_USER_POOL_ID is required when AUTH_MODE=cognito_jwt"
        )

    if not settings.cognito_region:
        errors.append(
            "COGNITO_REGION is required when AUTH_MODE=cognito_jwt"
        )

    if not settings.tenant_claim_name:
        errors.append(
            "TENANT_CLAIM_NAME is required when AUTH_MODE=cognito_jwt"
        )

    # Validate tenant claim name is not a principal claim
    if settings.tenant_claim_name:
        from .auth import _validate_tenant_claim_name
        try:
            _validate_tenant_claim_name(settings.tenant_claim_name)
        except ValueError:
            errors.append("TENANT_CLAIM_NAME cannot be a principal/identity claim")

    # ── P0-002 Rule 7: tenant_claim_name must be custom:customerId in non-local ──
    if is_customer_deployment and settings.tenant_claim_name != "custom:customerId":
        errors.append(
            f"TENANT_CLAIM_NAME='{settings.tenant_claim_name}' is not allowed "
            "in customer deployments. Must be 'custom:customerId' per P0-001/P0-002."
        )

    # In customer deployments, COGNITO_ALLOWED_CLIENT_IDS must not be empty
    allowed_clients = (settings.cognito_allowed_client_ids or "").strip()
    if is_customer_deployment and not allowed_clients:
        errors.append(
            "COGNITO_ALLOWED_CLIENT_IDS must not be empty in customer deployments "
            f"(APP_ENV='{env}'). "
            "Set it to the comma-separated list of allowed Cognito app client IDs."
        )

    if errors:
        msg = (
            f"Auth configuration invalid (AUTH_MODE={auth_mode}, APP_ENV={env}):\n"
            + "\n".join(f"  - {error_message}" for error_message in errors)
        )
        if is_customer_deployment:
            # In customer deployments, this is fatal — abort startup
            raise RuntimeError(msg)
        else:
            # In local/test/ci, log as error but allow startup
            import logging
            logging.getLogger("scanalyze.config").error(msg)
