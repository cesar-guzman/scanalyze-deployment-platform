import os
import re
import time
import logging
import boto3
from typing import Dict, Any, List

logger = logging.getLogger(__name__)


RUNTIME_CONFIG_SOURCE_ENV = "SCANALYZE_RUNTIME_CONFIG_SOURCE"
RUNTIME_CONFIG_ENV_PREFIX = "SCANALYZE_CONFIG_"
PLATFORM_ROUTING_CONTEXT = "platform"
# Settings of the legacy SSM tenant tree. Environment mode refuses them (ADR-001).
LEGACY_TENANT_SETTINGS = ("SCANALYZE_TENANT", "SCANALYZE_TENANTS", "SCANALYZE_PARAM_ROOT")


def runtime_config_source() -> str:
    """Return where runtime configuration comes from.

    "ssm" (default) keeps the legacy /scanalyze/<env>/tenants/<tenant> tree.
    "environment" reads every key from a SCANALYZE_CONFIG_<KEY> variable that
    Terraform sets on the task definition, without a tenant (ADR-001, GUG-108).
    """
    source = os.environ.get(RUNTIME_CONFIG_SOURCE_ENV, "ssm").strip().lower()
    if source not in ("ssm", "environment"):
        raise RuntimeError(f"{RUNTIME_CONFIG_SOURCE_ENV} must be 'ssm' or 'environment'")
    return source


def runtime_config_env_name(key: str) -> str:
    """Map a configuration key to its variable: queues/bank-extract_url -> SCANALYZE_CONFIG_QUEUES_BANK_EXTRACT_URL."""
    return RUNTIME_CONFIG_ENV_PREFIX + re.sub(r"[^A-Z0-9]", "_", key.upper())


def reject_legacy_tenant_settings() -> None:
    present = sorted(name for name in LEGACY_TENANT_SETTINGS if os.environ.get(name, "").strip())
    if present:
        raise RuntimeError(
            f"{', '.join(present)} must not be set when {RUNTIME_CONFIG_SOURCE_ENV}=environment"
        )


def read_environment_config(key: str, default: Any = None) -> Any:
    name = runtime_config_env_name(key)
    value = os.environ.get(name)
    if value is None or not value.strip():
        if default is not None:
            return default
        raise KeyError(f"Configuration key '{key}' is not set in {name}")
    return value.strip()


def require_nonempty_env(name: str) -> str:
    value = os.environ.get(name)
    if value is None or not value.strip():
        raise RuntimeError(f"{name} is required")
    return value.strip()


class ConfigCache:
    def __init__(self, ttl_seconds: int = 300):
        self._cache: Dict[str, Dict[str, Any]] = {}  # {tenant: {key: value}}
        self._last_fetch = 0
        self.ttl = ttl_seconds
        
        self.env = require_nonempty_env("SCANALYZE_ENV")
        self.customer_id = require_nonempty_env("SCANALYZE_DEPLOYMENT_CUSTOMER_ID")
        self.deployment_id = require_nonempty_env("SCANALYZE_DEPLOYMENT_ID")
        if not re.fullmatch(r"^cust_[0-9A-HJKMNP-TV-Z]{26}$", self.customer_id):
            raise RuntimeError("SCANALYZE_DEPLOYMENT_CUSTOMER_ID is invalid")
        if not re.fullmatch(r"^dep_[0-9A-HJKMNP-TV-Z]{26}$", self.deployment_id):
            raise RuntimeError("SCANALYZE_DEPLOYMENT_ID is invalid")

        self.source = runtime_config_source()
        if self.source == "environment":
            reject_legacy_tenant_settings()
            # One deployment-wide routing context replaces the legacy tenants (ADR-001).
            # "platform" accepts every supported domain route (routing.route_is_allowed).
            self.tenants = [PLATFORM_ROUTING_CONTEXT]
            self.param_root = None
            self.ssm_client = None
            return

        # In multi-tenant workers, SCANALYZE_TENANTS contains comma-separated tenant IDs
        tenants_str = os.environ.get("SCANALYZE_TENANTS", "").strip()
        if tenants_str:
            self.tenants = [t.strip() for t in tenants_str.split(",") if t.strip()]
            if not self.tenants:
                raise RuntimeError("SCANALYZE_TENANTS must contain at least one tenant")
        else:
            # Explicit single-tenant compatibility mode; never infer a tenant.
            single_tenant = require_nonempty_env("SCANALYZE_TENANT")
            self.tenants = [single_tenant]
            
        self.param_root = os.environ.get("SCANALYZE_PARAM_ROOT", f"/scanalyze/{self.env}/tenants")
        
        self.ssm_client = boto3.client('ssm')

    def _fetch_from_ssm(self) -> None:
        new_cache = {tenant: {} for tenant in self.tenants}
        
        for tenant in self.tenants:
            # Determine the SSM path for this tenant
            if self.param_root.endswith(f"/{tenant}"):
                tenant_root = self.param_root
            else:
                tenant_root = f"{self.param_root.rstrip('/')}/{tenant}"
                
            logger.info("Fetching tenant parameters from SSM")
            paginator = self.ssm_client.get_paginator('get_parameters_by_path')
            
            try:
                for page in paginator.paginate(Path=tenant_root, Recursive=True, WithDecryption=True):
                    for param in page.get('Parameters', []):
                        key = param['Name'].replace(f"{tenant_root}/", "")
                        new_cache[tenant][key] = param['Value']
                        
                # OVERRIDE: Route the tracking table to the platform tenant globally
                platform_root = f"/scanalyze/{self.env}/tenants/platform"
                platform_table_param = f"{platform_root}/data-foundation/documents_table_name"
                try:
                    platform_table = self.ssm_client.get_parameter(Name=platform_table_param, WithDecryption=True)
                    new_cache[tenant]["data-foundation/documents_table_name"] = platform_table['Parameter']['Value']
                    logger.info("Successfully fetched platform documents table override")
                except Exception as e:
                    logger.warning(
                        "Could not fetch platform documents table override",
                        extra={"errorType": type(e).__name__},
                    )
                    
            except Exception as e:
                logger.error("Failed to fetch tenant parameters", extra={"errorType": type(e).__name__})
                # Don't raise, try other tenants or continue with what we have
                
        self._cache = new_cache
        self._last_fetch = time.time()
        logger.debug("SSM cache updated", extra={"tenantCount": len(self.tenants)})

    def get(self, tenant: str, key: str, default: Any = None) -> Any:
        if self.source == "environment":
            if tenant not in self.tenants:
                if default is not None:
                    return default
                raise KeyError(f"Tenant '{tenant}' not configured or fetched")
            return read_environment_config(key, default)
        if time.time() - self._last_fetch > self.ttl:
            self._fetch_from_ssm()
            
        if tenant not in self._cache:
            if default is not None:
                return default
            raise KeyError(f"Tenant '{tenant}' not configured or fetched")
            
        if key not in self._cache[tenant]:
            if default is not None:
                return default
            raise KeyError(f"Configuration key '{key}' not found for tenant '{tenant}'")
            
        return self._cache[tenant][key]

    def require_owner(self, customer_id: str, deployment_id: str) -> None:
        if customer_id != self.customer_id or deployment_id != self.deployment_id:
            raise ValueError("Message ownership does not match the runtime deployment")

config = ConfigCache(ttl_seconds=300)
