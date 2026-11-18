import os
import re
import time
import logging
import boto3
from typing import Dict, Any

from .environment_contract import (
    require_runtime_environment,
    require_customer_id,
    require_deployment_id
)
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
    if value is None:
        raise RuntimeError(f"{name} is required")
    stripped = value.strip()
    if not stripped:
        raise RuntimeError(f"{name} is required")
    return stripped


class ConfigCache:
    def __init__(self, ttl_seconds: int = 300):
        self._cache: Dict[str, Any] = {}
        self._last_fetch = 0
        self.ttl = ttl_seconds
        
        self.env = require_runtime_environment(os.environ.get("SCANALYZE_ENV"))
        self.source = runtime_config_source()
        if self.source == "environment":
            reject_legacy_tenant_settings()
        self.customer_id = require_customer_id(os.environ.get("SCANALYZE_DEPLOYMENT_CUSTOMER_ID"))
        self.deployment_id = require_deployment_id(os.environ.get("SCANALYZE_DEPLOYMENT_ID"))
        self._ssm_client = None
        if self.source == "environment":
            # One deployment-wide routing context replaces the legacy tenant (ADR-001).
            self.tenant = PLATFORM_ROUTING_CONTEXT
            self.root = None
            return
        self.tenant = require_nonempty_env("SCANALYZE_TENANT")
            
        param_root = os.environ.get("SCANALYZE_PARAM_ROOT", f"/scanalyze/{self.env}/tenants")
        if param_root.endswith(f"/{self.tenant}"):
            self.root = param_root
        else:
            self.root = f"{param_root.rstrip('/')}/{self.tenant}"

    @property
    def ssm_client(self):
        if self._ssm_client is None:
            self._ssm_client = boto3.client('ssm')
        return self._ssm_client

    def _fetch_from_ssm(self) -> None:
        logger.info("Fetching SSM parameters from path")
        paginator = self.ssm_client.get_paginator('get_parameters_by_path')
        
        new_cache = {}
        try:
            for page in paginator.paginate(Path=self.root, Recursive=True, WithDecryption=True):
                for param in page.get('Parameters', []):
                    # For /scanalyze/<environment>/tenants/<tenant>/queues/ingest_url
                    # the key becomes queues/ingest_url
                    key = param['Name'].replace(f"{self.root}/", "")
                    new_cache[key] = param['Value']
        except Exception as e:
            logger.error("Failed to fetch parameters from SSM", extra={"errorType": type(e).__name__})
            raise
                
        self._cache = new_cache
        self._last_fetch = time.time()
        logger.debug("SSM cache updated", extra={"parameterCount": len(self._cache)})

    def get(self, key: str) -> str:
        if self.source == "environment":
            return read_environment_config(key)
        if time.time() - self._last_fetch > self.ttl:
            self._fetch_from_ssm()
            
        if key not in self._cache:
            raise KeyError(f"Configuration key '{key}' not found in SSM at {self.root}")
            
        return self._cache[key]

# Provide a global instance
config = ConfigCache(ttl_seconds=300)
