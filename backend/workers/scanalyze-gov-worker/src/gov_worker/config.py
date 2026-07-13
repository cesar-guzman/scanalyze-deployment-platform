import os
import re
import time
import logging
import boto3
from typing import Dict, Any

logger = logging.getLogger(__name__)


def require_nonempty_env(name: str) -> str:
    value = os.environ.get(name)
    if value is None or not value.strip():
        raise RuntimeError(f"{name} is required")
    return value.strip()


class ConfigCache:
    def __init__(self, ttl_seconds: int = 300):
        self._cache: Dict[str, Any] = {}
        self._last_fetch = 0
        self.ttl = ttl_seconds
        
        self.env = require_nonempty_env("SCANALYZE_ENV")
        self.customer_id = require_nonempty_env("SCANALYZE_DEPLOYMENT_CUSTOMER_ID")
        self.deployment_id = require_nonempty_env("SCANALYZE_DEPLOYMENT_ID")
        if not re.fullmatch(r"^cust_[0-9A-HJKMNP-TV-Z]{26}$", self.customer_id):
            raise RuntimeError("SCANALYZE_DEPLOYMENT_CUSTOMER_ID is invalid")
        if not re.fullmatch(r"^dep_[0-9A-HJKMNP-TV-Z]{26}$", self.deployment_id):
            raise RuntimeError("SCANALYZE_DEPLOYMENT_ID is invalid")
        self.tenant = os.environ.get("SCANALYZE_TENANT")
        
        if not self.tenant or self.tenant != "gov":
            logger.critical("Invalid tenant configuration")
            raise ValueError("SCANALYZE_TENANT must be 'gov'")
            
        # Optional root prefix config
        param_root = os.environ.get("SCANALYZE_PARAM_ROOT", f"/scanalyze/{self.env}/tenants")
        if param_root.endswith(f"/{self.tenant}"):
            self.root = param_root
        else:
            self.root = f"{param_root.rstrip('/')}/{self.tenant}"
            
        self.ssm_client = boto3.client('ssm')

    def _fetch_from_ssm(self) -> None:
        logger.info("Fetching tenant parameters from SSM")
        paginator = self.ssm_client.get_paginator('get_parameters_by_path')
        
        new_cache = {}
        try:
            for page in paginator.paginate(Path=self.root, Recursive=True, WithDecryption=True):
                for param in page.get('Parameters', []):
                    key = param['Name'].replace(f"{self.root}/", "")
                    new_cache[key] = param['Value']
        except Exception as e:
            logger.error("Failed to fetch parameters from SSM", extra={"errorType": type(e).__name__})
            raise
                
        # --- MULTI-TENANT TRACKING FIX ---
        # Fuerza lectura de tabla DynamoDB hacia platform para unificar estados
        try:
            logger.info("Fetching platform parameters from SSM")
            platform_paginator = self.ssm_client.get_paginator('get_parameters_by_path')
            for page in platform_paginator.paginate(Path=f"/scanalyze/{self.env}/tenants/platform", Recursive=True, WithDecryption=True):
                for param in page.get('Parameters', []):
                    if param['Name'].endswith("data-foundation/documents_table_name"):
                        new_cache["data-foundation/documents_table_name"] = param['Value']
                        logger.info("Successfully fetched platform documents table override")
        except Exception as e:
            logger.error("Failed to fetch platform override from SSM", extra={"errorType": type(e).__name__})
        # ---------------------------------
                
        self._cache = new_cache
        self._last_fetch = time.time()
        logger.debug("SSM cache updated", extra={"parameterCount": len(self._cache)})

    def get(self, key: str, default: Any = None) -> Any:
        if time.time() - self._last_fetch > self.ttl:
            self._fetch_from_ssm()
            
        if key not in self._cache:
            if default is not None:
                return default
            raise KeyError(f"Configuration key '{key}' not found in SSM at {self.root}")
            
        return self._cache[key]

    def require_owner(self, customer_id: str, deployment_id: str) -> None:
        if customer_id != self.customer_id or deployment_id != self.deployment_id:
            raise ValueError("Message ownership does not match the runtime deployment")

config = ConfigCache(ttl_seconds=300)
