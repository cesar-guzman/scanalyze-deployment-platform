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
        self.tenant = require_nonempty_env("SCANALYZE_TENANT")
        self.customer_id = require_nonempty_env("SCANALYZE_DEPLOYMENT_CUSTOMER_ID")
        self.deployment_id = require_nonempty_env("SCANALYZE_DEPLOYMENT_ID")
        if not re.fullmatch(r"^cust_[0-9A-HJKMNP-TV-Z]{26}$", self.customer_id):
            raise RuntimeError("SCANALYZE_DEPLOYMENT_CUSTOMER_ID is invalid")
        if not re.fullmatch(r"^dep_[0-9A-HJKMNP-TV-Z]{26}$", self.deployment_id):
            raise RuntimeError("SCANALYZE_DEPLOYMENT_ID is invalid")
            
        param_root = os.environ.get("SCANALYZE_PARAM_ROOT", f"/scanalyze/{self.env}/tenants")
        if param_root.endswith(f"/{self.tenant}"):
            self.root = param_root
        else:
            self.root = f"{param_root.rstrip('/')}/{self.tenant}"
            
        # Optional: session could check if we are local or in AWS, but standard boto3 behavior works.
        self.ssm_client = boto3.client('ssm')

    def _fetch_from_ssm(self) -> None:
        logger.info(f"Fetching SSM parameters from path: {self.root}")
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
        if time.time() - self._last_fetch > self.ttl:
            self._fetch_from_ssm()
            
        if key not in self._cache:
            raise KeyError(f"Configuration key '{key}' not found in SSM at {self.root}")
            
        return self._cache[key]

# Provide a global instance
config = ConfigCache(ttl_seconds=300)
