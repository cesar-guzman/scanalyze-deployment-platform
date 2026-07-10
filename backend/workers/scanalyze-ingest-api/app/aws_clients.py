from __future__ import annotations

from functools import lru_cache

import boto3
from botocore.config import Config as BotoConfig

from .config import get_settings

@lru_cache(maxsize=1)
def _botocore_config() -> BotoConfig:
    s = get_settings()
    return BotoConfig(
        connect_timeout=s.aws_connect_timeout_seconds,
        read_timeout=s.aws_read_timeout_seconds,
        retries={"max_attempts": s.aws_max_attempts, "mode": "standard"},
        signature_version="s3v4",
    )

@lru_cache(maxsize=1)
def s3_client():
    return boto3.client("s3", config=_botocore_config())

@lru_cache(maxsize=1)
def sqs_client():
    return boto3.client("sqs", config=_botocore_config())

@lru_cache(maxsize=1)
def dynamodb_resource():
    return boto3.resource("dynamodb", config=_botocore_config())

@lru_cache(maxsize=1)
def dynamodb_client():
    return boto3.client("dynamodb", config=_botocore_config())
