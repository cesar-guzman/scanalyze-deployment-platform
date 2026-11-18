"""Environment runtime configuration (ADR-001, GUG-108).

With SCANALYZE_RUNTIME_CONFIG_SOURCE=environment the worker reads every
configuration key from a SCANALYZE_CONFIG_<KEY> variable that Terraform sets
on the task definition. It never calls SSM and has no legacy tenant.
"""

import logging
import os
from unittest.mock import patch

import pytest

from ocr_worker.config import ConfigCache, runtime_config_env_name

LEGACY_SETTINGS = ("SCANALYZE_TENANT", "SCANALYZE_TENANTS", "SCANALYZE_PARAM_ROOT")
QUEUE_URL = "https://sqs.us-east-1.amazonaws.com/000000000000/dep_01ARZ3NDEKTSV4RRFFQ69G5FAV-validate-stage-queue"


@pytest.fixture
def environment_mode(monkeypatch):
    monkeypatch.setenv("SCANALYZE_RUNTIME_CONFIG_SOURCE", "environment")
    for name in LEGACY_SETTINGS:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("SCANALYZE_CONFIG_QUEUES_VALIDATE_URL", QUEUE_URL)
    return monkeypatch


def test_key_names_follow_the_terraform_contract():
    assert runtime_config_env_name("queues/bank-extract_url") == "SCANALYZE_CONFIG_QUEUES_BANK_EXTRACT_URL"
    assert (
        runtime_config_env_name("data-foundation/documents_table_name")
        == "SCANALYZE_CONFIG_DATA_FOUNDATION_DOCUMENTS_TABLE_NAME"
    )
    assert runtime_config_env_name("BEDROCK_MODEL_ID") == "SCANALYZE_CONFIG_BEDROCK_MODEL_ID"


@pytest.mark.parametrize("legacy", LEGACY_SETTINGS)
def test_environment_mode_rejects_legacy_tenant_settings(environment_mode, legacy):
    environment_mode.setenv(legacy, "platform")
    with pytest.raises(RuntimeError, match=f"{legacy} must not be set"):
        ConfigCache()


def test_unknown_config_source_is_rejected(monkeypatch):
    monkeypatch.setenv("SCANALYZE_RUNTIME_CONFIG_SOURCE", "consul")
    with pytest.raises(RuntimeError, match="must be 'ssm' or 'environment'"):
        ConfigCache()


def test_environment_mode_reads_keys_without_ssm(environment_mode):
    with patch("ocr_worker.config.boto3.client") as boto_client:
        config = ConfigCache()
        assert config.get("queues/validate_url") == QUEUE_URL
    boto_client.assert_not_called()
    assert config.source == "environment"
    assert config.tenant == "platform"


def test_environment_mode_fails_closed_on_missing_key(environment_mode):
    config = ConfigCache()
    with pytest.raises(KeyError, match="SCANALYZE_CONFIG_QUEUES_PERSIST_URL"):
        config.get("queues/persist_url")


def test_ssm_remains_the_default_source(monkeypatch):
    monkeypatch.delenv("SCANALYZE_RUNTIME_CONFIG_SOURCE", raising=False)
    with patch("ocr_worker.config.boto3.client"):
        config = ConfigCache()
    assert config.source == "ssm"
    assert config.root.endswith("/" + os.environ["SCANALYZE_TENANT"])


def test_logging_works_without_a_tenant_in_environment_mode(environment_mode):
    from ocr_worker.logger import setup_logging

    root = logging.getLogger()
    saved_handlers = root.handlers[:]
    saved_level = root.level
    try:
        setup_logging()
        assert root.handlers[-1].formatter.tenant == "platform"
    finally:
        for handler in root.handlers[:]:
            root.removeHandler(handler)
        for handler in saved_handlers:
            root.addHandler(handler)
        root.setLevel(saved_level)
