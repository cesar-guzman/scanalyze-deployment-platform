import os
import json
import logging
import io
import pytest
from src.ocr_worker.logger import setup_logging, JSONFormatter

@pytest.fixture
def capture_log(monkeypatch):
    monkeypatch.setenv("SCANALYZE_TENANT", "test-tenant")
    monkeypatch.setenv("SCANALYZE_ENV", "test")
    def _capture(**env_vars):
        for k, v in env_vars.items():
            if v is None:
                monkeypatch.delenv(k, raising=False)
            else:
                monkeypatch.setenv(k, v)
        
        stream = io.StringIO()
        handler = logging.StreamHandler(stream)
        formatter = JSONFormatter(tenant="test-tenant", stage="ocr_ingest")
        handler.setFormatter(formatter)
        
        logger = logging.getLogger("test_identities")
        logger.setLevel(logging.INFO)
        # Clear existing handlers
        for h in logger.handlers[:]:
            logger.removeHandler(h)
        logger.addHandler(handler)
        
        logger.info("test message")
        
        output = stream.getvalue()
        return json.loads(output)
    return _capture

def test_logger_identities_valid(capture_log):
    log = capture_log(
        SCANALYZE_DEPLOYMENT_CUSTOMER_ID="cust_AAAAAAAAAAAAAAAAAAAAAAAAAA",
        SCANALYZE_DEPLOYMENT_ID="dep_AAAAAAAAAAAAAAAAAAAAAAAAAA"
    )
    assert log["customerId"] == "cust_AAAAAAAAAAAAAAAAAAAAAAAAAA"
    assert log["deploymentId"] == "dep_AAAAAAAAAAAAAAAAAAAAAAAAAA"

def test_logger_identities_missing(capture_log):
    log = capture_log(
        SCANALYZE_DEPLOYMENT_CUSTOMER_ID=None,
        SCANALYZE_DEPLOYMENT_ID=None
    )
    assert log["customerId"] == "unknown"
    assert log["deploymentId"] == "unknown"

def test_logger_identities_whitespace(capture_log):
    log = capture_log(
        SCANALYZE_DEPLOYMENT_CUSTOMER_ID="  ",
        SCANALYZE_DEPLOYMENT_ID="\t"
    )
    assert log["customerId"] == "unknown"
    assert log["deploymentId"] == "unknown"

def test_logger_identities_malformed_prefix(capture_log):
    log = capture_log(
        SCANALYZE_DEPLOYMENT_CUSTOMER_ID="bad_AAAAAAAAAAAAAAAAAAAAAAAAAA",
        SCANALYZE_DEPLOYMENT_ID="cust_AAAAAAAAAAAAAAAAAAAAAAAAAA"
    )
    assert log["customerId"] == "unknown"
    assert log["deploymentId"] == "unknown"

def test_logger_identities_wrong_length(capture_log):
    log = capture_log(
        SCANALYZE_DEPLOYMENT_CUSTOMER_ID="cust_123",
        SCANALYZE_DEPLOYMENT_ID="dep_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    )
    assert log["customerId"] == "unknown"
    assert log["deploymentId"] == "unknown"

def test_logger_identities_lowercase_invalid_chars(capture_log):
    log = capture_log(
        SCANALYZE_DEPLOYMENT_CUSTOMER_ID="cust_0123456789abcdefghjkmnp123",
        SCANALYZE_DEPLOYMENT_ID="dep_AAAAAAAAAAAAAAAAABCLUIO!@#$QWERTY"
    )
    assert log["customerId"] == "unknown"
    assert log["deploymentId"] == "unknown"

def test_logger_identities_sentinels(capture_log):
    # OCR-content sentinel
    log = capture_log(
        SCANALYZE_DEPLOYMENT_CUSTOMER_ID="<OCR_CONTENT>",
        SCANALYZE_DEPLOYMENT_ID="<PII_SENTINEL_NAME>"
    )
    assert log["customerId"] == "unknown"
    assert log["deploymentId"] == "unknown"
    
    # Prove sentinels are entirely absent from the complete JSON line
    raw_json = json.dumps(log)
    assert "<OCR_CONTENT>" not in raw_json
    assert "<PII_SENTINEL_NAME>" not in raw_json

def test_logger_identities_control_characters(capture_log):
    log = capture_log(
        SCANALYZE_DEPLOYMENT_CUSTOMER_ID="cust_AAAAAAAAAAAAAAAAAAAAAAAAAA\n",
        SCANALYZE_DEPLOYMENT_ID="dep_AAAAAAAAAAAAAAAAAAAAAAAAAA\x01"
    )
    assert log["customerId"] == "unknown"
    assert log["deploymentId"] == "unknown"

def test_logger_identities_nested_object_values(capture_log):
    # This represents a situation where env vars are somehow not strings
    # We can't strictly pass objects to os.environ, but we can test the formatter directly
    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    formatter = JSONFormatter(tenant="test-tenant", stage="ocr_ingest")
    
    # Force injection
    formatter.customer_id = formatter.deployment_id = "unknown"
    
    from src.ocr_worker.environment_contract import project_customer_id
    assert project_customer_id({"nested": "dict"}) == "unknown"
    assert project_customer_id(["list"]) == "unknown"
