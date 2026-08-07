import pytest
from src.ocr_worker.environment_contract import (
    require_runtime_environment,
    project_log_environment,
    SUPPORTED_RUNTIME_ENVIRONMENTS,
    require_customer_id,
    require_deployment_id,
    project_customer_id,
    project_deployment_id
)

def test_require_runtime_environment():
    assert require_runtime_environment("demo") == "demo"
    assert require_runtime_environment("production") == "production"
    assert require_runtime_environment("local") == "local"
    assert require_runtime_environment("test") == "test"
    assert require_runtime_environment("ci") == "ci"

    with pytest.raises(RuntimeError):
        require_runtime_environment(None)
    with pytest.raises(RuntimeError):
        require_runtime_environment("")
    with pytest.raises(RuntimeError):
        require_runtime_environment("prod")
    with pytest.raises(RuntimeError):
        require_runtime_environment(" demo")
    with pytest.raises(RuntimeError):
        require_runtime_environment("demo\n")

def test_project_log_environment():
    assert project_log_environment("demo") == "demo"
    assert project_log_environment("production") == "production"
    assert project_log_environment(None) == "unknown"
    assert project_log_environment("") == "unknown"
    assert project_log_environment("prod") == "unknown"
    assert project_log_environment(" demo") == "unknown"
    assert project_log_environment({"env": "demo"}) == "unknown"

def test_drift_contract():
    assert "demo" in SUPPORTED_RUNTIME_ENVIRONMENTS
    assert "local" in SUPPORTED_RUNTIME_ENVIRONMENTS
    assert "test" in SUPPORTED_RUNTIME_ENVIRONMENTS
    assert "ci" in SUPPORTED_RUNTIME_ENVIRONMENTS

def test_require_customer_id():
    valid = "cust_0123456789ABCDEFGHJKMNP123"
    assert require_customer_id(valid) == valid

    with pytest.raises(RuntimeError):
        require_customer_id(None)
    with pytest.raises(RuntimeError):
        require_customer_id("")
    with pytest.raises(RuntimeError):
        require_customer_id(valid + " ")
    with pytest.raises(RuntimeError):
        require_customer_id(valid.lower()) # Crockford base32 is uppercase typically in our regex

def test_require_deployment_id():
    valid = "dep_0123456789ABCDEFGHJKMNP123"
    assert require_deployment_id(valid) == valid

    with pytest.raises(RuntimeError):
        require_deployment_id(None)
    with pytest.raises(RuntimeError):
        require_deployment_id("")
    with pytest.raises(RuntimeError):
        require_deployment_id(valid + " ")

def test_project_customer_id():
    valid = "cust_0123456789ABCDEFGHJKMNP123"
    assert project_customer_id(valid) == valid
    assert project_customer_id(None) == "unknown"
    assert project_customer_id("") == "unknown"
    assert project_customer_id(valid + "\n") == "unknown"

def test_project_deployment_id():
    valid = "dep_0123456789ABCDEFGHJKMNP123"
    assert project_deployment_id(valid) == valid
    assert project_deployment_id(None) == "unknown"
    assert project_deployment_id("") == "unknown"
    assert project_deployment_id("dep_invalid_chars_here") == "unknown"
