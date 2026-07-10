from unittest.mock import MagicMock

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from pydantic import BaseModel

from app.errors import AppError, register_exception_handlers
from app.services.analytics import AnalyticsService


def test_cost_analytics_rejects_missing_deployment_environment(monkeypatch):
    monkeypatch.delenv("SCANALYZE_ENV", raising=False)
    service = object.__new__(AnalyticsService)
    service.logger = MagicMock()

    with pytest.raises(AppError) as captured:
        service.get_costs_dashboard("tenant-test")

    assert captured.value.status_code == 500
    assert captured.value.details == {}


def test_validation_response_omits_input_value():
    sensitive_value = "SYNTHETIC-PII-IN-REQUEST"

    class RequestBody(BaseModel):
        amount: int

    app = FastAPI()
    register_exception_handlers(app)

    @app.post("/validate")
    def validate(body: RequestBody):
        return body

    response = TestClient(app).post("/validate", json={"amount": sensitive_value})

    assert response.status_code == 422
    assert response.json()["message"] == "Request validation failed"
    assert response.json()["details"]["errorType"] == "RequestValidationError"
    assert sensitive_value not in response.text
