"""Shared test configuration for scanalyze-ingest-api.

Sets APP_ENV=local so that tests importing `app.main` don't fail
due to P0-002 startup validation requiring full Cognito config.

This runs before any test module is imported, so it must be at the
conftest.py level (pytest loads conftest before collecting tests).
"""
import os

# Must be set before any import of app.config / app.main
os.environ.setdefault("APP_ENV", "local")
os.environ.setdefault("AUTH_MODE", "local_mock")
os.environ.setdefault("LOCAL_MOCK_TENANT_ID", "test-tenant")
