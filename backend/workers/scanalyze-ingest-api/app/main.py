from __future__ import annotations

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .config import get_settings, validate_auth_config
from .errors import register_exception_handlers
from .logging import configure_logging
from .middleware import RequestContextMiddleware
from .api.health import router as health_router
from .api.v1.router import router as v1_router

def create_app() -> FastAPI:
    s = get_settings()

    configure_logging(s.log_level, s.service_name, s.env)

    # P0-001: Fail-fast if auth is misconfigured in prod/staging.
    # This runs before the app starts accepting traffic.
    validate_auth_config(s)

    app = FastAPI(
        title="Scanalyze Ingest API",
        version="1.0.0",
        docs_url="/docs",
        redoc_url=None,
        openapi_url="/openapi.json",
    )

    # Middlewares
    app.add_middleware(RequestContextMiddleware, service_name=s.service_name)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=s.cors_origins_list(),
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
        allow_headers=["Authorization", "Content-Type", "Idempotency-Key"],
        expose_headers=["X-Correlation-ID", "X-Request-ID", "X-Trace-ID"],
    )

    # Routers
    app.include_router(health_router)
    app.include_router(v1_router)

    # Error handling
    register_exception_handlers(app)

    return app

app = create_app()
