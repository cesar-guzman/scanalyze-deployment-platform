from __future__ import annotations

from fastapi import APIRouter

from ..config import get_settings

router = APIRouter(tags=["health"])

@router.get("/health")
def health() -> dict:
    s = get_settings()
    return {"status": "ok", "service": s.service_name}

@router.get("/api/v1/health")
def health_v1() -> dict:
    return health()
