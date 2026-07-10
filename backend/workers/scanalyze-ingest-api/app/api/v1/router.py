from __future__ import annotations

from fastapi import APIRouter

from .documents import router as documents_router
from .batches import router as batches_router
from .analytics import router as analytics_router
from .addons.employee_profiles import router as employee_profiles_router

router = APIRouter(prefix="/api/v1")
router.include_router(documents_router, prefix="/documents", tags=["documents"])
router.include_router(batches_router, prefix="/batches", tags=["batches"])
router.include_router(analytics_router, prefix="/analytics", tags=["analytics"])
router.include_router(employee_profiles_router, prefix="/addons/employee-profiles", tags=["addons-employee-profiles"])

