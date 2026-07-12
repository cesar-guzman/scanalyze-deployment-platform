from __future__ import annotations

import csv
import io
import json
import os
from collections import defaultdict
from typing import Any, Dict, List

import boto3
from fastapi.responses import StreamingResponse

from ..auth import AuthContext
from ..authorization import ObjectAction, ObjectOwnership, authorize_document
from ..aws_clients import s3_client
from ..config import get_settings
from ..errors import AppError
from ..logging import bind_context, get_logger
from ..repositories.documents import DocumentsRepository
from .documents import DocumentsService


class AnalyticsService:
    """Ownership-bound analytics over the canonical documents index."""

    def __init__(self) -> None:
        self.settings = get_settings()
        self.logger = get_logger()
        self.repo = DocumentsRepository()
        self.document_service = DocumentsService()

    def _owned_documents(
        self,
        auth: AuthContext,
        action: ObjectAction,
    ) -> List[Dict[str, Any]]:
        ownership = ObjectOwnership.from_auth(auth)
        documents = self.repo.list_owned_documents(ownership=ownership)
        for document in documents:
            authorize_document(auth, document, action)
        return documents

    def get_dashboard(
        self,
        auth: AuthContext,
        start_date: str | None = None,
        end_date: str | None = None,
        doc_type: str | None = None,
        batch_id: str | None = None,
        status: str | None = None,
    ) -> Dict[str, Any]:
        bind_context(tenant=auth.customer_id)
        documents = self._owned_documents(auth, ObjectAction.READ)

        filtered_docs: List[Dict[str, Any]] = []
        for document in documents:
            created = document.get("createdAt", "")
            if start_date and created < start_date:
                continue
            if end_date and created > end_date:
                continue
            if batch_id and document.get("batchId") != batch_id:
                continue
            if status and document.get("status") != status:
                continue
            input_info = document.get("input") or {}
            current_type = input_info.get("contentType", "") if isinstance(input_info, dict) else ""
            if doc_type and current_type != doc_type:
                continue
            filtered_docs.append(document)

        completed_states = ("COMPLETED", "SUCCESS", "OCR_COMPLETED")
        documents_completed = sum(
            1 for document in filtered_docs if document.get("status") in completed_states
        )
        documents_failed = sum(
            1
            for document in filtered_docs
            if str(document.get("status")).endswith("FAILED")
            or document.get("status") == "ERROR"
        )

        pages_total = 0
        pages_by_user: defaultdict[str, int] = defaultdict(int)
        documents_by_user: defaultdict[str, int] = defaultdict(int)
        user_names: Dict[str, str] = {}
        pages_by_day: defaultdict[str, int] = defaultdict(int)
        documents_by_day: defaultdict[str, int] = defaultdict(int)
        pages_by_type: defaultdict[str, int] = defaultdict(int)
        documents_by_type: defaultdict[str, int] = defaultdict(int)
        pages_by_batch: defaultdict[str, int] = defaultdict(int)
        documents_by_batch: defaultdict[str, int] = defaultdict(int)

        for document in filtered_docs:
            pages = int(float(document.get("pagesScanned", 0) or 0))
            if pages == 0 and document.get("status") in completed_states:
                pages = 1
            pages_total += pages

            user_id = document.get("uploaderUserId", "Unknown")
            if user_id != "Unknown":
                user_names[user_id] = (
                    document.get("createdByDisplayName")
                    or document.get("createdByEmail")
                    or user_id
                )
            pages_by_user[user_id] += pages
            documents_by_user[user_id] += 1

            day = str(document.get("createdAt", ""))[:10]
            if day:
                pages_by_day[day] += pages
                documents_by_day[day] += 1

            input_info = document.get("input") or {}
            current_type = input_info.get("contentType", "Unknown") if isinstance(input_info, dict) else "Unknown"
            current_type = current_type or "Unknown"
            pages_by_type[current_type] += pages
            documents_by_type[current_type] += 1

            current_batch = document.get("batchId", "Unknown")
            pages_by_batch[current_batch] += pages
            documents_by_batch[current_batch] += 1

        by_user = [
            {
                "userId": key,
                "displayName": user_names.get(key, key),
                "pagesScanned": value,
                "documentsCount": documents_by_user[key],
            }
            for key, value in pages_by_user.items()
        ]
        by_user.sort(key=lambda item: item["documentsCount"], reverse=True)
        by_day = [
            {"day": key, "pagesScanned": value, "documentsCount": documents_by_day[key]}
            for key, value in pages_by_day.items()
        ]
        by_day.sort(key=lambda item: item["day"], reverse=True)

        return {
            "overview": {
                "documentsUploaded": len(filtered_docs),
                "documentsCompleted": documents_completed,
                "documentsFailed": documents_failed,
                "pagesScanned": pages_total,
            },
            "byUser": by_user,
            "byDay": by_day,
            "byDocType": [
                {
                    "docType": key,
                    "pagesScanned": value,
                    "documentsCount": documents_by_type[key],
                }
                for key, value in pages_by_type.items()
            ],
            "byBatch": [
                {
                    "batchId": key,
                    "pagesScanned": value,
                    "documentsCount": documents_by_batch[key],
                }
                for key, value in pages_by_batch.items()
            ],
        }

    def get_overview(self, auth: AuthContext) -> Dict[str, Any]:
        return self.get_dashboard(auth=auth).get("overview", {})

    def get_by_day(self, auth: AuthContext) -> List[Dict[str, Any]]:
        return self.get_dashboard(auth=auth).get("byDay", [])

    def get_by_user(self, auth: AuthContext) -> List[Dict[str, Any]]:
        return self.get_dashboard(auth=auth).get("byUser", [])

    def get_by_batch(self, auth: AuthContext) -> List[Dict[str, Any]]:
        return self.get_dashboard(auth=auth).get("byBatch", [])

    def get_by_doc_type(self, auth: AuthContext) -> List[Dict[str, Any]]:
        return self.get_dashboard(auth=auth).get("byDocType", [])

    def get_costs_dashboard(self, auth: AuthContext) -> Dict[str, Any]:
        deployment_env = os.getenv("SCANALYZE_ENV")
        if not deployment_env or not deployment_env.strip():
            self.logger.error(
                "cost_analytics_failed",
                reason="missing_deployment_environment",
            )
            raise AppError(
                code="DB_ERROR",
                message="Failed to fetch cost analytics",
                status_code=500,
                details={},
            )

        bind_context(tenant=auth.customer_id)
        documents = self._owned_documents(auth, ObjectAction.READ)
        rate_per_page = 0.0015
        try:
            response = boto3.client("ssm").get_parameter(
                Name=f"/scanalyze/{deployment_env.strip()}/settings/textract_rate_per_page"
            )
            rate_per_page = float(response["Parameter"]["Value"])
        except Exception:
            rate_per_page = 0.0015

        total_pages = 0
        total_docs = 0
        pages_by_type: defaultdict[str, int] = defaultdict(int)
        for document in documents:
            if document.get("status") not in ("COMPLETED", "SUCCESS", "OCR_COMPLETED"):
                continue
            pages = int(float(document.get("pagesScanned", 0) or 0)) or 1
            total_pages += pages
            total_docs += 1
            input_info = document.get("input") or {}
            doc_type = input_info.get("contentType", "Unknown") if isinstance(input_info, dict) else "Unknown"
            pages_by_type[doc_type or "Unknown"] += pages

        return {
            "summary": {
                "total_documents": total_docs,
                "total_cost": float(total_pages * rate_per_page),
                "average_cost_per_doc": (
                    float(total_pages * rate_per_page / total_docs) if total_docs else 0
                ),
            },
            "cost_by_tenant": [
                {
                    "tenant_id": auth.customer_id,
                    "total_pages": total_pages,
                    "total_cost": float(total_pages * rate_per_page),
                }
            ],
            "cost_by_doc_type": [
                {
                    "document_type": doc_type,
                    "total_pages": pages,
                    "total_cost": float(pages * rate_per_page),
                }
                for doc_type, pages in pages_by_type.items()
            ],
            "calculation_details": {"rate_per_page": rate_per_page, "currency": "USD"},
        }

    def export_ine_data(
        self,
        auth: AuthContext,
        start_date: str | None = None,
        end_date: str | None = None,
        user_id: str | None = None,
    ) -> StreamingResponse:
        bind_context(tenant=auth.customer_id)
        documents = self._owned_documents(auth, ObjectAction.EXPORT)
        s3 = s3_client()
        authorized_locators: List[tuple[Dict[str, Any], str, str]] = []
        for document in documents:
            if document.get("status") not in ("COMPLETED", "SUCCESS", "PERSONAL_EXTRACTED"):
                continue
            created = document.get("createdAt", "")
            if start_date and created < start_date:
                continue
            if end_date and created > end_date:
                continue
            if user_id and document.get("uploaderUserId", "Unknown") != user_id:
                continue
            bucket, key, _alias = self.document_service.get_trusted_artifact_locator(
                auth,
                document,
                "final",
            )
            authorized_locators.append((document, bucket, key))

        def stream_generator():
            output = io.StringIO()
            writer = csv.writer(output)
            writer.writerow(
                [
                    "documentId",
                    "createdAt",
                    "uploaderUserId",
                    "subType",
                    "fullName",
                    "curp",
                    "claveElector",
                    "dob",
                    "overallConfidence",
                ]
            )
            yield output.getvalue()
            output.seek(0)
            output.truncate(0)

            for document, bucket, key in authorized_locators:
                try:
                    body = s3.get_object(Bucket=bucket, Key=key)["Body"].read()
                    data = json.loads(body.decode("utf-8"))
                    if data.get("docType") != "personal_doc":
                        continue
                    person = data.get("person", {})
                    identifiers = data.get("identifiers", {})
                    writer.writerow(
                        [
                            document.get("documentId", ""),
                            document.get("createdAt", ""),
                            document.get("uploaderUserId", ""),
                            data.get("subType", ""),
                            person.get("fullName", ""),
                            identifiers.get("curp", ""),
                            identifiers.get("claveElector", ""),
                            person.get("dob", ""),
                            data.get("overallConfidence", ""),
                        ]
                    )
                    yield output.getvalue()
                    output.seek(0)
                    output.truncate(0)
                except Exception as exc:
                    self.logger.warning("ine_export_doc_error", errorType=type(exc).__name__)

        return StreamingResponse(
            stream_generator(),
            media_type="text/csv; charset=utf-8",
            headers={"Content-Disposition": "attachment; filename=ine_export.csv"},
        )
