from __future__ import annotations

import csv
import hashlib
import hmac
import io
import json
import os
import re
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any, Dict, List

import boto3
from fastapi.responses import Response, StreamingResponse
from pydantic import ValidationError

from ..auth import AuthContext
from ..authorization import ObjectAction, ObjectOwnership, authorize_document
from ..aws_clients import s3_client
from ..config import get_settings
from ..csv_safety import neutralize_csv_cell
from ..document_contracts import public_document_content_type
from ..errors import AppError
from ..journey_contract import (
    CONTRACT_VERSION,
    JourneyContractError,
    OperationKind,
    OwnerScope,
    adapt_internal_document_status,
    owner_scope_from_auth,
)
from ..logging import bind_context, get_logger
from ..repositories.documents import DocumentsRepository
from .documents import DocumentsService
from .journey import JourneyService


MAX_BANK_EXPORT_DOCUMENTS = 10
MAX_BANK_EXPORT_ROWS = 50_000
MAX_BANK_EXPORT_BYTES = 20 * 1024 * 1024
_DOCUMENT_ID = re.compile(r"[0-9a-f]{32}")
_HISTORY_CURSOR = re.compile(r"v1:([0-9a-f]{32}):([0-9a-f]{64})")


def _history_scope(auth: AuthContext) -> OwnerScope:
    try:
        return owner_scope_from_auth(auth)
    except (JourneyContractError, TypeError, ValueError) as exc:
        raise AppError(code="FORBIDDEN", message="Invalid owner scope.", status_code=403, details={}) from exc


def _cursor_binding(scope: OwnerScope) -> str:
    # This is context binding, not a signature or access token. The repository
    # always derives the partition from auth; returned rows are authorized anew.
    frame = json.dumps({
        "version": 1, "actorDigest": scope.actor_digest,
        "customerId": scope.customer_id, "deploymentId": scope.deployment_id,
    }, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(b"scanalyze.bank-history.cursor.v1\0" + frame).hexdigest()


def _matches_journey_actor(record: Dict[str, Any], scope: OwnerScope) -> bool:
    # Match JourneyService._authorize_journey_record before listing metadata or
    # preflighting an export; canonical get_result enforces it again on read.
    return (
        record.get("journey_contract_version") == CONTRACT_VERSION
        and record.get("journey_operation") == OperationKind.DOCUMENT_CREATE.value
        and record.get("journey_actor_digest") == scope.actor_digest
        and record.get("journey_resource_schema_version") == 1
    )


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

    def get_bank_documents(
        self, auth: AuthContext, *, limit: int = 50, cursor: str | None = None,
    ) -> Dict[str, Any]:
        ownership = ObjectOwnership.from_auth(auth)
        scope = _history_scope(auth)
        binding = _cursor_binding(scope)
        after_id = None
        if cursor is not None:
            match = _HISTORY_CURSOR.fullmatch(cursor) if isinstance(cursor, str) else None
            if match is None or not hmac.compare_digest(match.group(2), binding):
                raise AppError(code="VALIDATION_ERROR", message="Invalid history cursor.", status_code=422, details={})
            # The last evaluated record may be another actor or document class.
            # Its ID is only a position within the trusted ownership partition.
            after_id = match.group(1)
        records, next_id = self.repo.list_owned_documents_page(
            ownership=ownership, limit=limit, after_document_id=after_id,
        )
        for record in records:
            authorize_document(auth, record, ObjectAction.READ)
        documents = []
        for record in records:
            if not _matches_journey_actor(record, scope):
                continue
            if record.get("processing_domain") != "bank" or record.get("documentRoute") != "bank":
                continue
            document_id = record.get("documentId")
            if not isinstance(document_id, str) or _DOCUMENT_ID.fullmatch(document_id) is None:
                raise AppError(code="UNSUPPORTED_STATE", message="Document metadata is invalid.", status_code=500, details={})
            try:
                projected = adapt_internal_document_status(record, now=datetime.now(timezone.utc))
            except (JourneyContractError, ValidationError, TypeError, ValueError) as exc:
                raise AppError(code="UNSUPPORTED_STATE", message="Document state is unsupported.", status_code=500, details={}) from exc
            source = record.get("input")
            filename = source.get("filename") if isinstance(source, dict) else None
            if not isinstance(filename, str) or not 1 <= len(filename) <= 128 or any(
                ord(char) < 32 or ord(char) == 127 or char in "/\\" for char in filename
            ):
                filename = None
            documents.append({
                "documentId": document_id, "filename": filename,
                "status": projected.lifecycle.value, "createdAt": projected.created_at.isoformat(),
            })
        # OwnershipIndex has no sort key; do not claim globally chronological
        # ordering or consume further pages to fill a filtered result page.
        return {"documents": documents, "nextCursor": f"v1:{next_id}:{binding}" if next_id else None}

    def export_bank_data(self, auth: AuthContext, *, document_ids: str) -> Response:
        ids = document_ids.split(",") if isinstance(document_ids, str) else []
        if not 1 <= len(ids) <= MAX_BANK_EXPORT_DOCUMENTS or len(set(ids)) != len(ids) or any(
            _DOCUMENT_ID.fullmatch(document_id) is None for document_id in ids
        ):
            raise AppError(code="VALIDATION_ERROR", message="Select up to ten distinct bank documents.", status_code=422, details={})
        # Authorize every selected record before reading any result. Never emit
        # a CSV header/partial body and then skip a denied or corrupt document.
        scope = _history_scope(auth)
        for document_id in ids:
            record = self.repo.get_document(document_id, consistent=True)
            authorize_document(auth, record, ObjectAction.EXPORT)
            if record.get("documentId") != document_id or not _matches_journey_actor(record, scope):
                raise AppError(code="NOT_FOUND", message="Document not found.", status_code=404, details={})
        journey = JourneyService(settings=self.settings, documents_repo=self.repo)
        chunks: list[str] = []
        total_bytes = 0
        row_count = 0

        def append_row(values: list[Any], *, data_row: bool = True) -> None:
            nonlocal total_bytes, row_count
            output = io.StringIO()
            csv.writer(output).writerow(neutralize_csv_cell(value) for value in values)
            encoded = output.getvalue()
            total_bytes += len(encoded.encode("utf-8"))
            row_count += int(data_row)
            if total_bytes > MAX_BANK_EXPORT_BYTES or row_count > MAX_BANK_EXPORT_ROWS:
                raise AppError(code="EXPORT_TOO_LARGE", message="Select fewer documents for this export.", status_code=413, details={})
            chunks.append(encoded)

        append_row([
            "documentId", "resultId", "resultVersion", "bankName", "accountNumberMasked", "currency",
            "periodStart", "periodEnd", "transactionDate", "description", "reference", "direction",
            "amount", "balanceAfter", "category", "warningCodes", "overallConfidence",
        ], data_row=False)
        for document_id in ids:
            result = journey.get_result(auth=auth, document_id=document_id)
            if result.document_id != document_id:
                raise AppError(code="MALFORMED_INTERNAL_RESULT", message="Stored result is invalid.", status_code=500, details={})
            data = result.data
            # An empty transaction list still identifies the selected statement;
            # unknown amounts remain empty cells, never fabricated zeroes.
            for transaction in data.transactions or (None,):
                append_row([
                    document_id, result.result_id, result.result_version, data.bank.name,
                    data.account.number_masked, data.account.currency,
                    data.statement.period_start, data.statement.period_end,
                    transaction.date if transaction else None,
                    transaction.description if transaction else None,
                    transaction.reference if transaction else None,
                    transaction.direction if transaction else None,
                    transaction.amount if transaction else None,
                    transaction.balance_after if transaction else None,
                    transaction.category.value if transaction and transaction.category else None,
                    "|".join(warning.code.value for warning in result.warnings), result.quality.overall_confidence,
                ])
        return Response(
            content="".join(chunks), media_type="text/csv; charset=utf-8",
            headers={"Content-Disposition": "attachment; filename=bank_statements.csv", "Cache-Control": "no-store"},
        )

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
            current_type = public_document_content_type(
                input_info.get("contentType") if isinstance(input_info, dict) else None
            )
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
            current_type = public_document_content_type(
                input_info.get("contentType") if isinstance(input_info, dict) else None
            )
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
            doc_type = public_document_content_type(
                input_info.get("contentType") if isinstance(input_info, dict) else None
            )
            pages_by_type[doc_type] += pages

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
                        neutralize_csv_cell(value)
                        for value in [
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
