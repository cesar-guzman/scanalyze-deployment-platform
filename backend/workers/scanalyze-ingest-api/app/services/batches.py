from __future__ import annotations

import csv
import io
import json
import os
import tempfile
import uuid
import zipfile
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Generator, Tuple

from fastapi.responses import StreamingResponse, FileResponse
from starlette.background import BackgroundTask

from ..auth import AuthContext
from ..authorization import (
    ObjectAction,
    ObjectOwnership,
    authorize_batch,
    authorize_batch_membership,
    authorize_document,
)
from ..aws_clients import s3_client
from ..repositories.batches import BatchesRepository
from ..repositories.documents import DocumentsRepository
from ..services.documents import DocumentsService
from ..errors import AppError
from ..logging import bind_context, get_logger

def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

def _normalize_nulls(obj: Any) -> Any:
    if isinstance(obj, dict):
        return {k: _normalize_nulls(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [_normalize_nulls(x) for x in obj]
    elif obj == "null":
        return None
    return obj


class BatchesService:
    def __init__(self) -> None:
        self.repo = BatchesRepository()
        self.docs_repo = DocumentsRepository()
        self.doc_service = DocumentsService()
        self.s3 = s3_client()
        self.logger = get_logger()

    def create_batch(
        self,
        auth: AuthContext,
        subject: Optional[str],
        email: Optional[str],
        name: Optional[str],
        metadata: Dict[str, Any],
    ) -> Dict[str, Any]:
        ownership = ObjectOwnership.from_auth(auth)
        authorize_batch(auth, ownership.record_fields(), ObjectAction.WRITE)
        tenant = ownership.customer_id
        batch_id = uuid.uuid4().hex
        bind_context(batchId=batch_id, tenant=tenant)
        
        now = _utc_now_iso()
        item = {
            "batch_id": batch_id,
            "batchId": batch_id,
            "tenantId": tenant,
            **ownership.record_fields(),
            "createdAt": now,
            "status": "OPEN",
            "metadata": metadata,
            "source": "web-bulk-upload",
        }
        if subject:
            item["createdBy"] = subject
            item["createdByUserSub"] = subject
        if email:
            item["createdByEmail"] = email
        if name:
            item["createdByDisplayName"] = name
            
        self.repo.create_batch(item, ownership=ownership)
        return item

    def _load_batch(
        self,
        auth: AuthContext,
        batch_id: str,
        action: ObjectAction,
    ) -> Tuple[Dict[str, Any], ObjectOwnership]:
        batch = self.repo.get_batch(batch_id)
        ownership = authorize_batch(auth, batch, action)
        return batch, ownership

    def _load_batch_documents(
        self,
        auth: AuthContext,
        batch: Dict[str, Any],
        ownership: ObjectOwnership,
        action: ObjectAction,
    ) -> List[Dict[str, Any]]:
        batch_id = batch.get("batchId")
        if not isinstance(batch_id, str) or not batch_id:
            raise AppError(code="NOT_FOUND", message="Batch not found", status_code=404, details={})
        sparse_docs = self.docs_repo.get_documents_by_batch(
            batch_id,
            ownership=ownership,
        )
        authorize_batch_membership(auth, batch, sparse_docs, action)

        full_docs: List[Dict[str, Any]] = []
        for sparse in sparse_docs:
            doc_id = sparse.get("documentId")
            if not isinstance(doc_id, str) or not doc_id:
                raise AppError(code="NOT_FOUND", message="Batch not found", status_code=404, details={})
            full = self.docs_repo.get_document(doc_id)
            if not full:
                raise AppError(code="NOT_FOUND", message="Batch not found", status_code=404, details={})
            try:
                authorize_document(auth, full, action)
            except AppError:
                raise AppError(code="NOT_FOUND", message="Batch not found", status_code=404, details={})
            if full.get("batchId") != batch_id:
                raise AppError(code="NOT_FOUND", message="Batch not found", status_code=404, details={})
            full_docs.append(full)
        authorize_batch_membership(auth, batch, full_docs, action)
        return full_docs

    def get_batch(self, auth: AuthContext, batch_id: str) -> Dict[str, Any]:
        tenant = auth.customer_id
        bind_context(batchId=batch_id, tenant=tenant)
        batch, ownership = self._load_batch(auth, batch_id, ObjectAction.READ)
        # Compute counters and aggregated status
        docs = self._load_batch_documents(
            auth,
            batch,
            ownership,
            ObjectAction.READ,
        )
        counters = {}
        for d in docs:
            st = d.get("status") or "UNKNOWN"
            counters[st] = counters.get(st, 0) + 1
            
        batch["counters"] = counters
        
        if not docs:
            batch["status"] = "OPEN"
        else:
            total = len(docs)
            completed = counters.get("COMPLETED", 0) + counters.get("SUCCESS", 0)
            failed = sum(v for k, v in counters.items() if "FAIL" in k or "ERROR" in k)
            
            if completed == total:
                batch["status"] = "COMPLETED"
            elif failed == total:
                batch["status"] = "FAILED"
            elif completed + failed == total:
                batch["status"] = "PARTIAL_SUCCESS"
            else:
                batch["status"] = "PROCESSING"
                
        return batch

    def get_batch_documents(self, auth: AuthContext, batch_id: str) -> List[Dict[str, Any]]:
        tenant = auth.customer_id
        bind_context(batchId=batch_id, tenant=tenant)
        batch, ownership = self._load_batch(auth, batch_id, ObjectAction.READ)
        docs = self._load_batch_documents(
            auth,
            batch,
            ownership,
            ObjectAction.READ,
        )
        result = []
        for full_doc in docs:
            doc_id = full_doc.get("documentId")
            input_info = full_doc.get("input") or {}
            result.append({
                "documentId": doc_id,
                "status": full_doc.get("status"),
                "createdAt": full_doc.get("createdAt") or full_doc.get("created_at") or _utc_now_iso(),
                "input": {
                    "filename": input_info.get("filename"),
                    "contentType": input_info.get("contentType"),
                },
            })
        return result

    def _build_manifest(
        self,
        auth: AuthContext,
        batch_id: str,
    ) -> Tuple[Dict[str, Any], Dict[str, Dict[str, Any]]]:
        tenant = auth.customer_id
        bind_context(batchId=batch_id, tenant=tenant)
        batch, ownership = self._load_batch(auth, batch_id, ObjectAction.EXPORT)
        full_docs = self._load_batch_documents(
            auth,
            batch,
            ownership,
            ObjectAction.EXPORT,
        )

        summary = {"total": 0, "completed": 0, "failed": 0, "pending": 0}
        documents = []
        auth_ownership = ObjectOwnership.from_auth(auth)

        for doc in full_docs:
            st = doc.get("status", "UNKNOWN")
            summary["total"] += 1
            if st in ("COMPLETED", "SUCCESS"):
                summary["completed"] += 1
            elif "FAIL" in st or "ERROR" in st:
                summary["failed"] += 1
            else:
                summary["pending"] += 1

            refs = []
            artifacts_dict = doc.get("artifacts", {})
            for alias, info in artifacts_dict.items():
                if info.get("bucket") and info.get("key"):
                    self.doc_service._validate_artifact_locator(
                        auth_ownership,
                        doc["documentId"],
                        info.get("bucket"),
                        info.get("key"),
                    )
                    refs.append({
                        "artifactType": alias,
                        "fileName": info.get("key").split("/")[-1],
                        "apiPath": f"/api/v1/documents/{doc['documentId']}/artifacts/{alias}",
                        "sizeBytes": info.get("sizeBytes"),
                        "contentType": info.get("contentType", "application/octet-stream")
                    })

            # Check for error status
            err_code, err_msg = None, None
            if "FAIL" in st or "ERROR" in st:
                for s_name, s_data in doc.get("stages", {}).items():
                    if s_data.get("status") in ("FAILED", "ENQUEUE_FAILED"):
                        err_code = s_data.get("errorCode")
                        err_msg = s_data.get("errorMessage")
                        break

            # Try to grab docType if present
            doc_type = None
            classification_data = doc.get("classification", {})
            if isinstance(classification_data, dict):
                doc_type = classification_data.get("docType")

            documents.append({
                "batchId": batch_id,
                "documentId": doc["documentId"],
                "docType": doc_type,
                "status": st,
                "generatedAt": doc.get("updatedAt"),
                "artifactReferences": refs,
                "errorCode": err_code,
                "errorMessage": err_msg
            })

        manifest = {
            "manifestVersion": "1.0",
            "batchId": batch_id,
            "generatedAt": _utc_now_iso(),
            "summary": summary,
            "documents": documents
        }
        return manifest, {doc["documentId"]: doc for doc in full_docs}

    def export_manifest(self, auth: AuthContext, batch_id: str) -> Dict[str, Any]:
        manifest, _documents = self._build_manifest(auth, batch_id)
        return manifest

    def export_json(self, auth: AuthContext, batch_id: str) -> StreamingResponse:
        manifest, authorized_documents = self._build_manifest(auth, batch_id)

        def stream_generator() -> Generator[str, None, None]:
            yield "{\n"
            yield f'  "manifestVersion": "{manifest["manifestVersion"]}",\n'
            yield f'  "batchId": "{manifest["batchId"]}",\n'
            yield f'  "generatedAt": "{manifest["generatedAt"]}",\n'
            yield f'  "summary": {json.dumps(manifest["summary"])},\n'
            yield '  "documents": [\n'

            first = True
            for doc_meta in manifest["documents"]:
                if not first:
                    yield ",\n"
                first = False

                doc_obj = dict(doc_meta)
                result_payload = None

                if doc_meta["status"] == "COMPLETED":
                    full_doc = authorized_documents.get(doc_meta["documentId"])
                    if full_doc:
                        try:
                            bucket, key, _alias = self.doc_service.get_trusted_artifact_locator(
                                auth,
                                full_doc,
                                "final",
                            )
                            s3_resp = self.s3.get_object(Bucket=bucket, Key=key)
                            body_str = s3_resp["Body"].read().decode("utf-8")
                            result_payload = _normalize_nulls(json.loads(body_str))
                        except AppError:
                            raise
                        except Exception as e:
                            self.logger.warning("export_json_artifact_fetch_failed", errorType=type(e).__name__)
                            result_payload = {"error": "Failed to load result blob"}

                doc_obj["result"] = result_payload
                yield "    " + json.dumps(doc_obj)

            yield "\n  ]\n}"

        return StreamingResponse(stream_generator(), media_type="application/json")

    def export_csv(self, auth: AuthContext, batch_id: str) -> StreamingResponse:
        manifest, _authorized_documents = self._build_manifest(auth, batch_id)

        def stream_generator() -> Generator[str, None, None]:
            output = io.StringIO()
            writer = csv.writer(output)

            columns = ["batchId", "documentId", "docType", "status", "generatedAt", "resultApiPath", "artifactCount", "errorCode", "errorMessage"]
            writer.writerow(columns)
            yield output.getvalue()
            output.seek(0)
            output.truncate(0)

            for doc in manifest["documents"]:
                result_path = ""
                for ref in doc["artifactReferences"]:
                    if ref["artifactType"] in ("result", "structured", "final"):
                        result_path = f"/api/v1/documents/{doc['documentId']}/result"
                        break

                writer.writerow([
                    doc["batchId"],
                    doc["documentId"],
                    doc.get("docType", "") or "",
                    doc["status"],
                    doc.get("generatedAt", "") or "",
                    result_path,
                    str(len(doc["artifactReferences"])),
                    doc.get("errorCode", "") or "",
                    doc.get("errorMessage", "") or ""
                ])
                val = output.getvalue()
                output.seek(0)
                output.truncate(0)
                yield val

        return StreamingResponse(stream_generator(), media_type="text/csv; charset=utf-8")

    def export_zip(self, auth: AuthContext, batch_id: str) -> FileResponse:
        manifest, authorized_documents = self._build_manifest(auth, batch_id)
        
        # Build CSV and JSON synchronously for the ZIP to save time
        # (This momentarily keeps data in memory or /tmp, but it's isolated per request)
        fd, temp_path = tempfile.mkstemp(suffix=".zip", prefix=f"scanalyze_batch_{batch_id}_")
        os.close(fd)

        def cleanup():
            if os.path.exists(temp_path):
                try:
                    os.remove(temp_path)
                except Exception:
                    pass

        try:
            with zipfile.ZipFile(temp_path, "w", zipfile.ZIP_DEFLATED) as zf:
                # 1. Manifest
                zf.writestr("manifest.json", json.dumps(manifest, indent=2))
                
                # 2. JSON consolidado
                export_data = {
                    "manifestVersion": manifest["manifestVersion"],
                    "batchId": manifest["batchId"],
                    "generatedAt": manifest["generatedAt"],
                    "summary": manifest["summary"],
                    "documents": []
                }
                
                # 3. Process documents
                csv_output = io.StringIO()
                csv_writer = csv.writer(csv_output)
                csv_writer.writerow(["batchId", "documentId", "docType", "status", "generatedAt", "resultApiPath", "artifactCount", "errorCode", "errorMessage"])

                for doc_meta in manifest["documents"]:
                    doc_obj = dict(doc_meta)
                    result_payload = None

                    result_path = ""
                    for ref in doc_meta["artifactReferences"]:
                        if ref["artifactType"] in ("result", "structured", "final"):
                            result_path = f"/api/v1/documents/{doc_meta['documentId']}/result"
                            break

                    csv_writer.writerow([
                        doc_meta["batchId"], doc_meta["documentId"], doc_meta.get("docType", "") or "",
                        doc_meta["status"], doc_meta.get("generatedAt", "") or "", result_path,
                        str(len(doc_meta["artifactReferences"])), doc_meta.get("errorCode", "") or "", doc_meta.get("errorMessage", "") or ""
                    ])

                    if doc_meta["status"] == "COMPLETED":
                        full_doc = authorized_documents.get(doc_meta["documentId"])
                        if full_doc:
                            try:
                                bucket, key, _alias = self.doc_service.get_trusted_artifact_locator(
                                    auth,
                                    full_doc,
                                    "final",
                                )
                                s3_resp = self.s3.get_object(Bucket=bucket, Key=key)
                                body_bytes = s3_resp["Body"].read()
                                result_payload = _normalize_nulls(json.loads(body_bytes.decode("utf-8")))
                                
                                # Export raw normalized file to ZIP
                                zf.writestr(f"documents/{doc_meta['documentId']}/result.json", json.dumps(result_payload))
                                
                            except AppError:
                                raise
                            except Exception as e:
                                self.logger.warning("export_zip_artifact_fetch_failed", errorType=type(e).__name__)
                                result_payload = {"error": "Failed to load result blob"}

                    doc_obj["result"] = result_payload
                    export_data["documents"].append(doc_obj)
                    
                    # Also record an index.json per document for references
                    index_data = {
                        "documentId": doc_meta["documentId"],
                        "artifactReferences": doc_meta["artifactReferences"]
                    }
                    zf.writestr(f"documents/{doc_meta['documentId']}/artifacts/index.json", json.dumps(index_data, indent=2))

                zf.writestr("export.json", json.dumps(export_data, indent=2))
                zf.writestr("summary.csv", csv_output.getvalue())

            return FileResponse(
                temp_path, 
                media_type="application/zip", 
                filename=f"batch_{batch_id}_export.zip",
                background=BackgroundTask(cleanup)
            )

        except AppError:
            cleanup()
            raise
        except Exception:
            cleanup()
            raise AppError(code="INTERNAL_ERROR", message="Failed to build ZIP export", status_code=500, details={})
