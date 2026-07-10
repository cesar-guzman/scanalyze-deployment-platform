from __future__ import annotations

import os
from typing import Any, Dict, List
import boto3
from ..aws_clients import dynamodb_resource
from ..config import get_settings
from ..errors import AppError
from ..logging import bind_context, get_logger

class AnalyticsService:
    def __init__(self) -> None:
        self.settings = get_settings()
        self.logger = get_logger()
        
    def _get_documents_table(self):
        return dynamodb_resource().Table(self.settings.documents_table_name)

    def get_dashboard(self, tenant: str, start_date: str = None, end_date: str = None, doc_type: str = None, batch_id: str = None, status: str = None) -> Dict[str, Any]:
        """
        Unified endpoint for Analytics Dashboard with memory-based server aggregation.
        Query `documents` table by tenant (Scan) to get counts.
        Query `usage-events` table by TenantIndex for accurate page counts.
        """
        bind_context(tenant=tenant)
        from boto3.dynamodb.conditions import Attr, Key
        from collections import defaultdict
        
        # 1. Fetch all documents for tenant to count files and status accurately
        docs_table = self._get_documents_table()
        docs_kwargs = {"FilterExpression": Attr("tenantId").eq(tenant)}
        docs_items = []
        try:
            while True:
                resp = docs_table.scan(**docs_kwargs)
                docs_items.extend(resp.get("Items", []))
                if "LastEvaluatedKey" in resp:
                    docs_kwargs["ExclusiveStartKey"] = resp["LastEvaluatedKey"]
                else:
                    break
        except Exception as e:
            self.logger.error("Failed to fetch documents for analytics", errorType=type(e).__name__)
            
        filtered_docs = []
        for d in docs_items:
            created = d.get("createdAt", "")
            if start_date and created < start_date: continue
            if end_date and created > end_date: continue
            if batch_id and d.get("batchId") != batch_id: continue
            if status and d.get("status") != status: continue
            
            d_type = d.get("input", {}).get("contentType", "") if isinstance(d.get("input"), dict) else d.get("input", "")
            if doc_type and d_type != doc_type: continue
            filtered_docs.append(d)
            
        subidos = len(filtered_docs)
        completados = sum(1 for d in filtered_docs if d.get("status") in ("COMPLETED", "SUCCESS", "OCR_COMPLETED"))
        fallidos = sum(1 for d in filtered_docs if str(d.get("status")).endswith("FAILED") or str(d.get("status")) == "ERROR")
        paginas_totales = 0
        for d in filtered_docs:
            p = int(float(d.get("pagesScanned", 0) or 0))
            if p == 0 and d.get("status") in ("COMPLETED", "SUCCESS", "OCR_COMPLETED"):
                p = 1
            paginas_totales += p
        
        # Aggregations
        agg_user = defaultdict(int)
        agg_user_docs = defaultdict(int)
        user_names = {}
        agg_day = defaultdict(int)
        agg_day_docs = defaultdict(int)
        agg_doctype = defaultdict(int)
        agg_doctype_docs = defaultdict(int)
        agg_batch = defaultdict(int)
        agg_batch_docs = defaultdict(int)
        
        for d in filtered_docs:
            uid = d.get("uploaderUserId", "Unknown")
            if uid != "Unknown":
                user_names[uid] = d.get("createdByDisplayName") or d.get("createdByEmail") or uid
            
            pages = int(float(d.get("pagesScanned", 0) or 0))
            if pages == 0 and d.get("status") in ("COMPLETED", "SUCCESS", "OCR_COMPLETED"):
                pages = 1
            
            agg_user[uid] += pages
            agg_user_docs[uid] += 1
            
            day = d.get("createdAt", "")[:10]
            if day: 
                agg_day[day] += pages
                agg_day_docs[day] += 1
            
            d_type = d.get("input", {}).get("contentType", "Unknown") if isinstance(d.get("input"), dict) else d.get("input", "Unknown")
            if not d_type: d_type = "Unknown"
            agg_doctype[d_type] += pages
            agg_doctype_docs[d_type] += 1
            
            bid = d.get("batchId", "Unknown")
            agg_batch[bid] += pages
            agg_batch_docs[bid] += 1
            
        by_user = [{"userId": k, "displayName": user_names.get(k, k), "pagesScanned": v, "documentsCount": agg_user_docs[k]} for k, v in agg_user.items()]
        by_user.sort(key=lambda x: x["documentsCount"], reverse=True)
        
        by_day = [{"day": k, "pagesScanned": v, "documentsCount": agg_day_docs[k]} for k, v in agg_day.items()]
        by_day.sort(key=lambda x: x["day"], reverse=True)
        
        by_doctype = [{"docType": k, "pagesScanned": v, "documentsCount": agg_doctype_docs[k]} for k, v in agg_doctype.items()]
        by_batch = [{"batchId": k, "pagesScanned": v, "documentsCount": agg_batch_docs[k]} for k, v in agg_batch.items()]
        
        return {
            "overview": {
                "documentsUploaded": subidos,
                "documentsCompleted": completados,
                "documentsFailed": fallidos,
                "pagesScanned": paginas_totales
            },
            "byUser": by_user,
            "byDay": by_day,
            "byDocType": by_doctype,
            "byBatch": by_batch
        }

    def get_overview(self, tenant: str) -> Dict[str, Any]:
        return self.get_dashboard(tenant=tenant).get("overview", {})

    def get_by_day(self, tenant: str) -> List[Dict[str, Any]]:
        return self.get_dashboard(tenant=tenant).get("byDay", [])

    def get_by_user(self, tenant: str) -> List[Dict[str, Any]]:
        return self.get_dashboard(tenant=tenant).get("byUser", [])

    def get_by_batch(self, tenant: str) -> List[Dict[str, Any]]:
        return self.get_dashboard(tenant=tenant).get("byBatch", [])

    def get_by_doc_type(self, tenant: str) -> List[Dict[str, Any]]:
        return self.get_dashboard(tenant=tenant).get("byDocType", [])

    def get_costs_dashboard(self, tenant: str) -> Dict[str, Any]:
        """
        Dashboard de Costos de AWS Textract.
        Cálculo super accurate basado en la tabla principal de documentos (idempotente).
        """
        bind_context(tenant=tenant)
        
        try:
            import boto3
            import os
            # Obtener tarifa dinámica o fallback a 0.0015
            deployment_env = os.getenv("SCANALYZE_ENV")
            if deployment_env is None or not deployment_env.strip():
                raise RuntimeError("SCANALYZE_ENV is required for cost analytics")
            deployment_env = deployment_env.strip()
            ssm = boto3.client("ssm")
            param_name = f"/scanalyze/{deployment_env}/settings/textract_rate_per_page"
            try:
                rate_response = ssm.get_parameter(Name=param_name)
                rate_per_page = float(rate_response["Parameter"]["Value"])
            except Exception:
                rate_per_page = 0.0015 # default fallback
                
            from boto3.dynamodb.conditions import Attr
            docs_table = self._get_documents_table()
            docs_kwargs = {}
            if tenant != "admin_all": # Support for any potential cross-tenant
                docs_kwargs["FilterExpression"] = Attr("tenantId").eq(tenant)
                
            docs_items = []
            try:
                while True:
                    resp = docs_table.scan(**docs_kwargs) if docs_kwargs else docs_table.scan()
                    docs_items.extend(resp.get("Items", []))
                    if "LastEvaluatedKey" in resp:
                        if docs_kwargs:
                            docs_kwargs["ExclusiveStartKey"] = resp["LastEvaluatedKey"]
                        else:
                            docs_kwargs = {"ExclusiveStartKey": resp["LastEvaluatedKey"]}
                    else:
                        break
            except Exception as e:
                self.logger.error("Failed to fetch documents for costs", errorType=type(e).__name__)

            total_pages = 0
            total_docs = 0
            
            from collections import defaultdict
            agg_doctype_pages = defaultdict(int)
            agg_tenant_pages = defaultdict(int)
            
            for d in docs_items:
                if d.get("status") not in ("COMPLETED", "SUCCESS", "OCR_COMPLETED"):
                    continue
                p = int(float(d.get("pagesScanned", 0) or 0))
                if p == 0:
                    p = 1
                
                total_pages += p
                total_docs += 1
                
                t_id = d.get("tenantId", tenant)
                agg_tenant_pages[t_id] += p
                
                d_type = d.get("input", {}).get("contentType", "Unknown") if isinstance(d.get("input"), dict) else d.get("input", "Unknown")
                if not d_type: d_type = "Unknown"
                agg_doctype_pages[d_type] += p
                
            by_tenant = []
            for t_id, pages in agg_tenant_pages.items():
                by_tenant.append({
                    "tenant_id": t_id,
                    "total_pages": pages,
                    "total_cost": float(pages * rate_per_page)
                })

            by_doctype = []
            for dt, pages in agg_doctype_pages.items():
                by_doctype.append({
                    "document_type": dt,
                    "total_pages": pages,
                    "total_cost": float(pages * rate_per_page)
                })
                
            return {
                "summary": {
                    "total_documents": total_docs,
                    "total_cost": float(total_pages * rate_per_page),
                    "average_cost_per_doc": float((total_pages * rate_per_page) / total_docs) if total_docs > 0 else 0
                },
                "cost_by_tenant": by_tenant,
                "cost_by_doc_type": by_doctype,
                "calculation_details": {
                    "rate_per_page": rate_per_page,
                    "currency": "USD"
                }
            }
        except Exception as e:
            self.logger.error("Failed to calculate costs dashboard", errorType=type(e).__name__)
            raise AppError(code="DB_ERROR", message="Failed to fetch cost analytics", status_code=500, details={})

    def export_ine_data(self, tenant: str, start_date: str = None, end_date: str = None, user_id: str = None):
        """
        Export data from INE classifications to CSV with filters.
        """
        import csv
        import io
        import json
        from fastapi.responses import StreamingResponse
        from ..aws_clients import s3_client
        from boto3.dynamodb.conditions import Attr

        bind_context(tenant=tenant)
        self.logger.info("Iniciando exportacion de INE data", start_date=start_date, end_date=end_date, user_id=user_id)
        docs_table = self._get_documents_table()
        s3 = s3_client()
        
        docs_kwargs = {"FilterExpression": Attr("tenantId").eq(tenant)}
        docs_items = []
        try:
            while True:
                resp = docs_table.scan(**docs_kwargs)
                docs_items.extend(resp.get("Items", []))
                if "LastEvaluatedKey" in resp:
                    docs_kwargs["ExclusiveStartKey"] = resp["LastEvaluatedKey"]
                else:
                    break
        except Exception as e:
            self.logger.error("Failed to fetch documents for INE export", errorType=type(e).__name__)
            raise AppError(code="DB_ERROR", message="Failed to fetch documents", status_code=500, details={})

        # Apply filters
        filtered_docs = []
        for d in docs_items:
            # We want only completed extractions where docType is personal_doc or id_document
            # Classification data usually lives in d['classification']['docType'] if it was set
            # Wait, dynamo document stores 'artifacts.result.bucket'
            if d.get("status") not in ("COMPLETED", "SUCCESS", "PERSONAL_EXTRACTED"):
                continue
                
            created = d.get("createdAt", "")
            if start_date and created < start_date: continue
            if end_date and created > end_date: continue
            
            uid = d.get("uploaderUserId", "Unknown")
            if user_id and uid != user_id: continue
            
            filtered_docs.append(d)

        def stream_generator():
            output = io.StringIO()
            writer = csv.writer(output)
            writer.writerow(["documentId", "createdAt", "uploaderUserId", "subType", "fullName", "curp", "claveElector", "dob", "overallConfidence"])
            yield output.getvalue()
            output.seek(0)
            output.truncate(0)

            for d in filtered_docs:
                try:
                    # Get result bucket and key
                    artifacts = d.get("artifacts", {})
                    # Usually final extraction lives under 'result' or 'final'
                    res_artifact = artifacts.get("result") or artifacts.get("final")
                    bucket, key = None, None
                    
                    if res_artifact:
                        bucket = res_artifact.get("bucket")
                        key = res_artifact.get("key")
                    else:
                        # try fallback to structured_bucket/key if they passed directly
                        bucket = d.get("structured_bucket")
                        key = d.get("structured_key")
                        
                    if not bucket or not key:
                        continue
                        
                    s3_resp = s3.get_object(Bucket=bucket, Key=key)
                    body_bytes = s3_resp["Body"].read()
                    data = json.loads(body_bytes.decode("utf-8"))
                    
                    # Ensure it's a personal doc
                    if data.get("docType") != "personal_doc":
                        continue
                        
                    sub_type = data.get("subType", "")
                    person = data.get("person", {})
                    identifiers = data.get("identifiers", {})
                    conf = data.get("overallConfidence", "")
                    
                    writer.writerow([
                        d.get("documentId", ""),
                        d.get("createdAt", ""),
                        d.get("uploaderUserId", ""),
                        sub_type,
                        person.get("fullName", ""),
                        identifiers.get("curp", ""),
                        identifiers.get("claveElector", ""),
                        person.get("dob", ""),
                        conf
                    ])
                    val = output.getvalue()
                    output.seek(0)
                    output.truncate(0)
                    yield val
                except Exception as e:
                    self.logger.warning("ine_export_doc_error", errorType=type(e).__name__)
                    
        self.logger.info("Stream generation started for INE export")
        return StreamingResponse(stream_generator(), media_type="text/csv; charset=utf-8", headers={"Content-Disposition": "attachment; filename=ine_export.csv"})
