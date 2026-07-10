from __future__ import annotations

import os
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Tuple

from botocore.exceptions import ClientError

from ..aws_clients import dynamodb_client, dynamodb_resource
from ..config import get_settings
from ..errors import AppError
from ..logging import get_logger

def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

@dataclass
class DynamoKeySchema:
    pk_name: str
    sk_name: Optional[str] = None
    pk_template: str = "{document_id}"
    sk_template: Optional[str] = None

class DocumentsRepository:
    """
    Repo DynamoDB para documents.
    Intenta auto-descubrir key schema (DescribeTable). Si no puede, usa env vars/fallback.

    Soporta (opcional) patrones:
      DOCUMENTS_TABLE_PK_TEMPLATE="{document_id}" (default)
      DOCUMENTS_TABLE_SK_TEMPLATE="METADATA" (default si hay SK y no se provee)
    """

    def __init__(self) -> None:
        self.settings = get_settings()
        if not self.settings.documents_table_name:
            # No explotamos aquí para que /health funcione.
            self.table_name = None
            self.table = None
            self.schema = None
            return

        self.table_name = self.settings.documents_table_name
        self.ddb = dynamodb_resource()
        self.ddb_client = dynamodb_client()
        self.table = self.ddb.Table(self.table_name)
        self.logger = get_logger()
        self.schema = self._load_schema()

    def _load_schema(self) -> DynamoKeySchema:
        # Usamos directamente las variables de entorno.
        # Fallback a documentId si no están presentes, como en los demás workers.
        pk_name = os.getenv("DOCUMENTS_TABLE_PK_NAME", "documentId")
        sk_name = os.getenv("DOCUMENTS_TABLE_SK_NAME")
        pk_template = os.getenv("DOCUMENTS_TABLE_PK_TEMPLATE", "{document_id}")
        sk_template = os.getenv("DOCUMENTS_TABLE_SK_TEMPLATE")

        if sk_name and not sk_template:
            sk_template = "METADATA"

        return DynamoKeySchema(
            pk_name=pk_name,
            sk_name=sk_name,
            pk_template=pk_template,
            sk_template=sk_template,
        )

    def _ensure_ready(self) -> None:
        if not self.table_name or not self.table or not self.schema:
            raise AppError(
                code="CONFIG_ERROR",
                message="DynamoDB is not configured (DOCUMENTS_TABLE_NAME missing)",
                status_code=500,
                details={},
            )

    def _key_for(self, document_id: str) -> Dict[str, Any]:
        assert self.schema
        pk_value = self.schema.pk_template.format(document_id=document_id)
        key: Dict[str, Any] = {self.schema.pk_name: pk_value}

        if self.schema.sk_name:
            sk_template = self.schema.sk_template or "METADATA"
            key[self.schema.sk_name] = sk_template.format(document_id=document_id)

        return key

    def create_document(self, item: Dict[str, Any]) -> None:
        self._ensure_ready()
        assert self.table is not None
        assert self.schema is not None

        # Condición: no sobrescribir
        condition = "attribute_not_exists(#pk)"
        expr_names = {"#pk": self.schema.pk_name}

        try:
            self.table.put_item(Item=item, ConditionExpression=condition, ExpressionAttributeNames=expr_names)
        except ClientError as e:
            code = e.response.get("Error", {}).get("Code", "")
            if code == "ConditionalCheckFailedException":
                raise AppError(
                    code="CONFLICT",
                    message="Document already exists",
                    status_code=409,
                    details={},
                )
            raise

    def get_document(self, document_id: str) -> Optional[Dict[str, Any]]:
        self._ensure_ready()
        assert self.table is not None

        key = self._key_for(document_id)
        resp = self.table.get_item(Key=key)
        return resp.get("Item")

    def set_stage_enqueue_pending(self, document_id: str, stage: str, enqueue_id: str) -> bool:
        """
        Idempotencia por stage:
        - Si no existe enqueuedAt, permite.
        - Si existe pero status==ENQUEUE_FAILED, permite retry.
        - Si ya está PENDING/ENQUEUED, no permite.

        Retorna True si se pudo marcar pending (debe encolarse).
        Retorna False si ya estaba en progreso/encolado (idempotente).
        """
        self._ensure_ready()
        assert self.table is not None

        now = _utc_now_iso()

        key = self._key_for(document_id)

        # Dynamo expressions
        expr_names = {
            "#stages": "stages",
            "#stage": stage,
            "#status": "status",
            "#enqueuedAt": "enqueuedAt",
            "#updatedAt": "updatedAt",
            "#docStatus": "status",
        }

        expr_values = {
            ":failed": "ENQUEUE_FAILED",
            ":now": now,
            ":docSubmitted": "SUBMITTED",
            ":stageData": {
                "status": "ENQUEUE_PENDING",
                "enqueuedAt": now,
                "enqueueId": enqueue_id
            }
        }

        # condition: attribute_not_exists(stages.stage.enqueuedAt) OR stages.stage.status == ENQUEUE_FAILED
        condition = "attribute_not_exists(#stages.#stage.#enqueuedAt) OR #stages.#stage.#status = :failed"

        update = (
            "SET #stages.#stage = :stageData, "
            "#updatedAt = :now, "
            "#docStatus = :docSubmitted"
        )

        try:
            self.table.update_item(
                Key=key,
                ConditionExpression=condition,
                UpdateExpression=update,
                ExpressionAttributeNames=expr_names,
                ExpressionAttributeValues=expr_values,
            )
            return True
        except ClientError as e:
            code = e.response.get("Error", {}).get("Code", "")
            if code == "ConditionalCheckFailedException":
                return False
            raise

    def set_stage_enqueued(self, document_id: str, stage: str, queue_url: str, message_id: str) -> None:
        self._ensure_ready()
        assert self.table is not None

        now = _utc_now_iso()
        key = self._key_for(document_id)

        expr_names = {
            "#stages": "stages",
            "#stage": stage,
            "#status": "status",
            "#queueUrl": "queueUrl",
            "#sqsMessageId": "sqsMessageId",
            "#updatedAt": "updatedAt",
        }
        expr_values = {
            ":enqueued": "ENQUEUED",
            ":queueUrl": queue_url,
            ":mid": message_id,
            ":now": now,
        }

        update = (
            "SET #stages.#stage.#status = :enqueued, "
            "#stages.#stage.#queueUrl = :queueUrl, "
            "#stages.#stage.#sqsMessageId = :mid, "
            "#updatedAt = :now"
        )

        self.table.update_item(
            Key=key,
            UpdateExpression=update,
            ExpressionAttributeNames=expr_names,
            ExpressionAttributeValues=expr_values,
        )

    def set_stage_enqueue_failed(self, document_id: str, stage: str, error_code: str, error_message: str) -> None:
        self._ensure_ready()
        assert self.table is not None

        now = _utc_now_iso()
        key = self._key_for(document_id)

        expr_names = {
            "#stages": "stages",
            "#stage": stage,
            "#status": "status",
            "#errorCode": "errorCode",
            "#errorMessage": "errorMessage",
            "#updatedAt": "updatedAt",
        }
        expr_values = {
            ":failed": "ENQUEUE_FAILED",
            ":code": error_code,
            ":msg": error_message,
            ":now": now,
        }

        update = (
            "SET #stages.#stage.#status = :failed, "
            "#stages.#stage.#errorCode = :code, "
            "#stages.#stage.#errorMessage = :msg, "
            "#updatedAt = :now"
        )

        self.table.update_item(
            Key=key,
            UpdateExpression=update,
            ExpressionAttributeNames=expr_names,
            ExpressionAttributeValues=expr_values,
        )

    def get_documents_by_batch(self, batch_id: str) -> List[Dict[str, Any]]:
        self._ensure_ready()
        assert self.table is not None

        try:
            resp = self.table.query(
                IndexName="BatchIndex",
                KeyConditionExpression="#batchId = :batchId",
                ExpressionAttributeNames={"#batchId": "batchId"},
                ExpressionAttributeValues={":batchId": batch_id}
            )
            items = resp.get("Items", [])
            
            # Resolve documentId from document_id (if not fully projected)
            for it in items:
                if "documentId" not in it and "document_id" in it:
                    it["documentId"] = it["document_id"]
                    
            return items
            
        except ClientError as e:
            self.logger.error("query_batch_index_failed", errorType=type(e).__name__)
            raise AppError(code="QUERY_FAILED", message="Failed to query batch documents", status_code=500, details={})
