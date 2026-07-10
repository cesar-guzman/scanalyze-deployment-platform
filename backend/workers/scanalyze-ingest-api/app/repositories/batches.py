from __future__ import annotations

import os
from typing import Any, Dict, List, Optional
from datetime import datetime, timezone

from botocore.exceptions import ClientError

from ..aws_clients import dynamodb_client, dynamodb_resource
from ..config import get_settings
from ..errors import AppError
from ..logging import get_logger


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class BatchesRepository:
    def __init__(self) -> None:
        self.settings = get_settings()
        if not self.settings.batches_table_name:
            self.table_name = None
            self.table = None
            return

        self.table_name = self.settings.batches_table_name
        self.ddb = dynamodb_resource()
        self.table = self.ddb.Table(self.table_name)
        self.logger = get_logger()
        self.pk_name = "batch_id"
    
    def _ensure_ready(self) -> None:
        if not self.table_name or not self.table:
            raise AppError(
                code="CONFIG_ERROR",
                message="DynamoDB is not configured (BATCHES_TABLE_NAME missing)",
                status_code=500,
                details={},
            )

    def _key_for(self, batch_id: str) -> Dict[str, Any]:
        return {self.pk_name: batch_id}

    def create_batch(self, item: Dict[str, Any]) -> None:
        self._ensure_ready()
        assert self.table is not None

        condition = "attribute_not_exists(#pk)"
        expr_names = {"#pk": self.pk_name}

        try:
            self.table.put_item(Item=item, ConditionExpression=condition, ExpressionAttributeNames=expr_names)
        except ClientError as e:
            code = e.response.get("Error", {}).get("Code", "")
            if code == "ConditionalCheckFailedException":
                raise AppError(
                    code="CONFLICT",
                    message="Batch already exists",
                    status_code=409,
                    details={},
                )
            raise

    def get_batch(self, batch_id: str) -> Optional[Dict[str, Any]]:
        self._ensure_ready()
        assert self.table is not None

        key = self._key_for(batch_id)
        resp = self.table.get_item(Key=key)
        return resp.get("Item")
