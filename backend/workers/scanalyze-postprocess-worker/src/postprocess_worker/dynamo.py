import os
from typing import Any, Callable, Dict

from botocore.exceptions import ClientError

from .aws import dynamodb_resource


def _required_env(name: str) -> str:
    value = os.environ.get(name)
    if value is None or not value.strip():
        raise RuntimeError(f"{name} is required")
    return value.strip()


def _render_key_template(name: str, template: str, tenant: str, document_id: str) -> str:
    try:
        value = template.format(
            tenant=tenant,
            tenant_id=tenant,
            document_id=document_id,
        )
    except (IndexError, KeyError, ValueError) as exc:
        raise RuntimeError(f"{name} is invalid") from exc

    if not value.strip():
        raise RuntimeError(f"{name} rendered an empty value")
    return value


def get_key_dict(table_name: str, tenant: str, document_id: str) -> dict:
    """Build the document key exclusively from the configured key contract."""
    del table_name  # Kept in the signature for compatibility with existing callers.

    if not tenant or not tenant.strip():
        raise ValueError("tenant is required")
    if not document_id or not document_id.strip():
        raise ValueError("document_id is required")

    pk_name = _required_env("DOCUMENTS_TABLE_PK_NAME")
    pk_template = _required_env("DOCUMENTS_TABLE_PK_TEMPLATE")
    sk_name = os.environ.get("DOCUMENTS_TABLE_SK_NAME", "").strip()
    sk_template = os.environ.get("DOCUMENTS_TABLE_SK_TEMPLATE", "").strip()

    if bool(sk_name) != bool(sk_template):
        raise RuntimeError(
            "DOCUMENTS_TABLE_SK_NAME and DOCUMENTS_TABLE_SK_TEMPLATE must be configured together"
        )

    key = {
        pk_name: _render_key_template(
            "DOCUMENTS_TABLE_PK_TEMPLATE", pk_template, tenant, document_id
        )
    }
    if sk_name:
        key[sk_name] = _render_key_template(
            "DOCUMENTS_TABLE_SK_TEMPLATE", sk_template, tenant, document_id
        )
    return key


def _is_conditional_failure(error: ClientError) -> bool:
    return error.response.get("Error", {}).get("Code") == "ConditionalCheckFailedException"


def _existing_item(table, key: dict) -> Dict[str, Any]:
    response = table.get_item(Key=key, ConsistentRead=True)
    item = response.get("Item")
    return item if isinstance(item, dict) else {}


def _nested(item: Dict[str, Any], *path: str) -> Any:
    value: Any = item
    for part in path:
        if not isinstance(value, dict):
            return None
        value = value.get(part)
    return value


def _resolve_conditional_failure(
    error: ClientError,
    table,
    key: dict,
    existing_value: Callable[[Dict[str, Any]], Any],
) -> Any:
    if not _is_conditional_failure(error):
        raise error

    item = _existing_item(table, key)
    value = existing_value(item) if item else None
    if value is not None:
        return value

    # A missing item or invalid transition must never be reported as idempotent success.
    raise error


def _expected_extracted_status(tenant: str) -> str:
    return f"{tenant.upper()}_EXTRACTED"


def update_validate_stage(table_name: str, tenant: str, document_id: str, payload: dict):
    table = dynamodb_resource.Table(table_name)
    key = get_key_dict(table_name, tenant, document_id)
    validation_status = payload["validation"]["status"]

    update_kwargs = {
        "Key": key,
        "UpdateExpression": (
            "SET #validation = :validation, "
            "#stages.#validate = :validate_stage, "
            "#updated_at = :updated_at"
        ),
        "ConditionExpression": (
            "attribute_exists(#pk) AND "
            "#status = :expected_status AND "
            "attribute_not_exists(#stages.#validate.#validated_at)"
        ),
        "ExpressionAttributeNames": {
            "#pk": next(iter(key)),
            "#status": "status",
            "#validation": "validation",
            "#stages": "stages",
            "#validate": "validate",
            "#validated_at": "validatedAt",
            "#updated_at": "updatedAt",
        },
        "ExpressionAttributeValues": {
            ":validation": payload["validation"],
            ":validate_stage": payload["stages_validate"],
            ":updated_at": payload["updatedAt"],
            ":expected_status": _expected_extracted_status(tenant),
        },
    }

    try:
        table.update_item(**update_kwargs)
        return payload["validation"]
    except ClientError as error:
        return _resolve_conditional_failure(
            error,
            table,
            key,
            lambda item: item.get("validation")
            if (
                isinstance(item.get("validation"), dict)
                and _nested(item, "stages", "validate", "status") == "DONE"
                and _nested(item, "validation", "status") == validation_status
            )
            else None,
        )


def update_persist_stage(table_name: str, tenant: str, document_id: str, payload: dict):
    table = dynamodb_resource.Table(table_name)
    key = get_key_dict(table_name, tenant, document_id)
    final_status = payload["status"]
    validation_status = payload["validationStatus"]
    expected_final_status = "COMPLETED" if validation_status == "PASS" else "FAILED"

    if final_status != expected_final_status:
        raise ValueError("persist status does not match validation status")
    if final_status == "COMPLETED" and not (
        payload.get("structured", {}).get("bucket")
        and payload.get("structured", {}).get("key")
    ):
        raise ValueError("COMPLETED persistence requires a structured pointer")

    update_kwargs = {
        "Key": key,
        "UpdateExpression": (
            "SET #status = :status, "
            "#completed_at = :completed_at, "
            "#stages.#persist = :persist_stage, "
            "#updated_at = :updated_at"
        ),
        "ConditionExpression": (
            "attribute_exists(#pk) AND "
            "#status = :expected_status AND "
            "#stages.#validate.#stage_status = :done AND "
            "#validation.#validation_status = :validation_status AND "
            "attribute_not_exists(#completed_at)"
        ),
        "ExpressionAttributeNames": {
            "#pk": next(iter(key)),
            "#status": "status",
            "#completed_at": "completedAt",
            "#stages": "stages",
            "#validate": "validate",
            "#persist": "persist",
            "#stage_status": "status",
            "#validation": "validation",
            "#validation_status": "status",
            "#updated_at": "updatedAt",
        },
        "ExpressionAttributeValues": {
            ":status": final_status,
            ":completed_at": payload["completedAt"],
            ":persist_stage": payload["stages_persist"],
            ":updated_at": payload["updatedAt"],
            ":expected_status": _expected_extracted_status(tenant),
            ":done": "DONE",
            ":validation_status": validation_status,
        },
    }

    if payload.get("structured"):
        update_kwargs["UpdateExpression"] += ", #structured = :structured"
        update_kwargs["ExpressionAttributeNames"]["#structured"] = "structured"
        update_kwargs["ExpressionAttributeValues"][":structured"] = payload["structured"]

    try:
        table.update_item(**update_kwargs)
        return payload["completedAt"]
    except ClientError as error:
        return _resolve_conditional_failure(
            error,
            table,
            key,
            lambda item: item.get("completedAt")
            if (
                item.get("status") == final_status
                and bool(item.get("completedAt"))
                and _nested(item, "validation", "status") == validation_status
                and _nested(item, "stages", "persist", "status") == "DONE"
                and _nested(item, "stages", "persist", "finalStatus") == final_status
            )
            else None,
        )


def update_notify_stage(table_name: str, tenant: str, document_id: str, payload: dict):
    table = dynamodb_resource.Table(table_name)
    key = get_key_dict(table_name, tenant, document_id)
    final_status = payload["finalStatus"]
    validation_status = payload["validationStatus"]
    expected_final_status = "COMPLETED" if validation_status == "PASS" else "FAILED"

    if final_status != expected_final_status:
        raise ValueError("notify status does not match validation status")

    update_kwargs = {
        "Key": key,
        "UpdateExpression": (
            "SET #notified_at = :notified_at, "
            "#stages.#notify = :notify_stage, "
            "#updated_at = :updated_at"
        ),
        "ConditionExpression": (
            "attribute_exists(#pk) AND "
            "#status = :final_status AND "
            "#completed_at = :completed_at AND "
            "#stages.#persist.#stage_status = :done AND "
            "#stages.#persist.#persist_final_status = :final_status AND "
            "#validation.#validation_status = :validation_status AND "
            "attribute_not_exists(#notified_at)"
        ),
        "ExpressionAttributeNames": {
            "#pk": next(iter(key)),
            "#status": "status",
            "#completed_at": "completedAt",
            "#notified_at": "notifiedAt",
            "#stages": "stages",
            "#persist": "persist",
            "#notify": "notify",
            "#stage_status": "status",
            "#persist_final_status": "finalStatus",
            "#validation": "validation",
            "#validation_status": "status",
            "#updated_at": "updatedAt",
        },
        "ExpressionAttributeValues": {
            ":notified_at": payload["notifiedAt"],
            ":notify_stage": payload["stages_notify"],
            ":updated_at": payload["updatedAt"],
            ":final_status": final_status,
            ":completed_at": payload["completedAt"],
            ":done": "DONE",
            ":validation_status": validation_status,
        },
    }

    try:
        table.update_item(**update_kwargs)
        return True
    except ClientError as error:
        return _resolve_conditional_failure(
            error,
            table,
            key,
            lambda item: True
            if (
                item.get("status") == final_status
                and item.get("completedAt") == payload["completedAt"]
                and _nested(item, "validation", "status") == validation_status
                and _nested(item, "stages", "persist", "status") == "DONE"
                and _nested(item, "stages", "notify", "status") == "DONE"
                and bool(item.get("notifiedAt"))
            )
            else None,
        )
