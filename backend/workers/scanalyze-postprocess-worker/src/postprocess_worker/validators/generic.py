import datetime
from typing import Dict, Any
from .base import BaseValidator
from ..contracts import ValidationResult, ValidationError

class GenericValidator(BaseValidator):
    def validate(
        self,
        document_id: str,
        payload: Dict[str, Any],
        tenant: str = "platform",
    ) -> ValidationResult:
        errors = []
        
        if not isinstance(payload, dict) or not payload:
            errors.append(ValidationError(code="EMPTY_PAYLOAD", message="Payload is empty or null"))
            return ValidationResult(
                status="FAIL",
                errors=errors,
                validatedAt=datetime.datetime.now(datetime.timezone.utc).isoformat()
            )
            
        required_fields = ["documentId", "docType", "schema_version"]
        for field in required_fields:
            value = payload.get(field)
            if not isinstance(value, str) or not value.strip():
                errors.append(ValidationError(
                    code="MISSING_FIELD",
                    message=f"Missing or empty required field: {field}",
                    path=field
                ))
            
        doc_id = payload.get("documentId")
        if isinstance(doc_id, str) and doc_id.strip() and doc_id != document_id:
            errors.append(ValidationError(
                code="ID_MISMATCH",
                message=(
                    f"Payload documentId ({doc_id}) does not match message "
                    f"documentId ({document_id})"
                ),
                path="documentId"
            ))
            
        status = "FAIL" if errors else "PASS"
        
        return ValidationResult(
            status=status,
            errors=errors,
            validatedAt=datetime.datetime.now(datetime.timezone.utc).isoformat()
        )
