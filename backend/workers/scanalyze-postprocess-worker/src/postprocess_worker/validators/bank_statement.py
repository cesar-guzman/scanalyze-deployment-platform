import datetime
from typing import Dict, Any
from .generic import GenericValidator
from ..contracts import ValidationResult, ValidationError
from ..config import config

class BankStatementValidator(GenericValidator):
    def validate(self, document_id: str, payload: Dict[str, Any], tenant: str = "platform") -> ValidationResult:
        # First, run generic validation
        result = super().validate(document_id, payload, tenant)
        
        # If generic validation completely failed due to missing fields, stop here to avoid KeyError
        if any(e.code in ("EMPTY_PAYLOAD", "MISSING_FIELD") for e in result.errors):
            return result
            
        errors = result.errors
            
        tolerance_str = config.get(tenant, "validation/balance_tolerance", "0.01")
        try:
            tolerance = float(tolerance_str)
        except ValueError:
            tolerance = 0.01
            
        balances = payload.get("balances", {})
        transactions = payload.get("transactions", [])
        
        opening = balances.get("openingBalance")
        closing = balances.get("closingBalance")
        
        if opening is not None and closing is not None:
            sum_credits = sum(t.get("amount", 0.0) for t in transactions if t.get("direction") == "credit" and t.get("amount") is not None)
            sum_debits = sum(t.get("amount", 0.0) for t in transactions if t.get("direction") == "debit" and t.get("amount") is not None)
            
            calculated_closing = opening + sum_credits - sum_debits
            diff = abs(calculated_closing - closing)
            
            if diff > tolerance:
                errors.append(ValidationError(
                    code="RECONCILIATION_FAILED",
                    message=f"Opening ({opening}) + Credits ({sum_credits}) - Debits ({sum_debits}) = {calculated_closing}, but Closing is {closing}. Diff: {diff} > Tolerance {tolerance}",
                    severity="WARNING" # Could be WARNING or ERROR depending on business logic
                ))
                
        status = "FAIL" if any(e.severity == "ERROR" for e in errors) else "PASS"
        
        return ValidationResult(
            status=status,
            errors=errors,
            validatedAt=datetime.datetime.now(datetime.timezone.utc).isoformat()
        )
