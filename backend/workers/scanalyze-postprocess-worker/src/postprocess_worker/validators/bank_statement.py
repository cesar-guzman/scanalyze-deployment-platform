import datetime
from decimal import Decimal, InvalidOperation, ROUND_HALF_UP
from typing import Any, Dict, Optional

from .generic import GenericValidator
from ..contracts import ValidationResult, ValidationError
from ..config import config

CENT = Decimal("0.01")
DEFAULT_TOLERANCE = Decimal("0.01")
# A misconfigured tolerance must not hide missing transactions.
MAX_TOLERANCE = Decimal("1.00")


def _cents(value: Any) -> Optional[Decimal]:
    """Amount rounded half-up to the cent, or None when absent or unusable."""
    if value is None or isinstance(value, bool):
        return None
    if not isinstance(value, (int, float, str, Decimal)):
        return None
    try:
        amount = Decimal(str(value))
    except InvalidOperation:
        return None
    if not amount.is_finite():
        return None
    return amount.quantize(CENT, rounding=ROUND_HALF_UP)


def _tolerance(tenant: str) -> Decimal:
    raw = config.get(tenant, "validation/balance_tolerance", str(DEFAULT_TOLERANCE))
    try:
        tolerance = Decimal(str(raw))
    except InvalidOperation:
        return DEFAULT_TOLERANCE
    if not tolerance.is_finite() or tolerance < 0:
        return DEFAULT_TOLERANCE
    return min(tolerance, MAX_TOLERANCE)


def _balance(balances: Dict[str, Any], key: str, legacy_key: str) -> Any:
    # The extractor writes balances.opening/closing. The legacy keys are read
    # only so that artifacts written before GUG-542 are still checked.
    value = balances.get(key)
    return balances.get(legacy_key) if value is None else value


class BankStatementValidator(GenericValidator):
    """Reconciles the complete extracted statement to the cent (GUG-542).

    Missing balances, unusable amounts, a closing balance that does not follow from
    the transactions, or printed totals that disagree with them are ERRORs, so a
    statement whose numbers do not add up is never accepted.
    """

    def validate(self, document_id: str, payload: Dict[str, Any], tenant: str = "platform") -> ValidationResult:
        # First, run generic validation
        result = super().validate(document_id, payload, tenant)

        # If generic validation completely failed due to missing fields, stop here to avoid KeyError
        if any(e.code in ("EMPTY_PAYLOAD", "MISSING_FIELD") for e in result.errors):
            return result

        errors = list(result.errors)
        tolerance = _tolerance(tenant)
        balances = payload.get("balances")
        balances = balances if isinstance(balances, dict) else {}
        transactions = payload.get("transactions")
        transactions = transactions if isinstance(transactions, list) else []

        opening = _cents(_balance(balances, "opening", "openingBalance"))
        closing = _cents(_balance(balances, "closing", "closingBalance"))
        if opening is None or closing is None:
            errors.append(ValidationError(
                code="RECONCILIATION_INSUFFICIENT_DATA",
                message="Opening or closing balance is missing or unusable",
                path="balances",
            ))
        else:
            credits = Decimal("0.00")
            debits = Decimal("0.00")
            unusable = 0
            for transaction in transactions:
                amount = _cents(transaction.get("amount")) if isinstance(transaction, dict) else None
                direction = transaction.get("direction") if isinstance(transaction, dict) else None
                if amount is None or direction not in ("credit", "debit"):
                    unusable += 1
                elif direction == "credit":
                    credits += amount
                else:
                    debits += amount

            if unusable:
                errors.append(ValidationError(
                    code="TRANSACTION_AMOUNT_UNUSABLE",
                    message=f"{unusable} transactions have no usable amount or direction",
                    path="transactions",
                ))
            else:
                implied_closing = opening + credits - debits
                diff = abs(implied_closing - closing)
                if diff > tolerance:
                    errors.append(ValidationError(
                        code="RECONCILIATION_FAILED",
                        message=(
                            f"Opening ({opening}) + Credits ({credits}) - Debits ({debits}) = "
                            f"{implied_closing}, but Closing is {closing}. Diff: {diff} > Tolerance {tolerance}"
                        ),
                        path="balances",
                    ))
                for key, summed in (("totalCredits", credits), ("totalDebits", debits)):
                    reported = _cents(balances.get(key))
                    if reported is not None and abs(reported - summed) > tolerance:
                        errors.append(ValidationError(
                            code="TOTALS_MISMATCH",
                            message=f"{key} is {reported} but the transactions sum {summed}",
                            path=f"balances.{key}",
                        ))

        status = "FAIL" if any(e.severity == "ERROR" for e in errors) else "PASS"

        return ValidationResult(
            status=status,
            errors=errors,
            validatedAt=datetime.datetime.now(datetime.timezone.utc).isoformat()
        )
