import json
import logging
import math
import re
import json_repair
from decimal import Decimal, InvalidOperation, ROUND_HALF_UP
from typing import Dict, Any, List, Optional, Sequence, Tuple
from datetime import datetime, timezone
from .contracts import BankStatementSchema, BankFieldConfidence, FieldValidation
from .logger import log_event, safe_error_details
from pydantic import ValidationError

logger = logging.getLogger(__name__)

# Common date patterns for normalization
DATE_PATTERNS = [
    # DD/MM/YYYY or DD-MM-YYYY
    (re.compile(r'^(\d{1,2})[/\-](\d{1,2})[/\-](\d{4})$'), lambda m: f"{m.group(3)}-{m.group(2).zfill(2)}-{m.group(1).zfill(2)}"),
    # MM/DD/YYYY (US format — detected by month > 12 heuristic applied in caller)
    (re.compile(r'^(\d{1,2})[/\-](\d{1,2})[/\-](\d{4})$'), None),  # Handled by the DD/MM/YYYY pattern above
    # DD-MMM-YYYY or DD/MMM/YYYY (e.g., 15-ENE-2024, 15/Jan/2024)
    (re.compile(r'^(\d{1,2})[/\-]([A-Za-z]{3,})[/\-](\d{4})$'), None),  # Handled separately
    # YYYY-MM-DD already ISO, pass through
    (re.compile(r'^\d{4}-\d{2}-\d{2}$'), None),
]

MONTH_MAP = {
    'ene': '01', 'jan': '01', 'feb': '02', 'mar': '03',
    'abr': '04', 'apr': '04', 'may': '05', 'jun': '06',
    'jul': '07', 'ago': '08', 'aug': '08', 'sep': '09', 'sept': '09',
    'oct': '10', 'nov': '11', 'dic': '12', 'dec': '12',
}


def normalize_date(date_str: str) -> str:
    """
    Normalizes various date formats to ISO-8601 (YYYY-MM-DD).
    Returns the original string if it cannot be parsed.
    """
    if not date_str or not isinstance(date_str, str):
        return date_str

    date_str = date_str.strip()

    # Already ISO
    if re.match(r'^\d{4}-\d{2}-\d{2}$', date_str):
        return date_str

    # DD/MM/YYYY or DD-MM-YYYY
    m = re.match(r'^(\d{1,2})[/\-](\d{1,2})[/\-](\d{4})$', date_str)
    if m:
        day, month, year = m.group(1), m.group(2), m.group(3)
        return f"{year}-{month.zfill(2)}-{day.zfill(2)}"

    # DD-MMM-YYYY or DD/MMM/YYYY (e.g., 15-Ene-2024)
    m = re.match(r'^(\d{1,2})[/\-]([A-Za-z]{3,})[/\-](\d{4})$', date_str)
    if m:
        day = m.group(1)
        month_name = m.group(2).lower()[:3]
        year = m.group(3)
        month_num = MONTH_MAP.get(month_name)
        if month_num:
            return f"{year}-{month_num}-{day.zfill(2)}"

    return date_str


CENT = Decimal("0.01")
# Amounts are rounded half-up to the cent before any sum. A reconciliation passes
# when the remaining difference is at most one cent.
RECONCILIATION_TOLERANCE = Decimal("0.01")
MAX_ISSUE_LENGTH = 500

_PLAIN_AMOUNT = re.compile(r"^-?\d+(\.\d+)?$")
_THOUSANDS_AMOUNT = re.compile(r"^-?\d{1,3}(,\d{3})+(\.\d+)?$")
_CURRENCY_MARKS = re.compile(r"(?i)\$|\b(mxn|mxp|usd|eur)\b")


def parse_amount(value: Any) -> Optional[Decimal]:
    """Parse an extracted amount. Returns None when absent; raises ValueError when unusable."""
    if value is None:
        return None
    if isinstance(value, bool):
        raise ValueError("amount is a boolean")
    if isinstance(value, (int, float)):
        if isinstance(value, float) and not math.isfinite(value):
            raise ValueError("amount is not finite")
        return Decimal(str(value))
    if isinstance(value, str):
        text = _CURRENCY_MARKS.sub("", value).strip().replace(" ", "")
        if text == "":
            return None
        if _THOUSANDS_AMOUNT.match(text):
            text = text.replace(",", "")
        if not _PLAIN_AMOUNT.match(text):
            raise ValueError("amount text is not a number")
        return Decimal(text)
    raise ValueError("amount has an unsupported type")


def to_cents(value: Any) -> Optional[Decimal]:
    """Amount rounded half-up to the cent, or None when absent or unusable."""
    try:
        amount = parse_amount(value)
    except (ValueError, InvalidOperation):
        return None
    if amount is None:
        return None
    return amount.quantize(CENT, rounding=ROUND_HALF_UP)


def _normalize_amount(value: Any, label: str, issues: List[str]) -> Optional[float]:
    try:
        amount = parse_amount(value)
    except (ValueError, InvalidOperation):
        issues.append(f"unparseable amount in {label}")
        return None
    return None if amount is None else float(amount)


def model_confidence(value: Any) -> float:
    """The model's self-reported 0-100 confidence. There is no default."""
    if isinstance(value, bool) or value is None:
        raise ValueError("Model did not report overallConfidence")
    try:
        confidence = float(value)
    except (TypeError, ValueError):
        raise ValueError("Model reported a non-numeric overallConfidence") from None
    if not math.isfinite(confidence) or not 0.0 <= confidence <= 100.0:
        raise ValueError("Model reported overallConfidence outside 0-100")
    return confidence


def _bounded_issue(parts: Sequence[str]) -> Optional[str]:
    text = "; ".join(part for part in parts if part)
    if not text:
        return None
    return text if len(text) <= MAX_ISSUE_LENGTH else text[: MAX_ISSUE_LENGTH - 3] + "..."


def reconcile_balances(
    balances: Dict[str, Any],
    transactions: Sequence[Dict[str, Any]],
    extra_issues: Sequence[str] = (),
) -> Tuple[Optional[bool], Optional[str]]:
    """Reconcile to the cent: opening + credits - debits = closing.

    Checks the transaction sums and, when the statement reports them, the printed
    totals and their agreement with the transactions. Returns (valid, issue);
    valid is None when the opening or closing balance is missing.
    """
    opening = to_cents(balances.get("opening"))
    closing = to_cents(balances.get("closing"))
    if opening is None or closing is None:
        return None, _bounded_issue(["opening or closing balance missing", *extra_issues])

    failures: List[str] = list(extra_issues)
    credits = Decimal("0.00")
    debits = Decimal("0.00")
    unusable = 0
    for transaction in transactions:
        amount = to_cents(transaction.get("amount"))
        if amount is None:
            unusable += 1
        elif transaction.get("direction") == "credit":
            credits += amount
        elif transaction.get("direction") == "debit":
            debits += amount
    if unusable:
        failures.append(f"{unusable} transactions without a usable amount")
    else:
        implied = opening + credits - debits
        if abs(implied - closing) > RECONCILIATION_TOLERANCE:
            failures.append(
                f"opening({opening})+credits({credits})-debits({debits})={implied}, closing={closing}"
            )

    total_credits = to_cents(balances.get("totalCredits"))
    total_debits = to_cents(balances.get("totalDebits"))
    if total_credits is not None and total_debits is not None:
        implied_totals = opening + total_credits - total_debits
        if abs(implied_totals - closing) > RECONCILIATION_TOLERANCE:
            failures.append(
                f"reported totals: opening({opening})+credits({total_credits})"
                f"-debits({total_debits})={implied_totals}, closing={closing}"
            )
    if not unusable:
        if total_credits is not None and abs(credits - total_credits) > RECONCILIATION_TOLERANCE:
            failures.append(f"credits sum {credits} differs from reported totalCredits {total_credits}")
        if total_debits is not None and abs(debits - total_debits) > RECONCILIATION_TOLERANCE:
            failures.append(f"debits sum {debits} differs from reported totalDebits {total_debits}")

    return (not failures), _bounded_issue(failures)


def compute_field_confidence(
    data: Dict[str, Any],
    ocr_char_count: int = 0,
    extra_issues: Sequence[str] = (),
) -> Tuple[BankFieldConfidence, float]:
    """
    Computes real per-field confidence and an adjusted overallConfidence
    based on actual validation results, not the LLM's self-assessment.

    The model's own confidence is the starting point and is required: a missing
    value raises ValueError instead of assuming one. ``extra_issues`` (parse
    errors, conflicting balances across pages) invalidate the reconciliation.
    """
    bank = data.get('bank', {}) or {}
    account = data.get('account', {}) or {}
    statement = data.get('statement', {}) or {}
    balances = data.get('balances', {}) or {}
    transactions = data.get('transactions', []) or []

    if data.get('modelConfidence') is not None:
        llm_confidence = model_confidence(data['modelConfidence'])
    else:
        llm_confidence = model_confidence(data.get('overallConfidence'))

    # --- Bank name validation ---
    bank_name = bank.get('name')
    bank_name_present = bool(bank_name and str(bank_name).strip())
    bank_name_score = 95.0 if bank_name_present else 0.0

    bank_name_validation = FieldValidation(
        present=bank_name_present,
        valid=bank_name_present,
        score=bank_name_score,
        issue=None if bank_name_present else "missing"
    )

    # --- Account holder validation ---
    holder = account.get('holder')
    holder_present = bool(holder and str(holder).strip())
    holder_score = 95.0 if holder_present else 0.0

    holder_validation = FieldValidation(
        present=holder_present,
        valid=holder_present,
        score=holder_score,
        issue=None if holder_present else "missing"
    )

    # --- Balance reconciliation, to the cent ---
    balances_present = (
        to_cents(balances.get('opening')) is not None
        and to_cents(balances.get('closing')) is not None
    )
    recon_valid, recon_issue = reconcile_balances(balances, transactions, extra_issues)
    if recon_valid is None:
        recon_score = 30.0
    else:
        recon_score = 95.0 if recon_valid else 20.0

    recon_validation = FieldValidation(
        present=balances_present,
        valid=recon_valid,
        score=recon_score,
        issue=recon_issue
    )

    # --- Transaction count validation ---
    txn_count = len(transactions)
    txn_present = txn_count > 0
    txn_score = 95.0 if txn_present else 0.0

    txn_validation = FieldValidation(
        present=txn_present,
        valid=txn_present,
        score=txn_score,
        issue=None if txn_present else "no transactions extracted"
    )

    # --- Period detection validation ---
    period_start = statement.get('periodStart')
    period_end = statement.get('periodEnd')
    period_present = bool(period_start and period_end)
    period_valid = period_present
    period_issue = None

    if period_present:
        # Check that periodStart < periodEnd
        try:
            if period_start > period_end:
                period_valid = False
                period_issue = f"periodStart({period_start}) > periodEnd({period_end})"
        except Exception:
            pass
    else:
        period_issue = "period dates missing"

    period_score = 95.0 if period_valid else (40.0 if period_present else 0.0)

    period_validation = FieldValidation(
        present=period_present,
        valid=period_valid,
        score=period_score,
        issue=period_issue
    )

    field_confidence = BankFieldConfidence(
        bankName=bank_name_validation,
        accountHolder=holder_validation,
        balanceReconciliation=recon_validation,
        transactionCount=txn_validation,
        periodDetected=period_validation
    )

    # --- Compute adjusted overallConfidence ---
    adjusted = float(llm_confidence)

    if not bank_name_present:
        adjusted -= 15.0

    if not holder_present:
        adjusted -= 10.0

    if recon_valid is False:
        adjusted -= 25.0
    elif not balances_present:
        adjusted -= 10.0

    if not txn_present:
        adjusted -= 20.0

    if not period_present:
        adjusted -= 10.0
    elif not period_valid:
        adjusted -= 5.0

    # Penalize very short OCR (indicates blurry or partial scan)
    if ocr_char_count > 0 and ocr_char_count < 300:
        adjusted -= 20.0

    adjusted = max(min(adjusted, 100.0), 0.0)

    return field_confidence, round(adjusted, 1)


def clean_json_string(raw_text: str) -> str:
    """
    Strips markdown code fences and extracts the first balanced JSON object.
    Because sometimes Claude ignores strict system prompts.
    """
    text = raw_text.strip()
    
    # Strip markdown block quotes
    if text.startswith("```"):
        lines = text.split("\n")
        # Remove first line if it's ```json or ```
        if lines[0].startswith("```"):
            lines.pop(0)
        # Remove last line if it's ```
        if lines and lines[-1].strip().startswith("```"):
            lines.pop(-1)
        text = "\n".join(lines).strip()
        
    # Extra protection: find first { and last }
    start_idx = text.find("{")
    end_idx = text.rfind("}")
    
    if start_idx != -1 and end_idx != -1 and end_idx > start_idx:
        text = text[start_idx:end_idx+1]
        
    return text

def parse_and_normalize(raw_json: str, document_id: str, prompt_version: str, model_id: str, ocr_char_count: int = 0) -> Dict[str, Any]:
    """
    Validates against strict Pydantic schema, applies post-extraction validation,
    and computes real confidence based on data quality.
    """
    cleaned = clean_json_string(raw_json)
    
    try:
        data = json_repair.loads(cleaned)
        if not isinstance(data, dict):
            raise ValueError(f"Parsed JSON is not a dictionary. Got: {type(data)}")
    except Exception as e:
        log_event(
            "bedrock_json_parse_failed",
            documentId=document_id,
            **safe_error_details(e),
        )
        raise ValueError("Bedrock returned invalid JSON dictionary") from None

    try:
        reported_confidence = model_confidence(data.get("overallConfidence"))
    except ValueError as e:
        log_event(
            "bedrock_confidence_missing",
            documentId=document_id,
            **safe_error_details(e),
        )
        raise

    # Enforce static schema requirements
    data["schema_version"] = "1.0"
    data["prompt_version"] = prompt_version
    data["tenant"] = "bank"
    data["documentId"] = document_id
    data["docType"] = "bank_statement"
    data["generatedAt"] = datetime.now(timezone.utc).isoformat()
    
    data["model"] = {
        "provider": "bedrock",
        "modelId": model_id,
        "usage": None  # We'll populate this later from metrics if needed
    }

    # Ensure top-level structures exist with defaults
    for key in ("bank", "account", "statement", "balances"):
        if key not in data or not isinstance(data.get(key), dict):
            data[key] = {}
    
    if "transactions" not in data or not isinstance(data["transactions"], list):
        data["transactions"] = []
    
    # --- Normalizations ---
    
    # Currency normalization
    if "account" in data and isinstance(data["account"], dict):
        if data["account"].get("currency"):
            data["account"]["currency"] = str(data["account"]["currency"]).upper()

    # CLABE normalization (18 digits, no spaces)
    account = data.get("account", {})
    if account.get("clabe"):
        raw_clabe = str(account["clabe"])
        digits_only = re.sub(r'\D', '', raw_clabe.strip())
        if len(digits_only) == 18:
            account["clabe"] = digits_only
        else:
            # Invalid CLABE → move to clabeMasked as fallback, clear clabe
            if not account.get("clabeMasked"):
                account["clabeMasked"] = raw_clabe
            account["clabe"] = None
            logger.info(f"CLABE invalid ({len(digits_only)} digits), moved to clabeMasked")

    # Account number normalization (strip whitespace)
    if account.get("number"):
        account["number"] = re.sub(r'\s', '', str(account["number"]))

    # bankCountry normalization
    if data.get("bankCountry"):
        data["bankCountry"] = str(data["bankCountry"]).upper()[:2]

    # Date normalization in statement
    if "statement" in data and isinstance(data["statement"], dict):
        for date_field in ("periodStart", "periodEnd"):
            if data["statement"].get(date_field):
                data["statement"][date_field] = normalize_date(data["statement"][date_field])

    # Filter out severely broken transactions and normalize dates
    valid_txns = []
    for t in data["transactions"]:
        if isinstance(t, dict):
            # Check basic required fields for our schema
            if "direction" in t and t["direction"] in ("credit", "debit"):
                # Normalize transaction date
                if t.get("date"):
                    t["date"] = normalize_date(t["date"])
                valid_txns.append(t)

    # Sort transactions by date ascending
    def sort_key(txn):
        d = txn.get("date") or ""
        return d

    valid_txns.sort(key=sort_key)
    data["transactions"] = valid_txns

    # Amounts become floats, or None with an explicit issue; never a silent 0.0.
    # Unusable balances or transaction amounts invalidate the reconciliation;
    # unusable fee or interest amounts are only logged.
    issues: List[str] = []
    notes: List[str] = []
    balances = data["balances"]
    for key in list(balances.keys()):
        balances[key] = _normalize_amount(balances.get(key), f"balances.{key}", issues)
    for index, transaction in enumerate(valid_txns):
        for key in ("amount", "balanceAfter"):
            if key in transaction:
                transaction[key] = _normalize_amount(
                    transaction.get(key), f"transactions[{index}].{key}", issues
                )
    if isinstance(data.get("fees"), dict):
        fees = data["fees"]
        for key in list(fees.keys()):
            fees[key] = _normalize_amount(fees.get(key), f"fees.{key}", notes)
    for key in ("interestEarned", "interestCharged"):
        if key in data:
            data[key] = _normalize_amount(data.get(key), key, notes)
    for note in notes:
        log_event("bank_amount_unparseable", documentId=document_id, field=note)
    data["modelConfidence"] = reported_confidence
    data["extractionIssues"] = issues

    # Compute field-level confidence and adjusted overall confidence
    field_confidence, adjusted_confidence = compute_field_confidence(
        data, ocr_char_count, extra_issues=issues
    )
    data["fieldConfidence"] = field_confidence.model_dump(exclude_none=False)
    data["overallConfidence"] = adjusted_confidence

    logger.info(f"Confidence adjusted to {adjusted_confidence}")
    
    try:
        # Validate through Pydantic (will cast floats properly if they are strings, drop extra fields)
        validated_obj = BankStatementSchema(**data)
        # Re-export exactly matching schema, dropping extras
        return validated_obj.model_dump(exclude_none=False)
    except ValidationError as ve:
        log_event(
            "bedrock_schema_validation_failed",
            documentId=document_id,
            **safe_error_details(ve),
        )
        raise ValueError("Schema violation") from None
