"""Merge per-page extraction results into one bank statement (GUG-542).

Each chunk covers different pages, so transactions are concatenated in page order
and nothing printed once for the whole statement is ever summed. The opening
balance comes from the first chunk that reports one and the closing balance from
the last; every other document-level value comes from the first chunk that
reports it.
"""

import copy
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from .normalize import to_cents

# Working fields that parse_and_normalize adds for this merge. They are not part
# of the artifact contract and must never be written.
WORKING_FIELDS = ("modelConfidence", "extractionIssues")

_SECTIONS = ("bank", "account", "statement")
_SCALARS = ("accountType", "bankCountry", "summaryText")
_DOCUMENT_AMOUNTS = ("interestEarned", "interestCharged")
# Values the reconciliation depends on: pages that disagree make it invalid.
_RECONCILED_TOTALS = ("totalCredits", "totalDebits")


def _first(values: Iterable[Any]) -> Any:
    for value in values:
        if value is not None:
            return value
    return None


def _keys_in_order(rows: Sequence[Dict[str, Any]]) -> List[str]:
    keys: List[str] = []
    for row in rows:
        for key in row:
            if key not in keys:
                keys.append(key)
    return keys


def _disagree(values: Sequence[Any]) -> bool:
    return len({to_cents(value) for value in values if value is not None}) > 1


def merge_chunk_results(
    chunks: Sequence[Dict[str, Any]],
) -> Tuple[Dict[str, Any], List[str], List[str], Optional[float]]:
    """Return (statement, reconciliation_issues, notes, model_confidence).

    ``reconciliation_issues`` invalidate the balance reconciliation. ``notes`` are
    disagreements on fees or interest that are logged only. ``model_confidence``
    is the lowest confidence any chunk reported, or None when one did not report.
    """
    if not chunks:
        raise ValueError("No extraction results to merge")

    merged = copy.deepcopy(dict(chunks[0]))
    issues: List[str] = []
    notes: List[str] = []
    for chunk in chunks:
        issues.extend(chunk.get("extractionIssues") or [])

    merged["transactions"] = [
        copy.deepcopy(transaction)
        for chunk in chunks
        for transaction in (chunk.get("transactions") or [])
    ]

    for section in _SECTIONS:
        target = dict(merged.get(section) or {})
        for chunk in chunks[1:]:
            for key, value in (chunk.get(section) or {}).items():
                if target.get(key) is None and value is not None:
                    target[key] = value
        merged[section] = target

    balance_rows = [chunk.get("balances") or {} for chunk in chunks]
    balances: Dict[str, Any] = {}
    for key in _keys_in_order(balance_rows):
        values = [row.get(key) for row in balance_rows]
        balances[key] = _first(reversed(values)) if key == "closing" else _first(values)
        if key in _RECONCILED_TOTALS and _disagree(values):
            issues.append(f"pages report different balances.{key}")
    merged["balances"] = balances

    for key in _SCALARS:
        merged[key] = _first(chunk.get(key) for chunk in chunks)

    for key in _DOCUMENT_AMOUNTS:
        values = [chunk.get(key) for chunk in chunks]
        merged[key] = _first(values)
        if _disagree(values):
            notes.append(key)

    fee_rows = [chunk["fees"] for chunk in chunks if isinstance(chunk.get("fees"), dict)]
    if fee_rows:
        fees: Dict[str, Any] = {}
        for key in _keys_in_order(fee_rows):
            values = [row.get(key) for row in fee_rows]
            fees[key] = _first(values)
            if _disagree(values):
                notes.append(f"fees.{key}")
        merged["fees"] = fees

    confidences = [chunk.get("modelConfidence") for chunk in chunks]
    model_confidence = (
        min(confidences) if all(value is not None for value in confidences) else None
    )

    for field in WORKING_FIELDS:
        merged.pop(field, None)
    return merged, issues, notes, model_confidence
