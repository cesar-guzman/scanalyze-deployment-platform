"""Shared safety helpers for spreadsheet-compatible CSV exports."""
from __future__ import annotations

import unicodedata
from typing import Any


_DANGEROUS_FORMULA_PREFIXES = frozenset("=+-@")


def neutralize_csv_cell(value: Any) -> Any:
    """Prevent string cells from being interpreted as spreadsheet formulas."""
    if not isinstance(value, str):
        return value

    for character in value:
        if character.isspace() or unicodedata.category(character) == "Cc":
            continue
        if character in _DANGEROUS_FORMULA_PREFIXES:
            return f"'{value}"
        break

    return value
