"""GUG-542: the bank statement validator reconciles the full statement to the cent."""

from unittest.mock import patch

from src.postprocess_worker.validators.bank_statement import BankStatementValidator


def _statement(**overrides):
    payload = {
        "documentId": "doc-1",
        "docType": "bank_statement",
        "schema_version": "1.0",
        "balances": {"opening": 1000.0, "closing": 1300.0, "totalCredits": 500.0, "totalDebits": 200.0},
        "transactions": [
            {"amount": 500.0, "direction": "credit"},
            {"amount": 200.0, "direction": "debit"},
        ],
    }
    payload.update(overrides)
    return payload


def _validate(payload, tolerance="0.01"):
    with patch(
        "src.postprocess_worker.validators.bank_statement.config.get",
        return_value=tolerance,
    ):
        return BankStatementValidator().validate("doc-1", payload, "bank")


def _codes(result):
    return [error.code for error in result.errors]


def test_reconciled_statement_passes():
    result = _validate(_statement())
    assert result.status == "PASS"
    assert result.errors == []


def test_one_cent_of_rounding_passes_and_two_cents_fail():
    assert _validate(_statement(balances={"opening": 1000.0, "closing": 1300.01})).status == "PASS"

    result = _validate(_statement(balances={"opening": 1000.0, "closing": 1300.02}))
    assert result.status == "FAIL"
    assert _codes(result) == ["RECONCILIATION_FAILED"]


def test_missing_balance_fails_as_insufficient_data():
    result = _validate(_statement(balances={"opening": 1000.0}))
    assert result.status == "FAIL"
    assert _codes(result) == ["RECONCILIATION_INSUFFICIENT_DATA"]


def test_empty_statement_never_passes():
    result = _validate(_statement(balances={}, transactions=[]))
    assert result.status == "FAIL"


def test_transaction_without_a_usable_amount_fails():
    result = _validate(_statement(transactions=[{"amount": None, "direction": "credit"}]))
    assert result.status == "FAIL"
    assert _codes(result) == ["TRANSACTION_AMOUNT_UNUSABLE"]


def test_printed_totals_must_match_the_transactions():
    result = _validate(_statement(balances={
        "opening": 1000.0,
        "closing": 1300.0,
        "totalCredits": 600.0,
        "totalDebits": 300.0,
    }))
    assert result.status == "FAIL"
    assert _codes(result) == ["TOTALS_MISMATCH", "TOTALS_MISMATCH"]


def test_legacy_balance_keys_are_still_checked():
    result = _validate(_statement(balances={"openingBalance": 1000.0, "closingBalance": 9999.0}))
    assert result.status == "FAIL"
    assert _codes(result) == ["RECONCILIATION_FAILED"]


def test_configured_tolerance_is_capped_at_one_unit():
    result = _validate(_statement(balances={"opening": 1000.0, "closing": 1305.0}), tolerance="1000")
    assert result.status == "FAIL"
    assert "Tolerance 1.00" in result.errors[0].message


def test_unusable_tolerance_falls_back_to_one_cent():
    result = _validate(_statement(balances={"opening": 1000.0, "closing": 1300.02}), tolerance="abc")
    assert result.status == "FAIL"
    assert "Tolerance 0.01" in result.errors[0].message
