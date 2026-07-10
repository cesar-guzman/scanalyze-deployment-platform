import pytest
from bank_worker.normalize import clean_json_string, parse_and_normalize, normalize_date, compute_field_confidence

def test_clean_json_string():
    raw_bedrock = "```json\n{\n  \"schema_version\": \"1.0\"\n}\n```"
    cleaned = clean_json_string(raw_bedrock)
    assert cleaned == "{\n  \"schema_version\": \"1.0\"\n}"
    
    dirty = "Aquí tienes tu estado de cuenta en JSON:\n\n```\n{\"a\": 1}\n```\n\nEspero te sirva."
    cleaned_dirty = clean_json_string(dirty)
    assert cleaned_dirty == "{\"a\": 1}"

def test_parse_and_normalize_success():
    raw_json = """{
        "bank": {"name": "Test Bank"},
        "account": {"holder": "John Doe", "numberMasked": "XXXX1234", "currency": "mxn"},
        "statement": {"periodStart": "2023-01-01", "periodEnd": "2023-01-31"},
        "balances": {"opening": 1000.50, "closing": "5000.00"},
        "transactions": [
            {"date": "2023-01-05", "description": "Deposit", "amount": "4000", "direction": "credit"}
        ]
    }"""
    
    result = parse_and_normalize(raw_json, "doc-123", "1.0.0", "model-xxx")
    
    assert result["docType"] == "bank_statement"
    assert result["tenant"] == "bank"
    assert result["documentId"] == "doc-123"
    assert result["model"]["modelId"] == "model-xxx"
    assert result["account"]["currency"] == "MXN"
    assert result["balances"]["closing"] == 5000.0  # Casted from string to float
    assert result["transactions"][0]["amount"] == 4000.0
    # New: should have confidence fields
    assert "overallConfidence" in result
    assert "fieldConfidence" in result
    assert result["overallConfidence"] is not None

def test_parse_and_normalize_invalid_json():
    # json_repair can parse "{bad json" into a partial dict, and with all Optional fields
    # it may pass validation. Test that truly unparseable input raises ValueError.
    with pytest.raises(ValueError, match="(dictionary|invalid JSON)"):
         parse_and_normalize("not json at all [[[{", "doc-123", "1.0.0", "model-xxx")

def test_parse_and_normalize_resilient_bad_json():
    # json_repair may fix "{bad json" -> dict or list depending on version.
    # With Optional fields and dict result, this should succeed gracefully.
    # With list result, it should raise ValueError.
    try:
        result = parse_and_normalize("{bad json", "doc-123", "1.0.0", "model-xxx")
        assert result["documentId"] == "doc-123"
        assert result["docType"] == "bank_statement"
        assert isinstance(result["transactions"], list)
    except ValueError:
        pass  # Also acceptable if json_repair produces non-dict
         
def test_parse_and_normalize_string_balances_resilient():
    # With resilient normalization, string balances get reset to {}
    # This should NOT raise, because the schema is now Optional.
    raw_json = """{
        "bank": {"name": "Test Bank"},
        "account": {"holder": "John Doe"},
        "statement": {"periodStart": "2023-01-01", "periodEnd": "2023-01-31"},
        "balances": "invalid_type",
        "transactions": []
    }"""
    result = parse_and_normalize(raw_json, "doc-123", "1.0.0", "model-xxx")
    assert result["balances"] == {}  # Reset to empty dict
    assert result["bank"]["name"] == "Test Bank"

# --- New tests for v2.0 features ---

def test_parse_and_normalize_optional_fields():
    """Top-level fields bank/account/statement/balances should default to {} if missing."""
    raw_json = """{
        "transactions": [
            {"date": "2023-01-05", "description": "Deposit", "amount": 100.0, "direction": "credit"}
        ]
    }"""
    result = parse_and_normalize(raw_json, "doc-opt", "2.0.0", "model-xxx")
    assert result["bank"] == {}
    assert result["account"] == {}
    assert result["statement"] == {}
    assert result["balances"] == {}
    assert len(result["transactions"]) == 1

def test_parse_and_normalize_new_fields():
    """Verify accountType, bankCountry, category, fees, interest fields."""
    raw_json = """{
        "bank": {"name": "BBVA"},
        "account": {"holder": "Juan Pérez", "currency": "mxn"},
        "statement": {"periodStart": "01/01/2024", "periodEnd": "31/01/2024"},
        "balances": {"opening": 10000.0, "closing": 15000.0},
        "accountType": "cheques",
        "bankCountry": "mx",
        "fees": {"totalFees": 150.0, "ivaOnFees": 24.0},
        "interestEarned": 45.50,
        "interestCharged": null,
        "summaryText": "BBVA cheques enero 2024 Juan Pérez",
        "transactions": [
            {"date": "05/01/2024", "description": "Nómina", "amount": 25000, "direction": "credit", "category": "nómina"},
            {"date": "10/01/2024", "description": "Retiro ATM", "amount": 5000, "direction": "debit", "category": "retiro_atm"}
        ]
    }"""
    result = parse_and_normalize(raw_json, "doc-new", "2.0.0", "model-xxx")
    
    assert result["accountType"] == "cheques"
    assert result["bankCountry"] == "MX"
    assert result["fees"]["totalFees"] == 150.0
    assert result["fees"]["ivaOnFees"] == 24.0
    assert result["interestEarned"] == 45.50
    assert result["interestCharged"] is None
    assert result["summaryText"] == "BBVA cheques enero 2024 Juan Pérez"
    assert result["transactions"][0]["category"] == "nómina"
    assert result["transactions"][1]["category"] == "retiro_atm"

def test_date_normalization():
    """Test date format normalization to ISO-8601."""
    # Already ISO
    assert normalize_date("2024-01-15") == "2024-01-15"
    # DD/MM/YYYY
    assert normalize_date("15/01/2024") == "2024-01-15"
    # DD-MM-YYYY
    assert normalize_date("15-01-2024") == "2024-01-15"
    # DD-MMM-YYYY (Spanish)
    assert normalize_date("15-Ene-2024") == "2024-01-15"
    # DD/MMM/YYYY (English)
    assert normalize_date("15/Jan/2024") == "2024-01-15"
    # None passthrough
    assert normalize_date(None) is None
    assert normalize_date("") == ""

def test_transaction_sorting():
    """Transactions should be sorted by date ascending after normalization."""
    raw_json = """{
        "bank": {"name": "Test"},
        "account": {},
        "statement": {},
        "balances": {},
        "transactions": [
            {"date": "2024-01-20", "description": "Later", "amount": 100, "direction": "credit"},
            {"date": "2024-01-05", "description": "Earlier", "amount": 200, "direction": "debit"},
            {"date": "2024-01-10", "description": "Middle", "amount": 300, "direction": "credit"}
        ]
    }"""
    result = parse_and_normalize(raw_json, "doc-sort", "2.0.0", "model-xxx")
    dates = [t["date"] for t in result["transactions"]]
    assert dates == ["2024-01-05", "2024-01-10", "2024-01-20"]

def test_currency_normalization():
    """Currency should be uppercased."""
    raw_json = """{
        "bank": {"name": "Chase"},
        "account": {"currency": "usd", "holder": "John"},
        "statement": {},
        "balances": {},
        "transactions": []
    }"""
    result = parse_and_normalize(raw_json, "doc-cur", "2.0.0", "model-xxx")
    assert result["account"]["currency"] == "USD"

def test_country_normalization():
    """bankCountry should be uppercased and truncated to 2 chars."""
    raw_json = """{
        "bank": {"name": "Chase"},
        "account": {},
        "statement": {},
        "balances": {},
        "bankCountry": "us",
        "transactions": []
    }"""
    result = parse_and_normalize(raw_json, "doc-country", "2.0.0", "model-xxx")
    assert result["bankCountry"] == "US"

# --- Confidence system tests ---

def test_compute_field_confidence_complete_data():
    """Complete data with reconciled balances should give high confidence."""
    data = {
        "bank": {"name": "BBVA"},
        "account": {"holder": "Juan Pérez"},
        "statement": {"periodStart": "2024-01-01", "periodEnd": "2024-01-31"},
        "balances": {"opening": 10000.0, "closing": 30000.0},
        "transactions": [
            {"date": "2024-01-05", "amount": 25000.0, "direction": "credit"},
            {"date": "2024-01-10", "amount": 5000.0, "direction": "debit"}
        ],
        "overallConfidence": 95.0
    }
    fc, adjusted = compute_field_confidence(data, ocr_char_count=5000)
    
    # All fields present
    assert fc.bankName.present is True
    assert fc.bankName.valid is True
    assert fc.accountHolder.present is True
    assert fc.transactionCount.present is True
    assert fc.periodDetected.present is True
    assert fc.balanceReconciliation.present is True
    assert fc.balanceReconciliation.valid is True
    # Adjusted confidence should be high (no penalties)
    assert adjusted >= 85.0

def test_compute_field_confidence_missing_bank():
    """Missing bank name should penalize confidence by 15 points."""
    data = {
        "bank": {},
        "account": {"holder": "Juan"},
        "statement": {"periodStart": "2024-01-01", "periodEnd": "2024-01-31"},
        "balances": {"opening": 1000.0, "closing": 2000.0},
        "transactions": [{"amount": 1000.0, "direction": "credit"}],
        "overallConfidence": 95.0
    }
    fc, adjusted = compute_field_confidence(data, ocr_char_count=5000)
    
    assert fc.bankName.present is False
    assert fc.bankName.issue == "missing"
    # 95 - 15 (bank) = 80
    assert adjusted <= 80.0

def test_compute_field_confidence_balance_mismatch():
    """Mismatched balances should penalize confidence by 25 points."""
    data = {
        "bank": {"name": "BBVA"},
        "account": {"holder": "Juan"},
        "statement": {"periodStart": "2024-01-01", "periodEnd": "2024-01-31"},
        "balances": {"opening": 1000.0, "closing": 9999.0},
        "transactions": [{"amount": 500.0, "direction": "credit"}],
        "overallConfidence": 95.0
    }
    fc, adjusted = compute_field_confidence(data, ocr_char_count=5000)
    
    assert fc.balanceReconciliation.valid is False
    assert fc.balanceReconciliation.issue is not None
    assert adjusted <= 70.0

def test_compute_field_confidence_short_ocr():
    """Very short OCR text should penalize confidence by 20 points."""
    data = {
        "bank": {"name": "BBVA"},
        "account": {"holder": "Juan"},
        "statement": {"periodStart": "2024-01-01", "periodEnd": "2024-01-31"},
        "balances": {"opening": 1000.0, "closing": 2000.0},
        "transactions": [{"amount": 1000.0, "direction": "credit"}],
        "overallConfidence": 95.0
    }
    fc, adjusted_short = compute_field_confidence(data, ocr_char_count=100)
    _, adjusted_normal = compute_field_confidence(data, ocr_char_count=5000)
    
    assert adjusted_short < adjusted_normal
    assert adjusted_normal - adjusted_short >= 19.0  # 20 point penalty

def test_compute_field_confidence_no_transactions():
    """No transactions should penalize confidence by 20 points."""
    data = {
        "bank": {"name": "BBVA"},
        "account": {"holder": "Juan"},
        "statement": {"periodStart": "2024-01-01", "periodEnd": "2024-01-31"},
        "balances": {"opening": 1000.0, "closing": 1000.0},
        "transactions": [],
        "overallConfidence": 95.0
    }
    fc, adjusted = compute_field_confidence(data, ocr_char_count=5000)
    
    assert fc.transactionCount.present is False
    assert fc.transactionCount.issue == "no transactions extracted"
    # 95 - 20 = 75 max
    assert adjusted <= 75.0

def test_compute_field_confidence_period_incoherent():
    """periodStart > periodEnd should lower period confidence."""
    data = {
        "bank": {"name": "BBVA"},
        "account": {"holder": "Juan"},
        "statement": {"periodStart": "2024-12-31", "periodEnd": "2024-01-01"},
        "balances": {"opening": 1000.0, "closing": 2000.0},
        "transactions": [{"amount": 1000.0, "direction": "credit"}],
        "overallConfidence": 95.0
    }
    fc, adjusted = compute_field_confidence(data, ocr_char_count=5000)
    
    assert fc.periodDetected.valid is False
    assert "periodStart" in fc.periodDetected.issue

def test_parse_and_normalize_includes_confidence():
    """parse_and_normalize should always include overallConfidence and fieldConfidence."""
    raw_json = """{
        "bank": {"name": "BBVA"},
        "account": {"holder": "Juan", "currency": "mxn"},
        "statement": {"periodStart": "2024-01-01", "periodEnd": "2024-01-31"},
        "balances": {"opening": 10000.0, "closing": 30000.0},
        "transactions": [
            {"date": "2024-01-15", "description": "Nómina", "amount": 25000, "direction": "credit"},
            {"date": "2024-01-20", "description": "Retiro", "amount": 5000, "direction": "debit"}
        ]
    }"""
    result = parse_and_normalize(raw_json, "doc-conf", "2.0.0", "model-xxx", ocr_char_count=5000)
    
    assert "overallConfidence" in result
    assert "fieldConfidence" in result
    assert isinstance(result["overallConfidence"], float)
    assert isinstance(result["fieldConfidence"], dict)
    assert "bankName" in result["fieldConfidence"]
    assert "balanceReconciliation" in result["fieldConfidence"]
    assert result["fieldConfidence"]["bankName"]["present"] is True
    assert result["fieldConfidence"]["bankName"]["valid"] is True


# ══════════════════════════════════════════════════════════════
# v2.1.0: CLABE normalization tests
# ══════════════════════════════════════════════════════════════

class TestClabeNormalization:
    """Tests for CLABE normalization in bank-worker v2.1.0."""

    def test_clabe_with_spaces_normalized(self):
        """CLABE with spaces should be normalized to 18 digits."""
        raw_json = """{
            "bank": {"name": "BBVA"},
            "account": {
                "holder": "PERSONA TEST",
                "clabe": "012 180 028 451 234 567",
                "numberMasked": "XXXX4567"
            },
            "statement": {"periodStart": "2024-01-01", "periodEnd": "2024-01-31"},
            "balances": {"opening": 1000.0, "closing": 1000.0},
            "transactions": []
        }"""
        result = parse_and_normalize(raw_json, "doc-clabe", "2.1.0", "model-xxx")
        assert result["account"]["clabe"] == "012180028451234567"
        assert len(result["account"]["clabe"]) == 18

    def test_clabe_already_clean(self):
        """CLABE already 18 digits should be preserved."""
        raw_json = """{
            "bank": {"name": "Banorte"},
            "account": {
                "holder": "TEST",
                "clabe": "072180012345678901"
            },
            "statement": {},
            "balances": {},
            "transactions": []
        }"""
        result = parse_and_normalize(raw_json, "doc-clabe-clean", "2.1.0", "model-xxx")
        assert result["account"]["clabe"] == "072180012345678901"

    def test_clabe_invalid_fallback_to_masked(self):
        """Invalid CLABE (not 18 digits) should fall back to clabeMasked."""
        raw_json = """{
            "bank": {"name": "HSBC"},
            "account": {
                "holder": "TEST",
                "clabe": "XXXX1234",
                "clabeMasked": null
            },
            "statement": {},
            "balances": {},
            "transactions": []
        }"""
        result = parse_and_normalize(raw_json, "doc-clabe-bad", "2.1.0", "model-xxx")
        assert result["account"].get("clabe") is None
        assert result["account"]["clabeMasked"] == "XXXX1234"

    def test_clabe_invalid_preserves_existing_masked(self):
        """Invalid CLABE should not overwrite existing clabeMasked."""
        raw_json = """{
            "bank": {"name": "Santander"},
            "account": {
                "holder": "TEST",
                "clabe": "SHORT123",
                "clabeMasked": "XXXX5678XXXX"
            },
            "statement": {},
            "balances": {},
            "transactions": []
        }"""
        result = parse_and_normalize(raw_json, "doc-clabe-keep", "2.1.0", "model-xxx")
        assert result["account"].get("clabe") is None
        assert result["account"]["clabeMasked"] == "XXXX5678XXXX"

    def test_account_number_whitespace_stripped(self):
        """Account number should have whitespace stripped."""
        raw_json = """{
            "bank": {"name": "BBVA"},
            "account": {
                "holder": "TEST",
                "number": "1234 5678 9012",
                "numberMasked": "XXXX9012"
            },
            "statement": {},
            "balances": {},
            "transactions": []
        }"""
        result = parse_and_normalize(raw_json, "doc-acct-num", "2.1.0", "model-xxx")
        assert result["account"]["number"] == "123456789012"

    def test_no_clabe_no_changes(self):
        """When no CLABE is present, nothing should change."""
        raw_json = """{
            "bank": {"name": "Banregio"},
            "account": {
                "holder": "TEST",
                "numberMasked": "XXXX5678"
            },
            "statement": {},
            "balances": {},
            "transactions": []
        }"""
        result = parse_and_normalize(raw_json, "doc-no-clabe", "2.1.0", "model-xxx")
        assert result["account"].get("clabe") is None
