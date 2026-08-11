import os
import json

def create_profiles(out_dir):
    os.makedirs(out_dir, exist_ok=True)
    profiles = [
        {"id": "01", "name": "Single-page happy path", "pages": 1, "warnings": [], "quality": {"overallConfidence": 98.0}},
        {"id": "02", "name": "Multi-page statement", "pages": 3, "warnings": [], "quality": {"overallConfidence": 95.0}},
        {"id": "03", "name": "Multiple transactions", "pages": 1, "warnings": [], "quality": {"overallConfidence": 95.0}, "transactions": 10},
        {"id": "04", "name": "Nullable and optional fields", "pages": 1, "warnings": [], "quality": {"overallConfidence": 92.0}, "nulls": True},
        {"id": "05", "name": "Zero-transaction statement", "pages": 1, "warnings": [], "quality": {"overallConfidence": 99.0}, "transactions": 0},
        {"id": "06", "name": "Fees and interest", "pages": 1, "warnings": [], "quality": {"overallConfidence": 97.0}, "fees": True},
        {"id": "07", "name": "Warning-producing result", "pages": 1, "warnings": [{"code": "INCOMPLETE_EXTRACTION"}], "quality": {"overallConfidence": 98.0}},
        {"id": "08", "name": "Low-confidence or incomplete extraction", "pages": 1, "warnings": [{"code": "LOW_CONFIDENCE"}], "quality": {"overallConfidence": 65.0}},
        {"id": "09", "name": "Balance-reconciliation warning", "pages": 1, "warnings": [{"code": "BALANCE_RECONCILIATION_WARNING"}], "quality": {"overallConfidence": 99.0}, "reconciliation_failure": True},
        {"id": "10", "name": "Period/currency/repeatability profile", "pages": 1, "warnings": [], "quality": {"overallConfidence": 99.0}, "currency": "USD"}
    ]
    for p in profiles:
        with open(os.path.join(out_dir, f"profile_{p['id']}.json"), 'w') as f:
            json.dump(p, f, indent=2)

create_profiles('/Users/cesarguzmanguadarrama/Developer/scanalyze-gug-364-synthetic-bank-statement-fixture-corpus/tests/fixtures/bank_statement/v1/profiles')
