import os
import json
import pytest
import jsonschema
import re

FIXTURE_DIR = os.path.join(os.path.dirname(__file__), '../fixtures/bank_statement/v1')
CATALOG_PATH = os.path.join(FIXTURE_DIR, 'catalog.json')
SCHEMA_PATH = os.path.join(os.path.dirname(__file__), '../../schemas/scanalyze-document-journey-result.v1.schema.json')

def load_catalog():
    with open(CATALOG_PATH, 'r') as f:
        return json.load(f)

def load_schema():
    with open(SCHEMA_PATH, 'r') as f:
        return json.load(f)

def test_catalog_counts():
    catalog = load_catalog()
    positives = [c for c in catalog if c['positiveOrNegative'] == 'positive']
    negatives = [c for c in catalog if c['positiveOrNegative'] == 'negative']
    
    assert len(positives) == 20, "Should have 20 execution instances"
    
    profiles = set(c['profileId'] for c in positives)
    assert len(profiles) == 10, "Should have exactly 10 positive profiles"
    
    assert len(negatives) == 8, "Should have exactly 8 negative controls"

def test_expected_result_schema_valid():
    catalog = load_catalog()
    schema = load_schema()
    positives = [c for c in catalog if c['positiveOrNegative'] == 'positive']
    
    for c in positives:
        expected_path = os.path.join(FIXTURE_DIR, c['expectedResultPath'])
        with open(expected_path, 'r') as f:
            expected_json = json.load(f)
            jsonschema.validate(instance=expected_json, schema=schema)

def test_no_real_data_attestation():
    catalog = load_catalog()
    for c in catalog:
        assert c['noRealDataAttestation'] is True
        assert c['sensitivity'] == "SYNTHETIC"

def test_no_pii_in_pdfs():
    catalog = load_catalog()
    positives = [c for c in catalog if c['positiveOrNegative'] == 'positive']
    
    # Just checking the raw bytes for obviously forbidden things like real card numbers or emails.
    # Our synthetic generation logic uses strictly fixed synthetic data.
    # This acts as a PII sentinel check.
    
    forbidden_patterns = [
        re.compile(b"[0-9]{4}-[0-9]{4}-[0-9]{4}-[0-9]{4}"),
        re.compile(b"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}")
    ]
    
    for c in positives:
        pdf_path = os.path.join(FIXTURE_DIR, c['filePath'])
        with open(pdf_path, 'rb') as f:
            content = f.read()
            for pattern in forbidden_patterns:
                assert not pattern.search(content), f"PII sentinel found in {pdf_path}"

def test_pdf_size_limits():
    catalog = load_catalog()
    positives = [c for c in catalog if c['positiveOrNegative'] == 'positive']
    for c in positives:
        pdf_path = os.path.join(FIXTURE_DIR, c['filePath'])
        size = os.path.getsize(pdf_path)
        assert size < 5 * 1024 * 1024, f"PDF {pdf_path} exceeds 5MiB limit"
