import os
import json
import pytest
import jsonschema
import re
import hashlib
from pypdf import PdfReader

FIXTURE_DIR = os.path.join(os.path.dirname(__file__), '../fixtures/bank_statement/v1')
CATALOG_PATH = os.path.join(FIXTURE_DIR, 'catalog.json')
SCHEMA_PATH = os.path.join(os.path.dirname(__file__), '../../schemas/scanalyze-document-journey-result.v1.schema.json')
CATALOG_SCHEMA_PATH = os.path.join(FIXTURE_DIR, 'catalog.schema.json')

def load_catalog():
    with open(CATALOG_PATH, 'r') as f:
        return json.load(f)

def load_schema(path):
    with open(path, 'r') as f:
        return json.load(f)

@pytest.fixture
def catalog():
    return load_catalog()

@pytest.fixture
def catalog_schema():
    return load_schema(CATALOG_SCHEMA_PATH)

@pytest.fixture
def result_schema():
    return load_schema(SCHEMA_PATH)

@pytest.fixture
def positive_fixtures(catalog):
    return [c for c in catalog.get("fixtures", []) if c['positiveOrNegative'] == 'POSITIVE']

@pytest.fixture
def negative_fixtures(catalog):
    return [c for c in catalog.get("fixtures", []) if c['positiveOrNegative'] == 'NEGATIVE']

def test_catalog_schema_valid(catalog, catalog_schema):
    jsonschema.validate(instance=catalog, schema=catalog_schema)

def test_catalog_counts(positive_fixtures, negative_fixtures):
    assert len(positive_fixtures) == 20, "Should have 20 execution instances"
    
    profiles = set(c['profileId'] for c in positive_fixtures)
    assert len(profiles) == 10, "Should have exactly 10 positive profiles"
    
    assert len(negative_fixtures) == 8, "Should have exactly 8 negative controls"

def test_expected_result_schema_valid(positive_fixtures, result_schema):
    for c in positive_fixtures:
        expected_path = os.path.join(FIXTURE_DIR, c['expectedResultPath'])
        with open(expected_path, 'r') as f:
            expected_json = json.load(f)
            jsonschema.validate(instance=expected_json, schema=result_schema)

def test_no_real_data_attestation(catalog):
    for c in catalog.get("fixtures", []):
        assert c['noRealDataAttestation'] is True
        assert c['sensitivity'] == "SYNTHETIC"

def test_pdf_content_matches_ground_truth(positive_fixtures):
    for c in positive_fixtures:
        expected_path = os.path.join(FIXTURE_DIR, c['expectedResultPath'])
        with open(expected_path, 'r') as f:
            expected_json = json.load(f)
        
        pdf_path = os.path.join(FIXTURE_DIR, c['filePath'])
        reader = PdfReader(pdf_path)
        
        # Security/Privacy structure check
        assert not reader.is_encrypted
        # Check no attachments, JS
        
        # Text checks
        full_text = "".join([p.extract_text() for p in reader.pages])
        assert "SYNTHETIC TEST FIXTURE" in full_text
        assert "NOT REAL CUSTOMER DATA" in full_text
        
        data = expected_json.get("data", {})
        bank = data.get("bank")
        if bank and bank.get("name"):
            assert bank["name"] in full_text
            
        account = data.get("account")
        if account:
            if account.get("holder"):
                assert account["holder"] in full_text
            if account.get("numberMasked"):
                assert account["numberMasked"] in full_text
            if account.get("clabeMasked"):
                assert account["clabeMasked"] in full_text
            if account.get("currency"):
                assert account["currency"] in full_text
                
        stmt = data.get("statement")
        if stmt and stmt.get("periodStart"):
            assert stmt["periodStart"] in full_text
            
        bals = data.get("balances")
        if bals and bals.get("opening") is not None:
            assert str(bals["opening"]) in full_text
            
        txs = data.get("transactions", [])
        for tx in txs:
            assert tx["description"] in full_text

        assert c['pageCount'] == len(reader.pages)
        if c['pageCount'] > 1:
            page_1_text = reader.pages[0].extract_text()
            page_2_text = reader.pages[1].extract_text()
            assert page_1_text != page_2_text

def test_exact_sha256_matches(catalog):
    for c in catalog.get("fixtures", []):
        if "expectedResultPath" in c:
            path = os.path.join(FIXTURE_DIR, c['expectedResultPath'])
            with open(path, 'rb') as f:
                actual_sha = hashlib.sha256(f.read()).hexdigest()
            assert actual_sha == c['expectedResultSha256']
            
        if "pdfSha256" in c:
            path = os.path.join(FIXTURE_DIR, c['filePath'])
            with open(path, 'rb') as f:
                actual_sha = hashlib.sha256(f.read()).hexdigest()
            assert actual_sha == c['pdfSha256']
            
        if "sourceSpecSha256" in c:
            path = os.path.join(FIXTURE_DIR, c['sourceSpecPath'])
            with open(path, 'rb') as f:
                actual_sha = hashlib.sha256(f.read()).hexdigest()
            assert actual_sha == c['sourceSpecSha256']

def test_orphan_files(catalog):
    # Ensure no unregistered files in expected/ pdf/ controls/ profiles/
    registered_files = set([os.path.normpath(CATALOG_PATH), os.path.normpath(CATALOG_SCHEMA_PATH), os.path.normpath(os.path.join(FIXTURE_DIR, "README.md"))])
    for c in catalog.get("fixtures", []):
        if "filePath" in c:
            registered_files.add(os.path.normpath(os.path.join(FIXTURE_DIR, c['filePath'])))
        if "expectedResultPath" in c:
            registered_files.add(os.path.normpath(os.path.join(FIXTURE_DIR, c['expectedResultPath'])))
        if "sourceSpecPath" in c:
            registered_files.add(os.path.normpath(os.path.join(FIXTURE_DIR, c['sourceSpecPath'])))
            
    actual_files = set()
    for root, dirs, files in os.walk(FIXTURE_DIR):
        for f in files:
            # Skip python/pycache in the fixtures folder if any
            if f.endswith('.py') or f.endswith('.pyc') or f == ".DS_Store":
                continue
            actual_files.add(os.path.normpath(os.path.join(root, f)))
            
    orphans = actual_files - registered_files
    assert len(orphans) == 0, f"Orphan files found: {orphans}"

def test_negative_controls_are_executable(negative_fixtures):
    for c in negative_fixtures:
        path = os.path.join(FIXTURE_DIR, c['filePath'])
        with open(path, 'r') as f:
            spec = json.load(f)
        assert "expectedHttpStatus" in spec.get("control", {})
        
def test_no_pii_in_pdfs(positive_fixtures):
    forbidden_patterns = [
        re.compile(b"[0-9]{4}-[0-9]{4}-[0-9]{4}-[0-9]{4}"),
        re.compile(b"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}")
    ]
    
    for c in positive_fixtures:
        pdf_path = os.path.join(FIXTURE_DIR, c['filePath'])
        with open(pdf_path, 'rb') as f:
            content = f.read()
            for pattern in forbidden_patterns:
                assert not pattern.search(content), f"PII sentinel found in {pdf_path}"

def test_pdf_size_limits(positive_fixtures):
    for c in positive_fixtures:
        pdf_path = os.path.join(FIXTURE_DIR, c['filePath'])
        size = os.path.getsize(pdf_path)
        assert size < 5 * 1024 * 1024, f"PDF {pdf_path} exceeds 5MiB limit"
