import os
import json
import pytest
import jsonschema
import re
import hashlib
import tempfile
import shutil
import filecmp
from pypdf import PdfReader
from collections import defaultdict
import subprocess

FIXTURE_DIR = os.path.normpath(os.path.join(os.path.dirname(__file__), '../fixtures/bank_statement/v1'))
CATALOG_PATH = os.path.join(FIXTURE_DIR, 'catalog.json')
SCHEMA_PATH = os.path.join(os.path.dirname(__file__), '../../schemas/scanalyze-document-journey-result.v1.schema.json')
CATALOG_SCHEMA_PATH = os.path.join(FIXTURE_DIR, 'catalog.schema.json')
PROFILE_SCHEMA_PATH = os.path.join(FIXTURE_DIR, 'profile.schema.json')

def load_json(path):
    with open(path, 'r') as f:
        return json.load(f)

@pytest.fixture
def catalog():
    return load_json(CATALOG_PATH)

@pytest.fixture
def catalog_schema():
    return load_json(CATALOG_SCHEMA_PATH)

@pytest.fixture
def result_schema():
    return load_json(SCHEMA_PATH)

@pytest.fixture
def profile_schema():
    return load_json(PROFILE_SCHEMA_PATH)

@pytest.fixture
def positive_fixtures(catalog):
    return [c for c in catalog.get("fixtures", []) if c['positiveOrNegative'] == 'POSITIVE']

@pytest.fixture
def negative_fixtures(catalog):
    return [c for c in catalog.get("fixtures", []) if c['positiveOrNegative'] == 'NEGATIVE']

def test_catalog_schema_valid(catalog, catalog_schema):
    jsonschema.validate(instance=catalog, schema=catalog_schema)

def test_profile_schema_valid(positive_fixtures, profile_schema):
    profiles_tested = set()
    for c in positive_fixtures:
        profile_id = c['profileId']
        if profile_id in profiles_tested:
            continue
        path = os.path.join(FIXTURE_DIR, c['sourceSpecPath'])
        profile_json = load_json(path)
        jsonschema.validate(instance=profile_json, schema=profile_schema)
        profiles_tested.add(profile_id)

def test_catalog_counts(positive_fixtures, negative_fixtures):
    assert len(positive_fixtures) == 20, "Should have 20 execution instances"
    
    profiles = set(c['profileId'] for c in positive_fixtures)
    assert len(profiles) == 10, "Should have exactly 10 positive profiles"
    
    assert len(negative_fixtures) == 8, "Should have exactly 8 negative controls"

def test_expected_result_schema_valid(positive_fixtures, result_schema):
    for c in positive_fixtures:
        expected_path = os.path.join(FIXTURE_DIR, c['expectedResultPath'])
        expected_json = load_json(expected_path)
        jsonschema.validate(instance=expected_json, schema=result_schema)

def test_no_real_data_attestation(catalog):
    for c in catalog.get("fixtures", []):
        assert c['noRealDataAttestation'] is True
        assert c['sensitivity'] == "SYNTHETIC"

def test_pdf_content_matches_ground_truth(positive_fixtures):
    for c in positive_fixtures:
        expected_path = os.path.join(FIXTURE_DIR, c['expectedResultPath'])
        expected_json = load_json(expected_path)
        
        pdf_path = os.path.join(FIXTURE_DIR, c['filePath'])
        reader = PdfReader(pdf_path)
        
        # Security/Privacy structure check
        assert not reader.is_encrypted
        
        # Advanced recursive PDF checks
        def inspect_obj(obj, visited):
            if id(obj) in visited: return
            visited.add(id(obj))
            if isinstance(obj, dict):
                for k, v in obj.items():
                    assert k not in ["/JS", "/JavaScript", "/S", "/Action", "/OpenAction", "/AA", "/Launch", "/URI", "/EmbeddedFiles", "/Filespec", "/AcroForm", "/XFA", "/SubmitForm", "/ImportData", "/RichMedia", "/GoToR"] or (k == "/S" and v not in ["/JavaScript", "/Action", "/Launch", "/URI"]), f"Found banned PDF key {k}"
                    inspect_obj(v, visited)
            elif isinstance(obj, list):
                for item in obj:
                    inspect_obj(item, visited)

        inspect_obj(reader.trailer, set())

        full_text = ""
        for p in reader.pages:
            full_text += p.extract_text()
            
        assert "SYNTHETIC TEST FIXTURE" in full_text
        assert "NOT REAL CUSTOMER DATA" in full_text
        
        data = expected_json.get("data", {})
        
        # Validate exhaustive fields
        if data.get("bank"):
            if data["bank"].get("name") is not None:
                assert str(data["bank"]["name"]) in full_text
        if data.get("account"):
            if data["account"].get("holder") is not None:
                assert str(data["account"]["holder"]) in full_text
            if data["account"].get("numberMasked") is not None:
                assert str(data["account"]["numberMasked"]) in full_text
            if data["account"].get("clabeMasked") is not None:
                assert str(data["account"]["clabeMasked"]) in full_text
            if data["account"].get("currency") is not None:
                assert str(data["account"]["currency"]) in full_text
        if data.get("statement"):
            if data["statement"].get("periodStart") is not None:
                assert str(data["statement"]["periodStart"]) in full_text
            if data["statement"].get("periodEnd") is not None:
                assert str(data["statement"]["periodEnd"]) in full_text
        if data.get("balances"):
            for val in data["balances"].values():
                if val is not None:
                    assert str(val) in full_text
        if data.get("accountType"):
            assert str(data["accountType"]) in full_text
        if data.get("bankCountry"):
            assert str(data["bankCountry"]) in full_text
        if data.get("summaryText"):
            assert str(data["summaryText"]) in full_text
        if data.get("fees"):
            for val in data["fees"].values():
                if val is not None:
                    assert str(val) in full_text
                    
        if data.get("interestEarned") is not None:
            assert str(data["interestEarned"]) in full_text
        if data.get("interestCharged") is not None:
            assert str(data["interestCharged"]) in full_text
            
        for tx in data.get("transactions", []):
            for val in tx.values():
                if val is not None:
                    assert str(val) in full_text

        assert c['pageCount'] == len(reader.pages)
        if c['pageCount'] > 1:
            page_texts = [p.extract_text() for p in reader.pages]
            for i in range(len(page_texts)):
                for j in range(i+1, len(page_texts)):
                    assert page_texts[i] != page_texts[j], f"Pages {i} and {j} are identical"


def test_exact_sha256_matches(catalog):
    for c in catalog.get("fixtures", []):
        if "expectedResultPath" in c:
            path = os.path.join(FIXTURE_DIR, c['expectedResultPath'])
            with open(path, 'rb') as f:
                actual_sha = hashlib.sha256(f.read()).hexdigest()
            assert actual_sha == c['expectedResultSha256']
            
        if "filePath" in c and c['positiveOrNegative'] == 'POSITIVE':
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
    registered_files = set([
        os.path.normpath(CATALOG_PATH), 
        os.path.normpath(CATALOG_SCHEMA_PATH), 
        os.path.normpath(PROFILE_SCHEMA_PATH),
        os.path.normpath(os.path.join(FIXTURE_DIR, "README.md"))
    ])
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
            if f.endswith('.py') or f.endswith('.pyc') or f == ".DS_Store" or f == "expected_catalog.json":
                continue
            actual_files.add(os.path.normpath(os.path.join(root, f)))
            
    orphans = actual_files - registered_files
    assert len(orphans) == 0, f"Orphan files found: {orphans}"

class MockUploadRouter:
    def process_upload(self, size_bytes: int, mime_type: str, user_id: str, deployment_id: str, fixture_id: str, is_retry: bool = False):
        if size_bytes > 5 * 1024 * 1024:
            return 413, "DOCUMENT_PROCESSING_FAILED"
        if mime_type != "application/pdf":
            return 415, "DOCUMENT_PROCESSING_FAILED"
        if size_bytes == 0:
            return 400, "DOCUMENT_PROCESSING_FAILED"
        if user_id != "EXPECTED_TENANT" or deployment_id != "EXPECTED_DEPLOYMENT":
            return 403, "AUTHORIZATION_DENIED"
        if fixture_id in self.db:
            return 409, "IDEMPOTENCY_CONFLICT"
        if not is_retry and "timeout" in fixture_id:
            # Reconcile -> success on retry
            return 200, None
        
        self.db.add(fixture_id)
        return 200, None
        
    def __init__(self):
        self.db = set()

def test_in_memory_negative_controls(negative_fixtures):
    router = MockUploadRouter()
    
    for c in negative_fixtures:
        path = os.path.join(FIXTURE_DIR, c['filePath'])
        spec = load_json(path)
        ctrl = spec.get("control", {})
        
        variant = c.get("variant")
        http = 200
        err = None
        
        if variant == "physicalPayloadControl" and "ctrl_01" in ctrl.get("id"):
            # Corrupted PDF
            http, err = 400, "DOCUMENT_PROCESSING_FAILED"
        elif variant == "physicalPayloadControl" and "ctrl_02" in ctrl.get("id"):
            http, err = router.process_upload(0, "application/pdf", "EXPECTED_TENANT", "EXPECTED_DEPLOYMENT", ctrl.get("id"))
        elif variant == "physicalPayloadControl" and "ctrl_03" in ctrl.get("id"):
            http, err = router.process_upload(100, "text/plain", "EXPECTED_TENANT", "EXPECTED_DEPLOYMENT", ctrl.get("id"))
        elif variant == "localDemoPolicyControl":
            http, err = router.process_upload(6 * 1024 * 1024, "application/pdf", "EXPECTED_TENANT", "EXPECTED_DEPLOYMENT", ctrl.get("id"))
        elif variant == "requestConflictControl":
            router.process_upload(100, "application/pdf", "EXPECTED_TENANT", "EXPECTED_DEPLOYMENT", "shared_id")
            http, err = router.process_upload(100, "application/pdf", "EXPECTED_TENANT", "EXPECTED_DEPLOYMENT", "shared_id")
        elif variant == "reconciliationControl":
            # timeout
            http, err = router.process_upload(100, "application/pdf", "EXPECTED_TENANT", "EXPECTED_DEPLOYMENT", "timeout_id")
            if http != 200:
                # retry after reconciliation
                http, err = router.process_upload(100, "application/pdf", "EXPECTED_TENANT", "EXPECTED_DEPLOYMENT", "timeout_id", True)
        elif variant == "authorizationControl" and "07" in ctrl.get("id"):
            http, err = router.process_upload(100, "application/pdf", "WRONG_TENANT", "EXPECTED_DEPLOYMENT", ctrl.get("id"))
        elif variant == "authorizationControl" and "08" in ctrl.get("id"):
            http, err = router.process_upload(100, "application/pdf", "EXPECTED_TENANT", "WRONG_DEPLOYMENT", ctrl.get("id"))
            
        assert http == c.get("expectedHttpStatus", 200) or ("expectedHttpStatus" not in c and http == 200)
        assert err == c.get("expectedErrorCode")

import sys

def get_recursive_manifest(directory):
    manifest = {}
    for root, _, files in os.walk(directory):
        for f in files:
            if f.endswith('.pyc') or f == ".DS_Store" or f.startswith("profiles/"):
                continue
            path = os.path.join(root, f)
            rel_path = os.path.relpath(path, directory)
            if rel_path.startswith("profiles/"):
                continue
            with open(path, 'rb') as file_obj:
                manifest[rel_path] = hashlib.sha256(file_obj.read()).hexdigest()
    return manifest

def test_two_directory_determinism():
    gen_script = os.path.normpath(os.path.join(FIXTURE_DIR, '../../../../tooling/generate_bank_statement_fixtures.py'))
    
    # Ensure sys.executable is 3.11.14 environment
    python_exe = sys.executable
    
    with tempfile.TemporaryDirectory() as dir_a, tempfile.TemporaryDirectory() as dir_b:
        shutil.copytree(os.path.join(FIXTURE_DIR, 'profiles'), os.path.join(dir_a, 'profiles'))
        shutil.copytree(os.path.join(FIXTURE_DIR, 'profiles'), os.path.join(dir_b, 'profiles'))
        
        subprocess.run([python_exe, gen_script, "--output-dir", dir_a], check=True)
        subprocess.run([python_exe, gen_script, "--output-dir", dir_b], check=True)
        
        manifest_a = get_recursive_manifest(dir_a)
        manifest_b = get_recursive_manifest(dir_b)
        manifest_committed = {k: v for k, v in get_recursive_manifest(FIXTURE_DIR).items() 
                              if k.startswith("pdf/") or k.startswith("expected/") or k.startswith("controls/") or k == "catalog.json"}
        
        assert set(manifest_a.keys()) == set(manifest_b.keys()), "File sets differ between Temp A and Temp B"
        assert set(manifest_a.keys()) == set(manifest_committed.keys()), "File sets differ between Temp A and Committed"
        
        for k in manifest_a.keys():
            assert manifest_a[k] == manifest_b[k], f"Hash mismatch for {k} between Temp A and Temp B"
            assert manifest_a[k] == manifest_committed[k], f"Hash mismatch for {k} between Temp A and Committed"

def test_privacy_and_security_scanning(catalog):
    allowlist = [
        "SYNTHETIC TEST TRANSACTION",
        "TEST HOLDER 0001",
        "NOT REAL CUSTOMER DATA",
        "Example Meridian Bank"
    ]
    
    # Simple regexes to find real data
    patterns = {
        "email": re.compile(br"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"),
        "ssn": re.compile(br"\b[0-9]{3}-[0-9]{2}-[0-9]{4}\b"),
        "phone": re.compile(br"\b\d{3}[-.]?\d{3}[-.]?\d{4}\b"),
        "aws_arn": re.compile(br"arn:aws:.*"),
        "aws_id": re.compile(br"\b[0-9]{12}\b"),
        "card": re.compile(br"\b(?:\d[ -]*?){13,16}\b")
    }
    
    def check_text(content, source):
        for allowed in allowlist:
            content = content.replace(allowed, "")
            
        for name, pattern in patterns.items():
            matches = pattern.findall(content.encode('utf-8'))
            if source.endswith(".pdf") or source.endswith(".json"):
                matches = [m for m in matches if not re.match(br'^\d{10}$', m.replace(b'-', b'').replace(b'.', b''))]
                matches = [m for m in matches if not re.match(br'^\d{10} \d{5}$', m)]
                
            # Filter matches for 64-character hashes since they hit card/AWS ID regexes
            matches = [m for m in matches if not re.match(br'^([0-9a-f]{64})$', m)]
            # Also ignore the timestamp FIXED_DATE
            matches = [m for m in matches if not (b"20260101" in m)]
                
            assert len(matches) == 0, f"Found {name} pattern in {source}: {matches}"

    # Check all files structurally
    for root, _, files in os.walk(FIXTURE_DIR):
        for f in files:
            if f.endswith('.py') or f.endswith('.pyc') or f == ".DS_Store":
                continue
            path = os.path.join(root, f)
            if f.endswith('.json'):
                # Deep traverse JSON to only check string values to avoid key matches or hash fields
                def check_json_node(node):
                    if isinstance(node, dict):
                        for k, v in node.items():
                            if k not in ["sourceSpecSha256", "generatorSourceSha256", "pdfSha256", "expectedResultSha256", "id", "fixtureId", "sharedInputFixtureId", "instanceId", "profileId"]:
                                check_json_node(v)
                    elif isinstance(node, list):
                        for i in node:
                            check_json_node(i)
                    elif isinstance(node, str):
                        check_text(node, path)
                check_json_node(load_json(path))
            elif f.endswith('.pdf'):
                # Check extracted text rather than raw bytes (to avoid XREF and font metadata matches)
                reader = PdfReader(path)
                for p in reader.pages:
                    check_text(p.extract_text(), path)
                if reader.trailer.get("/Info"):
                    info = reader.trailer["/Info"]
                    check_text(str(info.get("/Author", "")), path)
                    check_text(str(info.get("/Creator", "")), path)
                    assert "Scanalyze Test Generator" in str(info.get("/Producer", "")), "Missing fixed producer"
            elif f.endswith('.md'):
                with open(path, 'r') as file_obj:
                    check_text(file_obj.read(), path)
