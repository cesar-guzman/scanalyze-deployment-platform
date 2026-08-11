import os
import json
import hashlib
import datetime
import argparse

# Deterministic fixed date for provenance and generation
FIXED_DATE = "2026-01-01T00:00:00Z"
PRODUCER_VERSION = "1.0"
GENERATOR_VERSION = "v1"

def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def _deterministic_pdf_bytes(text: str, pages: int = 1) -> bytes:
    objects = []
    
    def create_obj(num, content):
        return f"{num} 0 obj\n{content}\nendobj\n"
    
    pdf_content = b"%PDF-1.4\n%\xE2\xE3\xCF\xD3\n"
    
    page_kids = " ".join([f"{3 + i*2} 0 R" for i in range(pages)])
    
    objects.append(create_obj(1, "<< /Type /Catalog /Pages 2 0 R >>"))
    objects.append(create_obj(2, f"<< /Type /Pages /Kids [ {page_kids} ] /Count {pages} >>"))
    
    current_obj = 3
    for p in range(pages):
        content_obj = current_obj + 1
        objects.append(create_obj(current_obj, f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents {content_obj} 0 R /Resources << /Font << /F1 {3 + pages*2} 0 R >> >> >>"))
        
        text_lines = text.split("\n")
        pdf_text = f"BT\n/F1 12 Tf\n100 700 Td\n"
        for i, line in enumerate(text_lines):
            pdf_text += f"({line}) Tj\n"
            if i < len(text_lines) - 1:
                pdf_text += "0 -15 Td\n"
        pdf_text += "ET"
        
        objects.append(create_obj(content_obj, f"<< /Length {len(pdf_text)} >>\nstream\n{pdf_text}\nendstream"))
        current_obj += 2
        
    objects.append(create_obj(current_obj, "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>"))
    
    info_dict = f"<< /Producer (Scanalyze Test Generator) /CreationDate (D:20260101000000Z) /ModDate (D:20260101000000Z) >>"
    info_obj_num = current_obj + 1
    objects.append(create_obj(info_obj_num, info_dict))
    
    offsets = []
    offset = len(pdf_content)
    
    for obj in objects:
        offsets.append(offset)
        pdf_content += obj.encode('ascii')
        offset += len(obj)
        
    xref_offset = offset
    pdf_content += b"xref\n0 " + str(len(objects) + 1).encode('ascii') + b"\n"
    pdf_content += b"0000000000 65535 f \n"
    for o in offsets:
        pdf_content += f"{o:010d} 00000 n \n".encode('ascii')
        
    pdf_content += b"trailer\n<< /Size " + str(len(objects) + 1).encode('ascii') + b" /Root 1 0 R /Info " + str(info_obj_num).encode('ascii') + b" 0 R >>\n"
    pdf_content += b"startxref\n" + str(xref_offset).encode('ascii') + b"\n%%EOF\n"
    
    return pdf_content

def build_expected_result(doc_id: str, profile: dict, pdf_bytes: bytes) -> dict:
    num_tx = profile.get("transactions", 1 if not profile.get("nulls") and not profile.get("transactions") == 0 else 0)
    if profile.get("nulls"):
        num_tx = 0
        
    txs = []
    credits = 0.0
    debits = 0.0
    for i in range(num_tx):
        amt = 100.0 * (i + 1)
        direction = "credit" if i % 2 == 0 else "debit"
        if direction == "credit":
            credits += amt
        else:
            debits += amt
        txs.append({
            "date": "2026-01-01",
            "description": f"SYNTHETIC TEST TRANSACTION {i+1:03d}",
            "reference": f"REF{i+1:03d}",
            "direction": direction,
            "amount": amt,
            "balanceAfter": 1000.0 + credits - debits,
            "category": "otro"
        })

    opening = 1000.0
    closing = opening + credits - debits
    
    if profile.get("reconciliation_failure"):
        closing = 99999.99

    bank_name = "Example Meridian Bank"
    holder = "TEST HOLDER 0001"
    account_mask = "****0001"
    clabe_mask = "****0001"
    currency = profile.get("currency", "MXN")
    
    if profile.get("nulls"):
        bank_name = None
        holder = None
        account_mask = None
        clabe_mask = None
        currency = None
        opening = None
        closing = None
        credits = None
        debits = None
        
    data = {
        "bank": {"name": bank_name},
        "account": {
            "holder": holder,
            "numberMasked": account_mask,
            "clabeMasked": clabe_mask,
            "currency": currency
        },
        "statement": {
            "periodStart": "2025-12-01" if not profile.get("nulls") else None,
            "periodEnd": "2025-12-31" if not profile.get("nulls") else None
        },
        "balances": {
            "opening": opening,
            "closing": closing,
            "totalCredits": credits,
            "totalDebits": debits
        },
        "transactions": txs,
        "accountType": None if profile.get("nulls") else "cheques",
        "bankCountry": None if profile.get("nulls") else "MX",
        "fees": {"totalFees": 50.0, "ivaOnFees": 8.0} if profile.get("fees") else None,
        "interestEarned": 10.0 if profile.get("fees") else (None if profile.get("nulls") else 0.0),
        "interestCharged": 0.0 if not profile.get("nulls") else None,
        "summaryText": "SYNTHETIC FIXTURE DATA" if not profile.get("nulls") else None
    }
    
    return {
        "schemaVersion": "scanalyze.document-result.v1",
        "contractVersion": "scanalyze.document-journey.v1",
        "documentType": "bank_statement",
        "resultType": "bank_statement",
        "documentId": doc_id,
        "resultId": f"result_{doc_id}_v1",
        "resultVersion": "1.0",
        "provenance": {
            "processor": "bank-extract",
            "producerSchemaVersion": "1.0",
            "promptVersion": "1.0.0",
            "generatedAt": FIXED_DATE
        },
        "data": data,
        "warnings": profile.get("warnings", []),
        "quality": profile.get("quality", {"overallConfidence": 98.0})
    }

def generate_fixtures(base_dir: str, check_only: bool = False):
    profiles_dir = os.path.join(base_dir, 'profiles')
    pdf_dir = os.path.join(base_dir, 'pdf')
    expected_dir = os.path.join(base_dir, 'expected')
    controls_dir = os.path.join(base_dir, 'controls')
    
    for d in [pdf_dir, expected_dir, controls_dir]:
        os.makedirs(d, exist_ok=True)
        
    catalog = []
    
    profiles = sorted([f for f in os.listdir(profiles_dir) if f.endswith('.json')])
    
    # Process positive profiles (10 profiles * 2 instances)
    for profile_file in profiles:
        with open(os.path.join(profiles_dir, profile_file), 'r') as f:
            profile_bytes = f.read().encode('utf-8')
            profile = json.loads(profile_bytes)
            
        for instance in [1, 2]:
            fixture_id = f"gug364_bank_statement_{profile['id']}_{instance:02d}"
            # deterministic documentId
            doc_id = hashlib.md5(fixture_id.encode()).hexdigest()
            
            pages = profile.get("pages", 1)
            text = f"SYNTHETIC TEST FIXTURE\nNOT REAL CUSTOMER DATA\nPROFILE: {profile['name']}\nINSTANCE: {instance}\nDOC_ID: {doc_id}"
            pdf_bytes = _deterministic_pdf_bytes(text, pages=pages)
            
            pdf_name = f"{fixture_id}.pdf"
            pdf_path = os.path.join(pdf_dir, pdf_name)
            
            expected_res = build_expected_result(doc_id, profile, pdf_bytes)
            expected_name = f"{fixture_id}_expected.json"
            expected_path = os.path.join(expected_dir, expected_name)
            
            # Catalog Entry
            entry = {
                "schemaVersion": "scanalyze.fixture-catalog.v1",
                "fixtureId": fixture_id,
                "fixtureVersion": "1.0",
                "profileId": profile['id'],
                "instanceId": f"{instance:02d}",
                "scenarioType": profile['name'],
                "positiveOrNegative": "positive",
                "filePath": f"pdf/{pdf_name}",
                "mimeType": "application/pdf",
                "sensitivity": "SYNTHETIC",
                "sourceSpecPath": f"profiles/{profile_file}",
                "sourceSpecSha256": sha256(profile_bytes),
                "generatorPath": "tooling/generate_bank_statement_fixtures.py",
                "generatorVersion": GENERATOR_VERSION,
                "pdfSha256": sha256(pdf_bytes),
                "expectedResultPath": f"expected/{expected_name}",
                "expectedResultSha256": sha256(json.dumps(expected_res, sort_keys=True).encode()),
                "byteSize": len(pdf_bytes),
                "pageCount": pages,
                "expectedLifecycle": "COMPLETE",
                "expectedTerminalState": "EXTRACTED",
                "acceptedDocumentDenominator": True,
                "manualReviewChecklist": ["Verify synthetic banner", "Verify transaction counts"],
                "retentionClass": "30_days",
                "noRealDataAttestation": True,
                "tags": ["positive", "synthetic", "bank_statement"]
            }
            catalog.append(entry)
            
            if not check_only:
                with open(pdf_path, 'wb') as f:
                    f.write(pdf_bytes)
                with open(expected_path, 'w') as f:
                    json.dump(expected_res, f, indent=2, sort_keys=True)
            else:
                with open(pdf_path, 'rb') as f:
                    if f.read() != pdf_bytes:
                        raise ValueError(f"Mismatch in {pdf_name}")
                with open(expected_path, 'r') as f:
                    if json.dumps(json.load(f), sort_keys=True) != json.dumps(expected_res, sort_keys=True):
                        raise ValueError(f"Mismatch in {expected_name}")
                        
    # Process negative controls
    controls = [
        {"id": "ctrl_01", "name": "Malformed PDF", "setup": "Upload corrupted PDF bytes", "mimeType": "application/pdf", "error": "MALFORMED_DOCUMENT"},
        {"id": "ctrl_02", "name": "Blank or low-text PDF", "setup": "Upload empty PDF", "mimeType": "application/pdf", "error": "LOW_TEXT_QUALITY"},
        {"id": "ctrl_03", "name": "Unsupported MIME", "setup": "Upload text/plain file", "mimeType": "text/plain", "error": "UNSUPPORTED_MIME_TYPE"},
        {"id": "ctrl_04", "name": "Oversized-file boundary", "setup": "Generate >5MiB file at runtime", "mimeType": "application/pdf", "error": "FILE_TOO_LARGE"},
        {"id": "ctrl_05", "name": "Idempotency conflict", "setup": "Upload diff doc with same key", "mimeType": "application/pdf", "error": "IDEMPOTENCY_CONFLICT"},
        {"id": "ctrl_06", "name": "Response-loss reconciliation", "setup": "Retry after timeout", "mimeType": "application/pdf", "error": "NONE"},
        {"id": "ctrl_07", "name": "Wrong-user access", "setup": "Cross-tenant access", "mimeType": "application/pdf", "error": "ACCESS_DENIED"},
        {"id": "ctrl_08", "name": "Wrong-deployment access", "setup": "Cross-deployment access", "mimeType": "application/pdf", "error": "ACCESS_DENIED"}
    ]
    
    for c in controls:
        ctrl_fixture_id = f"gug364_bank_statement_{c['id']}"
        ctrl_path = os.path.join(controls_dir, f"{ctrl_fixture_id}.json")
        entry = {
            "schemaVersion": "scanalyze.fixture-catalog.v1",
            "fixtureId": ctrl_fixture_id,
            "fixtureVersion": "1.0",
            "profileId": c['id'],
            "instanceId": "01",
            "scenarioType": c['name'],
            "positiveOrNegative": "negative",
            "filePath": f"controls/{ctrl_fixture_id}.json",
            "mimeType": "application/json", # The control spec itself is json
            "sensitivity": "SYNTHETIC",
            "sourceSpecPath": f"controls/{ctrl_fixture_id}.json",
            "sourceSpecSha256": "", # Calculated later
            "generatorPath": "tooling/generate_bank_statement_fixtures.py",
            "generatorVersion": GENERATOR_VERSION,
            "expectedErrorCode": c['error'],
            "acceptedDocumentDenominator": False,
            "manualReviewChecklist": [],
            "retentionClass": "30_days",
            "noRealDataAttestation": True,
            "tags": ["negative", "synthetic", "control"]
        }
        
        c_spec = {"control": c, "instruction": "Test runner parses this JSON to execute negative control."}
        c_bytes = json.dumps(c_spec, indent=2).encode()
        entry['sourceSpecSha256'] = sha256(c_bytes)
        
        catalog.append(entry)
        
        if not check_only:
            with open(ctrl_path, 'wb') as f:
                f.write(c_bytes)
        else:
            with open(ctrl_path, 'rb') as f:
                if f.read() != c_bytes:
                    raise ValueError(f"Mismatch in {ctrl_fixture_id}")

    catalog_path = os.path.join(base_dir, 'catalog.json')
    if not check_only:
        with open(catalog_path, 'w') as f:
            json.dump(catalog, f, indent=2)
    else:
        with open(catalog_path, 'r') as f:
            if json.dumps(json.load(f), indent=2) != json.dumps(catalog, indent=2):
                raise ValueError("Catalog mismatch")

    print(f"Generated {len(catalog)} catalog entries successfully.")

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    
    base = os.path.join(os.path.dirname(__file__), '../tests/fixtures/bank_statement/v1')
    try:
        generate_fixtures(base, check_only=args.check)
        if args.check:
            print("Check passed. No drift detected.")
    except Exception as e:
        if args.check:
            print(f"Check failed: {e}")
            exit(1)
        else:
            raise
