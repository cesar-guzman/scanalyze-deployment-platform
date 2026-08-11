import os
import json
import hashlib
import datetime
import argparse
import copy
from typing import Dict, Any, List

# Deterministic fixed date for provenance and generation
FIXED_DATE = "2026-01-01T00:00:00Z"
PRODUCER_VERSION = "1.0"
GENERATOR_VERSION = "v2"

def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def _deterministic_pdf_bytes(text: str, pages: int = 1, page_contents: List[str] = None) -> bytes:
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
        
        # Determine text for this page
        if page_contents:
            current_text = page_contents[p]
        else:
            current_text = text

        text_lines = current_text.split("\n")
        pdf_text = f"BT\n/F1 12 Tf\n100 700 Td\n"
        for i, line in enumerate(text_lines):
            # Escape PDF text
            safe_line = line.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")
            pdf_text += f"({safe_line}) Tj\n"
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

def build_profile_10_variations(instance: int) -> dict:
    # Instance 1: normal period, MXN
    # Instance 2: different period, USD
    if instance == 1:
        return {"periodStart": "2026-01-01", "periodEnd": "2026-01-31", "currency": "MXN"}
    else:
        return {"periodStart": "2026-02-01", "periodEnd": "2026-02-28", "currency": "USD"}

def build_expected_result(doc_id: str, profile: dict, instance: int) -> dict:
    # Build exact ground truth from profile
    is_nulls = profile.get("nulls", False)
    has_fees = profile.get("fees", False)
    is_recon_failure = profile.get("reconciliation_failure", False)
    
    bank_name = "Example Meridian Bank" if not is_nulls else None
    holder = "TEST HOLDER 0001" if not is_nulls else None
    account_mask = "****0001" if not is_nulls else None
    clabe_mask = "****0001" if not is_nulls else None
    currency = profile.get("currency", "MXN") if not is_nulls else None

    # Handle Profile 10 variations
    period_start = "2025-12-01"
    period_end = "2025-12-31"
    if profile.get("id") == "10" and not is_nulls:
        var = build_profile_10_variations(instance)
        period_start = var["periodStart"]
        period_end = var["periodEnd"]
        currency = var["currency"]
        
    if is_nulls:
        period_start = None
        period_end = None

    num_tx = profile.get("transactions", 1)
    if is_nulls or num_tx == 0:
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
            "date": period_start if period_start else "2025-12-01",
            "description": f"SYNTHETIC TEST TRANSACTION {i+1:03d}",
            "reference": f"REF{i+1:03d}",
            "direction": direction,
            "amount": amt,
            "balanceAfter": 1000.0 + credits - debits,
            "category": "otro"
        })

    opening = 1000.0 if not is_nulls else None
    closing = 1000.0 + credits - debits if not is_nulls else None
    
    if is_recon_failure:
        closing = 99999.99

    fees = {"totalFees": 50.0, "ivaOnFees": 8.0} if has_fees else None
    interest_earned = 10.0 if has_fees else (0.0 if not is_nulls else None)
    interest_charged = 0.0 if not is_nulls else None

    data = {
        "bank": {"name": bank_name},
        "account": {
            "holder": holder,
            "numberMasked": account_mask,
            "clabeMasked": clabe_mask,
            "currency": currency
        },
        "statement": {
            "periodStart": period_start,
            "periodEnd": period_end
        },
        "balances": {
            "opening": opening,
            "closing": closing,
            "totalCredits": credits if not is_nulls else None,
            "totalDebits": debits if not is_nulls else None
        },
        "transactions": txs,
        "accountType": "cheques" if not is_nulls else None,
        "bankCountry": "MX" if not is_nulls else None,
        "fees": fees,
        "interestEarned": interest_earned,
        "interestCharged": interest_charged,
        "summaryText": "SYNTHETIC FIXTURE DATA" if not is_nulls else None
    }
    
    # The schema scanalyze-document-journey-result.v1.schema.json specifies them as optional or nullable.
    cleaned_data = data

    res = {
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
        "data": cleaned_data,
        "warnings": profile.get("warnings", []),
        "quality": profile.get("quality", {"overallConfidence": 98.0})
    }
    return res

def build_pdf_text_from_expected(expected: dict, fixture_id: str, instance: int, total_pages: int, page_num: int) -> str:
    # Ensure PDF visually matches the ground truth for this page
    data = expected.get("data", {})
    bank = data.get("bank") or {}
    account = data.get("account") or {}
    statement = data.get("statement") or {}
    balances = data.get("balances") or {}
    txs = data.get("transactions") or []
    
    lines = [
        "SYNTHETIC TEST FIXTURE",
        "NOT REAL CUSTOMER DATA",
        f"FIXTURE_ID: {fixture_id}",
        f"PAGE {page_num+1} OF {total_pages}"
    ]
    
    if bank.get("name"):
        lines.append(f"Bank: {bank['name']}")
    if account.get("holder"):
        lines.append(f"Holder: {account['holder']}")
    if account.get("numberMasked"):
        lines.append(f"Account: {account['numberMasked']}")
    if account.get("clabeMasked"):
        lines.append(f"CLABE: {account['clabeMasked']}")
    if account.get("currency"):
        lines.append(f"Currency: {account['currency']}")
    if statement.get("periodStart"):
        lines.append(f"Period: {statement['periodStart']} to {statement.get('periodEnd', '')}")
        
    if page_num == 0:
        if balances.get("opening") is not None:
            lines.append(f"Opening Balance: {balances['opening']}")
        if balances.get("closing") is not None:
            lines.append(f"Closing Balance: {balances['closing']}")
        if balances.get("totalCredits") is not None:
            lines.append(f"Total Credits: {balances['totalCredits']}")
        if balances.get("totalDebits") is not None:
            lines.append(f"Total Debits: {balances['totalDebits']}")
        
        fees = data.get("fees", {})
        if fees:
            lines.append(f"Fees: {fees.get('totalFees')} IVA: {fees.get('ivaOnFees')}")
            
    lines.append("TRANSACTIONS:")
    if len(txs) == 0 and page_num == 0:
        lines.append("No activity")
    
    # Distribute txs across pages
    txs_per_page = max(1, len(txs) // total_pages + (1 if len(txs) % total_pages > 0 else 0))
    start_tx = page_num * txs_per_page
    end_tx = start_tx + txs_per_page
    
    for tx in txs[start_tx:end_tx]:
        lines.append(f"{tx['date']} | {tx['description']} | {tx['direction']} | {tx['amount']} | {tx['balanceAfter']}")
        
    return "\n".join(lines)


def generate_fixtures(base_dir: str, check_only: bool = False):
    profiles_dir = os.path.join(base_dir, 'profiles')
    pdf_dir = os.path.join(base_dir, 'pdf')
    expected_dir = os.path.join(base_dir, 'expected')
    controls_dir = os.path.join(base_dir, 'controls')
    
    for d in [pdf_dir, expected_dir, controls_dir]:
        os.makedirs(d, exist_ok=True)
        
    catalog = {"fixtures": []}
    
    profiles = sorted([f for f in os.listdir(profiles_dir) if f.endswith('.json')])
    
    # Generate profiles 1-10 if they don't exist yet, wait, we are modifying the existing repo.
    # The prompt says we modify the fixture generator.

    for profile_file in profiles:
        with open(os.path.join(profiles_dir, profile_file), 'r') as f:
            profile_bytes = f.read().encode('utf-8')
            profile = json.loads(profile_bytes)
            
        for instance in [1, 2]:
            fixture_id = f"gug364_bank_statement_{profile['id']}_{instance:02d}"
            doc_id = hashlib.md5(fixture_id.encode()).hexdigest()
            
            pages = profile.get("pages", 1)
            
            expected_res = build_expected_result(doc_id, profile, instance)
            
            # Create page contents distributing txs
            page_contents = []
            for p in range(pages):
                page_contents.append(build_pdf_text_from_expected(expected_res, fixture_id, instance, pages, p))
                
            pdf_bytes = _deterministic_pdf_bytes("", pages=pages, page_contents=page_contents)
            
            pdf_name = f"{fixture_id}.pdf"
            pdf_path = os.path.join(pdf_dir, pdf_name)
            
            # Write exactly and deterministically
            expected_json_bytes = json.dumps(expected_res, indent=2, sort_keys=True).encode('utf-8')
            expected_name = f"{fixture_id}_expected.json"
            expected_path = os.path.join(expected_dir, expected_name)
            
            # Current public lifecycle values include: UPLOAD_PENDING, SUBMITTED, PROCESSING, COMPLETED, FAILED
            # Current terminal representation includes: currentStage = TERMINAL, stageState = SUCCEEDED or FAILED
            entry = {
                "schemaVersion": "scanalyze.fixture-catalog.v1",
                "fixtureId": fixture_id,
                "fixtureVersion": "1.0",
                "profileId": profile['id'],
                "instanceId": f"{instance:02d}",
                "scenarioType": profile['name'],
                "positiveOrNegative": "POSITIVE",
                "filePath": f"pdf/{pdf_name}",
                "mimeType": "application/pdf",
                "sensitivity": "SYNTHETIC",
                "sourceSpecPath": f"profiles/{profile_file}",
                "sourceSpecSha256": sha256(profile_bytes),
                "generatorPath": "tooling/generate_bank_statement_fixtures.py",
                "generatorVersion": GENERATOR_VERSION,
                "pdfSha256": sha256(pdf_bytes),
                "expectedResultPath": f"expected/{expected_name}",
                "expectedResultSha256": sha256(expected_json_bytes),
                "byteSize": len(pdf_bytes),
                "pageCount": pages,
                "expectedLifecycle": "COMPLETED",
                "expectedCurrentStage": "TERMINAL",
                "expectedStageState": "SUCCEEDED",
                "acceptedDocumentDenominator": True,
                "manualReviewChecklist": ["Verify synthetic banner", "Verify transaction counts", "Verify expected ground truth presence"],
                "retentionClass": "30_days",
                "noRealDataAttestation": True,
                "tags": ["positive", "synthetic", "bank_statement"]
            }
            entry = {k: v for k, v in entry.items() if v is not None}
            catalog["fixtures"].append(entry)
            
            if not check_only:
                with open(pdf_path, 'wb') as f:
                    f.write(pdf_bytes)
                with open(expected_path, 'wb') as f:
                    f.write(expected_json_bytes)
            else:
                with open(pdf_path, 'rb') as f:
                    if f.read() != pdf_bytes:
                        raise ValueError(f"Mismatch in {pdf_name}")
                with open(expected_path, 'rb') as f:
                    if f.read() != expected_json_bytes:
                        raise ValueError(f"Mismatch in {expected_name}")
                        
    # Process negative controls
    controls = [
        {"id": "ctrl_01", "name": "Malformed PDF", "setup": "Upload corrupted PDF bytes", "mimeType": "application/pdf", "error": "DOCUMENT_PROCESSING_FAILED", "http": 200, "retry": "NO_RETRY", "stageState": "FAILED"},
        {"id": "ctrl_02", "name": "Blank or low-text PDF", "setup": "Upload empty PDF", "mimeType": "application/pdf", "error": "OCR_FAILED", "http": 200, "retry": "NO_RETRY", "stageState": "FAILED"},
        {"id": "ctrl_03", "name": "Unsupported MIME", "setup": "Upload text/plain file", "mimeType": "text/plain", "error": "UNSUPPORTED_MIME_TYPE", "http": 400, "retry": "NO_RETRY", "stageState": "FAILED"},
        {"id": "ctrl_04", "name": "Oversized-file boundary", "setup": "Generate >5MiB file at runtime", "mimeType": "application/pdf", "error": "FILE_TOO_LARGE", "http": 400, "retry": "NO_RETRY", "stageState": "FAILED"},
        {"id": "ctrl_05", "name": "Idempotency conflict", "setup": "Upload diff doc with same key", "mimeType": "application/pdf", "error": "IDEMPOTENCY_CONFLICT", "http": 409, "retry": "NO_RETRY", "stageState": "FAILED"},
        {"id": "ctrl_06", "name": "Response-loss reconciliation", "setup": "Retry after timeout", "mimeType": "application/pdf", "error": None, "http": 200, "retry": "RETRY_SAFE", "stageState": "SUCCEEDED"},
        {"id": "ctrl_07", "name": "Wrong-user access", "setup": "Cross-tenant access", "mimeType": "application/pdf", "error": "AUTHORIZATION_DENIED", "http": 403, "retry": "NO_RETRY", "stageState": "FAILED"},
        {"id": "ctrl_08", "name": "Wrong-deployment access", "setup": "Cross-deployment access", "mimeType": "application/pdf", "error": "AUTHORIZATION_DENIED", "http": 403, "retry": "NO_RETRY", "stageState": "FAILED"}
    ]
    
    for c in controls:
        ctrl_fixture_id = f"gug364_bank_statement_{c['id']}"
        ctrl_path = os.path.join(controls_dir, f"{ctrl_fixture_id}.json")
        
        c_spec = {
            "control": {
                "id": c['id'],
                "name": c['name'],
                "setup": c['setup'],
                "mimeType": c['mimeType'],
                "operation": "CREATE",
                "fixtureReference": "gug364_bank_statement_01_01" if c['id'] in ("ctrl_05", "ctrl_06", "ctrl_07", "ctrl_08") else None,
                "expectedHttpStatus": c['http'],
                "expectedErrorCode": c['error'] if c['http'] >= 400 else None,
                "expectedSafeFailureCode": c['error'] if c['http'] < 400 and c['error'] else None,
                "expectedStageState": c['stageState'],
                "retryClass": c['retry'],
                "actor": "other_user" if c['id'] == "ctrl_07" else "valid_user",
                "deployment": "other_deployment" if c['id'] == "ctrl_08" else "valid_deployment"
            },
            "instruction": "Test runner parses this JSON to execute negative control."
        }
        c_bytes = json.dumps(c_spec, indent=2).encode()
        
        entry = {
            "schemaVersion": "scanalyze.fixture-catalog.v1",
            "fixtureId": ctrl_fixture_id,
            "fixtureVersion": "1.0",
            "profileId": c['id'],
            "instanceId": "01",
            "scenarioType": c['name'],
            "positiveOrNegative": "NEGATIVE",
            "filePath": f"controls/{ctrl_fixture_id}.json",
            "mimeType": "application/json",
            "sensitivity": "SYNTHETIC",
            "sourceSpecPath": f"controls/{ctrl_fixture_id}.json",
            "sourceSpecSha256": sha256(c_bytes),
            "generatorPath": "tooling/generate_bank_statement_fixtures.py",
            "generatorVersion": GENERATOR_VERSION,
            "expectedLifecycle": "FAILED" if c['stageState'] == "FAILED" else "COMPLETED",
            "expectedCurrentStage": "TERMINAL",
            "expectedStageState": c['stageState'],
            "expectedHttpStatus": c['http'],
            "expectedErrorCode": c['error'] if c['http'] >= 400 else None,
            "expectedSafeFailureCode": c['error'] if c['http'] < 400 and c['error'] else None,
            "expectedRetryClass": c['retry'],
            "sharedInputFixtureId": "gug364_bank_statement_01_01" if c['id'] in ("ctrl_05", "ctrl_06", "ctrl_07", "ctrl_08") else None,
            "acceptedDocumentDenominator": False,
            "manualReviewChecklist": [],
            "retentionClass": "30_days",
            "noRealDataAttestation": True,
            "tags": ["negative", "synthetic", "control"]
        }
        
        entry = {k: v for k, v in entry.items() if v is not None}
        catalog["fixtures"].append(entry)
        
        if not check_only:
            with open(ctrl_path, 'wb') as f:
                f.write(c_bytes)
        else:
            with open(ctrl_path, 'rb') as f:
                if f.read() != c_bytes:
                    raise ValueError(f"Mismatch in {ctrl_fixture_id}")

    # Write generator source hash to all entries
    with open(__file__, 'rb') as f:
        gen_sha = sha256(f.read())
    for e in catalog["fixtures"]:
        e["generatorSourceSha256"] = gen_sha

    catalog_path = os.path.join(base_dir, 'catalog.json')
    if not check_only:
        with open(catalog_path, 'w') as f:
            json.dump(catalog, f, indent=2)
    else:
        with open(catalog_path, 'r') as f:
            if json.dumps(json.load(f), indent=2) != json.dumps(catalog, indent=2):
                raise ValueError("Catalog mismatch")

    print(f"Generated {len(catalog['fixtures'])} catalog entries successfully.")

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
