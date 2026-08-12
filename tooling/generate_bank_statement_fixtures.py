import os
import json
import hashlib
import argparse
import copy
from typing import Dict, Any, List

# Deterministic fixed date for provenance and generation
FIXED_DATE = "2026-01-01T00:00:00Z"
PRODUCER_VERSION = "1.0"
GENERATOR_VERSION = "v3"

def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def _deterministic_pdf_bytes(text: str, pages: int = 1, page_contents: List[str] = None, warning_cond: str = None) -> bytes:
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
        if warning_cond == "LOW_CONTRAST_TEXT":
            pdf_text = f"BT\n/F1 12 Tf\n0.85 0.85 0.85 rg\n100 700 Td\n"
        else:
            pdf_text = f"BT\n/F1 12 Tf\n0 0 0 rg\n100 700 Td\n"
            
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

def merge_overrides(base, overrides):
    if isinstance(base, dict) and isinstance(overrides, dict):
        merged = base.copy()
        for k, v in overrides.items():
            merged[k] = merge_overrides(base.get(k), v)
        return merged
    return copy.deepcopy(overrides)

def get_null_policy(policy_map: dict, field_path: str) -> str:
    # First exact match
    if field_path in policy_map:
        return policy_map[field_path]
    # Then wildcard match
    if ".*" in policy_map:
        return policy_map[".*"]
    return "OMIT"

def build_expected_result(doc_id: str, profile: dict, instance_override: dict) -> dict:
    defaults = profile.get("commonDefaults", {})
    ground_truth = merge_overrides(defaults, instance_override)
    
    stmt_period = ground_truth.get("statementPeriod")
    statement_mapped = None
    if stmt_period is not None:
        statement_mapped = {
            "periodStart": stmt_period.get("start"),
            "periodEnd": stmt_period.get("end")
        }
        
    data = {
        "bank": ground_truth.get("bank"),
        "account": ground_truth.get("account"),
        "statement": statement_mapped,
        "balances": ground_truth.get("balances"),
        "transactions": ground_truth.get("transactions", []),
        "accountType": ground_truth.get("accountType"),
        "bankCountry": ground_truth.get("country"),
        "fees": ground_truth.get("fees"),
        "interestEarned": ground_truth.get("interest", {}).get("earned") if ground_truth.get("interest") else None,
        "interestCharged": ground_truth.get("interest", {}).get("charged") if ground_truth.get("interest") else None,
        "summaryText": ground_truth.get("summary")
    }
    
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
        "data": data,
        "warnings": [{"code": w} for w in ground_truth.get("expectedWarnings", [])],
        "quality": ground_truth.get("quality")
    }
    return res, ground_truth

def render_field(name: str, value: Any, policy: str) -> str:
    if value is not None:
        return f"{name}: {value}"
    if policy == "RENDER_NOT_AVAILABLE":
        return f"{name}: NOT AVAILABLE"
    if policy == "RENDER_EMPTY_SECTION":
        return f"{name}:"
    return None # OMIT

def build_pdf_text_from_ground_truth(ground_truth: dict, fixture_id: str, total_pages: int, page_num: int) -> str:
    policy_map = ground_truth.get("nullRenderingPolicy", {})
    
    lines = [
        "SYNTHETIC TEST FIXTURE",
        "NOT REAL CUSTOMER DATA",
        f"FIXTURE_ID: {fixture_id}",
        f"PAGE {page_num+1} OF {total_pages}"
    ]
    
    bank = ground_truth.get("bank") or {}
    account = ground_truth.get("account") or {}
    stmt = ground_truth.get("statementPeriod") or {}
    bals = ground_truth.get("balances") or {}
    
    fields_to_render = [
        ("Bank", bank.get("name"), get_null_policy(policy_map, "bank.name")),
        ("Holder", account.get("holder"), get_null_policy(policy_map, "account.holder")),
        ("Account", account.get("numberMasked"), get_null_policy(policy_map, "account.numberMasked")),
        ("CLABE", account.get("clabeMasked"), get_null_policy(policy_map, "account.clabeMasked")),
        ("Currency", account.get("currency"), get_null_policy(policy_map, "account.currency")),
        ("Period Start", stmt.get("start"), get_null_policy(policy_map, "statementPeriod.start")),
        ("Period End", stmt.get("end"), get_null_policy(policy_map, "statementPeriod.end")),
        ("Account Type", ground_truth.get("accountType"), get_null_policy(policy_map, "accountType")),
        ("Bank Country", ground_truth.get("country"), get_null_policy(policy_map, "country")),
        ("Summary Text", ground_truth.get("summary"), get_null_policy(policy_map, "summary")),
    ]
    
    if ground_truth.get("warningSourceCondition"):
        # For Profiles 07, 08, 09, we inject a visual condition that creates the warning
        fields_to_render.append(("Warning Source Condition", ground_truth.get("warningSourceCondition"), "OMIT"))

    for f_name, f_val, f_pol in fields_to_render:
        rendered = render_field(f_name, f_val, f_pol)
        if rendered:
            lines.append(rendered)

    if page_num == 0:
        bal_fields = [
            ("Opening Balance", bals.get("opening"), get_null_policy(policy_map, "balances.opening")),
            ("Closing Balance", bals.get("closing"), get_null_policy(policy_map, "balances.closing")),
            ("Total Credits", bals.get("totalCredits"), get_null_policy(policy_map, "balances.totalCredits")),
            ("Total Debits", bals.get("totalDebits"), get_null_policy(policy_map, "balances.totalDebits"))
        ]
        for f_name, f_val, f_pol in bal_fields:
            rendered = render_field(f_name, f_val, f_pol)
            if rendered:
                lines.append(rendered)
                
        fees = ground_truth.get("fees") or {}
        if fees.get("totalFees") is not None or get_null_policy(policy_map, "fees") != "OMIT":
            fee_lines = []
            if fees.get("totalFees") is not None:
                fee_lines.append(f"Fees: {fees.get('totalFees')}")
            elif get_null_policy(policy_map, "fees") == "RENDER_NOT_AVAILABLE":
                fee_lines.append("Fees: NOT AVAILABLE")
                
            if fees.get("ivaOnFees") is not None:
                fee_lines.append(f"IVA: {fees.get('ivaOnFees')}")
            
            if fee_lines:
                lines.append(" ".join(fee_lines))
                
        interest = ground_truth.get("interest") or {}
        if interest.get("earned") is not None:
            lines.append(f"Interest Earned: {interest.get('earned')}")
        if interest.get("charged") is not None:
            lines.append(f"Interest Charged: {interest.get('charged')}")
    lines.append("TRANSACTIONS:")
    txs = ground_truth.get("transactions") or []
    if len(txs) == 0 and page_num == 0:
        lines.append("No activity")
    
    warning_cond = ground_truth.get("warningSourceCondition")
    
    if warning_cond == "MISSING_MIDDLE_PAGE":
        if page_num == 1:
            txs_to_render = []
        elif page_num == 0:
            txs_to_render = txs[:len(txs)//2]
        else:
            txs_to_render = txs[len(txs)//2:]
    else:
        txs_per_page = max(1, len(txs) // total_pages + (1 if len(txs) % total_pages > 0 else 0))
        start_tx = page_num * txs_per_page
        end_tx = start_tx + txs_per_page
        txs_to_render = txs[start_tx:end_tx]
    
    for tx in txs_to_render:
        tx_line = []
        for k in ["date", "description", "reference", "direction", "amount", "balanceAfter", "category"]:
            val = tx.get(k)
            pol = get_null_policy(policy_map, f"transactions.{k}")
            if val is not None:
                tx_line.append(str(val))
            elif pol == "RENDER_NOT_AVAILABLE":
                tx_line.append("NOT AVAILABLE")
            elif pol == "RENDER_EMPTY_SECTION":
                tx_line.append("")
        if tx_line:
            lines.append(" | ".join(tx_line))
            
    return "\\n".join(lines)


def generate_fixtures(base_dir: str, out_dir: str = None, check_only: bool = False):
    if out_dir is None:
        out_dir = base_dir
        
    profiles_dir = os.path.join(base_dir, 'profiles')
    pdf_dir = os.path.join(out_dir, 'pdf')
    expected_dir = os.path.join(out_dir, 'expected')
    controls_dir = os.path.join(out_dir, 'controls')
    
    if not check_only:
        for d in [pdf_dir, expected_dir, controls_dir]:
            os.makedirs(d, exist_ok=True)
        
    catalog = {"fixtures": []}
    
    profiles = sorted([f for f in os.listdir(profiles_dir) if f.endswith('.json')])
    
    for profile_file in profiles:
        with open(os.path.join(profiles_dir, profile_file), 'r') as f:
            profile_bytes = f.read().encode('utf-8')
            profile = json.loads(profile_bytes)
            
        for instance_def in profile.get("instances", []):
            instance = instance_def["instanceId"]
            fixture_id = f"gug364_bank_statement_{profile['id']}_{instance}"
            doc_id = hashlib.md5(fixture_id.encode()).hexdigest()
            
            expected_res, ground_truth = build_expected_result(doc_id, profile, instance_def["overrides"])
            pages = ground_truth.get("pages", 1)
            
            page_contents = []
            for p in range(pages):
                page_contents.append(build_pdf_text_from_ground_truth(ground_truth, fixture_id, pages, p))
                
            pdf_bytes = _deterministic_pdf_bytes("", pages=pages, page_contents=page_contents, warning_cond=ground_truth.get("warningSourceCondition"))
            
            pdf_name = f"{fixture_id}.pdf"
            pdf_path = os.path.join(pdf_dir, pdf_name)
            
            expected_json_bytes = json.dumps(expected_res, indent=2, sort_keys=True).encode('utf-8')
            expected_name = f"{fixture_id}_expected.json"
            expected_path = os.path.join(expected_dir, expected_name)
            
            entry = {
                "schemaVersion": "scanalyze.fixture-catalog.v1",
                "variant": "positiveFixture",
                "fixtureId": fixture_id,
                "fixtureVersion": "1.0",
                "profileId": profile['id'],
                "instanceId": instance,
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
                        
    # Process negative controls using discriminated variants
    controls = [
        # physicalNegativeFixture
        {"id": "ctrl_01", "name": "Malformed PDF", "setup": "Upload corrupted PDF bytes", "mimeType": "application/pdf", "error": "DOCUMENT_PROCESSING_FAILED", "http": 400, "retry": "NOT_RETRYABLE", "stageState": "FAILED", "lifecycle": "FAILED", "variant": "physicalPayloadControl"},
        {"id": "ctrl_02", "name": "Blank or low-text PDF", "setup": "Upload empty PDF", "mimeType": "application/pdf", "error": "DOCUMENT_PROCESSING_FAILED", "http": 400, "retry": "NOT_RETRYABLE", "stageState": "FAILED", "lifecycle": "FAILED", "variant": "physicalPayloadControl"},
        {"id": "ctrl_03", "name": "Unsupported MIME", "setup": "Upload text/plain file", "mimeType": "text/plain", "error": "DOCUMENT_PROCESSING_FAILED", "http": 415, "retry": "NOT_RETRYABLE", "stageState": "FAILED", "lifecycle": "FAILED", "variant": "physicalPayloadControl"},
        # local demo-policy rejection -> HTTP 400 with a custom demo error or HTTP 413
        {"id": "ctrl_04", "name": "Oversized-file boundary", "setup": "Generate >5MiB file at runtime", "mimeType": "application/pdf", "error": "DOCUMENT_PROCESSING_FAILED", "http": 413, "retry": "NOT_RETRYABLE", "variant": "localDemoPolicyControl"},
        # request conflict
        {"id": "ctrl_05", "name": "Idempotency conflict", "setup": "Upload diff doc with same key", "mimeType": "application/pdf", "error": "IDEMPOTENCY_CONFLICT", "http": 409, "retry": "TERMINAL", "variant": "requestConflictControl"},
        # reconciliation
        {"id": "ctrl_06", "name": "Response-loss reconciliation", "setup": "Retry after timeout", "mimeType": "application/pdf", "error": None, "http": 200, "retry": "RETRY_ONLY_AFTER_RECONCILIATION", "ledgerState": "SUCCEEDED", "variant": "reconciliationControl"},
        # authorization
        {"id": "ctrl_07", "name": "Wrong-user access", "setup": "Cross-tenant access", "mimeType": "application/pdf", "error": "AUTHORIZATION_DENIED", "http": 403, "retry": "TERMINAL", "variant": "authorizationControl"},
        {"id": "ctrl_08", "name": "Wrong-deployment access", "setup": "Cross-deployment access", "mimeType": "application/pdf", "error": "AUTHORIZATION_DENIED", "http": 403, "retry": "TERMINAL", "variant": "authorizationControl"}
    ]
    
    for c in controls:
        ctrl_fixture_id = f"gug364_bank_statement_{c['id']}"
        ctrl_path = os.path.join(controls_dir, f"{ctrl_fixture_id}.json")
        
        c_spec = {
            "control": {
                "id": c['id'],
                "name": c['name'],
                "setup": c['setup'],
                "mimeType": c['mimeType']
            },
            "instruction": "Test runner parses this JSON to execute negative control."
        }
        c_bytes = json.dumps(c_spec, indent=2).encode()
        
        entry = {
            "schemaVersion": "scanalyze.fixture-catalog.v1",
            "variant": c["variant"],
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
            "retentionClass": "30_days",
            "noRealDataAttestation": True,
            "tags": ["negative", "synthetic", "control"],
            "acceptedDocumentDenominator": False
        }

        if c['variant'] == "physicalPayloadControl":
            entry.update({
                "expectedLifecycle": c['lifecycle'],
                "expectedCurrentStage": "TERMINAL",
                "expectedStageState": c['stageState'],
                "expectedHttpStatus": c['http'],
                "expectedErrorCode": c['error'] if c['http'] >= 400 else None,
                "expectedSafeFailureCode": c['error'] if c['http'] < 400 and c['error'] else None,
                "expectedRetryClass": c['retry'],
            })
        elif c['variant'] == "localDemoPolicyControl":
            entry.update({
                "expectedHttpStatus": c['http'],
                "expectedErrorCode": c['error']
            })
        elif c['variant'] == "requestConflictControl":
            entry.update({
                "sharedInputFixtureId": "gug364_bank_statement_01_01",
                "expectedHttpStatus": c['http'],
                "expectedErrorCode": c['error'],
                "expectedRetryClass": c['retry']
            })
        elif c['variant'] == "reconciliationControl":
            entry.update({
                "sharedInputFixtureId": "gug364_bank_statement_01_01",
                "expectedLedgerState": c['ledgerState']
            })
        elif c['variant'] == "authorizationControl":
            entry.update({
                "sharedInputFixtureId": "gug364_bank_statement_01_01",
                "expectedHttpStatus": c['http'],
                "expectedErrorCode": c['error'],
                "expectedRetryClass": c['retry']
            })
            
        entry = {k: v for k, v in entry.items() if v is not None}
        catalog["fixtures"].append(entry)
        
        if not check_only:
            with open(ctrl_path, 'wb') as f:
                f.write(c_bytes)
        else:
            with open(ctrl_path, 'rb') as f:
                if f.read() != c_bytes:
                    raise ValueError(f"Mismatch in {ctrl_fixture_id}")

    with open(__file__, 'rb') as f:
        gen_sha = sha256(f.read())
    for e in catalog["fixtures"]:
        e["generatorSourceSha256"] = gen_sha

    catalog_path = os.path.join(out_dir, 'catalog.json')
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
    parser.add_argument('--output-dir', type=str, default=None)
    args = parser.parse_args()
    
    base = os.path.join(os.path.dirname(__file__), '../tests/fixtures/bank_statement/v1')
    try:
        generate_fixtures(base, out_dir=args.output_dir, check_only=args.check)
        if args.check:
            print("Check passed. No drift detected.")
    except Exception as e:
        if args.check:
            print(f"Check failed: {e}")
            exit(1)
        else:
            raise
