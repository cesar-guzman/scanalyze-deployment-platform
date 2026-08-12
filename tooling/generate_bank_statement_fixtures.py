import argparse
import base64
import copy
import hashlib
import json
import os
import textwrap
from pathlib import Path
from typing import Any

# Deterministic fixed date for provenance and generation
FIXED_DATE = "2026-01-01T00:00:00Z"
PRODUCER_VERSION = "1.0"
GENERATOR_VERSION = "v4"
PROMPT_VERSION = "1.0.0"
MAX_RENDERED_LINE_CHARS = 72
MANAGED_DIRECTORIES = ("pdf", "expected", "controls")

def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def _deterministic_pdf_bytes(
    text: str,
    pages: int = 1,
    page_contents: list[str] | None = None,
    warning_cond: str | None = None,
) -> bytes:
    objects = []
    
    def create_obj(num, content):
        return f"{num} 0 obj\n{content}\nendobj\n"
    
    # Include a NUL in the binary marker so Git and other tooling treat the
    # deterministic PDF as binary while retaining spec-compliant xref rows.
    pdf_content = b"%PDF-1.4\n%\xE2\xE3\xCF\xD3\x00\n"
    
    page_kids = " ".join([f"{3 + i*2} 0 R" for i in range(pages)])
    
    objects.append(create_obj(1, "<< /Type /Catalog /Pages 2 0 R >>"))
    objects.append(create_obj(2, f"<< /Type /Pages /Kids [ {page_kids} ] /Count {pages} >>"))
    
    current_obj = 3
    for p in range(pages):
        content_obj = current_obj + 1
        page_object = (
            "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
            f"/Contents {content_obj} 0 R /Resources "
            f"<< /Font << /F1 {3 + pages * 2} 0 R >> >> >>"
        )
        objects.append(create_obj(current_obj, page_object))
        
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
    
    info_dict = (
        "<< /Producer (Scanalyze Test Generator) "
        "/CreationDate (D:20260101000000Z) "
        "/ModDate (D:20260101000000Z) >>"
    )
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
        
    pdf_content += (
        b"trailer\n<< /Size "
        + str(len(objects) + 1).encode("ascii")
        + b" /Root 1 0 R /Info "
        + str(info_obj_num).encode("ascii")
        + b" 0 R >>\n"
    )
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
            "promptVersion": PROMPT_VERSION,
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


def wrap_rendered_lines(lines: list[str]) -> list[str]:
    wrapped: list[str] = []
    for line in lines:
        if " | " in line:
            parts = line.split(" | ")
            current = ""
            for part in parts:
                candidate = part if not current else f"{current} | {part}"
                if current and len(candidate) > MAX_RENDERED_LINE_CHARS:
                    wrapped.append(current)
                    current = f"  {part}"
                else:
                    current = candidate
            if current:
                wrapped.append(current)
            continue
        wrapped.extend(
            textwrap.wrap(
                line,
                width=MAX_RENDERED_LINE_CHARS,
                break_long_words=False,
                break_on_hyphens=False,
                subsequent_indent="  ",
            )
            or [""]
        )
    return wrapped

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
    
    txs_per_page = max(
        1,
        len(txs) // total_pages + (1 if len(txs) % total_pages > 0 else 0),
    )
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
            
    return "\n".join(wrap_rendered_lines(lines))


def _managed_paths(root: str) -> set[str]:
    root_path = Path(root)
    return {
        path.relative_to(root_path).as_posix()
        for directory in MANAGED_DIRECTORIES
        for path in (root_path / directory).rglob("*")
        if path.is_file()
    }


CONTROL_PRINCIPALS = {
    "owner": {
        "principalType": "user",
        "subject": "gug364-owner",
        "customerId": "cust_01ARZ3NDEKTSV4RRFFQ69G5FAW",
        "deploymentId": "dep_01ARZ3NDEKTSV4RRFFQ69G5FAV",
    },
    "otherActor": {
        "principalType": "user",
        "subject": "gug364-other-actor",
        "customerId": "cust_01ARZ3NDEKTSV4RRFFQ69G5FAW",
        "deploymentId": "dep_01ARZ3NDEKTSV4RRFFQ69G5FAV",
    },
    "otherDeployment": {
        "principalType": "user",
        "subject": "gug364-owner",
        "customerId": "cust_01ARZ3NDEKTSV4RRFFQ69G5FAW",
        "deploymentId": "dep_01ARZ3NDEKTSV4RRFFQ69G5FAZ",
    },
}


def _error_expectation(status: int, code: str, retry_class: str) -> dict:
    return {
        "kind": "errorEnvelope",
        "httpStatus": status,
        "code": code,
        "retryClass": retry_class,
    }


def build_control_recipe(control: dict, positive_artifacts: dict[str, dict[str, Any]]) -> dict:
    control_id = control["id"]
    default_fixture_id = "gug364_bank_statement_01_01"
    default_byte_size = positive_artifacts[default_fixture_id]["byteSize"]
    base = {
        "schemaVersion": "scanalyze.bank-statement-control.v1",
        "controlId": control_id,
        "name": control["name"],
        "executionBoundary": "journey-v2-local-contract",
        "setup": control["setup"],
        "principals": CONTROL_PRINCIPALS,
        "inputFixtureIds": [],
        "evidenceState": "PROVEN_LOCAL",
        "steps": [],
        "invariants": {},
    }
    if control_id == "ctrl_01":
        malformed_pdf = b"%PDF-1.4\nTHIS_IS_NOT_A_VALID_PDF"
        base.update(
            {
                "executionBoundary": "artifact-structure-plus-status-contract",
                "evidenceState": "NONPROD_REQUIRED",
                "steps": [
                    {
                        "stepId": "reject-malformed-artifact",
                        "operation": "artifact.pdf_parse",
                        "artifact": {
                            "encoding": "base64",
                            "value": base64.b64encode(malformed_pdf).decode("ascii"),
                            "sha256": sha256(malformed_pdf),
                            "byteSize": len(malformed_pdf),
                        },
                        "expect": {"kind": "artifactAssertion", "parseable": False},
                    },
                    {
                        "stepId": "verify-status-policy",
                        "operation": "documents.status_policy",
                        "internalStatus": {
                            "documentId": "a" * 32,
                            "status": "OCR_FAILED",
                            "createdAt": "2026-01-01T00:00:00+00:00",
                            "updatedAt": "2026-01-01T00:01:00+00:00",
                            "stages": {"ocr": {"status": "IN_PROGRESS"}},
                        },
                        "evaluationTime": "2026-01-01T00:02:00+00:00",
                        "expect": {
                            "kind": "documentStatus",
                            "httpStatus": 200,
                            "lifecycle": "FAILED",
                            "safeFailureCode": "OCR_FAILED",
                            "failureDisposition": "TERMINAL",
                        },
                    },
                ],
                "invariants": {"causalRuntimeOutcomeProven": False},
            }
        )
    elif control_id == "ctrl_02":
        blank_pdf = _deterministic_pdf_bytes(
            "",
            pages=1,
            page_contents=[""],
        )
        base.update(
            {
                "executionBoundary": "artifact-structure",
                "evidenceState": "NOT_PROVEN",
                "steps": [
                    {
                        "stepId": "verify-empty-extracted-text",
                        "operation": "artifact.pdf_text",
                        "artifact": {
                            "encoding": "base64",
                            "value": base64.b64encode(blank_pdf).decode("ascii"),
                            "sha256": sha256(blank_pdf),
                            "byteSize": len(blank_pdf),
                            "pageCount": 1,
                        },
                        "expect": {"kind": "artifactAssertion", "maximumTextCharacters": 0},
                    }
                ],
                "invariants": {"terminalRuntimeOutcomeClaimed": False},
            }
        )
    elif control_id == "ctrl_03":
        base["inputFixtureIds"] = [default_fixture_id]
        base["steps"] = [
            {
                "stepId": "reject-document-mime",
                "operation": "documents.create",
                "principal": "owner",
                "idempotencyKey": "00000000-0000-4000-8000-000000000003",
                "inputFixtureId": default_fixture_id,
                "request": {
                    "filename": "synthetic.txt",
                    "contentType": "text/plain",
                    "contentLength": default_byte_size,
                },
                "expect": _error_expectation(422, "SEMANTIC_VALIDATION_FAILED", "NOT_RETRYABLE"),
            }
        ]
        base["invariants"] = {"documentCreateEffects": 0}
    elif control_id == "ctrl_04":
        base["inputFixtureIds"] = [default_fixture_id]
        base["steps"] = [
            {
                "stepId": "reject-oversized-metadata",
                "operation": "documents.create",
                "principal": "owner",
                "idempotencyKey": "00000000-0000-4000-8000-000000000004",
                "inputFixtureId": default_fixture_id,
                "request": {"filename": "synthetic.pdf", "contentType": "application/pdf", "contentLength": 536870913},
                "expect": _error_expectation(422, "SEMANTIC_VALIDATION_FAILED", "NOT_RETRYABLE"),
            }
        ]
        base["invariants"] = {"maximumAcceptedDocumentBytes": 536870912, "documentCreateEffects": 0}
    elif control_id == "ctrl_05":
        base["inputFixtureIds"] = ["gug364_bank_statement_01_01", "gug364_bank_statement_01_02"]
        base["steps"] = [
            {
                "stepId": "first-create",
                "operation": "documents.create",
                "principal": "owner",
                "idempotencyKey": "00000000-0000-4000-8000-000000000005",
                "inputFixtureId": "gug364_bank_statement_01_01",
                "request": {
                    "filename": "first.pdf",
                    "contentType": "application/pdf",
                    "contentLength": positive_artifacts["gug364_bank_statement_01_01"]["byteSize"],
                },
                "expect": {"kind": "documentCreateResponse", "httpStatus": 201, "replayed": False},
            },
            {
                "stepId": "conflicting-create",
                "operation": "documents.create",
                "principal": "owner",
                "idempotencyKey": "00000000-0000-4000-8000-000000000005",
                "inputFixtureId": "gug364_bank_statement_01_02",
                "request": {
                    "filename": "second.pdf",
                    "contentType": "application/pdf",
                    "contentLength": positive_artifacts["gug364_bank_statement_01_02"]["byteSize"],
                },
                "expect": _error_expectation(409, "IDEMPOTENCY_CONFLICT", "TERMINAL"),
            },
        ]
        base["invariants"] = {"documentCreateEffects": 1}
    elif control_id == "ctrl_06":
        base["inputFixtureIds"] = [default_fixture_id]
        base["steps"] = [
            {
                "stepId": "create-and-discard-response",
                "operation": "documents.create",
                "principal": "owner",
                "idempotencyKey": "00000000-0000-4000-8000-000000000006",
                "inputFixtureId": default_fixture_id,
                "request": {
                    "filename": "reconcile.pdf",
                    "contentType": "application/pdf",
                    "contentLength": default_byte_size,
                },
                "discardResponse": True,
                "expect": {"kind": "documentCreateResponse", "httpStatus": 201, "replayed": False},
            },
            {
                "stepId": "reconcile",
                "operation": "operations.reconcile",
                "principal": "owner",
                "idempotencyKey": "00000000-0000-4000-8000-000000000006",
                "targetOperation": "DOCUMENT_CREATE",
                "expect": {"kind": "reconciliationResponse", "httpStatus": 200, "ledgerState": "SUCCEEDED"},
            },
            {
                "stepId": "safe-replay",
                "operation": "documents.create",
                "principal": "owner",
                "idempotencyKey": "00000000-0000-4000-8000-000000000006",
                "inputFixtureId": default_fixture_id,
                "request": {
                    "filename": "reconcile.pdf",
                    "contentType": "application/pdf",
                    "contentLength": default_byte_size,
                },
                "expect": {"kind": "documentCreateResponse", "httpStatus": 201, "replayed": True},
            },
        ]
        base["invariants"] = {"documentCreateEffects": 1, "sameDocumentId": True}
    else:
        principal = "otherActor" if control_id == "ctrl_07" else "otherDeployment"
        base["inputFixtureIds"] = [default_fixture_id]
        base["steps"] = [
            {
                "stepId": "create-owned-document",
                "operation": "documents.create",
                "principal": "owner",
                "idempotencyKey": "00000000-0000-4000-8000-000000" + f"00000{control_id[-1]}",
                "inputFixtureId": default_fixture_id,
                "request": {
                    "filename": "owned.pdf",
                    "contentType": "application/pdf",
                    "contentLength": default_byte_size,
                },
                "expect": {"kind": "documentCreateResponse", "httpStatus": 201, "replayed": False},
            },
            {
                "stepId": "hide-foreign-document",
                "operation": "documents.get_status",
                "principal": principal,
                "documentIdFromStep": "create-owned-document",
                "expect": _error_expectation(404, "NOT_FOUND", "TERMINAL"),
            },
        ]
        base["invariants"] = {"documentCreateEffects": 1, "existenceHidden": True}
    return base


def build_control_input_artifacts(
    recipe: dict[str, Any], positive_artifacts: dict[str, dict[str, Any]]
) -> list[dict[str, Any]]:
    resolved: list[dict[str, Any]] = []
    for fixture_id in recipe["inputFixtureIds"]:
        artifact = positive_artifacts[fixture_id]
        step_ids = [
            step["stepId"]
            for step in recipe["steps"]
            if step.get("inputFixtureId") == fixture_id
        ]
        resolved.append(
            {
                "bindingType": "SHARED_POSITIVE_FIXTURE",
                "fixtureId": fixture_id,
                "stepIds": step_ids,
                "mimeType": "application/pdf",
                "pdfSha256": artifact["pdfSha256"],
                "byteSize": artifact["byteSize"],
                "pageCount": artifact["pageCount"],
            }
        )
    for step in recipe["steps"]:
        if "artifact" not in step:
            continue
        artifact = step["artifact"]
        resolved.append(
            {
                "bindingType": "EMBEDDED_CONTROL_ARTIFACT",
                "stepIds": [step["stepId"]],
                "mimeType": "application/pdf",
                "pdfSha256": artifact["sha256"],
                "byteSize": artifact["byteSize"],
                "pageCount": artifact.get("pageCount", 0),
            }
        )
    return resolved


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
    expected_managed_paths: set[str] = set()
    positive_artifacts: dict[str, dict[str, Any]] = {}
    
    profiles = sorted([f for f in os.listdir(profiles_dir) if f.endswith('.json')])
    
    for profile_file in profiles:
        with open(os.path.join(profiles_dir, profile_file), 'r') as f:
            profile_bytes = f.read().encode('utf-8')
            profile = json.loads(profile_bytes)
            
        for instance_def in profile.get("instances", []):
            instance = instance_def["instanceId"]
            fixture_id = f"gug364_bank_statement_{profile['id']}_{instance}"
            doc_id = hashlib.md5(
                fixture_id.encode(),
                usedforsecurity=False,
            ).hexdigest()
            
            expected_res, ground_truth = build_expected_result(doc_id, profile, instance_def["overrides"])
            pages = ground_truth.get("pages", 1)
            render_fixture_id = profile.get("renderFixtureId", fixture_id)
            
            page_contents = []
            for p in range(pages):
                page_contents.append(build_pdf_text_from_ground_truth(ground_truth, render_fixture_id, pages, p))
                
            pdf_bytes = _deterministic_pdf_bytes(
                "",
                pages=pages,
                page_contents=page_contents,
                warning_cond=ground_truth.get("warningSourceCondition"),
            )
            
            pdf_name = f"{fixture_id}.pdf"
            pdf_path = os.path.join(pdf_dir, pdf_name)
            
            expected_json_bytes = json.dumps(expected_res, indent=2, sort_keys=True).encode('utf-8')
            expected_name = f"{fixture_id}_expected.json"
            expected_path = os.path.join(expected_dir, expected_name)
            expected_managed_paths.update(
                {f"pdf/{pdf_name}", f"expected/{expected_name}"}
            )
            
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
                "lifecycleApplicability": "APPLICABLE",
                "acceptedDocumentDenominator": True,
                "manualReviewChecklist": [
                    "Verify synthetic banner",
                    "Verify transaction counts",
                    "Verify expected ground truth presence",
                ],
                "retentionClass": "30_days",
                "noRealDataAttestation": True,
                "tags": ["positive", "synthetic", "bank_statement"]
            }
            if profile.get("replayGroupId"):
                entry.update(
                    {
                        "replayGroupId": profile["replayGroupId"],
                        "replayOrdinal": instance_def["replayOrdinal"],
                    }
                )
            catalog["fixtures"].append(entry)
            positive_artifacts[fixture_id] = {
                "pdfSha256": entry["pdfSha256"],
                "byteSize": entry["byteSize"],
                "pageCount": entry["pageCount"],
            }
            
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
        {
            "id": "ctrl_01",
            "name": "Malformed PDF",
            "setup": "Verify malformed bytes locally; asynchronous OCR status requires non-production evidence",
            "mimeType": "application/pdf",
            "error": "OCR_FAILED",
            "http": 200,
            "retry": "TERMINAL",
            "stageState": "FAILED",
            "lifecycle": "FAILED",
            "lifecycleApplicability": "APPLICABLE",
            "variant": "physicalPayloadControl",
        },
        {
            "id": "ctrl_02",
            "name": "Blank or low-text PDF",
            "setup": "Verify blank text locally; terminal runtime outcome is not proven by the current contract",
            "mimeType": "application/pdf",
            "error": None,
            "http": None,
            "retry": None,
            "lifecycleApplicability": "UNDEFINED_BY_CURRENT_CONTRACT",
            "variant": "artifactAssertionControl",
        },
        {
            "id": "ctrl_03",
            "name": "Unsupported MIME",
            "setup": "Validate text/plain through DocumentCreateRequest",
            "mimeType": "text/plain",
            "error": "SEMANTIC_VALIDATION_FAILED",
            "http": 422,
            "retry": "NOT_RETRYABLE",
            "lifecycleApplicability": "NOT_APPLICABLE",
            "variant": "requestValidationControl",
        },
        # Contract maximum is 512 MiB; this recipe tests metadata validation without allocating it.
        {
            "id": "ctrl_04",
            "name": "Oversized-file boundary",
            "setup": "Validate contentLength=536870913 against the 536870912-byte contract maximum",
            "mimeType": "application/pdf",
            "error": "SEMANTIC_VALIDATION_FAILED",
            "http": 422,
            "retry": "NOT_RETRYABLE",
            "lifecycleApplicability": "NOT_APPLICABLE",
            "variant": "requestValidationControl",
        },
        # request conflict
        {
            "id": "ctrl_05",
            "name": "Idempotency conflict",
            "setup": "Upload diff doc with same key",
            "mimeType": "application/pdf",
            "error": "IDEMPOTENCY_CONFLICT",
            "http": 409,
            "retry": "TERMINAL",
            "lifecycleApplicability": "NOT_APPLICABLE",
            "variant": "requestConflictControl",
        },
        # reconciliation
        {
            "id": "ctrl_06",
            "name": "Response-loss reconciliation",
            "setup": "Retry after timeout",
            "mimeType": "application/pdf",
            "error": None,
            "http": 200,
            "retry": "RETRY_ONLY_AFTER_RECONCILIATION",
            "ledgerState": "SUCCEEDED",
            "lifecycleApplicability": "NOT_APPLICABLE",
            "variant": "reconciliationControl",
        },
        # authorization
        {
            "id": "ctrl_07",
            "name": "Wrong-user access",
            "setup": "Read an owner-bound document as a different actor",
            "mimeType": "application/pdf",
            "error": "NOT_FOUND",
            "http": 404,
            "retry": "TERMINAL",
            "lifecycleApplicability": "NOT_APPLICABLE",
            "variant": "authorizationControl",
        },
        {
            "id": "ctrl_08",
            "name": "Wrong-deployment access",
            "setup": "Read an owner-bound document from a different deployment",
            "mimeType": "application/pdf",
            "error": "NOT_FOUND",
            "http": 404,
            "retry": "TERMINAL",
            "lifecycleApplicability": "NOT_APPLICABLE",
            "variant": "authorizationControl",
        },
    ]
    
    for c in controls:
        ctrl_fixture_id = f"gug364_bank_statement_{c['id']}"
        ctrl_path = os.path.join(controls_dir, f"{ctrl_fixture_id}.json")
        expected_managed_paths.add(f"controls/{ctrl_fixture_id}.json")
        
        c_spec = build_control_recipe(c, positive_artifacts)
        c_bytes = json.dumps(c_spec, indent=2).encode()
        input_artifacts = build_control_input_artifacts(c_spec, positive_artifacts)
        
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
            "acceptedDocumentDenominator": False,
            "controlSpecSha256": sha256(c_bytes),
            "controlSpecByteSize": len(c_bytes),
            "evidenceState": c_spec["evidenceState"],
            "lifecycleApplicability": c["lifecycleApplicability"],
            "inputFixtureIds": c_spec["inputFixtureIds"],
            "inputArtifacts": input_artifacts,
        }

        if c['variant'] == "physicalPayloadControl":
            entry.update({
                "expectedLifecycle": c['lifecycle'],
                "expectedCurrentStage": "TERMINAL",
                "expectedStageState": c['stageState'],
                "expectedHttpStatus": c['http'],
                "expectedErrorCode": c['error'] if c['http'] >= 400 else None,
                "expectedSafeFailureCode": c['error'] if c['http'] < 400 and c['error'] else None,
                "expectedFailureDisposition": c['retry'],
            })
        elif c['variant'] == "artifactAssertionControl":
            entry.update({
                "expectedAssertion": "EMPTY_EXTRACTED_TEXT"
            })
        elif c['variant'] == "requestValidationControl":
            entry.update({
                "expectedHttpStatus": c['http'],
                "expectedErrorCode": c['error'],
                "expectedRetryClass": c['retry']
            })
        elif c['variant'] == "requestConflictControl":
            entry.update({
                "expectedHttpStatus": c['http'],
                "expectedErrorCode": c['error'],
                "expectedRetryClass": c['retry']
            })
        elif c['variant'] == "reconciliationControl":
            entry.update({
                "expectedHttpStatus": c['http'],
                "expectedLedgerState": c['ledgerState']
            })
        elif c['variant'] == "authorizationControl":
            entry.update({
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

        actual_managed_paths = _managed_paths(out_dir)
        missing = sorted(expected_managed_paths - actual_managed_paths)
        unexpected = sorted(actual_managed_paths - expected_managed_paths)
        if missing or unexpected:
            raise ValueError(
                "Managed artifact drift: "
                f"missing={missing}, unexpected={unexpected}"
            )

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
