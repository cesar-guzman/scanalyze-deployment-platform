"""GUG-542: model settings, page chunks, merge and reconciliation to the cent."""

import json
from unittest.mock import patch

import pytest

from bank_worker import bedrock as bank_bedrock
from bank_worker.merge import merge_chunk_results
from bank_worker.model_profile import inference_config, output_was_truncated
from bank_worker.normalize import compute_field_confidence, parse_and_normalize, reconcile_balances
from bank_worker.processors import extract as bank_extract
from bank_worker.processors.extract import (
    ExtractionIncompleteError,
    PageChunk,
    build_page_chunks,
    process_bank_extract_message,
    split_pages,
)

CUSTOMER_ID = "cust_01ARZ3NDEKTSV4RRFFQ69G5FAW"
DEPLOYMENT_ID = "dep_01ARZ3NDEKTSV4RRFFQ69G5FAV"
HAIKU_45 = "us.anthropic.claude-haiku-4-5-20251001-v1:0"


# --- Model settings -----------------------------------------------------------

@pytest.mark.parametrize(
    ("model_id", "expected"),
    [
        ("anthropic.claude-3-haiku-20240307-v1:0", {"temperature": 0.0, "topP": 0.1, "maxTokens": 4096}),
        ("anthropic.claude-3-5-sonnet-20241022-v2:0", {"temperature": 0.0, "topP": 0.1, "maxTokens": 8192}),
        (HAIKU_45, {"temperature": 0.0, "maxTokens": 16000}),
        ("anthropic.claude-sonnet-4-20250514-v1:0", {"temperature": 0.0, "maxTokens": 16000}),
        ("global.anthropic.claude-opus-4-7", {"maxTokens": 16000}),
        ("anthropic.claude-haiku-5-5", {"maxTokens": 16000}),
        ("anthropic.some-future-name", {"maxTokens": 16000}),
        ("amazon.nova-lite-v1:0", {"temperature": 0.0, "maxTokens": 16000}),
    ],
)
def test_inference_config_sends_only_what_each_model_accepts(model_id, expected):
    assert inference_config(model_id, 16000) == expected


def test_inference_config_requires_a_model_id():
    with pytest.raises(ValueError):
        inference_config("  ", 1000)


def test_output_truncation_is_read_from_the_stop_reason():
    assert output_was_truncated({"stopReason": "max_tokens"}) is True
    assert output_was_truncated({"stopReason": "tool_use"}) is False
    assert output_was_truncated({}) is False


def _converse_response(tool_input, stop_reason="tool_use"):
    return {
        "output": {"message": {"content": [{"toolUse": {"input": tool_input}}]}},
        "usage": {"inputTokens": 10, "outputTokens": 5, "totalTokens": 15},
        "metrics": {"latencyMs": 7},
        "stopReason": stop_reason,
    }


def test_bank_call_uses_model_settings_requires_confidence_and_reports_stop_reason():
    response = _converse_response({"overallConfidence": 90}, "max_tokens")
    with patch.object(bank_bedrock.bedrock_client, "converse", return_value=response) as converse:
        raw_json, metrics = bank_bedrock.invoke_bedrock_bank_statement(
            "doc-1", "texto", HAIKU_45, (2, 3), 5
        )

    kwargs = converse.call_args.kwargs
    assert kwargs["modelId"] == HAIKU_45
    assert kwargs["inferenceConfig"] == {"temperature": 0.0, "maxTokens": bank_bedrock.MAX_OUTPUT_TOKENS}
    prompt = kwargs["messages"][0]["content"][0]["text"]
    assert "las páginas 2 a 3 de un estado de cuenta de 5 páginas" in prompt
    schema = kwargs["toolConfig"]["tools"][0]["toolSpec"]["inputSchema"]["json"]
    assert schema["required"] == ["overallConfidence"]
    assert metrics["stopReason"] == "max_tokens"
    assert json.loads(raw_json) == {"overallConfidence": 90}


def test_single_page_statement_prompt_has_no_fragment_rules():
    prompt = bank_bedrock.get_user_prompt("doc-1", HAIKU_45, "texto", (1, 1), 1)
    assert "fragmento" not in prompt


# --- Pages and chunks -----------------------------------------------------------

def test_pages_keep_their_numbers_and_blank_pages_are_skipped():
    assert split_pages("uno\f \fdos") == [(1, "uno"), (3, "dos")]
    assert split_pages("") == [(1, "")]


def test_chunks_group_pages_and_split_an_oversized_page_by_lines():
    pages = [(1, "a"), (2, "b"), (3, "c"), (4, "d"), (5, "x\n" * 30)]
    chunks = build_page_chunks(pages, pages_per_chunk=3, max_chars=20)

    assert [(chunk.first, chunk.last) for chunk in chunks[:2]] == [(1, 3), (4, 4)]
    assert len(chunks) > 3
    assert all((chunk.first, chunk.last) == (5, 5) for chunk in chunks[2:])


def test_multi_page_chunk_marks_each_page_and_splits_into_single_pages():
    chunk = PageChunk(1, 2, ((1, "uno"), (2, "dos")))
    assert chunk.text == "--- Página 1 ---\nuno\n--- Página 2 ---\ndos"
    assert [single.text for single in chunk.single_pages()] == ["uno", "dos"]
    assert PageChunk(3, 3, ((3, "tres"),)).single_pages() == []


# --- Merge ------------------------------------------------------------------------

def _chunk(**fields):
    chunk = {
        "model": {"provider": "bedrock", "modelId": HAIKU_45, "usage": None},
        "bank": {},
        "account": {},
        "statement": {},
        "balances": {},
        "transactions": [],
        "modelConfidence": 90.0,
        "extractionIssues": [],
    }
    chunk.update(fields)
    return chunk


def test_merge_keeps_true_opening_and_closing_and_never_sums_document_totals():
    first = _chunk(
        bank={"name": "BBVA"},
        balances={"opening": 1000.0, "closing": None, "totalCredits": 300.0, "totalDebits": 100.0},
        transactions=[{"date": "2024-01-02", "amount": 300.0, "direction": "credit"}],
        interestEarned=1.5,
        fees={"totalFees": 10.0, "ivaOnFees": 1.6},
        modelConfidence=92.0,
    )
    second = _chunk(
        balances={"opening": 1300.0, "closing": 1200.0},
        transactions=[{"date": "2024-01-20", "amount": 100.0, "direction": "debit"}],
        interestEarned=1.5,
        fees={"totalFees": 10.0, "ivaOnFees": 1.6},
        modelConfidence=80.0,
    )

    merged, issues, notes, confidence = merge_chunk_results([first, second])

    assert merged["balances"]["opening"] == 1000.0
    assert merged["balances"]["closing"] == 1200.0
    assert merged["interestEarned"] == 1.5
    assert merged["fees"] == {"totalFees": 10.0, "ivaOnFees": 1.6}
    assert [txn["amount"] for txn in merged["transactions"]] == [300.0, 100.0]
    assert merged["bank"]["name"] == "BBVA"
    assert issues == [] and notes == []
    assert confidence == 80.0
    assert "modelConfidence" not in merged
    assert "extractionIssues" not in merged


def test_merge_flags_pages_that_disagree_on_totals_and_interest():
    first = _chunk(balances={"totalCredits": 300.0}, interestEarned=1.5)
    second = _chunk(
        balances={"totalCredits": 250.0},
        interestEarned=2.0,
        extractionIssues=["unparseable amount in transactions[0].amount"],
    )

    _, issues, notes, _ = merge_chunk_results([first, second])

    assert "pages report different balances.totalCredits" in issues
    assert "unparseable amount in transactions[0].amount" in issues
    assert notes == ["interestEarned"]


def test_merge_has_no_confidence_when_a_chunk_did_not_report_one():
    _, _, _, confidence = merge_chunk_results([_chunk(), _chunk(modelConfidence=None)])
    assert confidence is None


# --- Reconciliation and confidence ------------------------------------------------

def test_reconciliation_is_exact_to_the_cent():
    transactions = [{"amount": 0.1, "direction": "credit"}, {"amount": 0.2, "direction": "credit"}]

    assert reconcile_balances({"opening": 100.0, "closing": 100.3}, transactions) == (True, None)
    valid, issue = reconcile_balances({"opening": 100.0, "closing": 100.32}, transactions)
    assert valid is False
    assert "closing=100.32" in issue


def test_reconciliation_compares_printed_totals_with_the_transactions():
    valid, issue = reconcile_balances(
        {"opening": 1000.0, "closing": 1200.0, "totalCredits": 300.0, "totalDebits": 100.0},
        [{"amount": 300.0, "direction": "credit"}],
    )
    assert valid is False
    assert "debits sum 0.00 differs from reported totalDebits 100.00" in issue


def test_missing_balances_leave_the_reconciliation_undetermined():
    assert reconcile_balances({"opening": 1.0}, []) == (None, "opening or closing balance missing")


def test_model_confidence_is_required_and_an_explicit_zero_is_kept():
    data = {
        "bank": {"name": "BBVA"},
        "account": {"holder": "Ana"},
        "statement": {"periodStart": "2024-01-01", "periodEnd": "2024-01-31"},
        "balances": {"opening": 1.0, "closing": 1.0},
        "transactions": [
            {"amount": 1.0, "direction": "credit"},
            {"amount": 1.0, "direction": "debit"},
        ],
    }
    with pytest.raises(ValueError):
        compute_field_confidence(data)

    _, adjusted = compute_field_confidence({**data, "overallConfidence": 0})
    assert adjusted == 0.0

    with pytest.raises(ValueError, match="overallConfidence"):
        parse_and_normalize(json.dumps({"transactions": []}), "doc-1", "2.2.0", HAIKU_45)


def test_amount_text_is_parsed_or_reported_never_zeroed():
    raw = json.dumps({
        "overallConfidence": 90,
        "balances": {"opening": "1,000.00", "closing": "$1,234.56"},
        "transactions": [
            {"amount": "234.56", "direction": "credit"},
            {"amount": "12,3x", "direction": "debit"},
        ],
    })

    result = parse_and_normalize(raw, "doc-1", "2.2.0", HAIKU_45)

    assert result["balances"] == {"opening": 1000.0, "closing": 1234.56}
    assert [txn["amount"] for txn in result["transactions"]] == [234.56, None]
    reconciliation = result["fieldConfidence"]["balanceReconciliation"]
    assert reconciliation["valid"] is False
    assert "unparseable amount in transactions[1].amount" in reconciliation["issue"]


# --- Extraction loop ----------------------------------------------------------------

def _ok(confidence=90):
    return json.dumps({"overallConfidence": confidence}), {"inputTokens": 1, "stopReason": "tool_use"}


def _usage():
    return {"inputTokens": 0, "outputTokens": 0, "totalTokens": 0, "latencyMs": 0}


def _counters():
    return {"truncatedOutputs": 0, "schemaViolations": 0, "pageSplits": 0}


def _run_chunk(chunk, counters):
    return bank_extract._extract_chunk(
        chunk,
        document_id="doc-1",
        model_id=HAIKU_45,
        total_pages=2,
        ocr_char_count=500,
        usage=_usage(),
        counters=counters,
    )


def test_a_truncated_chunk_is_retried_page_by_page():
    chunk = PageChunk(1, 2, ((1, "uno"), (2, "dos")))
    responses = [("{}", {"stopReason": "max_tokens"}), _ok(), _ok()]
    counters = _counters()

    with patch.object(bank_extract, "invoke_bedrock_bank_statement", side_effect=responses) as invoke:
        results = _run_chunk(chunk, counters)

    assert len(results) == 2
    assert [call.args[3] for call in invoke.call_args_list] == [(1, 2), (1, 1), (2, 2)]
    assert counters == {"truncatedOutputs": 1, "schemaViolations": 0, "pageSplits": 1}


def test_a_schema_violation_is_retried_before_anything_else():
    chunk = PageChunk(1, 1, ((1, "uno"),))
    counters = _counters()

    with patch.object(
        bank_extract,
        "invoke_bedrock_bank_statement",
        side_effect=[('{"transactions": []}', {}), _ok()],
    ):
        results = _run_chunk(chunk, counters)

    assert len(results) == 1
    assert counters["schemaViolations"] == 1


def test_a_page_that_keeps_failing_stops_the_document_instead_of_being_skipped():
    chunk = PageChunk(4, 4, ((4, "cuatro"),))

    with patch.object(
        bank_extract,
        "invoke_bedrock_bank_statement",
        return_value=('{"transactions": []}', {}),
    ):
        with pytest.raises(ExtractionIncompleteError, match="Pages 4-4"):
            _run_chunk(chunk, _counters())


def _message():
    return {
        "schemaVersion": "scanalyze.extract.v2",
        "documentId": "doc-123",
        "customer_id": CUSTOMER_ID,
        "deployment_id": DEPLOYMENT_ID,
        "ownership_schema_version": 1,
        "pipeline_stage": "bank-extract",
        "processing_domain": "bank",
        "raw": {"bucket": "raw-trusted", "key": "raw/doc-123.pdf"},
        "ocr": {"bucket": "ocr-trusted", "key": "ocr/doc-123.json"},
    }


def _ocr_completed_record():
    return {
        "documentId": "doc-123",
        "customer_id": CUSTOMER_ID,
        "deployment_id": DEPLOYMENT_ID,
        "ownership_schema_version": 1,
        "processing_domain": "bank",
        "status": "OCR_COMPLETED",
        "input": {"bucket": "raw-trusted", "key": "raw/doc-123.pdf"},
        "artifacts": {"ocr": {"bucket": "ocr-trusted", "key": "ocr/doc-123.json"}},
    }


def _config_value(key, default=None):
    return {
        "data-foundation/structured_bucket_name": "structured-trusted",
        "data-foundation/documents_table_name": "documents",
        "queues/validate_url": "https://sqs.test/validate",
    }.get(key, default)


def _page_responses(document_id, text, model_id, page_span, total_pages):
    if page_span == (1, 3):
        payload = {
            "overallConfidence": 95,
            "bank": {"name": "BBVA"},
            "account": {"holder": "Ana"},
            "statement": {"periodStart": "2024-01-01", "periodEnd": "2024-01-31"},
            "balances": {"opening": 1000.0, "totalCredits": 500.0, "totalDebits": 200.0},
            "transactions": [{"date": "2024-01-03", "amount": 500.0, "direction": "credit"}],
            "interestEarned": 1.5,
        }
    else:
        payload = {
            "overallConfidence": 90,
            "balances": {"closing": 1300.0},
            "transactions": [{"date": "2024-01-28", "amount": 200.0, "direction": "debit"}],
            "interestEarned": 1.5,
        }
    return json.dumps(payload), {"inputTokens": 3, "outputTokens": 2, "stopReason": "tool_use"}


def test_four_page_statement_is_extracted_by_page_and_reconciled_as_a_whole():
    ocr_text = "\f".join(f"página {number}\n" + "movimiento\n" * 20 for number in range(1, 5))

    with (
        patch("bank_worker.processors.extract.config.get", side_effect=_config_value),
        patch(
            "bank_worker.processors.extract.require_authorized_document",
            return_value=_ocr_completed_record(),
        ),
        patch("bank_worker.processors.extract.is_already_extracted", return_value=False),
        patch("bank_worker.processors.extract.reserve_structured_artifact"),
        patch(
            "bank_worker.processors.extract.get_ocr_text",
            return_value=(ocr_text, {"chars": len(ocr_text), "truncated": False, "pages": 4}),
        ),
        patch(
            "bank_worker.processors.extract.invoke_bedrock_bank_statement",
            side_effect=_page_responses,
        ) as invoke,
        patch(
            "bank_worker.processors.extract.save_structured_artifact",
            return_value=(True, "a" * 64),
        ) as save,
        patch("bank_worker.processors.extract.update_document_status") as finalize,
        patch(
            "bank_worker.processors.extract.sqs_client.send_message",
            return_value={"MessageId": "synthetic"},
        ),
    ):
        assert process_bank_extract_message(json.dumps(_message()), "r", "q") is True

    assert [call.args[3:] for call in invoke.call_args_list] == [((1, 3), 4), ((4, 4), 4)]

    artifact = save.call_args.args[2]
    assert artifact["balances"]["opening"] == 1000.0
    assert artifact["balances"]["closing"] == 1300.0
    assert artifact["interestEarned"] == 1.5
    assert [txn["date"] for txn in artifact["transactions"]] == ["2024-01-03", "2024-01-28"]
    assert artifact["fieldConfidence"]["balanceReconciliation"]["valid"] is True
    assert artifact["overallConfidence"] == 90.0
    assert artifact["model"]["usage"] == {
        "inputTokens": 6,
        "outputTokens": 4,
        "totalTokens": 0,
        "latencyMs": 0,
    }
    assert "modelConfidence" not in artifact
    assert "extractionIssues" not in artifact

    metadata = finalize.call_args.kwargs["metadata"]
    assert metadata["modelId"] == HAIKU_45
    assert metadata["extraction"] == {
        "pages": 4,
        "chunks": 2,
        "truncatedOutputs": 0,
        "schemaViolations": 0,
        "pageSplits": 0,
    }
