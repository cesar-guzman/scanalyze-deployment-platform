"""GUG-542: the government extractor sends only settings its model accepts."""

from unittest.mock import patch

import pytest

from gov_worker import bedrock as gov_bedrock
from gov_worker.model_profile import OutputTruncatedError

HAIKU_45 = "us.anthropic.claude-haiku-4-5-20251001-v1:0"


def _response(content, stop_reason="end_turn"):
    return {
        "output": {"message": {"content": content}},
        "usage": {"inputTokens": 1, "outputTokens": 1, "totalTokens": 2},
        "metrics": {"latencyMs": 1},
        "stopReason": stop_reason,
    }


def test_gov_call_drops_top_p_for_claude_4():
    with patch.object(gov_bedrock.bedrock_client, "converse", return_value=_response([{"text": "{}"}])) as converse:
        gov_bedrock.invoke_bedrock_gov_doc("doc-1", "texto", HAIKU_45)

    assert converse.call_args.kwargs["inferenceConfig"] == {"temperature": 0.0, "maxTokens": 4000}


def test_gov_call_reads_text_even_when_it_is_not_the_first_block():
    content = [{"reasoningContent": {"reasoningText": {"text": "..."}}}, {"text": "{\"a\": 1}"}]
    with patch.object(gov_bedrock.bedrock_client, "converse", return_value=_response(content)):
        raw_text, _ = gov_bedrock.invoke_bedrock_gov_doc("doc-1", "texto", HAIKU_45)

    assert raw_text == "{\"a\": 1}"


def test_gov_call_rejects_output_cut_at_max_tokens():
    with patch.object(
        gov_bedrock.bedrock_client,
        "converse",
        return_value=_response([{"text": "{\"a\":"}], "max_tokens"),
    ):
        with pytest.raises(OutputTruncatedError):
            gov_bedrock.invoke_bedrock_gov_doc("doc-1", "texto", HAIKU_45)
