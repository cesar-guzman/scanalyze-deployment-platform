"""GUG-542: the personal extractor sends only settings its model accepts."""

from unittest.mock import patch

import pytest

from personal_worker import bedrock as personal_bedrock
from personal_worker.model_profile import OutputTruncatedError

HAIKU_45 = "us.anthropic.claude-haiku-4-5-20251001-v1:0"


def _response(stop_reason):
    return {
        "output": {"message": {"content": [{"toolUse": {"input": {"documentType": "ine_mx"}}}]}},
        "usage": {"inputTokens": 1, "outputTokens": 1, "totalTokens": 2},
        "metrics": {"latencyMs": 1},
        "stopReason": stop_reason,
    }


def test_personal_call_drops_top_p_for_claude_4():
    with patch.object(personal_bedrock.bedrock_client, "converse", return_value=_response("tool_use")) as converse:
        personal_bedrock.invoke_bedrock_personal_doc("doc-1", "texto", HAIKU_45)

    assert converse.call_args.kwargs["inferenceConfig"] == {"temperature": 0.0, "maxTokens": 4000}


def test_personal_call_rejects_output_cut_at_max_tokens():
    with patch.object(personal_bedrock.bedrock_client, "converse", return_value=_response("max_tokens")):
        with pytest.raises(OutputTruncatedError):
            personal_bedrock.invoke_bedrock_personal_doc("doc-1", "texto", HAIKU_45)
