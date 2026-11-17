"""Bedrock Converse settings that each model generation accepts (GUG-542).

Claude 3 accepts ``temperature`` and ``topP`` together. Claude 4 through 4.6 rejects
that pair, so only ``temperature`` is sent. Claude 4.7 and later, including the 5.x
models, reject any non-default sampling value, so none is sent. Unknown Anthropic
names also get no sampling values. Other providers keep ``temperature``.

The extractors keep identical copies of this module; a repository test fails if
they drift.
"""

import re
from typing import Any, Dict, Optional, Tuple

TRUNCATED_STOP_REASON = "max_tokens"

_INFERENCE_PROFILE_PREFIX = re.compile(r"^(us|eu|apac|au|jp|in|ca|us-gov|global)\.")
_NAMED_CLAUDE = re.compile(
    r"^anthropic\.claude-(?:haiku|sonnet|opus|fable|mythos)-(\d+)(?:-(\d{1,2}))?(?=[-:]|$)"
)
_CLAUDE_3_OUTPUT_CAP = 8192
_CLAUDE_3_HAIKU_OUTPUT_CAP = 4096


class OutputTruncatedError(ValueError):
    """The model stopped at maxTokens, so its structured output is incomplete."""


def base_model_id(model_id: str) -> str:
    """Strip a cross-region inference-profile prefix such as ``us.``."""
    return _INFERENCE_PROFILE_PREFIX.sub("", model_id.strip())


def claude_version(model_id: str) -> Optional[Tuple[int, int]]:
    """Return (major, minor) for an Anthropic Claude model ID, or None."""
    base = base_model_id(model_id)
    if base.startswith("anthropic.claude-3"):
        return (3, 0)
    match = _NAMED_CLAUDE.match(base)
    if match is None:
        return None
    return int(match.group(1)), int(match.group(2) or 0)


def inference_config(model_id: str, max_tokens: int) -> Dict[str, Any]:
    """Build the Converse ``inferenceConfig`` the given model accepts."""
    if not isinstance(model_id, str) or not model_id.strip():
        raise ValueError("A Bedrock model ID is required")
    if not isinstance(max_tokens, int) or isinstance(max_tokens, bool) or max_tokens < 1:
        raise ValueError("maxTokens must be a positive integer")

    base = base_model_id(model_id)
    version = claude_version(model_id)
    if version is None:
        if base.startswith("anthropic."):
            return {"maxTokens": max_tokens}
        return {"temperature": 0.0, "maxTokens": max_tokens}
    if version[0] == 3:
        cap = (
            _CLAUDE_3_HAIKU_OUTPUT_CAP
            if base.startswith("anthropic.claude-3-haiku")
            else _CLAUDE_3_OUTPUT_CAP
        )
        return {"temperature": 0.0, "topP": 0.1, "maxTokens": min(max_tokens, cap)}
    if version < (4, 7):
        return {"temperature": 0.0, "maxTokens": max_tokens}
    return {"maxTokens": max_tokens}


def output_was_truncated(response: Dict[str, Any]) -> bool:
    """True when Converse stopped because it reached maxTokens."""
    return response.get("stopReason") == TRUNCATED_STOP_REASON
