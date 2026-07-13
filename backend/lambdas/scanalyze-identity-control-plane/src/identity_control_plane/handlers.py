from __future__ import annotations

import logging
from collections.abc import Callable, Mapping
from typing import Any

from .pre_token import PreTokenDenied, PreTokenProcessor


def build_pre_token_handler(
    processor: PreTokenProcessor,
    *,
    logger: logging.Logger | None = None,
) -> Callable[[Mapping[str, Any], object], dict[str, Any]]:
    """Wrap the pre-token processor and sanitize unexpected failures.

    The deployed SQS control path is composed exclusively by
    ``entrypoints.build_control_processor_entrypoint``. Keeping it out of this
    module prevents an alternate handler from bypassing the exact queue/region
    binding and FIFO stop-first-failure behavior.
    """

    safe_logger = logger or logging.getLogger(__name__)

    def handler(event: Mapping[str, Any], context: object) -> dict[str, Any]:
        del context
        try:
            return processor.handle(event)
        except PreTokenDenied:
            raise
        except Exception:
            safe_logger.error("pre_token_handler_failed")
            raise PreTokenDenied("pre_token_runtime_failure") from None

    return handler
