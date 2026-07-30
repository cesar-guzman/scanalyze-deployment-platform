#!/usr/bin/env python3
"""Invoke the private GUG-221 repair PEP with an empty payload.

This entrypoint never calls Identity Center, Identity Store, IAM, STS relay,
or DynamoDB mutation APIs.  The only protected effect available to the human
operator is synchronous invocation of one exact, version-qualified Lambda
alias in the authority account.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys


REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from tooling.platform_authority_lambda_audit_repair_invoker import (  # noqa: E402
    BrokerInvokeError,
    MODE_BINDINGS,
    invoke_broker,
    sanitized_failure,
)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Invoke the fail-closed GUG-221 private Lambda PEP once."
    )
    parser.add_argument("mode", choices=tuple(MODE_BINDINGS))
    parser.add_argument(
        "--profile",
        required=True,
        help="Exact authority-account ScanalyzeLambdaAuditRepair SSO profile.",
    )
    parser.add_argument(
        "--expected-source-commit",
        required=True,
        help="Reviewed 40-character source commit bound into the Lambda version.",
    )
    parser.add_argument(
        "--expected-function-version",
        required=True,
        help="Published numeric Lambda version behind the reviewed alias.",
    )
    parser.add_argument(
        "--allow-server-side-repair",
        action="store_true",
        help="Required only for repair; it does not bypass server-side controls.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        receipt = invoke_broker(
            mode=args.mode,
            profile=args.profile,
            expected_source_commit=args.expected_source_commit,
            expected_function_version=args.expected_function_version,
            allow_server_side_repair=args.allow_server_side_repair,
        )
    except BrokerInvokeError as exc:
        print(json.dumps(sanitized_failure(exc), sort_keys=True, separators=(",", ":")))
        return 3 if exc.may_have_reached_function else 2
    print(json.dumps(receipt, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
