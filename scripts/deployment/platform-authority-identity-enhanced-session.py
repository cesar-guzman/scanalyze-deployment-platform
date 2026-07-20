#!/usr/bin/env python3
"""Offline GUG-216 compatibility and evidence commands.

No command in this client calls AWS, opens a browser, creates a token, assumes
a role, or invokes the GUG-215 broker. A future live entrypoint requires a new
review after the downstream action is supported by the STS-managed policy.
"""
from __future__ import annotations

import argparse
import sys
from datetime import UTC, datetime
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from tooling.platform_authority_identity_context_compatibility import (
    CompatibilityError,
    bundled_compatibility_decision,
)  # noqa: E402


def _timestamp() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _compatibility_check(_: argparse.Namespace) -> None:
    decision = bundled_compatibility_decision()
    receipt = decision.to_receipt(observed_at=_timestamp())
    print(f"COMPATIBILITY_STATUS: {receipt['status']}")
    print(f"MANAGED_POLICY_VERSION: {receipt['managed_policy_version']}")
    print(f"MANAGED_POLICY_DIGEST: {receipt['managed_policy_digest']}")
    print("TOKEN_ISSUED: false")
    print("STS_SESSION_ISSUED: false")
    print("BROKER_INVOCATION_PERFORMED: false")
    print("INDEPENDENT_APPROVER_AVAILABLE: false")
    print("PRODUCTION: NO-GO")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Validate GUG-216 identity-context compatibility offline"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    check = subparsers.add_parser(
        "compatibility-check",
        help="Evaluate the reviewed STS managed-policy snapshot without AWS",
    )
    check.set_defaults(handler=_compatibility_check)
    return parser


def main() -> int:
    args = _parser().parse_args()
    try:
        args.handler(args)
    except CompatibilityError as exc:
        print(f"DENY: {exc.code}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
