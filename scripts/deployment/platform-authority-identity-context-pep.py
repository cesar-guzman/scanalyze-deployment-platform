#!/usr/bin/env python3
"""Offline control surface for the GUG-217 identity-context PEP.

This command never opens a browser, exchanges an authorization code, creates
an STS session, invokes Lambda, mutates the retirement ledger, or calls AWS.
The live proof flow remains deployment- and two-operator-gated.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from tooling.platform_authority_identity_context_pep import (  # noqa: E402
    ProofBoundaryError,
    proof_compatibility_decision,
)


def _compatibility_check(_: argparse.Namespace) -> None:
    decision = proof_compatibility_decision()
    print(f"COMPATIBILITY_STATUS: {decision.status}")
    print(f"MANAGED_POLICY_VERSION: {decision.policy_version}")
    print(f"MANAGED_POLICY_DIGEST: {decision.policy_digest}")
    print(f"PROOF_REQUIRED_ACTION: {decision.required_action}")
    print("PROOF_AUTHORITY: DENY_ALL")
    print("TOKEN_ISSUED: false")
    print("STS_PROOF_SESSION_ISSUED: false")
    print("BROKER_INVOCATION_PERFORMED: false")
    print("AWS_EFFECT_PERFORMED: false")
    print("CURRENT_HUMAN_OPERATOR_COUNT: 1")
    print("INDEPENDENT_APPROVER_AVAILABLE: false")
    print("LIVE_RETIREMENT_AUTHORIZED: false")
    print("PRODUCTION: NO-GO")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Validate the GUG-217 proof-only transport offline"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    check = subparsers.add_parser(
        "compatibility-check",
        help="Validate the reviewed v12 sts:SetContext proof boundary",
    )
    check.set_defaults(handler=_compatibility_check)
    return parser


def main() -> int:
    args = _parser().parse_args()
    try:
        args.handler(args)
    except ProofBoundaryError as exc:
        print(f"DENY: {exc.code}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
