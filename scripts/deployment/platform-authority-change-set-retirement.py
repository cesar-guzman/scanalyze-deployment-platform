#!/usr/bin/env python3
"""Fail-closed client boundary for the GUG-215 retirement PEP.

GUG-216 proved that the STS-managed identity-context allowlist currently
blocks ``lambda:InvokeFunction``. The historical AWS_PROFILE invocation path
is therefore disabled. This file preserves the reviewed command surface but
never exchanges tokens, assumes a role, or invokes Lambda.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from tooling.platform_authority_identity_context_compatibility import (
    COMPATIBLE_REVIEWED_ACTION,
    bundled_compatibility_decision,
)  # noqa: E402


BROKER_FUNCTION_NAME = "scanalyze-platform-authority-gug215-retirement"
BROKER_ALIASES = frozenset({"classify", "retire", "reconcile"})
ACCOUNT_ID = re.compile(r"^(?!000000000000$)[0-9]{12}$")
REGION = re.compile(r"^[a-z]{2}(?:-[a-z]+)+-[0-9]+$")
FORBIDDEN_CREDENTIAL_ENV = frozenset(
    {
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
        "AWS_SESSION_TOKEN",
        "AWS_WEB_IDENTITY_TOKEN_FILE",
        "AWS_ROLE_ARN",
    }
)


class RetirementAuthorizationError(RuntimeError):
    """The requested operation does not satisfy the GUG-215 boundary."""


class AwsCliError(RuntimeError):
    """A sanitized AWS CLI read failed."""


def _require_sso_environment() -> None:
    if any(os.environ.get(name) for name in FORBIDDEN_CREDENTIAL_ENV):
        raise RetirementAuthorizationError(
            "static or ambient role credentials are forbidden"
        )
    if not os.environ.get("AWS_PROFILE"):
        raise RetirementAuthorizationError("an explicit AWS SSO profile is required")


class AwsCli:
    """Sanitized AWS CLI adapter for read-only caller identity checks."""

    def __init__(self, *, region: str) -> None:
        if REGION.fullmatch(region) is None:
            raise RetirementAuthorizationError("region is malformed")
        self.region = region

    def _command(self, *parts: str) -> list[str]:
        return [
            "aws",
            *parts,
            "--region",
            self.region,
            "--output",
            "json",
            "--no-cli-pager",
        ]

    def get_caller_identity(self) -> dict[str, Any]:
        completed = subprocess.run(
            self._command("sts", "get-caller-identity"),
            check=False,
            capture_output=True,
            text=True,
            env=os.environ.copy(),
        )
        if completed.returncode != 0:
            raise AwsCliError("STS identity read failed")
        try:
            value = json.loads(completed.stdout or "{}")
        except json.JSONDecodeError as exc:
            raise AwsCliError("AWS read returned malformed JSON") from exc
        if not isinstance(value, dict):
            raise AwsCliError("AWS read returned a non-object response")
        return value

def _cmd_broker(args: argparse.Namespace) -> None:
    alias = str(args.broker_alias)
    if alias == "classify" and not args.allow_broker_classification:
        raise RetirementAuthorizationError(
            "classification requires --allow-broker-classification"
        )
    if alias == "retire" and not args.allow_retire_exact_change_set:
        raise RetirementAuthorizationError(
            "retirement requires --allow-retire-exact-change-set"
        )
    if alias == "reconcile" and not args.allow_broker_reconciliation:
        raise RetirementAuthorizationError(
            "reconciliation requires --allow-broker-reconciliation"
        )
    decision = bundled_compatibility_decision()
    if decision.status != COMPATIBLE_REVIEWED_ACTION:
        raise RetirementAuthorizationError(decision.status)
    raise RetirementAuthorizationError("IDENTITY_ENHANCED_LIVE_ENTRYPOINT_NOT_REVIEWED")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Invoke the AWS-enforced retained Change Set retirement PEP"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    commands = (
        ("broker-classify", "classify", "Create one exact durable classification"),
        ("broker-retire", "retire", "Claim and attempt one exact retirement"),
        ("broker-reconcile", "reconcile", "Reconcile absence without retrying delete"),
    )
    for command, alias, help_text in commands:
        subparser = subparsers.add_parser(command, help=help_text)
        subparser.add_argument("--authority-account-id", required=True)
        subparser.add_argument("--region", required=True)
        subparser.add_argument("--allow-broker-classification", action="store_true")
        subparser.add_argument("--allow-retire-exact-change-set", action="store_true")
        subparser.add_argument("--allow-broker-reconciliation", action="store_true")
        subparser.set_defaults(handler=_cmd_broker, broker_alias=alias)
    return parser


def main() -> int:
    args = _parser().parse_args()
    try:
        args.handler(args)
    except (RetirementAuthorizationError, AwsCliError) as exc:
        print(f"DENY: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
