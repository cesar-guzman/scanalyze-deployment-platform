#!/usr/bin/env python3
"""Invoke the AWS-enforced GUG-215 retained Change Set retirement PEP.

The human-facing client has no direct CloudFormation or DynamoDB mutation
path. It invokes one immutable Lambda alias with an empty payload after
verifying the exact identity-enhanced invoker role.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any


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


class AwsMutationUncertain(RuntimeError):
    """A broker invocation did not return an attributable response."""


def _partition(region: str) -> str:
    if region.startswith("cn-"):
        return "aws-cn"
    if region.startswith("us-gov-"):
        return "aws-us-gov"
    return "aws"


def _require_sso_environment() -> None:
    if any(os.environ.get(name) for name in FORBIDDEN_CREDENTIAL_ENV):
        raise RetirementAuthorizationError(
            "static or ambient role credentials are forbidden"
        )
    if not os.environ.get("AWS_PROFILE"):
        raise RetirementAuthorizationError("an explicit AWS SSO profile is required")


class AwsCli:
    """Sanitized AWS CLI adapter for identity readback and broker invocation."""

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

    def invoke_broker_once(self, *, alias: str) -> dict[str, Any]:
        if alias not in BROKER_ALIASES:
            raise RetirementAuthorizationError("broker alias is not authorized")
        invocation_env = os.environ.copy()
        invocation_env.update({"AWS_MAX_ATTEMPTS": "1", "AWS_RETRY_MODE": "standard"})
        descriptor, output_name = tempfile.mkstemp(prefix="gug215-broker-", suffix=".json")
        os.close(descriptor)
        output_path = Path(output_name)
        output_path.chmod(0o600)
        try:
            completed = subprocess.run(
                self._command(
                    "lambda",
                    "invoke",
                    "--function-name",
                    f"{BROKER_FUNCTION_NAME}:{alias}",
                    "--invocation-type",
                    "RequestResponse",
                    "--cli-binary-format",
                    "raw-in-base64-out",
                    "--payload",
                    "{}",
                    str(output_path),
                ),
                check=False,
                capture_output=True,
                text=True,
                env=invocation_env,
            )
            if completed.returncode != 0:
                raise AwsMutationUncertain("broker invocation response is ambiguous")
            metadata = json.loads(completed.stdout or "{}")
            response = json.loads(output_path.read_text(encoding="utf-8") or "{}")
            allowed_response_keys = {
                "status",
                "reason_code",
                "ledger_digest",
                "next_required_control",
            }
            if (
                not isinstance(metadata, dict)
                or metadata.get("StatusCode") != 200
                or metadata.get("FunctionError") is not None
                or not isinstance(response, dict)
                or set(response) - allowed_response_keys
            ):
                raise AwsMutationUncertain("broker invocation response is ambiguous")
            return response
        except json.JSONDecodeError as exc:
            raise AwsMutationUncertain("broker invocation response is ambiguous") from exc
        finally:
            output_path.unlink(missing_ok=True)


def _broker_identity(
    client: AwsCli,
    *,
    authority_account_id: str,
    region: str,
    alias: str,
) -> None:
    if ACCOUNT_ID.fullmatch(authority_account_id) is None:
        raise RetirementAuthorizationError("authority account ID is malformed")
    expected_role = (
        "ScanalyzeGug215ClassifierInvoker"
        if alias == "classify"
        else "ScanalyzeGug215ApproverInvoker"
    )
    response = client.get_caller_identity()
    arn = response.get("Arn")
    account = response.get("Account")
    pattern = re.compile(
        rf"^arn:{re.escape(_partition(region))}:sts::"
        rf"{re.escape(authority_account_id)}:assumed-role/"
        rf"{re.escape(expected_role)}/[A-Za-z0-9+=,.@_-]{{2,64}}$"
    )
    if (
        account != authority_account_id
        or not isinstance(arn, str)
        or pattern.fullmatch(arn) is None
    ):
        raise RetirementAuthorizationError(
            "caller does not use the exact identity-enhanced broker invocation role"
        )


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
    _require_sso_environment()
    client = AwsCli(region=args.region)
    _broker_identity(
        client,
        authority_account_id=args.authority_account_id,
        region=args.region,
        alias=alias,
    )
    response = client.invoke_broker_once(alias=alias)
    status = response.get("status")
    if status == "DENY":
        reason = response.get("reason_code", "BROKER_DENIED")
        raise RetirementAuthorizationError(f"broker denied the request: {reason}")
    if not isinstance(status, str):
        raise RetirementAuthorizationError("broker response is incomplete")
    print(f"BROKER_STATUS: {status}")
    if isinstance(response.get("ledger_digest"), str):
        print(f"LEDGER_DIGEST: {response['ledger_digest']}")
    if isinstance(response.get("next_required_control"), str):
        print(f"NEXT_REQUIRED_CONTROL: {response['next_required_control']}")
    print("AWS_CHANGE: exact GUG-215 broker invocation only")


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
    except (RetirementAuthorizationError, AwsCliError, AwsMutationUncertain) as exc:
        print(f"DENY: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
