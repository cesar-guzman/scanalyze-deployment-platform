"""Fail-closed human-side invoker for the GUG-221 private Lambda PEP.

The operator session has no direct Identity Center, Identity Store, IAM, STS
relay, or DynamoDB mutation authority.  This client can invoke only the three
reviewed, version-qualified Lambda aliases with an empty JSON object.  It never
retries an invocation and validates the returned public receipt before it can
be used as evidence.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass
from datetime import datetime
import json
import os
from pathlib import Path
import pwd
import re
import stat
import subprocess
import tempfile
from typing import Any, Callable, Mapping, Sequence


AUTHORITY_ACCOUNT_ID = "042360977644"
AUTHORITY_ACCOUNT_SUFFIX = "7644"
MANAGEMENT_ACCOUNT_SUFFIX = "1433"
REGION = "us-east-1"
INVOKER_PERMISSION_SET_NAME = "ScanalyzeLambdaAuditRepair"
PLAN_FUNCTION_NAME = "scanalyze-authority-lambda-audit-plan"
REPAIR_FUNCTION_NAME = "scanalyze-authority-lambda-audit-repair"
READ_FUNCTION_NAME = "scanalyze-authority-lambda-audit-reconcile"
PRODUCTION_STATUS = "NO-GO"
MAX_PUBLIC_RECEIPT_BYTES = 64 * 1024
MODE_BINDINGS = {
    "plan": (PLAN_FUNCTION_NAME, "plan-v1"),
    "repair": (REPAIR_FUNCTION_NAME, "repair-v1"),
    "reconcile": (READ_FUNCTION_NAME, "reconcile-v1"),
}
MODE_INVOKE_TIMEOUTS = {
    "plan": (315, 330),
    "repair": (615, 630),
    "reconcile": (315, 330),
}
SYNC_CLIENT_CONTEXT_CUSTOM = {
    "scanalyze_transport": "REQUEST_RESPONSE",
    "scanalyze_work_package": "GUG-221",
}
SYNC_CLIENT_CONTEXT_B64 = base64.b64encode(
    json.dumps(
        {"custom": SYNC_CLIENT_CONTEXT_CUSTOM},
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
).decode("ascii")
PUBLIC_RECEIPT_FIELDS = frozenset(
    {
        "schema_version",
        "record_type",
        "mode",
        "status",
        "repair_id_digest",
        "source_commit",
        "function_version",
        "function_qualifier",
        "region",
        "authority_account_suffix",
        "management_account_suffix",
        "intent_digest",
        "ledger_digest",
        "state_digest",
        "effects_attempted",
        "effects_completed",
        "mutation_attribution",
        "required_next_action",
        "generated_at",
        "production_status",
    }
)
PUBLIC_STATUSES = frozenset(
    {
        "PLAN_VERIFIED",
        "REPAIR_VERIFIED",
        "RECONCILE_VERIFIED",
        "BLOCKED",
        "UNCERTAIN_RECONCILE_ONLY",
    }
)
NEXT_ACTIONS = frozenset(
    {
        "NONE",
        "INVOKE_REPAIR_ALIAS",
        "INVOKE_RECONCILE_ALIAS",
        "REVIEW_BLOCKER",
    }
)
MUTATION_ATTRIBUTIONS = frozenset({"PROVEN_BY_DURABLE_LEDGER", "UNPROVEN"})

_PROFILE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
_SESSION_ARN_RE = re.compile(
    rf"^arn:aws:sts::{AUTHORITY_ACCOUNT_ID}:assumed-role/"
    rf"AWSReservedSSO_{INVOKER_PERMISSION_SET_NAME}_[0-9A-Fa-f]{{16}}/"
    r"[A-Za-z0-9+=,.@_-]{2,64}$"
)
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
_VERSION_RE = re.compile(r"^[1-9][0-9]*$")
_TIMESTAMP_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")


class BrokerInvokeError(RuntimeError):
    """A stable, sanitized client-side invocation failure."""

    def __init__(self, code: str, *, may_have_reached_function: bool = False) -> None:
        super().__init__(code)
        self.code = code
        self.may_have_reached_function = may_have_reached_function


@dataclass(frozen=True)
class AwsCommandResult:
    returncode: int
    stdout: str


def _reject_duplicate_keys(pairs: Sequence[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise BrokerInvokeError("PUBLIC_RECEIPT_INVALID")
        result[key] = value
    return result


def _load_json_object(raw: str, code: str) -> dict[str, Any]:
    try:
        value = json.loads(raw, object_pairs_hook=_reject_duplicate_keys)
    except (json.JSONDecodeError, BrokerInvokeError) as exc:
        raise BrokerInvokeError(code) from exc
    if type(value) is not dict:
        raise BrokerInvokeError(code)
    return value


def _canonical_private_directory() -> Path:
    try:
        home = Path(pwd.getpwuid(os.geteuid()).pw_dir)
    except (KeyError, OSError) as exc:
        raise BrokerInvokeError("PRIVATE_DIRECTORY_UNAVAILABLE") from exc
    return home / ".scanalyze-private-evidence" / "gug-221-broker-invocations-v1"


def _private_directory() -> Path:
    directory = _canonical_private_directory()
    try:
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        details = directory.lstat()
        if stat.S_ISLNK(details.st_mode) or not stat.S_ISDIR(details.st_mode):
            raise BrokerInvokeError("PRIVATE_DIRECTORY_INVALID")
        if details.st_uid != os.geteuid():
            raise BrokerInvokeError("PRIVATE_DIRECTORY_INVALID")
        if stat.S_IMODE(details.st_mode) != 0o700:
            os.chmod(directory, 0o700)
            details = directory.lstat()
        if stat.S_IMODE(details.st_mode) != 0o700:
            raise BrokerInvokeError("PRIVATE_DIRECTORY_INVALID")
    except OSError as exc:
        raise BrokerInvokeError("PRIVATE_DIRECTORY_INVALID") from exc
    return directory


def _aws_environment() -> dict[str, str]:
    environment = dict(os.environ)
    environment.update(
        {
            "AWS_MAX_ATTEMPTS": "1",
            "AWS_RETRY_MODE": "standard",
            "AWS_PAGER": "",
            "AWS_CLI_AUTO_PROMPT": "off",
            "AWS_EC2_METADATA_DISABLED": "true",
        }
    )
    return environment


def _default_runner(command: Sequence[str], timeout_seconds: int) -> AwsCommandResult:
    try:
        completed = subprocess.run(
            list(command),
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=timeout_seconds,
            env=_aws_environment(),
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise BrokerInvokeError("AWS_COMMAND_UNCERTAIN") from exc
    return AwsCommandResult(returncode=completed.returncode, stdout=completed.stdout)


def validate_invoker_identity(identity: Mapping[str, Any]) -> None:
    if identity.get("Account") != AUTHORITY_ACCOUNT_ID:
        raise BrokerInvokeError("INVOKER_IDENTITY_INVALID")
    arn = identity.get("Arn")
    if not isinstance(arn, str) or _SESSION_ARN_RE.fullmatch(arn) is None:
        raise BrokerInvokeError("INVOKER_IDENTITY_INVALID")


def validate_public_receipt(
    receipt: Mapping[str, Any],
    *,
    expected_mode: str,
    expected_alias: str,
    expected_source_commit: str,
    expected_function_version: str,
) -> dict[str, Any]:
    """Validate the complete, sanitized public broker receipt."""

    if set(receipt) != PUBLIC_RECEIPT_FIELDS:
        raise BrokerInvokeError("PUBLIC_RECEIPT_INVALID")
    exact = {
        "schema_version": 1,
        "record_type": "scanalyze.platform_authority.lambda_audit_repair_broker_receipt.v1",
        "mode": expected_mode,
        "source_commit": expected_source_commit,
        "function_version": expected_function_version,
        "function_qualifier": expected_alias,
        "region": REGION,
        "authority_account_suffix": AUTHORITY_ACCOUNT_SUFFIX,
        "management_account_suffix": MANAGEMENT_ACCOUNT_SUFFIX,
        "production_status": PRODUCTION_STATUS,
    }
    if any(receipt.get(key) != value for key, value in exact.items()):
        raise BrokerInvokeError("PUBLIC_RECEIPT_BINDING_MISMATCH")
    if receipt.get("status") not in PUBLIC_STATUSES:
        raise BrokerInvokeError("PUBLIC_RECEIPT_INVALID")
    if receipt.get("required_next_action") not in NEXT_ACTIONS:
        raise BrokerInvokeError("PUBLIC_RECEIPT_INVALID")
    if receipt.get("mutation_attribution") not in MUTATION_ATTRIBUTIONS:
        raise BrokerInvokeError("PUBLIC_RECEIPT_INVALID")
    for key in ("repair_id_digest", "intent_digest", "state_digest"):
        if not isinstance(receipt.get(key), str) or _SHA256_RE.fullmatch(receipt[key]) is None:
            raise BrokerInvokeError("PUBLIC_RECEIPT_INVALID")
    ledger_digest = receipt.get("ledger_digest")
    if ledger_digest is not None and (
        not isinstance(ledger_digest, str) or _SHA256_RE.fullmatch(ledger_digest) is None
    ):
        raise BrokerInvokeError("PUBLIC_RECEIPT_INVALID")
    attempted = receipt.get("effects_attempted")
    completed = receipt.get("effects_completed")
    if (
        type(attempted) is not int
        or type(completed) is not int
        or attempted not in range(4)
        or completed not in range(4)
        or completed > attempted
    ):
        raise BrokerInvokeError("PUBLIC_RECEIPT_INVALID")
    generated_at = receipt.get("generated_at")
    if not isinstance(generated_at, str) or _TIMESTAMP_RE.fullmatch(generated_at) is None:
        raise BrokerInvokeError("PUBLIC_RECEIPT_INVALID")
    try:
        datetime.fromisoformat(generated_at[:-1] + "+00:00")
    except ValueError as exc:
        raise BrokerInvokeError("PUBLIC_RECEIPT_INVALID") from exc

    status = receipt["status"]
    attribution = receipt["mutation_attribution"]
    next_action = receipt["required_next_action"]
    if status == "PLAN_VERIFIED":
        if (
            expected_mode,
            expected_alias,
            attempted,
            completed,
            attribution,
            next_action,
        ) != (
            "plan",
            "plan-v1",
            0,
            0,
            "PROVEN_BY_DURABLE_LEDGER",
            "INVOKE_REPAIR_ALIAS",
        ) or ledger_digest is None:
            raise BrokerInvokeError("PUBLIC_RECEIPT_OVERCLAIM")
    elif status == "REPAIR_VERIFIED":
        if (
            expected_mode != "repair"
            or expected_alias != "repair-v1"
            or ledger_digest is None
            or (attempted, completed) != (3, 3)
            or attribution != "PROVEN_BY_DURABLE_LEDGER"
            or next_action != "NONE"
        ):
            raise BrokerInvokeError("PUBLIC_RECEIPT_OVERCLAIM")
    elif status == "RECONCILE_VERIFIED":
        if (
            expected_mode != "reconcile"
            or expected_alias != "reconcile-v1"
            or ledger_digest is None
            or (attempted, completed)
            not in {(2, 2), (3, 2), (3, 3)}
            or attribution != "PROVEN_BY_DURABLE_LEDGER"
            or next_action != "NONE"
        ):
            raise BrokerInvokeError("PUBLIC_RECEIPT_OVERCLAIM")
    elif status == "BLOCKED":
        if next_action != "REVIEW_BLOCKER":
            raise BrokerInvokeError("PUBLIC_RECEIPT_OVERCLAIM")
        if ledger_digest is None:
            if (
                expected_mode,
                expected_alias,
                attempted,
                completed,
                attribution,
            ) != ("reconcile", "reconcile-v1", 0, 0, "UNPROVEN"):
                raise BrokerInvokeError("PUBLIC_RECEIPT_OVERCLAIM")
        else:
            allowed_progress = {
                (0, 0, "UNPROVEN"),
                (1, 1, "PROVEN_BY_DURABLE_LEDGER"),
                (2, 2, "PROVEN_BY_DURABLE_LEDGER"),
            }
            if (
                expected_mode != "repair"
                or expected_alias != "repair-v1"
                or (attempted, completed, attribution) not in allowed_progress
            ):
                raise BrokerInvokeError("PUBLIC_RECEIPT_OVERCLAIM")
    elif status == "UNCERTAIN_RECONCILE_ONLY":
        if next_action != "INVOKE_RECONCILE_ALIAS":
            raise BrokerInvokeError("PUBLIC_RECEIPT_OVERCLAIM")
        if ledger_digest is None:
            if (
                expected_mode,
                expected_alias,
                attempted,
                completed,
                attribution,
            ) != ("repair", "repair-v1", 0, 0, "UNPROVEN"):
                raise BrokerInvokeError("PUBLIC_RECEIPT_OVERCLAIM")
        elif (
            expected_mode not in {"repair", "reconcile"}
            or (attempted, completed)
            not in {(1, 0), (1, 1), (2, 1), (2, 2), (3, 2), (3, 3)}
            or attribution != "PROVEN_BY_DURABLE_LEDGER"
        ):
            raise BrokerInvokeError("PUBLIC_RECEIPT_OVERCLAIM")
    else:  # Defensive: PUBLIC_STATUSES and the exact matrix must stay aligned.
        raise BrokerInvokeError("PUBLIC_RECEIPT_OVERCLAIM")
    return dict(receipt)


def _read_response(path: Path) -> dict[str, Any]:
    try:
        details = path.lstat()
        if not stat.S_ISREG(details.st_mode) or details.st_uid != os.geteuid():
            raise BrokerInvokeError("PUBLIC_RECEIPT_INVALID")
        if details.st_size <= 0 or details.st_size > MAX_PUBLIC_RECEIPT_BYTES:
            raise BrokerInvokeError("PUBLIC_RECEIPT_INVALID")
        raw = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise BrokerInvokeError("PUBLIC_RECEIPT_INVALID") from exc
    return _load_json_object(raw, "PUBLIC_RECEIPT_INVALID")


def invoke_broker(
    *,
    mode: str,
    profile: str,
    expected_source_commit: str,
    expected_function_version: str,
    allow_server_side_repair: bool,
    runner: Callable[[Sequence[str], int], AwsCommandResult] = _default_runner,
    private_directory_factory: Callable[[], Path] = _private_directory,
) -> dict[str, Any]:
    """Invoke one exact alias once and return a validated public receipt."""

    binding = MODE_BINDINGS.get(mode)
    if binding is None:
        raise BrokerInvokeError("MODE_INVALID")
    if not isinstance(profile, str) or _PROFILE_RE.fullmatch(profile) is None:
        raise BrokerInvokeError("PROFILE_INVALID")
    if _COMMIT_RE.fullmatch(expected_source_commit) is None:
        raise BrokerInvokeError("SOURCE_COMMIT_INVALID")
    if _VERSION_RE.fullmatch(expected_function_version) is None:
        raise BrokerInvokeError("FUNCTION_VERSION_INVALID")
    if (mode == "repair") != allow_server_side_repair:
        raise BrokerInvokeError("REPAIR_CONFIRMATION_INVALID")

    sts = runner(
        (
            "aws",
            "--profile",
            profile,
            "--region",
            REGION,
            "--no-cli-pager",
            "sts",
            "get-caller-identity",
            "--output",
            "json",
        ),
        30,
    )
    if sts.returncode != 0:
        raise BrokerInvokeError("STS_PREFLIGHT_BLOCKED")
    validate_invoker_identity(_load_json_object(sts.stdout, "STS_PREFLIGHT_BLOCKED"))

    function_name, alias = binding
    cli_read_timeout, process_timeout = MODE_INVOKE_TIMEOUTS[mode]
    directory = private_directory_factory()
    handle = tempfile.NamedTemporaryFile(
        mode="w",
        prefix="response-",
        suffix=".json",
        dir=directory,
        delete=False,
        encoding="utf-8",
    )
    response_path = Path(handle.name)
    handle.close()
    os.chmod(response_path, 0o600)
    try:
        try:
            response = runner(
                (
                    "aws",
                    "--profile",
                    profile,
                    "--region",
                    REGION,
                    "--no-cli-pager",
                    "--cli-connect-timeout",
                    "10",
                    "--cli-read-timeout",
                    str(cli_read_timeout),
                    "lambda",
                    "invoke",
                    "--function-name",
                    function_name,
                    "--qualifier",
                    alias,
                    "--invocation-type",
                    "RequestResponse",
                    "--client-context",
                    SYNC_CLIENT_CONTEXT_B64,
                    "--cli-binary-format",
                    "raw-in-base64-out",
                    "--payload",
                    "{}",
                    "--output",
                    "json",
                    str(response_path),
                ),
                process_timeout,
            )
        except BrokerInvokeError as exc:
            raise BrokerInvokeError(
                "INVOKE_RESPONSE_UNCERTAIN", may_have_reached_function=True
            ) from exc
        if response.returncode != 0:
            raise BrokerInvokeError(
                "INVOKE_RESPONSE_UNCERTAIN", may_have_reached_function=True
            )
        try:
            metadata = _load_json_object(
                response.stdout, "INVOKE_RESPONSE_UNCERTAIN"
            )
            if (
                metadata.get("StatusCode") != 200
                or metadata.get("ExecutedVersion") != expected_function_version
                or "FunctionError" in metadata
            ):
                raise BrokerInvokeError("INVOKE_RESPONSE_UNCERTAIN")
            receipt = _read_response(response_path)
            return validate_public_receipt(
                receipt,
                expected_mode=mode,
                expected_alias=alias,
                expected_source_commit=expected_source_commit,
                expected_function_version=expected_function_version,
            )
        except BrokerInvokeError as exc:
            # A successful transport return does not prove that the function
            # was side-effect free. Once ``lambda invoke`` has been dispatched,
            # every metadata, response-file, or receipt-validation failure is
            # an uncertain outcome and must force read-only reconciliation.
            raise BrokerInvokeError(
                "INVOKE_RESPONSE_UNCERTAIN", may_have_reached_function=True
            ) from exc
    finally:
        try:
            response_path.unlink(missing_ok=True)
        except OSError:
            # The response is already public/sanitized, but a failed cleanup is
            # still treated as a local evidence-handling defect by the caller.
            pass


def sanitized_failure(error: BrokerInvokeError) -> dict[str, Any]:
    return {
        "status": (
            "UNCERTAIN_RECONCILE_ONLY"
            if error.may_have_reached_function
            else "BLOCKED"
        ),
        "reason_code": error.code,
        "required_next_action": (
            "INVOKE_RECONCILE_ALIAS"
            if error.may_have_reached_function
            else "REVIEW_BLOCKER"
        ),
        "production_status": PRODUCTION_STATUS,
    }
