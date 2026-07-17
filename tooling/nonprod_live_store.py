"""Separated AWS CLI adapters for GUG-125 plan storage and execution ledger.

The adapter accepts only already-authorized metadata. It never prints AWS
responses, plan bytes, object locators, credentials, or ledger documents.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

from tooling.authorize_deployment_backend import AuthorizationError


CommandRunner = Callable[[Sequence[str]], str]
ROLE_ARN = re.compile(
    r"^arn:aws(?:-[a-z]+)*:sts::(?P<account>[0-9]{12}):"
    r"assumed-role/(?P<role>[A-Za-z0-9+=,.@_/-]+)/[^/]+$"
)
IAM_ROLE_ARN = re.compile(
    r"^arn:aws(?:-[a-z]+)*:iam::(?P<account>[0-9]{12}):"
    r"role/(?P<role>[A-Za-z0-9+=,.@_/-]+)$"
)
TERMINAL_ROLES = frozenset(
    {
        "ScanalyzeCustomer-Plan",
        "ScanalyzeCustomer-Apply",
        "ScanalyzeCustomer-Identity-Plan",
        "ScanalyzeCustomer-Identity-Apply",
        "ScanalyzeCustomer-Promotion",
        "ScanalyzeCustomer-Validation",
    }
)
DEPLOYMENT_ID = re.compile(r"^dep_[0-9A-HJKMNP-TV-Z]{26}$")


def _default_runner(command: Sequence[str]) -> str:
    try:
        result = subprocess.run(
            list(command),
            check=True,
            capture_output=True,
            text=True,
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        raise AuthorizationError("AWS live-store operation failed") from exc
    return result.stdout


def _json_output(raw: str, label: str) -> dict[str, Any]:
    try:
        value = json.loads(raw)
    except (TypeError, json.JSONDecodeError) as exc:
        raise AuthorizationError(f"{label} returned an invalid response") from exc
    if not isinstance(value, dict):
        raise AuthorizationError(f"{label} returned an invalid response")
    return value


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            for block in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(block)
    except OSError as exc:
        raise AuthorizationError("saved plan readback failed") from exc
    return "sha256:" + digest.hexdigest()


def _ddb_item(document: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "deployment_id": {"S": document["deployment_id"]},
        "record_key": {"S": f"execution#{document['execution_id']}#{document['layer']}"},
        "ledger_version": {"N": str(document["ledger_version"])},
        "ledger_digest": {"S": document["ledger_digest"]},
        "status": {"S": document["status"]},
        "document": {"S": json.dumps(document, sort_keys=True, separators=(",", ":"))},
    }


class AwsCliPlanStore:
    """Destination-account adapter for an immutable exact saved plan."""

    def __init__(
        self,
        *,
        region: str,
        account_id: str,
        runner: CommandRunner = _default_runner,
    ) -> None:
        if not re.fullmatch(r"^[a-z]{2}(?:-[a-z]+)+-[0-9]+$", region):
            raise AuthorizationError("AWS region binding is invalid")
        if not re.fullmatch(r"^(?!000000000000$)[0-9]{12}$", account_id):
            raise AuthorizationError("AWS account binding is invalid")
        self.region = region
        self.account_id = account_id
        self._run = runner

    def verify_terminal_identity(self, expected_role: str) -> dict[str, str]:
        if expected_role not in TERMINAL_ROLES:
            raise AuthorizationError("terminal role is not approved")
        identity = _json_output(
            self._run(
                (
                    "aws",
                    "sts",
                    "get-caller-identity",
                    "--region",
                    self.region,
                    "--output",
                    "json",
                )
            ),
            "caller identity",
        )
        match = ROLE_ARN.fullmatch(str(identity.get("Arn", "")))
        if identity.get("Account") != self.account_id or not match:
            raise AuthorizationError("terminal caller identity binding mismatch")
        if match.group("account") != self.account_id or match.group("role") != expected_role:
            raise AuthorizationError("terminal caller role binding mismatch")
        return {"account_id": self.account_id, "role": expected_role}

    def put_plan_once(
        self,
        *,
        path: Path,
        bucket: str,
        object_key: str,
        kms_key_arn: str,
    ) -> dict[str, Any]:
        if not path.is_file() or path.is_symlink():
            raise AuthorizationError("saved plan input must be a regular file")
        response = _json_output(
            self._run(
                (
                    "aws",
                    "s3api",
                    "put-object",
                    "--region",
                    self.region,
                    "--bucket",
                    bucket,
                    "--key",
                    object_key,
                    "--body",
                    str(path),
                    "--server-side-encryption",
                    "aws:kms",
                    "--ssekms-key-id",
                    kms_key_arn,
                    "--bucket-key-enabled",
                    "--checksum-algorithm",
                    "SHA256",
                    "--if-none-match",
                    "*",
                    "--output",
                    "json",
                )
            ),
            "saved plan write",
        )
        version_id = response.get("VersionId")
        if not isinstance(version_id, str) or not version_id or version_id == "null":
            raise AuthorizationError("saved plan write did not return an immutable version")
        return {
            "bucket": bucket,
            "object_key": object_key,
            "object_version_id": version_id,
            "sha256": _sha256(path),
            "size_bytes": path.stat().st_size,
        }

    def get_plan_version(
        self,
        *,
        bucket: str,
        object_key: str,
        object_version_id: str,
        destination: Path,
    ) -> dict[str, Any]:
        if destination.exists() or destination.is_symlink():
            raise AuthorizationError("saved plan destination must not already exist")
        if not destination.parent.is_dir() or destination.parent.is_symlink():
            raise AuthorizationError("saved plan destination directory is invalid")
        try:
            descriptor = os.open(
                destination,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
                0o600,
            )
            os.close(descriptor)
            self._run(
                (
                    "aws",
                    "s3api",
                    "get-object",
                    "--region",
                    self.region,
                    "--bucket",
                    bucket,
                    "--key",
                    object_key,
                    "--version-id",
                    object_version_id,
                    "--checksum-mode",
                    "ENABLED",
                    "--output",
                    "json",
                    str(destination),
                )
            )
            destination.chmod(0o600)
            return {
                "bucket": bucket,
                "object_key": object_key,
                "object_version_id": object_version_id,
                "sha256": _sha256(destination),
                "size_bytes": destination.stat().st_size,
            }
        except Exception:
            destination.unlink(missing_ok=True)
            raise

class AwsCliExecutionLedgerStore:
    """Shared-services adapter for the create-only, CAS execution ledger."""

    def __init__(
        self,
        *,
        region: str,
        shared_services_account_id: str,
        ledger_table: str,
        runner: CommandRunner = _default_runner,
    ) -> None:
        if not re.fullmatch(r"^[a-z]{2}(?:-[a-z]+)+-[0-9]+$", region):
            raise AuthorizationError("AWS region binding is invalid")
        if not re.fullmatch(
            r"^(?!000000000000$)[0-9]{12}$", shared_services_account_id
        ):
            raise AuthorizationError("shared-services account binding is invalid")
        if ledger_table != "scanalyze-deployment-executions":
            raise AuthorizationError("execution ledger table is not canonical")
        self.region = region
        self.shared_services_account_id = shared_services_account_id
        self.ledger_table = ledger_table
        self._run = runner

    def verify_destination_separation(
        self,
        destination_account_id: str,
    ) -> dict[str, str]:
        if not re.fullmatch(r"^(?!000000000000$)[0-9]{12}$", destination_account_id):
            raise AuthorizationError("destination account binding is invalid")
        if destination_account_id == self.shared_services_account_id:
            raise AuthorizationError(
                "shared-services authority must be separate from the destination account"
            )
        return {
            "destination_account_id": destination_account_id,
            "shared_services_account_id": self.shared_services_account_id,
        }

    def verify_orchestrator_identity(
        self,
        expected_role_arn: str,
        *,
        deployment_id: str,
    ) -> dict[str, str]:
        expected = IAM_ROLE_ARN.fullmatch(expected_role_arn)
        canonical_role = f"ScanalyzeOrchestrator-{deployment_id}"
        if (
            not DEPLOYMENT_ID.fullmatch(deployment_id)
            or not expected
            or expected.group("account") != self.shared_services_account_id
            or expected.group("role") != canonical_role
        ):
            raise AuthorizationError("orchestrator role authority is invalid")
        identity = _json_output(
            self._run(
                (
                    "aws",
                    "sts",
                    "get-caller-identity",
                    "--region",
                    self.region,
                    "--output",
                    "json",
                )
            ),
            "caller identity",
        )
        actual = ROLE_ARN.fullmatch(str(identity.get("Arn", "")))
        if (
            identity.get("Account") != self.shared_services_account_id
            or not actual
            or actual.group("account") != self.shared_services_account_id
            or actual.group("role") != expected.group("role")
        ):
            raise AuthorizationError("orchestrator caller identity binding mismatch")
        return {
            "account_id": self.shared_services_account_id,
            "role_arn": expected_role_arn,
        }

    def create_ledger(self, ledger: Mapping[str, Any]) -> None:
        self._run(
            (
                "aws",
                "dynamodb",
                "put-item",
                "--region",
                self.region,
                "--table-name",
                self.ledger_table,
                "--item",
                json.dumps(_ddb_item(ledger), sort_keys=True),
                "--condition-expression",
                "attribute_not_exists(deployment_id) AND attribute_not_exists(record_key)",
                "--return-consumed-capacity",
                "NONE",
                "--output",
                "json",
            )
        )

    def replace_ledger(
        self,
        *,
        ledger: Mapping[str, Any],
        expected_deployment_id: str,
        expected_execution_id: str,
        expected_layer: str,
        expected_version: int,
        expected_digest: str,
        expected_status: str,
    ) -> None:
        if (
            ledger.get("deployment_id") != expected_deployment_id
            or ledger.get("execution_id") != expected_execution_id
            or ledger.get("layer") != expected_layer
        ):
            raise AuthorizationError("execution ledger storage key binding mismatch")
        values = {
            ":expected_version": {"N": str(expected_version)},
            ":expected_digest": {"S": expected_digest},
            ":expected_status": {"S": expected_status},
        }
        self._run(
            (
                "aws",
                "dynamodb",
                "put-item",
                "--region",
                self.region,
                "--table-name",
                self.ledger_table,
                "--item",
                json.dumps(_ddb_item(ledger), sort_keys=True),
                "--condition-expression",
                (
                    "ledger_version = :expected_version AND ledger_digest = :expected_digest "
                    "AND #status = :expected_status"
                ),
                "--expression-attribute-names",
                json.dumps({"#status": "status"}),
                "--expression-attribute-values",
                json.dumps(values, sort_keys=True),
                "--return-consumed-capacity",
                "NONE",
                "--output",
                "json",
            )
        )

    def get_ledger(self, *, deployment_id: str, execution_id: str, layer: str) -> dict[str, Any]:
        key = {
            "deployment_id": {"S": deployment_id},
            "record_key": {"S": f"execution#{execution_id}#{layer}"},
        }
        response = _json_output(
            self._run(
                (
                    "aws",
                    "dynamodb",
                    "get-item",
                    "--region",
                    self.region,
                    "--table-name",
                    self.ledger_table,
                    "--key",
                    json.dumps(key, sort_keys=True),
                    "--consistent-read",
                    "--projection-expression",
                    "document",
                    "--output",
                    "json",
                )
            ),
            "execution ledger read",
        )
        try:
            document = json.loads(response["Item"]["document"]["S"])
        except (KeyError, TypeError, json.JSONDecodeError) as exc:
            raise AuthorizationError("execution ledger record is missing or malformed") from exc
        if not isinstance(document, dict):
            raise AuthorizationError("execution ledger record is missing or malformed")
        if (
            document.get("deployment_id") != deployment_id
            or document.get("execution_id") != execution_id
            or document.get("layer") != layer
        ):
            raise AuthorizationError("execution ledger storage key binding mismatch")
        return document
