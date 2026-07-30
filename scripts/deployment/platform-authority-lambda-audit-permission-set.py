#!/usr/bin/env python3
"""Provision and prove the dedicated GUG-220 Identity Center collector.

The write path is deliberately narrow: create one permission set, attach one
inline policy, create one direct USER assignment, and provision it to one
non-production authority account.  Mutations use a single AWS attempt.  Any
ambiguous response stops the workflow and permits only read-only reconciliation.
"""
from __future__ import annotations

import argparse
import json
import os
import pwd
import re
import stat
import subprocess
import sys
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Mapping, Sequence


REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from tooling.platform_authority_lambda_audit_permission_set import (  # noqa: E402
    AUTHORITY_ACCOUNT_ID,
    AUTHORITY_REGION,
    COLLECTOR_PERMISSION_SET_DESCRIPTION,
    COLLECTOR_PERMISSION_SET_NAME,
    EXPECTED_TAGS,
    IDENTITY_CENTER_REGION,
    MANAGEMENT_ACCOUNT_ID,
    SESSION_DURATION,
    AuditPermissionSetError,
    build_execution_ledger,
    build_provisioning_intent,
    build_provisioning_receipt,
    canonical_digest,
    current_provisioning_source_commit,
    exact_permission_set_readback,
    render_exact_collector_policy,
    required_provisioning_actions,
    sealed_collector_policy_for_intent,
    validate_collector_trust_policy,
    validate_execution_ledger_directory_binding,
    validate_intent_authority_binding,
    validate_intent_execution_binding,
    validate_provisioning_intent,
    validate_provisioning_source_commit_binding,
)


FORBIDDEN_CREDENTIAL_ENV = frozenset(
    {
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
        "AWS_SESSION_TOKEN",
        "AWS_WEB_IDENTITY_TOKEN_FILE",
        "AWS_ROLE_ARN",
    }
)
FORBIDDEN_TRANSPORT_ENV = frozenset(
    {
        "AWS_ENDPOINT_URL",
        "AWS_ENDPOINT_URL_STS",
        "AWS_ENDPOINT_URL_IAM",
        "AWS_ENDPOINT_URL_SSO",
        "AWS_ENDPOINT_URL_SSO_ADMIN",
        "AWS_ENDPOINT_URL_IDENTITYSTORE",
        "AWS_ENDPOINT_URL_IDENTITY_STORE",
        "AWS_CA_BUNDLE",
        "REQUESTS_CA_BUNDLE",
        "SSL_CERT_FILE",
    }
)
SSO_ARN = re.compile(
    r"^arn:aws:sts::(?P<account>[0-9]{12}):assumed-role/"
    r"(?P<role>AWSReservedSSO_[A-Za-z0-9+=,.@_-]+_[0-9A-Fa-f]{16})/"
    r"(?P<session>[A-Za-z0-9+=,.@_-]{2,64})$"
)
COLLECTOR_ROLE_NAME = re.compile(
    rf"AWSReservedSSO_{re.escape(COLLECTOR_PERMISSION_SET_NAME)}_"
    r"[0-9A-Fa-f]{16}"
)
SAML_PROVIDER_ARN = re.compile(
    rf"arn:aws:iam::{AUTHORITY_ACCOUNT_ID}:saml-provider/"
    r"AWSSSO_[0-9A-Fa-f]{16}_DO_NOT_DELETE"
)
PERMISSION_SET_ARN = re.compile(
    r"arn:aws:sso:::permissionSet/ssoins-[0-9a-f]{16}/ps-[0-9a-f]{16}"
)
MAX_PAGES = 100
CLI_PAGE_ITEMS = 100
MAX_POLLS = 60


class AwsReadError(RuntimeError):
    """A sanitized AWS read failure."""


class AwsMutationUncertain(RuntimeError):
    """A write may have succeeded and must never be blindly retried."""


def _now() -> datetime:
    return datetime.now(tz=UTC).replace(microsecond=0)


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise AuditPermissionSetError("PRIVATE_JSON_DUPLICATE_KEY")
        value[key] = item
    return value


def _private_input(path: Path) -> Path:
    source = Path(os.path.abspath(os.path.expanduser(os.fspath(path))))
    try:
        source.relative_to(REPO_ROOT.resolve())
    except ValueError:
        pass
    else:
        raise AuditPermissionSetError("PRIVATE_INPUT_INSIDE_REPOSITORY")
    try:
        metadata = source.lstat()
    except OSError as exc:
        raise AuditPermissionSetError("PRIVATE_INPUT_INVALID") from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise AuditPermissionSetError("PRIVATE_INPUT_INVALID")
    return source


def _read_private_bytes(path: Path, *, maximum_bytes: int) -> bytes:
    source = _private_input(path)
    nofollow = getattr(os, "O_NOFOLLOW", None)
    if nofollow is None:
        raise AuditPermissionSetError("PRIVATE_INPUT_NOFOLLOW_UNAVAILABLE")
    try:
        descriptor = os.open(source, os.O_RDONLY | nofollow)
    except OSError as exc:
        raise AuditPermissionSetError("PRIVATE_INPUT_UNREADABLE") from exc
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.getuid()
            or metadata.st_nlink != 1
        ):
            raise AuditPermissionSetError("PRIVATE_INPUT_INVALID")
        if stat.S_IMODE(metadata.st_mode) != 0o600:
            raise AuditPermissionSetError("PRIVATE_INPUT_MODE_INVALID")
        try:
            resolved = source.resolve(strict=True)
            resolved_metadata = resolved.stat()
            resolved.relative_to(REPO_ROOT.resolve())
        except ValueError:
            pass
        except OSError as exc:
            raise AuditPermissionSetError("PRIVATE_INPUT_INVALID") from exc
        else:
            raise AuditPermissionSetError("PRIVATE_INPUT_INSIDE_REPOSITORY")
        if (
            resolved_metadata.st_dev != metadata.st_dev
            or resolved_metadata.st_ino != metadata.st_ino
        ):
            raise AuditPermissionSetError("PRIVATE_INPUT_CHANGED")
        chunks: list[bytes] = []
        remaining = maximum_bytes + 1
        while remaining > 0:
            chunk = os.read(descriptor, min(remaining, 65536))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        payload = b"".join(chunks)
        if len(payload) > maximum_bytes:
            raise AuditPermissionSetError("PRIVATE_INPUT_TOO_LARGE")
        return payload
    finally:
        os.close(descriptor)


def _output_path(
    path: Path, *, already_exists_code: str = "PRIVATE_OUTPUT_INVALID"
) -> Path:
    target = Path(os.path.abspath(os.path.expanduser(os.fspath(path))))
    try:
        target.relative_to(REPO_ROOT.resolve())
    except ValueError:
        pass
    else:
        raise AuditPermissionSetError("PRIVATE_OUTPUT_INSIDE_REPOSITORY")
    try:
        target.lstat()
    except FileNotFoundError:
        pass
    except OSError as exc:
        raise AuditPermissionSetError("PRIVATE_OUTPUT_INVALID") from exc
    else:
        raise AuditPermissionSetError(already_exists_code)
    directory = _private_directory(target.parent)
    return directory / target.name


def _private_directory(path: Path) -> Path:
    source = Path(os.path.abspath(os.path.expanduser(os.fspath(path))))
    try:
        source.relative_to(REPO_ROOT.resolve())
    except ValueError:
        pass
    else:
        raise AuditPermissionSetError("PRIVATE_DIRECTORY_INSIDE_REPOSITORY")
    nofollow = getattr(os, "O_NOFOLLOW", None)
    directory_flag = getattr(os, "O_DIRECTORY", None)
    if nofollow is None or directory_flag is None:
        raise AuditPermissionSetError("PRIVATE_DIRECTORY_NOFOLLOW_UNAVAILABLE")
    try:
        descriptor = os.open(source, os.O_RDONLY | nofollow | directory_flag)
    except OSError as exc:
        raise AuditPermissionSetError("PRIVATE_DIRECTORY_INVALID") from exc
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != os.getuid()
            or stat.S_IMODE(metadata.st_mode) != 0o700
        ):
            raise AuditPermissionSetError("PRIVATE_OUTPUT_DIRECTORY_MODE_INVALID")
        try:
            resolved = source.resolve(strict=True)
            resolved_metadata = resolved.stat()
            resolved.relative_to(REPO_ROOT.resolve())
        except ValueError:
            pass
        except OSError as exc:
            raise AuditPermissionSetError("PRIVATE_DIRECTORY_INVALID") from exc
        else:
            raise AuditPermissionSetError("PRIVATE_DIRECTORY_INSIDE_REPOSITORY")
        if (
            resolved_metadata.st_dev != metadata.st_dev
            or resolved_metadata.st_ino != metadata.st_ino
        ):
            raise AuditPermissionSetError("PRIVATE_DIRECTORY_CHANGED")
        return resolved
    finally:
        os.close(descriptor)


def _canonical_execution_ledger_directory() -> Path:
    try:
        home = Path(pwd.getpwuid(os.geteuid()).pw_dir)
    except (KeyError, OSError):
        raise AuditPermissionSetError("EXECUTION_LEDGER_HOME_INVALID") from None
    return home / ".scanalyze-private-evidence" / "gug-220-live-v2"


def _bound_execution_ledger_directory(path: Path) -> Path:
    expected_source = Path(os.path.abspath(_canonical_execution_ledger_directory()))
    requested_source = Path(os.path.abspath(os.path.expanduser(os.fspath(path))))
    if requested_source != expected_source:
        raise AuditPermissionSetError("EXECUTION_LEDGER_DIRECTORY_NOT_CANONICAL")
    resolved = _private_directory(requested_source)
    try:
        expected = expected_source.resolve(strict=True)
    except OSError:
        raise AuditPermissionSetError("EXECUTION_LEDGER_DIRECTORY_INVALID") from None
    if expected != expected_source or resolved != expected:
        raise AuditPermissionSetError("EXECUTION_LEDGER_DIRECTORY_NOT_CANONICAL")
    return resolved


def _read_private_line(path: Path) -> str:
    try:
        value = _read_private_bytes(path, maximum_bytes=1024).decode("utf-8").strip()
    except UnicodeError as exc:
        raise AuditPermissionSetError("PRIVATE_INPUT_UNREADABLE") from exc
    if not value or "\n" in value or "\r" in value or len(value) > 320:
        raise AuditPermissionSetError("PRIVATE_LINE_INVALID")
    return value


def _read_private_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(
            _read_private_bytes(path, maximum_bytes=1024 * 1024).decode("utf-8"),
            object_pairs_hook=_reject_duplicate_keys,
        )
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise AuditPermissionSetError("PRIVATE_JSON_INVALID") from exc
    if not isinstance(value, dict):
        raise AuditPermissionSetError("PRIVATE_JSON_INVALID")
    return value


def _write_private(
    path: Path,
    value: Mapping[str, Any],
    *,
    already_exists_code: str = "PRIVATE_OUTPUT_INVALID",
) -> None:
    target = _output_path(path, already_exists_code=already_exists_code)
    nofollow = getattr(os, "O_NOFOLLOW", None)
    if nofollow is None:
        raise AuditPermissionSetError("PRIVATE_OUTPUT_NOFOLLOW_UNAVAILABLE")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | nofollow
    try:
        descriptor = os.open(target, flags, 0o600)
    except FileExistsError:
        raise AuditPermissionSetError(already_exists_code) from None
    except OSError:
        raise AuditPermissionSetError("PRIVATE_OUTPUT_INVALID") from None
    try:
        payload = (json.dumps(value, sort_keys=True, indent=2) + "\n").encode("utf-8")
        offset = 0
        while offset < len(payload):
            written = os.write(descriptor, payload[offset:])
            if written <= 0:
                raise AuditPermissionSetError("PRIVATE_OUTPUT_WRITE_FAILED")
            offset += written
        os.fsync(descriptor)
    except AuditPermissionSetError:
        raise
    except OSError:
        raise AuditPermissionSetError("PRIVATE_OUTPUT_WRITE_FAILED") from None
    finally:
        os.close(descriptor)
    _fsync_directory(target.parent)


def _fsync_directory(directory: Path) -> None:
    nofollow = getattr(os, "O_NOFOLLOW", None)
    directory_flag = getattr(os, "O_DIRECTORY", None)
    if nofollow is None or directory_flag is None:
        raise AuditPermissionSetError("PRIVATE_DIRECTORY_NOFOLLOW_UNAVAILABLE")
    try:
        descriptor = os.open(directory, os.O_RDONLY | nofollow | directory_flag)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    except OSError:
        raise AuditPermissionSetError("PRIVATE_DIRECTORY_FSYNC_FAILED") from None


def _reserve_private_output(path: Path) -> tuple[Path, int]:
    target = _output_path(path)
    nofollow = getattr(os, "O_NOFOLLOW", None)
    if nofollow is None:
        raise AuditPermissionSetError("PRIVATE_OUTPUT_NOFOLLOW_UNAVAILABLE")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | nofollow
    try:
        descriptor = os.open(target, flags, 0o600)
    except OSError:
        raise AuditPermissionSetError("PRIVATE_OUTPUT_INVALID") from None
    metadata = os.fstat(descriptor)
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or metadata.st_nlink != 1
        or stat.S_IMODE(metadata.st_mode) != 0o600
    ):
        os.close(descriptor)
        raise AuditPermissionSetError("PRIVATE_OUTPUT_INVALID")
    try:
        _fsync_directory(target.parent)
    except AuditPermissionSetError:
        os.close(descriptor)
        raise
    return target, descriptor


def _write_reserved_private(descriptor: int, value: Mapping[str, Any]) -> None:
    try:
        payload = (json.dumps(value, sort_keys=True, indent=2) + "\n").encode("utf-8")
        os.ftruncate(descriptor, 0)
        os.lseek(descriptor, 0, os.SEEK_SET)
        offset = 0
        while offset < len(payload):
            written = os.write(descriptor, payload[offset:])
            if written <= 0:
                raise AuditPermissionSetError("PRIVATE_OUTPUT_WRITE_FAILED")
            offset += written
        os.fsync(descriptor)
    except AuditPermissionSetError:
        raise
    except OSError:
        raise AuditPermissionSetError("PRIVATE_OUTPUT_WRITE_FAILED") from None


def _require_environment() -> None:
    if any(os.environ.get(name) for name in FORBIDDEN_CREDENTIAL_ENV):
        raise AuditPermissionSetError("STATIC_OR_AMBIENT_CREDENTIALS_FORBIDDEN")
    if any(os.environ.get(name) for name in FORBIDDEN_TRANSPORT_ENV):
        raise AuditPermissionSetError("AWS_TRANSPORT_OVERRIDE_FORBIDDEN")
    regions = {
        value
        for name in ("AWS_REGION", "AWS_DEFAULT_REGION")
        if (value := os.environ.get(name))
    }
    if regions and regions != {AUTHORITY_REGION}:
        raise AuditPermissionSetError("AWS_REGION_CONFLICT")


def _public_status(
    *, status: str, intent_digest: str, receipt_digest: str | None
) -> dict[str, str | None]:
    return {
        "status": status,
        "intent_digest": intent_digest,
        "receipt_digest": receipt_digest,
        "production_status": "NO-GO",
    }


def _persist_uncertain_receipt_or_report(
    *, descriptor: int, receipt: Mapping[str, Any], intent_digest: str
) -> None:
    try:
        _write_reserved_private(descriptor, receipt)
    except AuditPermissionSetError:
        print(
            json.dumps(
                _public_status(
                    status="UNCERTAIN_RECONCILE_ONLY",
                    intent_digest=intent_digest,
                    receipt_digest=None,
                ),
                sort_keys=True,
            )
        )
        raise


class AwsCli:
    """AWS CLI adapter that never emits response bodies or stderr."""

    def __init__(self, profile: str) -> None:
        if not profile or any(character.isspace() for character in profile):
            raise AuditPermissionSetError("AWS_PROFILE_INVALID")
        self.profile = profile

    def run(
        self,
        service: str,
        operation: str,
        *args: str,
        mutation: bool = False,
        allow_missing: bool = False,
    ) -> dict[str, Any] | None:
        environment = os.environ.copy()
        environment["AWS_MAX_ATTEMPTS"] = "1"
        environment["AWS_RETRY_MODE"] = "standard"
        environment["AWS_IGNORE_CONFIGURED_ENDPOINT_URLS"] = "true"
        command = [
            "aws",
            "--profile",
            self.profile,
            service,
            operation,
            *args,
            "--region",
            IDENTITY_CENTER_REGION if service in {"sso-admin", "identitystore"} else AUTHORITY_REGION,
            "--output",
            "json",
            "--no-cli-pager",
        ]
        try:
            completed = subprocess.run(
                command,
                check=False,
                capture_output=True,
                text=True,
                env=environment,
                timeout=90,
            )
        except (OSError, subprocess.TimeoutExpired):
            if mutation:
                raise AwsMutationUncertain(
                    "AWS_MUTATION_RESPONSE_UNCERTAIN"
                ) from None
            raise AwsReadError("AWS_READ_FAILED") from None
        if completed.returncode != 0:
            if allow_missing and any(
                marker in completed.stderr
                for marker in ("ResourceNotFoundException", "NoSuchEntity")
            ):
                return None
            if mutation:
                raise AwsMutationUncertain("AWS_MUTATION_RESPONSE_UNCERTAIN")
            raise AwsReadError("AWS_READ_FAILED")
        try:
            value = json.loads(completed.stdout or "{}")
        except json.JSONDecodeError as exc:
            if mutation:
                raise AwsMutationUncertain("AWS_MUTATION_RESPONSE_UNCERTAIN") from exc
            raise AwsReadError("AWS_READ_MALFORMED") from exc
        if not isinstance(value, dict):
            if mutation:
                raise AwsMutationUncertain("AWS_MUTATION_RESPONSE_UNCERTAIN")
            raise AwsReadError("AWS_READ_MALFORMED")
        return value


def _page(
    client: AwsCli,
    service: str,
    operation: str,
    result_key: str,
    *args: str,
    page_size_supported: bool = True,
) -> list[Any]:
    token: str | None = None
    seen: set[str] = set()
    result: list[Any] = []
    for _ in range(MAX_PAGES):
        call = [*args, "--max-items", str(CLI_PAGE_ITEMS)]
        if page_size_supported:
            call.extend(("--page-size", str(CLI_PAGE_ITEMS)))
        if token is not None:
            call.extend(("--starting-token", token))
        response = client.run(service, operation, *call)
        if not isinstance(response, Mapping):
            raise AwsReadError("AWS_PAGE_MALFORMED")
        items = response.get(result_key)
        if not isinstance(items, list):
            raise AwsReadError("AWS_PAGE_MALFORMED")
        result.extend(items)
        next_token = response.get("NextToken")
        if next_token is None:
            return result
        if (
            not isinstance(next_token, str)
            or not next_token
            or next_token in seen
        ):
            raise AwsReadError("AWS_PAGE_TOKEN_AMBIGUOUS")
        seen.add(next_token)
        token = next_token
    raise AwsReadError("AWS_PAGE_LIMIT_EXCEEDED")


def _iam_roles(client: AwsCli) -> list[dict[str, Any]]:
    token: str | None = None
    seen: set[str] = set()
    result: list[dict[str, Any]] = []
    for _ in range(MAX_PAGES):
        args = [
            "--path-prefix",
            "/aws-reserved/sso.amazonaws.com/",
            "--max-items",
            str(CLI_PAGE_ITEMS),
            "--page-size",
            str(CLI_PAGE_ITEMS),
        ]
        if token is not None:
            args.extend(("--starting-token", token))
        response = client.run("iam", "list-roles", *args)
        if not isinstance(response, Mapping) or not isinstance(response.get("Roles"), list):
            raise AwsReadError("IAM_ROLE_INVENTORY_MALFORMED")
        roles = response["Roles"]
        if any(not isinstance(item, dict) for item in roles):
            raise AwsReadError("IAM_ROLE_INVENTORY_MALFORMED")
        result.extend(roles)
        next_token = response.get("NextToken")
        if next_token is None:
            if response.get("IsTruncated") is True:
                raise AwsReadError("IAM_ROLE_PAGE_AMBIGUOUS")
            return result
        if (
            not isinstance(next_token, str)
            or not next_token
            or next_token in seen
        ):
            raise AwsReadError("IAM_ROLE_PAGE_AMBIGUOUS")
        seen.add(next_token)
        token = next_token
    raise AwsReadError("IAM_ROLE_PAGE_LIMIT_EXCEEDED")


def _iam_page(
    client: AwsCli, operation: str, result_key: str, *args: str
) -> list[Any]:
    token: str | None = None
    seen: set[str] = set()
    result: list[Any] = []
    for _ in range(MAX_PAGES):
        call = [
            *args,
            "--max-items",
            str(CLI_PAGE_ITEMS),
            "--page-size",
            str(CLI_PAGE_ITEMS),
        ]
        if token is not None:
            call.extend(("--starting-token", token))
        response = client.run("iam", operation, *call)
        if not isinstance(response, Mapping) or not isinstance(
            response.get(result_key), list
        ):
            raise AwsReadError("IAM_PAGE_MALFORMED")
        result.extend(response[result_key])
        next_token = response.get("NextToken")
        if next_token is None:
            if response.get("IsTruncated") is True:
                raise AwsReadError("IAM_PAGE_AMBIGUOUS")
            return result
        if (
            not isinstance(next_token, str)
            or not next_token
            or next_token in seen
        ):
            raise AwsReadError("IAM_PAGE_AMBIGUOUS")
        seen.add(next_token)
        token = next_token
    raise AwsReadError("IAM_PAGE_LIMIT_EXCEEDED")


class IdentityCenterAdapter:
    """Exact GUG-220 effect adapter; intentionally has no destructive API."""

    def __init__(
        self,
        *,
        management_profile: str,
        authority_readonly_profile: str,
        repo_root: Path = REPO_ROOT,
    ) -> None:
        self.management = AwsCli(management_profile)
        self.authority = AwsCli(authority_readonly_profile)
        self.repo_root = Path(repo_root).resolve()

    @staticmethod
    def _identity(client: AwsCli, account_id: str) -> str:
        response = client.run("sts", "get-caller-identity")
        arn = response.get("Arn") if isinstance(response, Mapping) else None
        match = SSO_ARN.fullmatch(arn) if isinstance(arn, str) else None
        if response is None or response.get("Account") != account_id or match is None:
            raise AuditPermissionSetError("AWS_CALLER_IDENTITY_INVALID")
        return arn

    def _instance(self) -> tuple[str, str, str]:
        caller_arn = self._identity(self.management, MANAGEMENT_ACCOUNT_ID)
        caller = SSO_ARN.fullmatch(caller_arn)
        if caller is None:
            raise AuditPermissionSetError("AWS_CALLER_IDENTITY_INVALID")
        instances = _page(
            self.management,
            "sso-admin",
            "list-instances",
            "Instances",
        )
        if len(instances) != 1:
            raise AuditPermissionSetError("IDENTITY_CENTER_INSTANCE_AMBIGUOUS")
        item = instances[0]
        if (
            not isinstance(item, Mapping)
            or item.get("OwnerAccountId") != MANAGEMENT_ACCOUNT_ID
            or item.get("Status") != "ACTIVE"
        ):
            raise AuditPermissionSetError("IDENTITY_CENTER_INSTANCE_INVALID")
        arn, store = item.get("InstanceArn"), item.get("IdentityStoreId")
        if not isinstance(arn, str) or not isinstance(store, str):
            raise AuditPermissionSetError("IDENTITY_CENTER_INSTANCE_INVALID")
        return arn, store, caller.group("session")

    def _principal(self, identity_store_id: str, user_name: str) -> str:
        alternate = {
            "UniqueAttribute": {
                "AttributePath": "emails.value",
                "AttributeValue": user_name,
            }
        }
        response = self.management.run(
            "identitystore",
            "get-user-id",
            "--identity-store-id",
            identity_store_id,
            "--alternate-identifier",
            json.dumps(alternate, sort_keys=True, separators=(",", ":")),
        )
        principal = response.get("UserId") if isinstance(response, Mapping) else None
        if (
            not isinstance(principal, str)
            or response.get("IdentityStoreId") != identity_store_id
        ):
            raise AuditPermissionSetError("IDENTITY_STORE_USER_AMBIGUOUS")
        described = self.management.run(
            "identitystore",
            "describe-user",
            "--identity-store-id",
            identity_store_id,
            "--user-id",
            principal,
        )
        emails = described.get("Emails") if isinstance(described, Mapping) else None
        matching = [
            item
            for item in emails or []
            if isinstance(item, Mapping)
            and isinstance(item.get("Value"), str)
            and item["Value"].casefold() == user_name.casefold()
        ]
        if described.get("UserId") != principal or len(matching) != 1:
            raise AuditPermissionSetError("IDENTITY_STORE_USER_AMBIGUOUS")
        return principal

    def _saml_provider(self) -> str:
        self._identity(self.authority, AUTHORITY_ACCOUNT_ID)
        response = self.authority.run("iam", "list-saml-providers")
        providers = (
            response.get("SAMLProviderList")
            if isinstance(response, Mapping)
            else None
        )
        if not isinstance(providers, list) or any(
            not isinstance(item, Mapping)
            or not isinstance(item.get("Arn"), str)
            for item in providers
        ):
            raise AuditPermissionSetError("SAML_PROVIDER_INVENTORY_MALFORMED")
        matches = [
            item["Arn"]
            for item in providers
            if SAML_PROVIDER_ARN.fullmatch(item["Arn"]) is not None
        ]
        if len(matches) != 1:
            raise AuditPermissionSetError("SAML_PROVIDER_AMBIGUOUS")
        return matches[0]

    def _records(self, instance_arn: str) -> list[dict[str, Any]]:
        arns = _page(
            self.management,
            "sso-admin",
            "list-permission-sets",
            "PermissionSets",
            "--instance-arn",
            instance_arn,
        )
        records: list[dict[str, Any]] = []
        for arn in arns:
            if not isinstance(arn, str):
                raise AuditPermissionSetError("PERMISSION_SET_INVENTORY_MALFORMED")
            response = self.management.run(
                "sso-admin",
                "describe-permission-set",
                "--instance-arn",
                instance_arn,
                "--permission-set-arn",
                arn,
            )
            record = response.get("PermissionSet") if isinstance(response, Mapping) else None
            if not isinstance(record, dict):
                raise AuditPermissionSetError("PERMISSION_SET_INVENTORY_MALFORMED")
            records.append(record)
        names = [item.get("Name") for item in records]
        if len(names) != len(set(names)):
            raise AuditPermissionSetError("PERMISSION_SET_NAME_AMBIGUOUS")
        return records

    def inventory(self, *, operator_user_name: str | None) -> dict[str, Any]:
        instance_arn, store, caller_session = self._instance()
        saml_provider_arn = self._saml_provider()
        if (
            operator_user_name is not None
            and operator_user_name.casefold() != caller_session.casefold()
        ):
            raise AuditPermissionSetError("OPERATOR_SESSION_BINDING_MISMATCH")
        authoritative_user_name = operator_user_name or caller_session
        principal = self._principal(store, authoritative_user_name)
        records = self._records(instance_arn)
        matches = [
            record for record in records if record.get("Name") == COLLECTOR_PERMISSION_SET_NAME
        ]
        if len(matches) > 1:
            raise AuditPermissionSetError("PERMISSION_SET_NAME_AMBIGUOUS")
        return {
            "instance_arn": instance_arn,
            "identity_store_id": store,
            "saml_provider_arn": saml_provider_arn,
            "principal_id": principal,
            "permission_set": matches[0] if matches else None,
        }

    def create_permission_set(self, *, instance_arn: str) -> dict[str, Any]:
        response = self.management.run(
            "sso-admin",
            "create-permission-set",
            "--instance-arn",
            instance_arn,
            "--name",
            COLLECTOR_PERMISSION_SET_NAME,
            "--description",
            COLLECTOR_PERMISSION_SET_DESCRIPTION,
            "--session-duration",
            SESSION_DURATION,
            "--tags",
            json.dumps(
                [{"Key": key, "Value": value} for key, value in EXPECTED_TAGS.items()],
                sort_keys=True,
                separators=(",", ":"),
            ),
            mutation=True,
        )
        record = response.get("PermissionSet") if isinstance(response, Mapping) else None
        if not isinstance(record, dict):
            raise AwsMutationUncertain("AWS_MUTATION_RESPONSE_UNCERTAIN")
        return record

    def put_inline_policy(
        self,
        *,
        instance_arn: str,
        permission_set_arn: str,
        expected_policy: Mapping[str, Any],
    ) -> None:
        self.management.run(
            "sso-admin",
            "put-inline-policy-to-permission-set",
            "--instance-arn",
            instance_arn,
            "--permission-set-arn",
            permission_set_arn,
            "--inline-policy",
            json.dumps(expected_policy, sort_keys=True, separators=(",", ":")),
            mutation=True,
        )

    def create_assignment(
        self, *, instance_arn: str, permission_set_arn: str, principal_id: str
    ) -> None:
        response = self.management.run(
            "sso-admin",
            "create-account-assignment",
            "--instance-arn",
            instance_arn,
            "--target-id",
            AUTHORITY_ACCOUNT_ID,
            "--target-type",
            "AWS_ACCOUNT",
            "--permission-set-arn",
            permission_set_arn,
            "--principal-type",
            "USER",
            "--principal-id",
            principal_id,
            mutation=True,
        )
        status = response.get("AccountAssignmentCreationStatus") if isinstance(response, Mapping) else None
        request_id = status.get("RequestId") if isinstance(status, Mapping) else None
        self._wait(
            operation="assignment",
            instance_arn=instance_arn,
            request_id=request_id,
            permission_set_arn=permission_set_arn,
            principal_id=principal_id,
        )

    def provision(self, *, instance_arn: str, permission_set_arn: str) -> None:
        response = self.management.run(
            "sso-admin",
            "provision-permission-set",
            "--instance-arn",
            instance_arn,
            "--permission-set-arn",
            permission_set_arn,
            "--target-type",
            "AWS_ACCOUNT",
            "--target-id",
            AUTHORITY_ACCOUNT_ID,
            mutation=True,
        )
        status = response.get("PermissionSetProvisioningStatus") if isinstance(response, Mapping) else None
        request_id = status.get("RequestId") if isinstance(status, Mapping) else None
        self._wait(
            operation="provision",
            instance_arn=instance_arn,
            request_id=request_id,
            permission_set_arn=permission_set_arn,
            principal_id=None,
        )

    def _wait(
        self,
        *,
        operation: str,
        instance_arn: str,
        request_id: object,
        permission_set_arn: str,
        principal_id: str | None,
    ) -> None:
        if not isinstance(request_id, str) or not request_id:
            raise AwsMutationUncertain("AWS_MUTATION_RESPONSE_UNCERTAIN")
        if operation == "assignment":
            api = "describe-account-assignment-creation-status"
            flag = "--account-assignment-creation-request-id"
            key = "AccountAssignmentCreationStatus"
        elif operation == "provision":
            api = "describe-permission-set-provisioning-status"
            flag = "--provision-permission-set-request-id"
            key = "PermissionSetProvisioningStatus"
        else:
            raise AuditPermissionSetError("ASYNC_OPERATION_INVALID")
        for _ in range(MAX_POLLS):
            response = self.management.run(
                "sso-admin",
                api,
                "--instance-arn",
                instance_arn,
                flag,
                request_id,
            )
            status = response.get(key) if isinstance(response, Mapping) else None
            state = status.get("Status") if isinstance(status, Mapping) else None
            if state == "SUCCEEDED":
                if (
                    status.get("RequestId") != request_id
                    or status.get("PermissionSetArn") != permission_set_arn
                ):
                    raise AwsMutationUncertain("AWS_MUTATION_RECEIPT_MISMATCH")
                account_field = "TargetId" if operation == "assignment" else "AccountId"
                if status.get(account_field) != AUTHORITY_ACCOUNT_ID:
                    raise AwsMutationUncertain("AWS_MUTATION_RECEIPT_MISMATCH")
                if operation == "assignment" and (
                    status.get("TargetType") != "AWS_ACCOUNT"
                    or status.get("PrincipalType") != "USER"
                    or status.get("PrincipalId") != principal_id
                ):
                    raise AwsMutationUncertain("AWS_MUTATION_RECEIPT_MISMATCH")
                return
            if state == "FAILED":
                raise AwsMutationUncertain("AWS_MUTATION_FAILED_RECONCILE_ONLY")
            if state != "IN_PROGRESS":
                raise AwsMutationUncertain("AWS_MUTATION_STATE_AMBIGUOUS")
            time.sleep(2)
        raise AwsMutationUncertain("AWS_MUTATION_TIMEOUT_RECONCILE_ONLY")

    def readback(
        self,
        *,
        instance_arn: str,
        permission_set: Mapping[str, Any],
        principal_id: str,
        expected_policy: Mapping[str, Any],
    ) -> dict[str, str]:
        arn = permission_set.get("PermissionSetArn")
        if not isinstance(arn, str):
            raise AuditPermissionSetError("PERMISSION_SET_ARN_INVALID")
        described = self.management.run(
            "sso-admin",
            "describe-permission-set",
            "--instance-arn",
            instance_arn,
            "--permission-set-arn",
            arn,
        )
        record = described.get("PermissionSet") if isinstance(described, Mapping) else None
        tags = _page(
            self.management,
            "sso-admin",
            "list-tags-for-resource",
            "Tags",
            "--instance-arn",
            instance_arn,
            "--resource-arn",
            arn,
            page_size_supported=False,
        )
        policy_response = self.management.run(
            "sso-admin",
            "get-inline-policy-for-permission-set",
            "--instance-arn",
            instance_arn,
            "--permission-set-arn",
            arn,
        )
        raw_policy = policy_response.get("InlinePolicy") if isinstance(policy_response, Mapping) else None
        try:
            policy = json.loads(raw_policy) if isinstance(raw_policy, str) and raw_policy else None
        except json.JSONDecodeError as exc:
            raise AuditPermissionSetError("PERMISSION_SET_INLINE_POLICY_INVALID") from exc
        managed = _page(
            self.management,
            "sso-admin",
            "list-managed-policies-in-permission-set",
            "AttachedManagedPolicies",
            "--instance-arn",
            instance_arn,
            "--permission-set-arn",
            arn,
        )
        customer = _page(
            self.management,
            "sso-admin",
            "list-customer-managed-policy-references-in-permission-set",
            "CustomerManagedPolicyReferences",
            "--instance-arn",
            instance_arn,
            "--permission-set-arn",
            arn,
        )
        boundary_response = self.management.run(
            "sso-admin",
            "get-permissions-boundary-for-permission-set",
            "--instance-arn",
            instance_arn,
            "--permission-set-arn",
            arn,
            allow_missing=True,
        )
        boundary = (
            boundary_response.get("PermissionsBoundary")
            if isinstance(boundary_response, Mapping)
            else None
        )
        assignments = _page(
            self.management,
            "sso-admin",
            "list-account-assignments",
            "AccountAssignments",
            "--instance-arn",
            instance_arn,
            "--account-id",
            AUTHORITY_ACCOUNT_ID,
            "--permission-set-arn",
            arn,
        )
        accounts = _page(
            self.management,
            "sso-admin",
            "list-accounts-for-provisioned-permission-set",
            "AccountIds",
            "--instance-arn",
            instance_arn,
            "--permission-set-arn",
            arn,
        )
        if not isinstance(record, Mapping):
            raise AuditPermissionSetError("PERMISSION_SET_READBACK_INVALID")
        return exact_permission_set_readback(
            permission_set=record,
            tags=tags,
            inline_policy=policy,
            managed_policies=managed,
            customer_managed_policy_references=customer,
            permissions_boundary=boundary,
            assignments=assignments,
            provisioned_account_ids=accounts,
            expected_principal_id=principal_id,
            expected_inline_policy=expected_policy,
        )

    def partial_state(
        self,
        *,
        instance_arn: str,
        permission_set: Mapping[str, Any],
        principal_id: str,
        expected_policy: Mapping[str, Any],
    ) -> dict[str, Any]:
        """Read a pre-existing owned record without silently adopting drift."""

        arn = permission_set.get("PermissionSetArn")
        if not isinstance(arn, str):
            raise AuditPermissionSetError("PERMISSION_SET_ARN_INVALID")
        described = self.management.run(
            "sso-admin", "describe-permission-set", "--instance-arn", instance_arn,
            "--permission-set-arn", arn,
        )
        record = described.get("PermissionSet") if isinstance(described, Mapping) else None
        if not isinstance(record, Mapping) or any(
            (
                record.get("Name") != COLLECTOR_PERMISSION_SET_NAME,
                record.get("Description") != COLLECTOR_PERMISSION_SET_DESCRIPTION,
                record.get("SessionDuration") != SESSION_DURATION,
                record.get("RelayState") not in (None, ""),
            )
        ):
            raise AuditPermissionSetError("PERMISSION_SET_METADATA_DRIFT")
        tags = _page(
            self.management, "sso-admin", "list-tags-for-resource", "Tags",
            "--instance-arn", instance_arn, "--resource-arn", arn,
            page_size_supported=False,
        )
        normalized = {
            item.get("Key"): item.get("Value") for item in tags if isinstance(item, Mapping)
        }
        if normalized != EXPECTED_TAGS or len(normalized) != len(tags):
            raise AuditPermissionSetError("PERMISSION_SET_TAG_DRIFT")
        policy_response = self.management.run(
            "sso-admin", "get-inline-policy-for-permission-set", "--instance-arn", instance_arn,
            "--permission-set-arn", arn,
        )
        raw = policy_response.get("InlinePolicy") if isinstance(policy_response, Mapping) else None
        try:
            policy = json.loads(raw) if isinstance(raw, str) and raw else None
        except json.JSONDecodeError as exc:
            raise AuditPermissionSetError("PERMISSION_SET_INLINE_POLICY_INVALID") from exc
        if policy not in (None, expected_policy):
            raise AuditPermissionSetError("PERMISSION_SET_INLINE_POLICY_DRIFT")
        managed = _page(
            self.management, "sso-admin", "list-managed-policies-in-permission-set",
            "AttachedManagedPolicies", "--instance-arn", instance_arn,
            "--permission-set-arn", arn,
        )
        customer = _page(
            self.management, "sso-admin",
            "list-customer-managed-policy-references-in-permission-set",
            "CustomerManagedPolicyReferences", "--instance-arn", instance_arn,
            "--permission-set-arn", arn,
        )
        boundary_response = self.management.run(
            "sso-admin", "get-permissions-boundary-for-permission-set",
            "--instance-arn", instance_arn, "--permission-set-arn", arn,
            allow_missing=True,
        )
        boundary = boundary_response.get("PermissionsBoundary") if isinstance(boundary_response, Mapping) else None
        if managed or customer or boundary not in (None, {}):
            raise AuditPermissionSetError("PERMISSION_SET_AUTHORITY_DRIFT")
        assignments = _page(
            self.management, "sso-admin", "list-account-assignments", "AccountAssignments",
            "--instance-arn", instance_arn, "--account-id", AUTHORITY_ACCOUNT_ID,
            "--permission-set-arn", arn,
        )
        expected_assignment = {
            "AccountId": AUTHORITY_ACCOUNT_ID,
            "PermissionSetArn": arn,
            "PrincipalType": "USER",
            "PrincipalId": principal_id,
        }
        if assignments not in ([], [expected_assignment]):
            raise AuditPermissionSetError("PERMISSION_SET_ASSIGNMENT_DRIFT")
        accounts = _page(
            self.management, "sso-admin", "list-accounts-for-provisioned-permission-set",
            "AccountIds", "--instance-arn", instance_arn, "--permission-set-arn", arn,
        )
        if accounts not in ([], [AUTHORITY_ACCOUNT_ID]):
            raise AuditPermissionSetError("PERMISSION_SET_PROVISIONING_DRIFT")
        return {
            "permission_set": dict(record),
            "inline_policy_present": policy is not None,
            "assignment_present": bool(assignments),
            "provisioning_present": bool(accounts),
        }

    def collector_role(
        self,
        *,
        expected_saml_provider_arn: str,
        expected_policy: Mapping[str, Any],
    ) -> dict[str, str]:
        self._identity(self.authority, AUTHORITY_ACCOUNT_ID)
        matches = [
            role
            for role in _iam_roles(self.authority)
            if isinstance(role.get("RoleName"), str)
            and COLLECTOR_ROLE_NAME.fullmatch(role["RoleName"])
        ]
        if len(matches) != 1:
            raise AuditPermissionSetError("COLLECTOR_ROLE_AMBIGUOUS")
        role = matches[0]
        name, arn = role.get("RoleName"), role.get("Arn")
        if not isinstance(name, str) or not isinstance(arn, str):
            raise AuditPermissionSetError("COLLECTOR_ROLE_INVALID")
        described = self.authority.run("iam", "get-role", "--role-name", name)
        record = described.get("Role") if isinstance(described, Mapping) else None
        if not isinstance(record, Mapping) or record.get("Arn") != arn or record.get("PermissionsBoundary") is not None:
            raise AuditPermissionSetError("COLLECTOR_ROLE_INVALID")
        trust = record.get("AssumeRolePolicyDocument")
        if not isinstance(trust, Mapping):
            raise AuditPermissionSetError("COLLECTOR_ROLE_TRUST_INVALID")
        validate_collector_trust_policy(
            trust, expected_saml_provider_arn=expected_saml_provider_arn
        )
        attached = _iam_page(
            self.authority,
            "list-attached-role-policies",
            "AttachedPolicies",
            "--role-name",
            name,
        )
        if attached != []:
            raise AuditPermissionSetError("COLLECTOR_ROLE_ATTACHMENT_DRIFT")
        policy_names = _iam_page(
            self.authority,
            "list-role-policies",
            "PolicyNames",
            "--role-name",
            name,
        )
        if len(policy_names) != 1 or not isinstance(policy_names[0], str):
            raise AuditPermissionSetError("COLLECTOR_ROLE_INLINE_POLICY_AMBIGUOUS")
        policy_response = self.authority.run(
            "iam", "get-role-policy", "--role-name", name, "--policy-name", policy_names[0]
        )
        policy = policy_response.get("PolicyDocument") if isinstance(policy_response, Mapping) else None
        if policy != expected_policy:
            raise AuditPermissionSetError("COLLECTOR_ROLE_INLINE_POLICY_DRIFT")
        return {"role_name": name, "role_arn": arn}


def _ensure_intent_principal(intent: Mapping[str, Any], principal_id: str) -> None:
    from tooling.platform_authority_lambda_invocation_authority import digest_text

    if not isinstance(principal_id, str) or not principal_id:
        raise AuditPermissionSetError("INTENT_PRINCIPAL_MISMATCH")
    if intent.get("principal_id_digest") != digest_text(principal_id):
        raise AuditPermissionSetError("INTENT_PRINCIPAL_MISMATCH")


def _validate_execution_inventory(
    intent: Mapping[str, Any], inventory: Mapping[str, Any]
) -> None:
    validate_provisioning_source_commit_binding(
        source_commit=str(intent.get("source_commit", "")),
        repo_root=REPO_ROOT,
    )
    principal_id = inventory.get("principal_id")
    instance_arn = inventory.get("instance_arn")
    identity_store_id = inventory.get("identity_store_id")
    saml_provider_arn = inventory.get("saml_provider_arn")
    if not all(
        isinstance(value, str) and value
        for value in (
            principal_id,
            instance_arn,
            identity_store_id,
            saml_provider_arn,
        )
    ):
        raise AuditPermissionSetError("INVENTORY_BINDING_INCOMPLETE")
    _ensure_intent_principal(intent, principal_id)
    validate_intent_execution_binding(
        intent,
        now=_now(),
        identity_center_instance_arn=instance_arn,
        identity_store_id=identity_store_id,
        saml_provider_arn=saml_provider_arn,
    )


def _refresh_execution_state(
    *,
    adapter: IdentityCenterAdapter,
    intent: Mapping[str, Any],
    operator_user_name: str | None,
    expected_policy: Mapping[str, Any],
) -> tuple[dict[str, Any], Mapping[str, Any] | None, tuple[str, ...]]:
    """Refresh authority state and recompute required actions before an effect."""

    inventory = adapter.inventory(operator_user_name=operator_user_name)
    _validate_execution_inventory(intent, inventory)
    permission_set = inventory["permission_set"]
    if permission_set is None:
        return inventory, None, ("create_permission_set",)
    partial = adapter.partial_state(
        instance_arn=inventory["instance_arn"],
        permission_set=permission_set,
        principal_id=inventory["principal_id"],
        expected_policy=expected_policy,
    )
    return inventory, permission_set, required_provisioning_actions(partial)


def _observed_permission_set_arn(record: object) -> str | None:
    value = record.get("PermissionSetArn") if isinstance(record, Mapping) else None
    if isinstance(value, str) and PERMISSION_SET_ARN.fullmatch(value) is not None:
        return value
    return None


def _adapter(args: argparse.Namespace) -> IdentityCenterAdapter:
    _require_environment()
    return IdentityCenterAdapter(
        management_profile=args.management_profile,
        authority_readonly_profile=args.authority_readonly_profile,
    )


def _operator_name(args: argparse.Namespace) -> str | None:
    if getattr(args, "operator_from_management_session", False):
        return None
    return _read_private_line(args.operator_user_name_file)


def _load_intent(args: argparse.Namespace) -> dict[str, Any]:
    intent = validate_provisioning_intent(_read_private_json(args.intent), repo_root=REPO_ROOT)
    if intent["intent_digest"] != args.expected_intent_digest:
        raise AuditPermissionSetError("EXPECTED_INTENT_DIGEST_MISMATCH")
    return intent


def _execution_ledger_path(directory: Path) -> Path:
    """Return the stable, one-shot lock for the entire GUG-220 mutation target."""

    return directory / "gug220-lambda-audit-provisioning.execution-ledger.v1.json"


def _cmd_plan(args: argparse.Namespace) -> int:
    adapter = _adapter(args)
    operator = _operator_name(args)
    ledger_directory = _bound_execution_ledger_directory(
        args.execution_ledger_directory
    )
    inventory = adapter.inventory(operator_user_name=operator)
    source_commit = current_provisioning_source_commit(REPO_ROOT)
    intent = build_provisioning_intent(
        principal_id=inventory["principal_id"],
        identity_center_instance_arn=inventory["instance_arn"],
        identity_store_id=inventory["identity_store_id"],
        saml_provider_arn=inventory["saml_provider_arn"],
        source_commit=source_commit,
        execution_ledger_directory_id=str(ledger_directory),
        created_at=_now(),
        repo_root=REPO_ROOT,
    )
    expected_policy = sealed_collector_policy_for_intent(intent, repo_root=REPO_ROOT)
    record = inventory["permission_set"]
    if record is not None:
        adapter.partial_state(
            instance_arn=inventory["instance_arn"],
            permission_set=record,
            principal_id=inventory["principal_id"],
            expected_policy=expected_policy,
        )
    receipt = build_provisioning_receipt(
        intent=intent,
        status="PLAN_ONLY",
        permission_set_arn=_observed_permission_set_arn(record),
        role_arn=None,
        aws_mutation_attempted=False,
        ambiguous_response=False,
        binding_written=False,
        created_at=_now(),
    )
    _write_private(args.intent_out, intent)
    _write_private(args.receipt_out, receipt)
    print(json.dumps(_public_status(
        status=receipt["status"], intent_digest=intent["intent_digest"],
        receipt_digest=receipt["receipt_digest"],
    ), sort_keys=True))
    return 0


def _cmd_apply(args: argparse.Namespace) -> int:
    if not args.allow_identity_center_mutation:
        raise AuditPermissionSetError("IDENTITY_CENTER_MUTATION_NOT_AUTHORIZED")
    intent = _load_intent(args)
    ledger_directory = _bound_execution_ledger_directory(
        args.execution_ledger_directory
    )
    validate_execution_ledger_directory_binding(
        intent, execution_ledger_directory_id=str(ledger_directory)
    )
    expected_policy = sealed_collector_policy_for_intent(intent, repo_root=REPO_ROOT)
    adapter = _adapter(args)
    operator = _operator_name(args)
    inventory, permission_set, actions = _refresh_execution_state(
        adapter=adapter,
        intent=intent,
        operator_user_name=operator,
        expected_policy=expected_policy,
    )
    mutation_attempted = False
    receipt_descriptor: int | None = None
    try:
        planned_actions = set(actions)
        performed_actions: set[str] = set()
        mutation_window_reserved = bool(actions)
        if actions:
            ledger = build_execution_ledger(intent=intent, created_at=_now())
            _write_private(
                _execution_ledger_path(ledger_directory),
                ledger,
                already_exists_code="EXECUTION_LEDGER_ALREADY_CONSUMED",
            )
            _, receipt_descriptor = _reserve_private_output(args.receipt_out)
        inventory, permission_set, actions = _refresh_execution_state(
            adapter=adapter,
            intent=intent,
            operator_user_name=operator,
            expected_policy=expected_policy,
        )
        if actions and not mutation_window_reserved:
            raise AuditPermissionSetError("PERMISSION_SET_STATE_CHANGED")
        if "create_permission_set" in planned_actions:
            if "create_permission_set" not in actions:
                raise AuditPermissionSetError("PERMISSION_SET_STATE_CHANGED")
            _validate_execution_inventory(intent, inventory)
            mutation_attempted = True
            adapter.create_permission_set(instance_arn=inventory["instance_arn"])
            performed_actions.add("create_permission_set")
            inventory, permission_set, actions = _refresh_execution_state(
                adapter=adapter,
                intent=intent,
                operator_user_name=operator,
                expected_policy=expected_policy,
            )
            if permission_set is None:
                raise AwsMutationUncertain("AWS_MUTATION_NOT_VISIBLE")
            planned_actions = set(actions)
        elif permission_set is None or "create_permission_set" in actions:
            raise AuditPermissionSetError("PERMISSION_SET_STATE_CHANGED")

        mutation_order = (
            "put_inline_policy",
            "create_assignment",
            "provision",
        )
        for position, action in enumerate(mutation_order):
            inventory, permission_set, actions = _refresh_execution_state(
                adapter=adapter,
                intent=intent,
                operator_user_name=operator,
                expected_policy=expected_policy,
            )
            if actions and not mutation_window_reserved:
                raise AuditPermissionSetError("PERMISSION_SET_STATE_CHANGED")
            if permission_set is None or "create_permission_set" in actions:
                raise AuditPermissionSetError("PERMISSION_SET_STATE_CHANGED")
            if any(previous in actions for previous in mutation_order[:position]):
                raise AuditPermissionSetError("PERMISSION_SET_STATE_CHANGED")
            current_actions = set(actions)
            if current_actions - planned_actions:
                raise AuditPermissionSetError("PERMISSION_SET_STATE_CHANGED")
            arn = permission_set.get("PermissionSetArn")
            if not isinstance(arn, str):
                raise AuditPermissionSetError("PERMISSION_SET_ARN_INVALID")
            causally_required = action == "provision" and bool(
                performed_actions & {"put_inline_policy", "create_assignment"}
            )
            if action not in planned_actions:
                if action in current_actions:
                    raise AuditPermissionSetError("PERMISSION_SET_STATE_CHANGED")
                continue
            if action not in current_actions and not causally_required:
                raise AuditPermissionSetError("PERMISSION_SET_STATE_CHANGED")
            _validate_execution_inventory(intent, inventory)
            mutation_attempted = True
            if action == "put_inline_policy":
                adapter.put_inline_policy(
                    instance_arn=inventory["instance_arn"],
                    permission_set_arn=arn,
                    expected_policy=expected_policy,
                )
            elif action == "create_assignment":
                adapter.create_assignment(
                    instance_arn=inventory["instance_arn"],
                    permission_set_arn=arn,
                    principal_id=inventory["principal_id"],
                )
            else:
                adapter.provision(
                    instance_arn=inventory["instance_arn"],
                    permission_set_arn=arn,
                )
            performed_actions.add(action)

        inventory, permission_set, actions = _refresh_execution_state(
            adapter=adapter,
            intent=intent,
            operator_user_name=operator,
            expected_policy=expected_policy,
        )
        if permission_set is None:
            raise AwsMutationUncertain("AWS_MUTATION_NOT_VISIBLE")
        if actions:
            raise AuditPermissionSetError("PERMISSION_SET_STATE_CHANGED")
        adapter.readback(
            instance_arn=inventory["instance_arn"],
            permission_set=permission_set,
            principal_id=inventory["principal_id"],
            expected_policy=expected_policy,
        )
        role = adapter.collector_role(
            expected_saml_provider_arn=inventory["saml_provider_arn"],
            expected_policy=expected_policy,
        )
        _validate_execution_inventory(intent, inventory)
        receipt = build_provisioning_receipt(
            intent=intent,
            status="READBACK_VERIFIED",
            permission_set_arn=permission_set["PermissionSetArn"],
            role_arn=role["role_arn"],
            aws_mutation_attempted=mutation_attempted,
            ambiguous_response=False,
            binding_written=False,
            created_at=_now(),
        )
        if receipt_descriptor is not None:
            _write_reserved_private(receipt_descriptor, receipt)
    except (AwsMutationUncertain, AwsReadError, AuditPermissionSetError) as error:
        if not mutation_attempted:
            if receipt_descriptor is None:
                raise
            status = (
                "READBACK_INCOMPLETE"
                if isinstance(error, AwsReadError)
                else "BLOCKED_DRIFT"
            )
            receipt = build_provisioning_receipt(
                intent=intent,
                status=status,
                permission_set_arn=_observed_permission_set_arn(permission_set),
                role_arn=None,
                aws_mutation_attempted=False,
                ambiguous_response=status == "READBACK_INCOMPLETE",
                binding_written=False,
                created_at=_now(),
            )
            _write_reserved_private(receipt_descriptor, receipt)
            print(json.dumps(_public_status(
                status=receipt["status"], intent_digest=intent["intent_digest"],
                receipt_digest=receipt["receipt_digest"],
            ), sort_keys=True))
            return 2
        receipt = build_provisioning_receipt(
            intent=intent,
            status="UNCERTAIN_RECONCILE_ONLY",
            permission_set_arn=_observed_permission_set_arn(permission_set),
            role_arn=None,
            aws_mutation_attempted=True,
            ambiguous_response=True,
            binding_written=False,
            created_at=_now(),
        )
        if receipt_descriptor is None:
            raise AuditPermissionSetError("PRIVATE_RECEIPT_NOT_RESERVED")
        _persist_uncertain_receipt_or_report(
            descriptor=receipt_descriptor,
            receipt=receipt,
            intent_digest=intent["intent_digest"],
        )
        print(json.dumps(_public_status(
            status=receipt["status"], intent_digest=intent["intent_digest"],
            receipt_digest=receipt["receipt_digest"],
        ), sort_keys=True))
        return 2
    finally:
        if receipt_descriptor is not None:
            os.close(receipt_descriptor)
    if receipt_descriptor is None:
        _write_private(args.receipt_out, receipt)
    print(json.dumps(_public_status(
        status=receipt["status"], intent_digest=intent["intent_digest"],
        receipt_digest=receipt["receipt_digest"],
    ), sort_keys=True))
    return 0


def _cmd_reconcile(args: argparse.Namespace) -> int:
    intent = _load_intent(args)
    expected_policy = sealed_collector_policy_for_intent(intent, repo_root=REPO_ROOT)
    adapter = _adapter(args)
    operator = _operator_name(args)
    record: Mapping[str, Any] | None = None
    try:
        inventory = adapter.inventory(operator_user_name=operator)
        _ensure_intent_principal(intent, inventory["principal_id"])
        validate_intent_authority_binding(
            intent,
            identity_center_instance_arn=inventory["instance_arn"],
            identity_store_id=inventory["identity_store_id"],
            saml_provider_arn=inventory["saml_provider_arn"],
        )
        validate_provisioning_source_commit_binding(
            source_commit=str(intent.get("source_commit", "")),
            repo_root=REPO_ROOT,
        )
        record = inventory["permission_set"]
        if record is None:
            status, role_arn = "BLOCKED_DRIFT", None
        else:
            adapter.readback(
                instance_arn=inventory["instance_arn"],
                permission_set=record,
                principal_id=inventory["principal_id"],
                expected_policy=expected_policy,
            )
            role_arn = adapter.collector_role(
                expected_saml_provider_arn=inventory["saml_provider_arn"],
                expected_policy=expected_policy,
            )["role_arn"]
            validate_provisioning_source_commit_binding(
                source_commit=str(intent.get("source_commit", "")),
                repo_root=REPO_ROOT,
            )
            status = "READBACK_VERIFIED"
    except AwsReadError:
        status, role_arn = "READBACK_INCOMPLETE", None
    except AuditPermissionSetError:
        if record is None:
            raise
        status, role_arn = "BLOCKED_DRIFT", None
    receipt = build_provisioning_receipt(
        intent=intent,
        status=status,
        permission_set_arn=_observed_permission_set_arn(record),
        role_arn=role_arn,
        aws_mutation_attempted=False,
        ambiguous_response=status == "READBACK_INCOMPLETE",
        binding_written=False,
        created_at=_now(),
    )
    _write_private(args.receipt_out, receipt)
    print(json.dumps(_public_status(
        status=receipt["status"], intent_digest=intent["intent_digest"],
        receipt_digest=receipt["receipt_digest"],
    ), sort_keys=True))
    return 0 if status == "READBACK_VERIFIED" else 2


def _cmd_bind_session(args: argparse.Namespace) -> int:
    intent = _load_intent(args)
    expected_policy = sealed_collector_policy_for_intent(intent, repo_root=REPO_ROOT)
    adapter = _adapter(args)
    operator = _operator_name(args)
    inventory = adapter.inventory(operator_user_name=operator)
    _ensure_intent_principal(intent, inventory["principal_id"])
    validate_intent_authority_binding(
        intent,
        identity_center_instance_arn=inventory["instance_arn"],
        identity_store_id=inventory["identity_store_id"],
        saml_provider_arn=inventory["saml_provider_arn"],
    )
    validate_provisioning_source_commit_binding(
        source_commit=str(intent.get("source_commit", "")),
        repo_root=REPO_ROOT,
    )
    if inventory["permission_set"] is None:
        raise AuditPermissionSetError("PERMISSION_SET_MISSING")
    adapter.readback(
        instance_arn=inventory["instance_arn"],
        permission_set=inventory["permission_set"],
        principal_id=inventory["principal_id"],
        expected_policy=expected_policy,
    )
    role = adapter.collector_role(
        expected_saml_provider_arn=inventory["saml_provider_arn"],
        expected_policy=expected_policy,
    )
    validate_provisioning_source_commit_binding(
        source_commit=str(intent.get("source_commit", "")),
        repo_root=REPO_ROOT,
    )
    collector = AwsCli(args.collector_profile)
    caller = collector.run("sts", "get-caller-identity")
    sts_arn = caller.get("Arn") if isinstance(caller, Mapping) else None
    match = SSO_ARN.fullmatch(sts_arn) if isinstance(sts_arn, str) else None
    if (
        caller.get("Account") != AUTHORITY_ACCOUNT_ID
        or match is None
        or match.group("role") != role["role_name"]
    ):
        raise AuditPermissionSetError("COLLECTOR_SESSION_BINDING_INVALID")
    binding = {
        "identity_center_region": IDENTITY_CENTER_REGION,
        "collector_iam_role_arn": role["role_arn"],
        "collector_sts_session_arn": sts_arn,
    }
    if set(binding) != {
        "identity_center_region",
        "collector_iam_role_arn",
        "collector_sts_session_arn",
    }:
        raise AuditPermissionSetError("COLLECTOR_BINDING_SHAPE_INVALID")
    _write_private(args.binding_out, binding)
    receipt = build_provisioning_receipt(
        intent=intent,
        status="READBACK_VERIFIED",
        permission_set_arn=inventory["permission_set"]["PermissionSetArn"],
        role_arn=role["role_arn"],
        aws_mutation_attempted=False,
        ambiguous_response=False,
        binding_written=True,
        created_at=_now(),
    )
    _write_private(args.receipt_out, receipt)
    print(json.dumps(_public_status(
        status=receipt["status"], intent_digest=intent["intent_digest"],
        receipt_digest=receipt["receipt_digest"],
    ), sort_keys=True))
    return 0


def _common(parser: argparse.ArgumentParser, *, with_intent: bool) -> None:
    parser.add_argument("--management-profile", required=True)
    parser.add_argument("--authority-readonly-profile", required=True)
    operator = parser.add_mutually_exclusive_group(required=True)
    operator.add_argument("--operator-user-name-file", type=Path)
    operator.add_argument("--operator-from-management-session", action="store_true")
    parser.add_argument("--receipt-out", type=Path, required=True)
    if with_intent:
        parser.add_argument("--intent", type=Path, required=True)
        parser.add_argument("--expected-intent-digest", required=True)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    plan = subparsers.add_parser("plan", help="Create a private read-only intent")
    _common(plan, with_intent=False)
    plan.add_argument("--execution-ledger-directory", type=Path, required=True)
    plan.add_argument("--intent-out", type=Path, required=True)
    plan.set_defaults(handler=_cmd_plan)

    apply = subparsers.add_parser("apply", help="Apply the exact reviewed Identity Center state")
    _common(apply, with_intent=True)
    apply.add_argument("--execution-ledger-directory", type=Path, required=True)
    apply.add_argument("--allow-identity-center-mutation", action="store_true")
    apply.set_defaults(handler=_cmd_apply)

    reconcile = subparsers.add_parser("reconcile", help="Read-only reconciliation; never retries")
    _common(reconcile, with_intent=True)
    reconcile.set_defaults(handler=_cmd_reconcile)

    bind = subparsers.add_parser("bind-session", help="Bind a verified collector SSO session")
    _common(bind, with_intent=True)
    bind.add_argument("--collector-profile", required=True)
    bind.add_argument("--binding-out", type=Path, required=True)
    bind.set_defaults(handler=_cmd_bind_session)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        return int(args.handler(args))
    except (AuditPermissionSetError, AwsReadError) as exc:
        print(json.dumps({"status": str(exc), "production_status": "NO-GO"}), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
