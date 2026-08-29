#!/usr/bin/env python3
"""Fail-closed AWS CLI adapters for immutable SSM layer contracts.

The catalog's content-addressed parameter is the sole authority.  Resolution
discovers the one digest leaf below the catalog-owned release prefix with two
bounded, identical paginated reads, then performs two exact ``GetParameter``
reads.  A mutable ``latest`` pointer or secondary index is deliberately not
created: the release prefix is already a canonical, immutable index and more
than one digest leaf is treated as ambiguous producer evidence.

The adapter never logs commands, stderr, parameter names, or payloads.  Its
runner protocol is injectable so all behavior can be tested without AWS.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
from dataclasses import dataclass
from typing import Any, Mapping, Protocol, Sequence

from tooling.validate_digest import canonicalize, compute_digest


class LiveContractIoError(ValueError):
    """A sanitized live contract I/O failure."""


class AwsJsonRunner(Protocol):
    """Minimal injectable JSON AWS CLI boundary."""

    def invoke(
        self,
        service: str,
        operation: str,
        *,
        region: str,
        arguments: Sequence[str] = (),
    ) -> Mapping[str, Any]: ...


ACCOUNT_ID_PATTERN = re.compile(r"^[0-9]{12}$")
AWS_REGION_PATTERN = re.compile(r"^[a-z]{2}(?:-gov)?-[a-z]+-[0-9]+$")
DEPLOYMENT_ID_PATTERN = re.compile(r"^dep_[0-9A-HJKMNP-TV-Z]{26}$")
DIGEST_PATTERN = re.compile(r"^sha256:[0-9a-f]{64}$")
PROFILE_PATTERN = re.compile(r"^[A-Za-z0-9+=,.@_-]{1,128}$")
PARAMETER_NAME_PATTERN = re.compile(r"^[A-Za-z0-9_.\-/]+$")

MAX_PARAMETER_VALUE_BYTES = 4096
MAX_PARAMETER_NAME_CHARS = 1011
MAX_REQUIRED_CONTRACTS = 8
MAX_DISCOVERY_PAGES = 4
MAX_DISCOVERY_RESULTS = 32
DISCOVERY_PAGE_SIZE = 10
MAX_CLI_OUTPUT_BYTES = 256 * 1024
MAX_NEXT_TOKEN_CHARS = 4096

_ALLOWED_OPERATIONS = {
    ("sts", "get-caller-identity"),
    ("ssm", "get-parameter"),
    ("ssm", "get-parameters-by-path"),
    ("ssm", "list-tags-for-resource"),
    ("ssm", "put-parameter"),
}


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise LiveContractIoError("AWS JSON contains a duplicate object key")
        result[key] = value
    return result


def _reject_nonfinite(_value: str) -> None:
    raise LiveContractIoError("AWS JSON contains a non-finite numeric value")


class SubprocessAwsCliRunner:
    """Execute a closed set of AWS CLI JSON operations without a shell.

    Callers must explicitly select either a named profile or the already
    established runtime credential chain (for example GitHub OIDC).  There is
    no implicit default-profile fallback.
    """

    def __init__(
        self,
        *,
        executable: str = "aws",
        profile: str | None = None,
        use_runtime_credentials: bool = False,
        timeout_seconds: int = 30,
    ) -> None:
        if not isinstance(executable, str) or not executable or "\x00" in executable:
            raise LiveContractIoError("AWS CLI executable is invalid")
        if profile is not None and not PROFILE_PATTERN.fullmatch(profile):
            raise LiveContractIoError("AWS profile name is invalid")
        if (profile is None) == (not use_runtime_credentials):
            raise LiveContractIoError(
                "select exactly one explicit AWS credential source"
            )
        if type(timeout_seconds) is not int or not 1 <= timeout_seconds <= 60:
            raise LiveContractIoError("AWS CLI timeout is outside the approved range")
        self._executable = executable
        self._profile = profile
        self._use_runtime_credentials = use_runtime_credentials
        self._timeout_seconds = timeout_seconds

    def invoke(
        self,
        service: str,
        operation: str,
        *,
        region: str,
        arguments: Sequence[str] = (),
    ) -> Mapping[str, Any]:
        if (service, operation) not in _ALLOWED_OPERATIONS:
            raise LiveContractIoError("AWS CLI operation is not allowlisted")
        _validate_region(region)
        if any(not isinstance(value, str) or "\x00" in value for value in arguments):
            raise LiveContractIoError("AWS CLI argument is invalid")

        command = [
            self._executable,
            service,
            operation,
            "--region",
            region,
            "--no-cli-pager",
            "--no-paginate",
            "--cli-connect-timeout",
            "5",
            "--cli-read-timeout",
            str(min(20, self._timeout_seconds)),
            "--output",
            "json",
        ]
        if self._profile is not None:
            command.extend(["--profile", self._profile])
        command.extend(arguments)
        environment = os.environ.copy()
        environment["AWS_PAGER"] = ""
        environment["AWS_CLI_AUTO_PROMPT"] = "off"
        environment["AWS_IGNORE_CONFIGURED_ENDPOINT_URLS"] = "true"
        environment["AWS_MAX_ATTEMPTS"] = "1"
        environment["AWS_RETRY_MODE"] = "standard"
        for key in tuple(environment):
            if key == "AWS_ENDPOINT_URL" or key.startswith("AWS_ENDPOINT_URL_"):
                environment.pop(key, None)
        if self._use_runtime_credentials:
            # Runtime mode may use environment, web-identity, or container
            # credentials, but never silently falls back to a local default
            # profile or shared credentials file.
            environment.pop("AWS_PROFILE", None)
            environment.pop("AWS_DEFAULT_PROFILE", None)
            environment["AWS_CONFIG_FILE"] = os.devnull
            environment["AWS_SHARED_CREDENTIALS_FILE"] = os.devnull
        try:
            completed = subprocess.run(
                command,
                check=False,
                capture_output=True,
                text=False,
                timeout=self._timeout_seconds,
                env=environment,
            )
        except (OSError, subprocess.TimeoutExpired):
            raise LiveContractIoError("AWS CLI request did not complete safely") from None
        if completed.returncode != 0:
            raise LiveContractIoError("AWS CLI request was rejected")
        if len(completed.stdout) > MAX_CLI_OUTPUT_BYTES:
            raise LiveContractIoError("AWS CLI response exceeds the approved bound")
        try:
            document = json.loads(
                completed.stdout.decode("utf-8"),
                object_pairs_hook=_reject_duplicate_keys,
                parse_constant=_reject_nonfinite,
            )
        except (UnicodeError, json.JSONDecodeError) as exc:
            raise LiveContractIoError("AWS CLI response is not valid JSON") from exc
        if not isinstance(document, dict):
            raise LiveContractIoError("AWS CLI response must be a JSON object")
        return document


@dataclass(frozen=True)
class CallerIdentity:
    account_id: str
    arn: str
    user_id: str
    partition: str
    region: str


def _validate_region(region: str) -> None:
    if not isinstance(region, str) or not AWS_REGION_PATTERN.fullmatch(region):
        raise LiveContractIoError("AWS region is invalid")


def verify_caller_identity(
    runner: AwsJsonRunner,
    *,
    expected_account_id: str,
    region: str,
) -> CallerIdentity:
    """Verify the exact account and bind every call to the explicit region.

    STS has no response-region field.  Region identity is therefore proved by
    requiring the explicit region on the STS request and reusing that same
    validated value for every subsequent adapter call.
    """
    if not ACCOUNT_ID_PATTERN.fullmatch(expected_account_id):
        raise LiveContractIoError("expected AWS account identifier is invalid")
    _validate_region(region)
    response = runner.invoke("sts", "get-caller-identity", region=region)
    account = response.get("Account")
    arn = response.get("Arn")
    user_id = response.get("UserId")
    if (
        account != expected_account_id
        or not isinstance(arn, str)
        or not arn
        or not isinstance(user_id, str)
        or not user_id
    ):
        raise LiveContractIoError("STS caller identity does not match the expected account")
    match = re.fullmatch(
        r"arn:(aws(?:-us-gov|-cn)?):(?:sts|iam)::([0-9]{12}):(.+)", arn
    )
    if match is None or match.group(2) != expected_account_id:
        raise LiveContractIoError("STS caller ARN is not bound to the expected account")
    if match.group(3) == "root":
        raise LiveContractIoError("root AWS identity is forbidden")
    return CallerIdentity(
        account_id=expected_account_id,
        arn=arn,
        user_id=user_id,
        partition=match.group(1),
        region=region,
    )


def _digest_component(value: str) -> str:
    """Render a schema digest into the SSM name alphabet.

    Catalog placeholders carry ``sha256:<hex>`` values, while SSM parameter
    names do not permit ``:``.  The canonical storage component is therefore
    ``sha256-<hex>``.  This mapping is one-to-one and is enforced for both
    publication and resolution.
    """
    if not isinstance(value, str) or not DIGEST_PATTERN.fullmatch(value):
        raise LiveContractIoError("contract path digest is invalid")
    return value.replace(":", "-", 1)


def canonical_parameter_name(
    *,
    path_template: str,
    contract_id: str,
    deployment_id: str,
    release_digest: str,
    contract_digest: str,
) -> str:
    if not DEPLOYMENT_ID_PATTERN.fullmatch(deployment_id):
        raise LiveContractIoError("deployment identifier is invalid")
    expected_template = (
        f"/scanalyze/deployments/{{deployment_id}}/contracts/{contract_id}/"
        "releases/{release_digest}/digests/{contract_digest}"
    )
    if path_template != expected_template:
        raise LiveContractIoError("catalog SSM path template is not canonical")
    name = (
        path_template.replace("{deployment_id}", deployment_id)
        .replace("{release_digest}", _digest_component(release_digest))
        .replace("{contract_digest}", _digest_component(contract_digest))
    )
    if (
        len(name) > MAX_PARAMETER_NAME_CHARS
        or not PARAMETER_NAME_PATTERN.fullmatch(name)
    ):
        raise LiveContractIoError("canonical SSM parameter name is invalid")
    return name


def _release_prefix(
    *,
    path_template: str,
    contract_id: str,
    deployment_id: str,
    release_digest: str,
) -> str:
    sentinel = "sha256:" + ("0" * 64)
    name = canonical_parameter_name(
        path_template=path_template,
        contract_id=contract_id,
        deployment_id=deployment_id,
        release_digest=release_digest,
        contract_digest=sentinel,
    )
    return name.rsplit("/", 1)[0]


def _expected_parameter_arn(identity: CallerIdentity, name: str) -> str:
    return (
        f"arn:{identity.partition}:ssm:{identity.region}:{identity.account_id}:"
        f"parameter{name}"
    )


def _normalize_parameter(
    raw: Any,
    *,
    identity: CallerIdentity,
) -> dict[str, Any]:
    if not isinstance(raw, dict):
        raise LiveContractIoError("SSM parameter evidence is malformed")
    name = raw.get("Name")
    value = raw.get("Value")
    version = raw.get("Version")
    if (
        not isinstance(name, str)
        or not PARAMETER_NAME_PATTERN.fullmatch(name)
        or len(name) > MAX_PARAMETER_NAME_CHARS
        or raw.get("Type") != "String"
        or raw.get("DataType") != "text"
        or not isinstance(value, str)
        or len(value.encode("utf-8")) > MAX_PARAMETER_VALUE_BYTES
        or type(version) is not int
        or version != 1
        or raw.get("ARN") != _expected_parameter_arn(identity, name)
    ):
        raise LiveContractIoError("SSM parameter evidence violates the immutable contract")
    return {
        "ARN": raw["ARN"],
        "DataType": "text",
        "Name": name,
        "Type": "String",
        "Value": value,
        "Version": 1,
    }


def _list_snapshot(
    runner: AwsJsonRunner,
    *,
    identity: CallerIdentity,
    prefix: str,
) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    seen_names: set[str] = set()
    seen_tokens: set[str] = set()
    next_token: str | None = None
    for _page in range(MAX_DISCOVERY_PAGES):
        arguments = [
            "--path",
            prefix,
            "--recursive",
            "--max-results",
            str(DISCOVERY_PAGE_SIZE),
        ]
        if next_token is not None:
            arguments.extend(["--next-token", next_token])
        response = runner.invoke(
            "ssm",
            "get-parameters-by-path",
            region=identity.region,
            arguments=arguments,
        )
        parameters = response.get("Parameters")
        if not isinstance(parameters, list) or len(parameters) > DISCOVERY_PAGE_SIZE:
            raise LiveContractIoError("SSM discovery page is malformed or over its bound")
        for raw in parameters:
            parameter = _normalize_parameter(raw, identity=identity)
            name = parameter["Name"]
            if not name.startswith(prefix + "/") or "/" in name[len(prefix) + 1 :]:
                raise LiveContractIoError("SSM discovery returned a non-canonical descendant")
            if name in seen_names:
                raise LiveContractIoError("SSM discovery returned duplicate evidence")
            seen_names.add(name)
            results.append(parameter)
            if len(results) > MAX_DISCOVERY_RESULTS:
                raise LiveContractIoError("SSM discovery exceeds the approved result bound")

        token = response.get("NextToken")
        if token is None:
            return sorted(results, key=lambda item: item["Name"])
        if (
            not isinstance(token, str)
            or not token
            or len(token) > MAX_NEXT_TOKEN_CHARS
            or token in seen_tokens
        ):
            raise LiveContractIoError("SSM discovery pagination token is invalid")
        seen_tokens.add(token)
        next_token = token
    raise LiveContractIoError("SSM discovery exceeds the approved page bound")


def _get_exact_parameter(
    runner: AwsJsonRunner,
    *,
    identity: CallerIdentity,
    name: str,
) -> dict[str, Any]:
    response = runner.invoke(
        "ssm",
        "get-parameter",
        region=identity.region,
        arguments=("--name", name),
    )
    return _normalize_parameter(response.get("Parameter"), identity=identity)


def _decode_contract(value: str) -> dict[str, Any]:
    try:
        document = json.loads(
            value,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_nonfinite,
        )
    except json.JSONDecodeError as exc:
        raise LiveContractIoError("SSM contract value is not valid JSON") from exc
    if not isinstance(document, dict):
        raise LiveContractIoError("SSM contract value must be a JSON object")
    return document


def resolve_required_ssm_contracts(
    runner: AwsJsonRunner,
    *,
    identity: CallerIdentity,
    catalog: Mapping[str, Any],
    required_contracts: set[str],
    deployment_id: str,
    release_digest: str,
) -> list[dict[str, Any]]:
    """Resolve only the exact catalog-declared immutable SSM contracts."""
    if (
        not required_contracts
        or len(required_contracts) > MAX_REQUIRED_CONTRACTS
        or any(not isinstance(item, str) for item in required_contracts)
    ):
        raise LiveContractIoError("required contract set is outside the approved bound")
    records = catalog.get("contracts")
    if not isinstance(records, dict):
        raise LiveContractIoError("contract catalog is malformed")

    resolved: list[dict[str, Any]] = []
    for contract_id in sorted(required_contracts):
        record = records.get(contract_id)
        transport = record.get("transport") if isinstance(record, dict) else None
        if (
            not isinstance(record, dict)
            or record.get("authority") != "terraform-root"
            or not isinstance(transport, dict)
            or transport.get("kind") != "ssm"
            or set(transport) != {"kind", "path_template"}
        ):
            raise LiveContractIoError("required contract is not an SSM Terraform contract")
        template = transport.get("path_template")
        if not isinstance(template, str):
            raise LiveContractIoError("catalog SSM path template is malformed")
        prefix = _release_prefix(
            path_template=template,
            contract_id=contract_id,
            deployment_id=deployment_id,
            release_digest=release_digest,
        )
        first = _list_snapshot(runner, identity=identity, prefix=prefix)
        second = _list_snapshot(runner, identity=identity, prefix=prefix)
        if first != second or len(first) != 1:
            raise LiveContractIoError(
                "SSM contract discovery is missing, ambiguous, or inconsistent"
            )
        discovered = first[0]
        contract = _decode_contract(discovered["Value"])
        if contract.get("output_schema_version") != contract_id:
            raise LiveContractIoError("SSM contract identifier is not catalog-bound")
        digest = contract.get("contract_digest")
        if not isinstance(digest, str):
            raise LiveContractIoError("SSM contract digest is missing")
        expected_name = canonical_parameter_name(
            path_template=template,
            contract_id=contract_id,
            deployment_id=deployment_id,
            release_digest=release_digest,
            contract_digest=digest,
        )
        if discovered["Name"] != expected_name:
            raise LiveContractIoError("SSM contract path is not digest-bound")
        exact_first = _get_exact_parameter(
            runner, identity=identity, name=expected_name
        )
        exact_second = _get_exact_parameter(
            runner, identity=identity, name=expected_name
        )
        if exact_first != exact_second or exact_first != discovered:
            raise LiveContractIoError("SSM contract double read is inconsistent")
        resolved.append(contract)
    return resolved


def _contract_tags(envelope: Mapping[str, Any]) -> list[dict[str, str]]:
    tags = {
        "scanalyze:contract-digest": envelope.get("contract_digest"),
        "scanalyze:contract-id": envelope.get("output_schema_version"),
        "scanalyze:customer-id": envelope.get("customer_id"),
        "scanalyze:deployment-id": envelope.get("deployment_id"),
        "scanalyze:managed-by": "contract-publisher",
        "scanalyze:producer": envelope.get("producer"),
        "scanalyze:release-digest": envelope.get("release_digest"),
    }
    if any(
        not isinstance(key, str)
        or not 1 <= len(key) <= 128
        or not isinstance(value, str)
        or not 1 <= len(value) <= 256
        for key, value in tags.items()
    ):
        raise LiveContractIoError("SSM contract tags are invalid")
    return [{"Key": key, "Value": tags[key]} for key in sorted(tags)]


def _read_exact_tags(
    runner: AwsJsonRunner,
    *,
    identity: CallerIdentity,
    name: str,
) -> list[dict[str, str]]:
    response = runner.invoke(
        "ssm",
        "list-tags-for-resource",
        region=identity.region,
        arguments=("--resource-type", "Parameter", "--resource-id", name),
    )
    raw_tags = response.get("TagList")
    if not isinstance(raw_tags, list) or len(raw_tags) > 16:
        raise LiveContractIoError("SSM contract tag readback is malformed")
    tags: list[dict[str, str]] = []
    seen: set[str] = set()
    for item in raw_tags:
        if not isinstance(item, dict) or set(item) != {"Key", "Value"}:
            raise LiveContractIoError("SSM contract tag readback is malformed")
        key = item.get("Key")
        value = item.get("Value")
        if not isinstance(key, str) or not isinstance(value, str) or key in seen:
            raise LiveContractIoError("SSM contract tag readback is malformed")
        seen.add(key)
        tags.append({"Key": key, "Value": value})
    return sorted(tags, key=lambda item: item["Key"])


def publish_immutable_ssm_contract(
    runner: AwsJsonRunner,
    *,
    identity: CallerIdentity,
    catalog: Mapping[str, Any],
    envelope: Mapping[str, Any],
) -> str:
    """Create or exactly reconcile one immutable envelope.

    ``PutParameter`` is intentionally attempted once.  Its response can be
    lost after SSM commits the create, and a protected workflow can then be
    re-entered.  In both cases the only success authority is two exact
    parameter reads plus two exact tag reads.  A missing or different record
    remains a terminal conflict; no overwrite or second write is attempted.
    """
    contract_id = envelope.get("output_schema_version")
    records = catalog.get("contracts")
    record = records.get(contract_id) if isinstance(records, dict) else None
    transport = record.get("transport") if isinstance(record, dict) else None
    if (
        not isinstance(contract_id, str)
        or not isinstance(record, dict)
        or record.get("authority") != "terraform-root"
        or not isinstance(transport, dict)
        or transport.get("kind") != "ssm"
        or set(transport) != {"kind", "path_template"}
        or envelope.get("layer") != record.get("producer")
        or envelope.get("producer") != f"roots/{record.get('producer')}"
        or envelope.get("aws_account_id") != identity.account_id
    ):
        raise LiveContractIoError("contract publication is not catalog-bound")
    scope = record.get("scope")
    if (
        envelope.get("scope") != scope
        or (scope == "global" and envelope.get("region") != "global")
        or (scope == "regional" and envelope.get("region") != identity.region)
        or scope not in {"global", "regional"}
    ):
        raise LiveContractIoError("contract publication scope is not catalog-bound")
    template = transport.get("path_template")
    if not isinstance(template, str):
        raise LiveContractIoError("catalog SSM path template is malformed")
    deployment_id = envelope.get("deployment_id")
    release_digest = envelope.get("release_digest")
    contract_digest = envelope.get("contract_digest")
    outputs = envelope.get("outputs")
    if not all(
        isinstance(value, str)
        for value in (deployment_id, release_digest, contract_digest)
    ) or not isinstance(outputs, dict):
        raise LiveContractIoError("contract publication binding is incomplete")
    if compute_digest(canonicalize(outputs)) != contract_digest:
        raise LiveContractIoError("contract publication digest is invalid")
    name = canonical_parameter_name(
        path_template=template,
        contract_id=contract_id,
        deployment_id=deployment_id,
        release_digest=release_digest,
        contract_digest=contract_digest,
    )
    encoded = canonicalize(dict(envelope))
    if len(encoded) > MAX_PARAMETER_VALUE_BYTES:
        raise LiveContractIoError("contract envelope exceeds the SSM Standard bound")
    value = encoded.decode("ascii")
    tags = _contract_tags(envelope)
    try:
        response = runner.invoke(
            "ssm",
            "put-parameter",
            region=identity.region,
            arguments=(
                "--name",
                name,
                "--description",
                "Immutable Scanalyze Terraform layer contract",
                "--type",
                "String",
                "--data-type",
                "text",
                "--tier",
                "Standard",
                "--value",
                value,
                "--no-overwrite",
                "--tags",
                json.dumps(tags, sort_keys=True, separators=(",", ":")),
            ),
        )
        create_response_exact = (
            response.get("Version") == 1 and response.get("Tier") == "Standard"
        )
    except LiveContractIoError:
        # The create can have committed before its response was lost, or an
        # earlier protected invocation can already have published this exact
        # content-addressed record.  Readback below is the sole recovery path.
        create_response_exact = False

    expected_parameter = {
        "ARN": _expected_parameter_arn(identity, name),
        "DataType": "text",
        "Name": name,
        "Type": "String",
        "Value": value,
        "Version": 1,
    }
    try:
        first = _get_exact_parameter(runner, identity=identity, name=name)
        second = _get_exact_parameter(runner, identity=identity, name=name)
    except (LiveContractIoError, KeyError):
        raise LiveContractIoError(
            "SSM contract publication could not be reconciled"
        ) from None
    if first != expected_parameter or second != expected_parameter:
        raise LiveContractIoError("SSM contract readback does not match the publication")
    try:
        first_tags = _read_exact_tags(runner, identity=identity, name=name)
        second_tags = _read_exact_tags(runner, identity=identity, name=name)
    except (LiveContractIoError, KeyError):
        raise LiveContractIoError(
            "SSM contract publication tags could not be reconciled"
        ) from None
    if first_tags != tags or second_tags != tags:
        raise LiveContractIoError("SSM contract tags do not match the publication")
    if not create_response_exact:
        # Exact immutable readback proves the requested end state.  This does
        # not authorize an overwrite and deliberately performs no second put.
        return name
    return name


__all__ = [
    "AwsJsonRunner",
    "CallerIdentity",
    "LiveContractIoError",
    "SubprocessAwsCliRunner",
    "canonical_parameter_name",
    "publish_immutable_ssm_contract",
    "resolve_required_ssm_contracts",
    "verify_caller_identity",
]
