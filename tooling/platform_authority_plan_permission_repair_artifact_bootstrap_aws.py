"""Zero-retry AWS boundary for the temporary GUG-376 artifact bootstrap.

Every public operation validates a sealed offline contract, calls STS before
any other AWS API, and creates an owner-only O_EXCL claim before its sole
mutation.  Mutation failures are classified as uncertain and are never
retried.  Recovery and terminal readback are separate, read-only operations.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import base64
from hashlib import sha256
from itertools import permutations, product
import json
import os
from pathlib import Path
import re
import stat
import subprocess
from typing import Any, Callable, Mapping
from urllib.parse import urlsplit
import yaml

from tooling import platform_authority_plan_permission_repair_artifact_bootstrap as contract


DISPATCH_RECEIPT_TYPE = (
    "scanalyze.platform_authority.gug376_artifact_bootstrap_dispatch.v1"
)
EXECUTION_RECEIPT_TYPE = (
    "scanalyze.platform_authority.gug376_artifact_bootstrap_execution.v1"
)
CHANGE_SET_ATTESTATION_TYPE = (
    "scanalyze.platform_authority.gug376_artifact_bootstrap_change_set_attestation.v1"
)
STACK_READBACK_TYPE = contract.STACK_READBACK_TYPE
FOUNDATION_READBACK_TYPE = contract.FOUNDATION_READBACK_TYPE
OBJECT_DISPATCH_TYPE = (
    "scanalyze.platform_authority.gug376_artifact_object_dispatch.v1"
)
SIGNING_DISPATCH_TYPE = (
    "scanalyze.platform_authority.gug376_artifact_signing_dispatch.v1"
)
SIGNING_READBACK_TYPE = (
    "scanalyze.platform_authority.gug376_artifact_signing_readback.v1"
)

_MGMT_CALLER = re.compile(
    r"^arn:aws:sts::839393571433:assumed-role/"
    r"AWSReservedSSO_AWSAdministratorAccess_[0-9A-Fa-f]{16}/"
    r"[A-Za-z0-9+=,.@_-]{1,64}$"
)
_AUTH_CALLER = re.compile(
    r"^arn:aws:sts::042360977644:assumed-role/"
    r"AWSReservedSSO_ScanalyzeGug376ArtifactBootstrap_[0-9A-Fa-f]{16}/"
    r"[A-Za-z0-9+=,.@_-]{1,64}$"
)
_VERSION = re.compile(r"^[A-Za-z0-9._~+/=-]{1,1024}$")
_JOB = re.compile(r"^[a-f0-9]{8}-(?:[a-f0-9]{4}-){3}[a-f0-9]{12}$")
_REQUEST_ID = re.compile(
    r"^[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$"
)
_S3_REQUEST_ID = re.compile(r"^[A-Za-z0-9]{16,64}$")
_EXPECTED_SSO_PROFILES = {
    contract.MANAGEMENT_PROFILE: (
        contract.MANAGEMENT_ACCOUNT_ID,
        "AWSAdministratorAccess",
    ),
    contract.AUTHORITY_PROFILE: (
        contract.AUTHORITY_ACCOUNT_ID,
        "ScanalyzeGug376ArtifactBootstrap",
    ),
}
_PROFILE_CONFIGURATION_KEYS = frozenset(
    {
        "cli_pager",
        "output",
        "region",
        "sso_account_id",
        "sso_region",
        "sso_role_name",
        "sso_session",
        "sso_start_url",
    }
)
_SSO_SESSION_CONFIGURATION_KEYS = frozenset(
    {"sso_region", "sso_registration_scopes", "sso_start_url"}
)
_AMBIENT_AWS_FORBIDDEN = frozenset(
    {
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
        "AWS_SESSION_TOKEN",
        "AWS_SECURITY_TOKEN",
        "AWS_WEB_IDENTITY_TOKEN_FILE",
        "AWS_ROLE_ARN",
        "AWS_CONTAINER_CREDENTIALS_FULL_URI",
        "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI",
        "AWS_SHARED_CREDENTIALS_FILE",
        "AWS_CONFIG_FILE",
        "AWS_CA_BUNDLE",
        "BOTO_CONFIG",
        "REQUESTS_CA_BUNDLE",
        "SSL_CERT_FILE",
        "SSL_CERT_DIR",
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "http_proxy",
        "https_proxy",
        "all_proxy",
    }
)


class ConnectedArtifactBootstrapError(RuntimeError):
    """Stable provider error; uncertain means a mutation may have landed."""

    def __init__(self, code: str, *, uncertain: bool = False) -> None:
        self.code = code
        self.uncertain = uncertain
        super().__init__(f"GUG376_ARTIFACT_BOOTSTRAP_BLOCKED:{code}")


def _fail(code: str, *, uncertain: bool = False) -> None:
    raise ConnectedArtifactBootstrapError(code, uncertain=uncertain)


def _exact_parameter_values(raw: Any, *, code: str) -> dict[str, str]:
    """Project one unique, unmasked CloudFormation parameter set."""

    if not isinstance(raw, list):
        _fail(code)
    values: dict[str, str] = {}
    for item in raw:
        if not isinstance(item, Mapping):
            _fail(code)
        key = item.get("ParameterKey")
        value = item.get("ParameterValue")
        if (
            not isinstance(key, str)
            or not key
            or key in values
            or not isinstance(value, str)
            or not value
        ):
            _fail(code)
        values[key] = value
    return values


def _stamp(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        _fail("CLOCK_INVALID")
    return (
        value.astimezone(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def _response_id(
    response: Mapping[str, Any], code: str, *, service: str | None = None
) -> str:
    metadata = response.get("ResponseMetadata")
    request_id = metadata.get("RequestId") if isinstance(metadata, Mapping) else None
    if not isinstance(request_id, str) or (
        _REQUEST_ID.fullmatch(request_id) is None
        and (service != "s3" or _S3_REQUEST_ID.fullmatch(request_id) is None)
    ):
        _fail(code)
    return request_id


def _aws_error_code(exc: Exception) -> str | None:
    response = getattr(exc, "response", None)
    error = response.get("Error") if isinstance(response, Mapping) else None
    code = error.get("Code") if isinstance(error, Mapping) else None
    return code if isinstance(code, str) else None


def _call(method: Any, /, *, mutation: bool = False, code: str, **kwargs: Any) -> Mapping[str, Any]:
    try:
        response = method(**kwargs)
    except Exception as exc:
        raise ConnectedArtifactBootstrapError(code, uncertain=mutation) from exc
    if not isinstance(response, Mapping):
        _fail(code, uncertain=mutation)
    return response


def _cloudtrail_cfn_request(request: Mapping[str, Any]) -> dict[str, Any]:
    """Render the exact CreateChangeSet request shape recorded by CloudTrail."""

    expected_fields = {
        "StackName",
        "ChangeSetName",
        "ChangeSetType",
        "Description",
        "TemplateBody",
        "Parameters",
        "Capabilities",
        "Tags",
        "IncludeNestedStacks",
        "NotificationARNs",
        "RollbackConfiguration",
        "ClientToken",
    }
    request_fields = set(request)
    change_set_type = request.get("ChangeSetType")
    if (
        change_set_type == "CREATE"
        and (
            request_fields != expected_fields | {"OnStackFailure"}
            or request.get("OnStackFailure") != "DELETE"
        )
    ) or (
        change_set_type == "UPDATE" and request_fields != expected_fields
    ) or change_set_type not in {"CREATE", "UPDATE"}:
        _fail("CLOUDFORMATION_REQUEST_INVALID")
    result: dict[str, Any] = {
        "stackName": request["StackName"],
        "changeSetName": request["ChangeSetName"],
        "changeSetType": request["ChangeSetType"],
        "description": request["Description"],
        "templateBody": request["TemplateBody"],
        "parameters": [
            {
                "parameterKey": item["ParameterKey"],
                "parameterValue": item["ParameterValue"],
            }
            for item in request["Parameters"]
        ],
        "capabilities": list(request["Capabilities"]),
        "tags": [
            {"key": item["Key"], "value": item["Value"]}
            for item in request["Tags"]
        ],
        "includeNestedStacks": request["IncludeNestedStacks"],
        "notificationARNs": list(request["NotificationARNs"]),
        "rollbackConfiguration": {
            "monitoringTimeInMinutes": request["RollbackConfiguration"][
                "MonitoringTimeInMinutes"
            ],
            "rollbackTriggers": [
                {"arn": item["Arn"], "type": item["Type"]}
                for item in request["RollbackConfiguration"]["RollbackTriggers"]
            ],
        },
        "clientToken": request["ClientToken"],
    }
    if "OnStackFailure" in request:
        result["onStackFailure"] = request["OnStackFailure"]
    return result


def _cloudtrail_execute_request(request: Mapping[str, Any]) -> dict[str, str]:
    """Render the only ExecuteChangeSet request accepted by this route."""

    if set(request) != {"ChangeSetName", "StackName", "ClientRequestToken"} or any(
        not isinstance(request[key], str) or not request[key]
        for key in request
    ):
        _fail("CLOUDFORMATION_EXECUTE_REQUEST_INVALID")
    return {
        "changeSetName": request["ChangeSetName"],
        "stackName": request["StackName"],
        "clientRequestToken": request["ClientRequestToken"],
    }


def _allowed_change_detail_digests(
    *, property_name: str, references: frozenset[str]
) -> set[str]:
    """Enumerate the closed DescribeChangeSet detail shapes we attest."""

    def detail(
        *, source: str, evaluation: str, causing: str | None
    ) -> dict[str, Any]:
        return {
            "ChangeSource": source,
            "Evaluation": evaluation,
            "CausingEntity": causing,
            "Target": {
                "Attribute": "Properties",
                "Name": property_name,
                "RequiresRecreation": "Never",
            },
        }

    allowed = {
        contract.digest_value(
            [
                detail(
                    source="DirectModification",
                    evaluation=evaluation,
                    causing=None,
                )
            ]
        )
        for evaluation in ("Static", "Dynamic")
    }
    ordered = tuple(sorted(references))
    for ordering in permutations(ordered):
        for evaluations in product(("Static", "Dynamic"), repeat=len(ordering)):
            allowed.add(
                contract.digest_value(
                    [
                        detail(
                            source="ParameterReference",
                            evaluation=evaluation,
                            causing=reference,
                        )
                        for reference, evaluation in zip(
                            ordering, evaluations, strict=True
                        )
                    ]
                )
            )
    return allowed


def _read_bounded_stream(stream: Any, *, code: str) -> bytes:
    if stream is None or not callable(getattr(stream, "read", None)):
        _fail(code)
    chunks: list[bytes] = []
    remaining = 16 * 1024 * 1024 + 1
    try:
        while remaining:
            chunk = stream.read(min(65_536, remaining))
            if not isinstance(chunk, bytes):
                _fail(code)
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        payload = b"".join(chunks)
        if len(payload) > 16 * 1024 * 1024:
            _fail(code)
        return payload
    finally:
        close = getattr(stream, "close", None)
        if callable(close):
            close()


class _CloudFormationLoader(yaml.SafeLoader):
    """Minimal loader used only to materialize the reviewed bridge policy."""


def _cloudformation_tag(
    loader: _CloudFormationLoader, suffix: str, node: yaml.Node
) -> Any:
    if isinstance(node, yaml.ScalarNode):
        value = loader.construct_scalar(node)
    elif isinstance(node, yaml.SequenceNode):
        value = loader.construct_sequence(node)
    else:
        value = loader.construct_mapping(node)
    return {"Ref" if suffix == "Ref" else f"Fn::{suffix}": value}


_CloudFormationLoader.add_multi_constructor("!", _cloudformation_tag)


def _resolve_bridge_policy(
    *,
    template_body: str,
    parameters: Mapping[str, str],
    logical_id: str = "ArtifactBootstrapPermissionSet",
) -> dict[str, Any]:
    try:
        template = yaml.load(template_body, Loader=_CloudFormationLoader)
        policy = template["Resources"][logical_id][
            "Properties"
        ]["InlinePolicy"]
    except (KeyError, TypeError, yaml.YAMLError) as exc:
        raise ConnectedArtifactBootstrapError("BRIDGE_POLICY_SOURCE_INVALID") from exc

    substitutions = {
        **{key: str(value) for key, value in parameters.items()},
        "AWS::Partition": "aws",
        "AWS::Region": contract.REGION,
        "AWS::AccountId": contract.MANAGEMENT_ACCOUNT_ID,
    }

    def resolve(value: Any) -> Any:
        if isinstance(value, list):
            return [resolve(item) for item in value]
        if not isinstance(value, Mapping):
            return value
        if set(value) == {"Ref"}:
            result = substitutions.get(str(value["Ref"]))
            if result is None:
                _fail("BRIDGE_POLICY_SOURCE_INVALID")
            return result
        if set(value) == {"Fn::Sub"}:
            raw = value["Fn::Sub"]
            local = dict(substitutions)
            if isinstance(raw, list) and len(raw) == 2 and isinstance(raw[1], Mapping):
                template_text = raw[0]
                local.update({key: str(resolve(item)) for key, item in raw[1].items()})
            else:
                template_text = raw
            if not isinstance(template_text, str):
                _fail("BRIDGE_POLICY_SOURCE_INVALID")
            return re.sub(
                r"\$\{([A-Za-z0-9:._-]+)\}",
                lambda match: local.get(match.group(1), match.group(0)),
                template_text,
            )
        return {str(key): resolve(item) for key, item in value.items()}

    resolved = resolve(policy)
    if not isinstance(resolved, dict) or "${" in contract.canonical_json(resolved):
        _fail("BRIDGE_POLICY_SOURCE_INVALID")
    return resolved


def _resolve_bridge_role_contract(
    *, template_body: str, parameters: Mapping[str, str]
) -> dict[str, Any]:
    """Resolve the exact bridge-owned management recovery role contract."""

    try:
        template = yaml.load(template_body, Loader=_CloudFormationLoader)
        properties = template["Resources"]["ManagementRecoveryRole"]["Properties"]
    except (KeyError, TypeError, yaml.YAMLError) as exc:
        raise ConnectedArtifactBootstrapError("BRIDGE_ROLE_SOURCE_INVALID") from exc
    substitutions = {
        **{key: str(value) for key, value in parameters.items()},
        "AWS::Partition": "aws",
        "AWS::Region": contract.REGION,
        "AWS::AccountId": contract.MANAGEMENT_ACCOUNT_ID,
    }

    def resolve(value: Any) -> Any:
        if isinstance(value, list):
            return [resolve(item) for item in value]
        if not isinstance(value, Mapping):
            return value
        if set(value) == {"Ref"}:
            result = substitutions.get(str(value["Ref"]))
            if result is None:
                _fail("BRIDGE_ROLE_SOURCE_INVALID")
            return result
        if set(value) == {"Fn::Sub"}:
            raw = value["Fn::Sub"]
            local = dict(substitutions)
            if isinstance(raw, list) and len(raw) == 2 and isinstance(raw[1], Mapping):
                text = raw[0]
                local.update({key: str(resolve(item)) for key, item in raw[1].items()})
            else:
                text = raw
            if not isinstance(text, str):
                _fail("BRIDGE_ROLE_SOURCE_INVALID")
            return re.sub(
                r"\$\{([A-Za-z0-9:._-]+)\}",
                lambda match: local.get(match.group(1), match.group(0)),
                text,
            )
        return {str(key): resolve(item) for key, item in value.items()}

    resolved = resolve(properties)
    if not isinstance(resolved, Mapping) or "${" in contract.canonical_json(resolved):
        _fail("BRIDGE_ROLE_SOURCE_INVALID")
    return json.loads(contract.canonical_json(dict(resolved)))


def _parse_policy(value: Any, *, code: str) -> dict[str, Any]:
    if isinstance(value, Mapping):
        return json.loads(contract.canonical_json(dict(value)))

    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, item in pairs:
            if key in result:
                raise ValueError("duplicate key")
            result[key] = item
        return result

    try:
        parsed = json.loads(str(value), object_pairs_hook=reject_duplicates)
    except (TypeError, ValueError, json.JSONDecodeError) as exc:
        raise ConnectedArtifactBootstrapError(code) from exc
    if not isinstance(parsed, dict):
        _fail(code)
    return parsed


@dataclass(frozen=True, slots=True)
class Clients:
    sts: Any
    cloudformation: Any
    cloudtrail: Any | None = None
    sso_admin: Any | None = None
    kms: Any | None = None
    s3: Any | None = None
    signer: Any | None = None
    lambda_client: Any | None = None
    iam: Any | None = None


def read_clean_reviewed_source_bytes(
    *, source_root: Path, source_commit: str
) -> dict[str, bytes]:
    """Read reviewed templates only from one clean exact origin/main commit."""

    if re.fullmatch(r"[0-9a-f]{40}", source_commit) is None:
        _fail("SOURCE_COMMIT_INVALID")
    if not source_root.is_absolute() or source_root.is_symlink():
        _fail("SOURCE_ROOT_INVALID")
    try:
        root = source_root.resolve(strict=True)
    except OSError as exc:
        raise ConnectedArtifactBootstrapError("SOURCE_ROOT_INVALID") from exc
    if root != source_root:
        _fail("SOURCE_ROOT_INVALID")

    def run(*arguments: str) -> bytes:
        try:
            completed = subprocess.run(
                ["git", "-C", str(root), *arguments],
                check=False,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=30,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise ConnectedArtifactBootstrapError("GIT_READ_FAILED") from exc
        if completed.returncode != 0:
            _fail("GIT_READ_FAILED")
        return completed.stdout

    try:
        top = Path(run("rev-parse", "--show-toplevel").decode().strip()).resolve()
        branch = run("symbolic-ref", "--short", "HEAD").decode().strip()
        head = run("rev-parse", "HEAD").decode("ascii").strip()
        origin_main = run("rev-parse", "origin/main").decode("ascii").strip()
        status = run(
            "status", "--porcelain=v1", "--untracked-files=all"
        ).decode()
    except (OSError, UnicodeError) as exc:
        raise ConnectedArtifactBootstrapError("GIT_READ_FAILED") from exc
    if (
        top != root
        or branch != "main"
        or head != source_commit
        or origin_main != source_commit
        or status != ""
    ):
        _fail("CLEAN_EXACT_MAIN_REQUIRED")
    bridge = run(
        "show",
        f"{source_commit}:{contract.BRIDGE_TEMPLATE_PATH}",
    )
    foundation = run(
        "show",
        f"{source_commit}:{contract.FOUNDATION_TEMPLATE_PATH}",
    )
    route = run(
        "show",
        f"{source_commit}:{contract.ROUTE_TEMPLATE_SOURCE_PATH}",
    )
    delegation = run(
        "show",
        f"{source_commit}:{contract.DELEGATION_TEMPLATE_SOURCE_PATH}",
    )
    return {
        "bridge": bridge,
        "foundation": foundation,
        "route": route,
        "delegation": delegation,
    }


def attest_clean_reviewed_sources(
    *, source_root: Path, bootstrap_intent: Mapping[str, Any]
) -> dict[str, Any]:
    """Seal all executable templates from one clean exact main Git tree."""

    bootstrap = contract.validate_bootstrap_intent(bootstrap_intent)
    sources = read_clean_reviewed_source_bytes(
        source_root=source_root,
        source_commit=bootstrap["source_commit"],
    )
    return contract.seal_reviewed_sources(
        bootstrap_intent=bootstrap,
        bridge_template=sources["bridge"],
        foundation_template=sources["foundation"],
        route_template=sources["route"],
        delegation_template=sources["delegation"],
    )


class OExclClaimStore:
    """Durable one-attempt claim store outside the repository."""

    def __init__(self, root: Path) -> None:
        candidate = Path(os.path.abspath(os.path.expanduser(os.fspath(root))))
        try:
            metadata = candidate.lstat()
            resolved = candidate.resolve(strict=True)
        except OSError as exc:
            raise ConnectedArtifactBootstrapError("CLAIM_ROOT_INVALID") from exc
        if (
            resolved != candidate
            or not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or stat.S_IMODE(metadata.st_mode) != 0o700
        ):
            _fail("CLAIM_ROOT_INVALID")
        nofollow = getattr(os, "O_NOFOLLOW", None)
        directory_flag = getattr(os, "O_DIRECTORY", None)
        if nofollow is None or directory_flag is None:
            _fail("NOFOLLOW_UNAVAILABLE")
        try:
            directory = os.open(
                candidate,
                os.O_RDONLY | directory_flag | nofollow,
            )
            opened = os.fstat(directory)
        except OSError as exc:
            raise ConnectedArtifactBootstrapError("CLAIM_ROOT_INVALID") from exc
        if (
            opened.st_dev != metadata.st_dev
            or opened.st_ino != metadata.st_ino
            or not stat.S_ISDIR(opened.st_mode)
            or opened.st_uid != os.geteuid()
            or stat.S_IMODE(opened.st_mode) != 0o700
        ):
            os.close(directory)
            _fail("CLAIM_ROOT_INVALID")
        self._root = candidate
        self._root_device = opened.st_dev
        self._root_inode = opened.st_ino
        self._directory = directory

    def _assert_root_unchanged(self) -> None:
        try:
            current = self._root.lstat()
        except OSError as exc:
            raise ConnectedArtifactBootstrapError("CLAIM_ROOT_CHANGED") from exc
        if (
            not stat.S_ISDIR(current.st_mode)
            or current.st_dev != self._root_device
            or current.st_ino != self._root_inode
        ):
            _fail("CLAIM_ROOT_CHANGED")

    def close(self) -> None:
        directory = getattr(self, "_directory", -1)
        if directory >= 0:
            os.close(directory)
            self._directory = -1

    def __del__(self) -> None:
        try:
            self.close()
        except OSError:
            pass

    @staticmethod
    def _claim_name(operation: str, digest: str) -> str:
        return f"gug376-artifact-bootstrap-{operation}-{digest[7:23]}.claim.json"

    def reserve(
        self,
        *,
        operation: str,
        digest: str,
        claimed_at: str,
        caller_arn: str | None = None,
        request_digest: str | None = None,
        authorization_digest: str | None = None,
        authorization_record: Mapping[str, Any] | None = None,
        request_token: str | None = None,
        preflight_digest: str | None = None,
        preflight_calls: int | None = None,
        mutation_nonce: str | None = None,
        causal_claim_digest: str | None = None,
    ) -> Path:
        if (
            re.fullmatch(r"[a-z0-9-]{3,80}", operation) is None
            or re.fullmatch(r"sha256:[a-f0-9]{64}", digest) is None
            or (
                request_digest is not None
                and re.fullmatch(r"sha256:[a-f0-9]{64}", request_digest) is None
            )
            or (
                authorization_digest is not None
                and re.fullmatch(
                    r"sha256:[a-f0-9]{64}", authorization_digest
                )
                is None
            )
            or (
                authorization_record is not None
                and (
                    not isinstance(authorization_record, Mapping)
                    or authorization_record.get("authorization_digest")
                    != authorization_digest
                    or contract.digest_value(
                        {
                            key: value
                            for key, value in authorization_record.items()
                            if key != "authorization_digest"
                        }
                    )
                    != authorization_digest
                )
            )
            or (
                caller_arn is not None
                and re.fullmatch(
                    r"arn:aws:sts::[0-9]{12}:assumed-role/"
                    r"[A-Za-z0-9+=,.@_/-]{1,256}",
                    caller_arn,
                )
                is None
            )
            or (
                request_token is not None
                and re.fullmatch(r"[A-Za-z0-9._-]{1,128}", request_token) is None
            )
            or (
                preflight_digest is not None
                and re.fullmatch(r"sha256:[a-f0-9]{64}", preflight_digest) is None
            )
            or (
                preflight_calls is not None
                and (type(preflight_calls) is not int or not 1 <= preflight_calls <= 100)
            )
            or (
                mutation_nonce is not None
                and re.fullmatch(r"[a-f0-9]{64}", mutation_nonce) is None
            )
            or (
                causal_claim_digest is not None
                and re.fullmatch(
                    r"sha256:[a-f0-9]{64}", causal_claim_digest
                )
                is None
            )
        ):
            _fail("CLAIM_INPUT_INVALID")
        self._assert_root_unchanged()
        name = self._claim_name(operation, digest)
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        nofollow = getattr(os, "O_NOFOLLOW", None)
        if nofollow is None:
            _fail("NOFOLLOW_UNAVAILABLE")
        try:
            descriptor = os.open(
                name,
                flags | nofollow,
                0o600,
                dir_fd=self._directory,
            )
        except FileExistsError as exc:
            raise ConnectedArtifactBootstrapError("MUTATION_ALREADY_CLAIMED") from exc
        except OSError as exc:
            raise ConnectedArtifactBootstrapError("CLAIM_CREATE_FAILED") from exc
        record = {
            "schema_version": 1,
            "record_type": "scanalyze.platform_authority.gug376_artifact_bootstrap_claim.v1",
            "operation": operation,
            "target_digest": digest,
            "claimed_at": claimed_at,
            "caller_arn": caller_arn,
            "request_digest": request_digest,
            "authorization_digest": authorization_digest,
            "authorization_record": (
                json.loads(contract.canonical_json(dict(authorization_record)))
                if authorization_record is not None
                else None
            ),
            "request_token": request_token,
            "preflight_digest": preflight_digest,
            "preflight_calls": preflight_calls,
            "mutation_nonce": mutation_nonce,
            "causal_claim_digest": causal_claim_digest,
            "retry_permitted": False,
            "production_authorized": False,
        }
        record["claim_digest"] = contract.digest_value(record)
        payload = (contract.canonical_json(record) + "\n").encode("utf-8")
        try:
            remaining = memoryview(payload)
            while remaining:
                written = os.write(descriptor, remaining)
                if written <= 0:
                    raise OSError("short claim write")
                remaining = remaining[written:]
            os.fsync(descriptor)
            os.close(descriptor)
            descriptor = -1
            os.fsync(self._directory)
            self._assert_root_unchanged()
        except OSError as exc:
            if descriptor >= 0:
                os.close(descriptor)
            raise ConnectedArtifactBootstrapError("CLAIM_PERSIST_FAILED") from exc
        return self._root / name

    def read_exact(self, *, operation: str, digest: str) -> dict[str, Any]:
        """Read one canonical causal claim without following any path component."""

        if (
            re.fullmatch(r"[a-z0-9-]{3,80}", operation) is None
            or re.fullmatch(r"sha256:[a-f0-9]{64}", digest) is None
        ):
            _fail("CLAIM_INPUT_INVALID")
        self._assert_root_unchanged()
        nofollow = getattr(os, "O_NOFOLLOW", None)
        if nofollow is None:
            _fail("NOFOLLOW_UNAVAILABLE")
        name = self._claim_name(operation, digest)
        try:
            descriptor = os.open(
                name,
                os.O_RDONLY | nofollow,
                dir_fd=self._directory,
            )
        except FileNotFoundError as exc:
            raise ConnectedArtifactBootstrapError("CAUSAL_CLAIM_REQUIRED") from exc
        except OSError as exc:
            raise ConnectedArtifactBootstrapError("CLAIM_READ_FAILED") from exc
        try:
            metadata = os.fstat(descriptor)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_uid != os.geteuid()
                or stat.S_IMODE(metadata.st_mode) != 0o600
                or not 0 < metadata.st_size <= 65_536
            ):
                _fail("CLAIM_RECORD_INVALID")
            chunks: list[bytes] = []
            remaining = 65_537
            while remaining:
                chunk = os.read(descriptor, min(16_384, remaining))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            payload = b"".join(chunks)
        except OSError as exc:
            raise ConnectedArtifactBootstrapError("CLAIM_READ_FAILED") from exc
        finally:
            os.close(descriptor)
        try:
            record = json.loads(payload.decode("utf-8"))
        except (UnicodeError, json.JSONDecodeError) as exc:
            raise ConnectedArtifactBootstrapError("CLAIM_RECORD_INVALID") from exc
        required = {
            "schema_version",
            "record_type",
            "operation",
            "target_digest",
            "claimed_at",
            "caller_arn",
            "request_digest",
            "authorization_digest",
            "authorization_record",
            "request_token",
            "preflight_digest",
            "preflight_calls",
            "mutation_nonce",
            "causal_claim_digest",
            "retry_permitted",
            "production_authorized",
            "claim_digest",
        }
        if (
            not isinstance(record, Mapping)
            or set(record) != required
            or payload
            != (contract.canonical_json(record) + "\n").encode("utf-8")
            or record.get("schema_version") != 1
            or record.get("record_type")
            != "scanalyze.platform_authority.gug376_artifact_bootstrap_claim.v1"
            or record.get("operation") != operation
            or record.get("target_digest") != digest
            or (
                record.get("authorization_record") is not None
                and (
                    not isinstance(record.get("authorization_record"), Mapping)
                    or record["authorization_record"].get("authorization_digest")
                    != record.get("authorization_digest")
                    or contract.digest_value(
                        {
                            key: value
                            for key, value in record["authorization_record"].items()
                            if key != "authorization_digest"
                        }
                    )
                    != record.get("authorization_digest")
                )
            )
            or record.get("retry_permitted") is not False
            or record.get("production_authorized") is not False
            or contract.digest_value(
                {key: value for key, value in record.items() if key != "claim_digest"}
            )
            != record.get("claim_digest")
        ):
            _fail("CLAIM_RECORD_INVALID")
        self._assert_root_unchanged()
        return json.loads(contract.canonical_json(dict(record)))


class ConnectedArtifactBootstrapProvider:
    def __init__(
        self,
        *,
        clients: Clients,
        claims: OExclClaimStore,
        profile: str,
        clock: Callable[[], datetime],
        source_attestor: Callable[..., Mapping[str, Any]] = attest_clean_reviewed_sources,
        cleanup_success_revalidator: Callable[..., Mapping[str, Any]] | None = None,
    ) -> None:
        if profile not in {contract.MANAGEMENT_PROFILE, contract.AUTHORITY_PROFILE}:
            _fail("PROFILE_INVALID")
        self._clients = clients
        self._claims = claims
        self._profile = profile
        self._clock = clock
        self._source_attestor = source_attestor
        self._cleanup_success_revalidator = cleanup_success_revalidator

    def _revalidate_cleanup_success(
        self,
        *,
        cleanup_retire: Mapping[str, Any],
        seed_intent: Mapping[str, Any] | None,
        terminal_readbacks: Mapping[str, Any] | None,
    ) -> int:
        """Require just-in-time connected seed terminal re-read for SUCCESS."""

        if cleanup_retire.get("mode") != "SUCCESS":
            return 0
        if (
            self._cleanup_success_revalidator is None
            or seed_intent is None
            or terminal_readbacks is None
        ):
            _fail("CLEANUP_RETIRE_LIVE_REVALIDATOR_REQUIRED")
        try:
            live = self._cleanup_success_revalidator(
                seed_intent=seed_intent,
                terminal_readbacks=terminal_readbacks,
            )
        except ConnectedArtifactBootstrapError:
            raise
        except Exception as exc:
            raise ConnectedArtifactBootstrapError(
                "CLEANUP_RETIRE_LIVE_REVALIDATION_FAILED"
            ) from exc
        if (
            not isinstance(live, Mapping)
            or set(live) != {"route", "broker", "broker-protection"}
        ):
            _fail("CLEANUP_RETIRE_LIVE_REVALIDATION_MISMATCH")
        observed_now = self._clock()
        if observed_now.tzinfo is None or observed_now.utcoffset() is None:
            _fail("CLOCK_INVALID")
        current = observed_now.astimezone(timezone.utc).replace(microsecond=0)
        calls = 0
        freshness = {"read_at", "readback_digest"}
        for target in ("route", "broker", "broker-protection"):
            supplied = terminal_readbacks.get(target)
            observed = live.get(target)
            if (
                not isinstance(supplied, Mapping)
                or not isinstance(observed, Mapping)
                or set(observed) != set(supplied)
                or contract.digest_value(
                    {
                        key: value
                        for key, value in observed.items()
                        if key != "readback_digest"
                    }
                )
                != observed.get("readback_digest")
                or type(observed.get("aws_calls")) is not int
                or observed["aws_calls"] < 4
            ):
                _fail("CLEANUP_RETIRE_LIVE_REVALIDATION_MISMATCH")
            try:
                supplied_at = self._parse_claim_time(
                    supplied.get("read_at"),
                    code="CLEANUP_RETIRE_LIVE_REVALIDATION_MISMATCH",
                )
                observed_at = self._parse_claim_time(
                    observed.get("read_at"),
                    code="CLEANUP_RETIRE_LIVE_REVALIDATION_MISMATCH",
                )
            except ConnectedArtifactBootstrapError:
                raise
            supplied_immutable = {
                key: value for key, value in supplied.items() if key not in freshness
            }
            observed_immutable = {
                key: value for key, value in observed.items() if key not in freshness
            }
            if (
                supplied_immutable != observed_immutable
                or not supplied_at <= observed_at <= current
            ):
                _fail("CLEANUP_RETIRE_LIVE_REVALIDATION_MISMATCH")
            calls += observed["aws_calls"]
        if calls != cleanup_retire.get("terminal_revalidation_aws_calls"):
            _fail("CLEANUP_RETIRE_LIVE_REVALIDATION_MISMATCH")
        return calls

    def _reviewed_sources(
        self, *, source_root: Path, bootstrap: Mapping[str, Any]
    ) -> dict[str, Any]:
        if not isinstance(source_root, Path):
            _fail("SOURCE_ROOT_INVALID")
        try:
            value = self._source_attestor(
                source_root=source_root,
                bootstrap_intent=bootstrap,
            )
            return contract.validate_reviewed_sources(
                value, bootstrap_intent=bootstrap
            )
        except contract.ArtifactBootstrapError as exc:
            raise ConnectedArtifactBootstrapError(
                "REVIEWED_SOURCES_INVALID"
            ) from exc

    def _identity(self) -> tuple[str, str, str]:
        expected_account = (
            contract.MANAGEMENT_ACCOUNT_ID
            if self._profile == contract.MANAGEMENT_PROFILE
            else contract.AUTHORITY_ACCOUNT_ID
        )
        caller_pattern = (
            _MGMT_CALLER
            if self._profile == contract.MANAGEMENT_PROFILE
            else _AUTH_CALLER
        )
        response = _call(
            self._clients.sts.get_caller_identity,
            code="STS_GET_CALLER_IDENTITY_FAILED",
        )
        caller = response.get("Arn")
        if (
            response.get("Account") != expected_account
            or not isinstance(caller, str)
            or caller_pattern.fullmatch(caller) is None
        ):
            _fail("AWS_IDENTITY_INVALID")
        return expected_account, caller, _response_id(response, "STS_RESPONSE_INVALID")

    def _verifier(self, account: str, caller: str) -> dict[str, str]:
        return {
            "account_id": account,
            "caller_arn": caller,
            "profile": self._profile,
            "region": contract.REGION,
        }

    def _require_window(
        self, bootstrap: Mapping[str, Any], *, read_only: bool
    ) -> datetime:
        """Fail locally before STS when the exact operation window is closed."""

        current = self._clock()
        if current.tzinfo is None or current.utcoffset() is None:
            _fail("CLOCK_INVALID")
        now = current.astimezone(timezone.utc)
        start = self._parse_claim_time(
            bootstrap.get("access_not_before"), code="WINDOW_INVALID"
        )
        boundary = self._parse_claim_time(
            bootstrap.get(
                "recovery_not_after" if read_only else "access_not_after"
            ),
            code="WINDOW_INVALID",
        )
        if not read_only:
            boundary -= timedelta(
                seconds=contract.MUTATION_COMPLETION_RESERVE_SECONDS
            )
        if not start <= now < boundary:
            _fail(
                "RECOVERY_WINDOW_CLOSED" if read_only else "WRITE_WINDOW_CLOSED"
            )
        return now

    def _require_cleanup_retire_clock(
        self, cleanup_retire: Mapping[str, Any], *, admission: bool
    ) -> datetime:
        """Enforce SUCCESS/EXPIRED retirement chronology before any AWS call."""

        current = self._clock()
        if current.tzinfo is None or current.utcoffset() is None:
            _fail("CLOCK_INVALID")
        now = current.astimezone(timezone.utc).replace(microsecond=0)
        evaluated = self._parse_claim_time(
            cleanup_retire.get("evaluated_at"), code="CLEANUP_RETIRE_WINDOW_INVALID"
        )
        cleanup_end = self._parse_claim_time(
            cleanup_retire.get("cleanup_not_after"),
            code="CLEANUP_RETIRE_WINDOW_INVALID",
        )
        mode = cleanup_retire.get("mode")
        if now < evaluated:
            _fail("CLEANUP_RETIRE_WINDOW_INVALID")
        if admission and (
            (mode == "SUCCESS" and not now < cleanup_end)
            or (mode == "EXPIRED" and not cleanup_end <= now)
            or mode not in {"SUCCESS", "EXPIRED"}
        ):
            _fail("CLEANUP_RETIRE_WINDOW_INVALID")
        return now

    @staticmethod
    def _validate_cleanup_retire_receipt_time(
        value: object, *, cleanup_retire: Mapping[str, Any], code: str
    ) -> datetime:
        observed = ConnectedArtifactBootstrapProvider._parse_claim_time(
            value, code=code
        )
        evaluated = ConnectedArtifactBootstrapProvider._parse_claim_time(
            cleanup_retire.get("evaluated_at"), code=code
        )
        cleanup_end = ConnectedArtifactBootstrapProvider._parse_claim_time(
            cleanup_retire.get("cleanup_not_after"), code=code
        )
        mode = cleanup_retire.get("mode")
        if (
            observed < evaluated
            or (mode == "SUCCESS" and not observed < cleanup_end)
            or (mode == "EXPIRED" and not cleanup_end <= observed)
            or mode not in {"SUCCESS", "EXPIRED"}
        ):
            _fail(code)
        return observed

    @staticmethod
    def _validate_receipt_time(
        value: object,
        *,
        bootstrap: Mapping[str, Any],
        read_only: bool,
        code: str,
    ) -> datetime:
        observed = ConnectedArtifactBootstrapProvider._parse_claim_time(
            value, code=code
        )
        start = ConnectedArtifactBootstrapProvider._parse_claim_time(
            bootstrap.get("access_not_before"), code=code
        )
        boundary = ConnectedArtifactBootstrapProvider._parse_claim_time(
            bootstrap.get(
                "recovery_not_after" if read_only else "access_not_after"
            ),
            code=code,
        )
        if not start <= observed < boundary:
            _fail(code)
        return observed

    @staticmethod
    def _validate_dispatch_receipt(
        receipt: Mapping[str, Any],
        *,
        bootstrap: Mapping[str, Any],
        operation: str,
        intent_digest: str,
        request_digest: str,
        request: Mapping[str, Any],
        cleanup_retire: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        required = {
            "schema_version",
            "record_type",
            "source_commit",
            "operation",
            "intent_digest",
            "request_digest",
            "authorization_digest",
            "verifier",
            "stack_id",
            "change_set_id",
            "request_id",
            "dispatched_at",
            "aws_calls",
            "aws_mutations",
            "retry_permitted",
            "production_authorized",
            "production_status",
            "receipt_digest",
        }
        authority_operation = operation in {
            "foundation-create",
            "foundation-access-update",
        }
        expected_account = (
            contract.AUTHORITY_ACCOUNT_ID
            if authority_operation
            else contract.MANAGEMENT_ACCOUNT_ID
        )
        expected_profile = (
            contract.AUTHORITY_PROFILE
            if authority_operation
            else contract.MANAGEMENT_PROFILE
        )
        caller_pattern = _AUTH_CALLER if authority_operation else _MGMT_CALLER
        verifier = receipt.get("verifier") if isinstance(receipt, Mapping) else None
        stack_name = request.get("StackName") if isinstance(request, Mapping) else None
        change_set_name = (
            request.get("ChangeSetName") if isinstance(request, Mapping) else None
        )
        stack_pattern = re.compile(
            rf"^arn:aws:cloudformation:{re.escape(contract.REGION)}:"
            rf"{expected_account}:stack/{re.escape(str(stack_name))}/"
            r"[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$"
        )
        change_set_pattern = re.compile(
            rf"^arn:aws:cloudformation:{re.escape(contract.REGION)}:"
            rf"{expected_account}:changeSet/{re.escape(str(change_set_name))}/"
            r"[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$"
        )
        if (
            not isinstance(receipt, Mapping)
            or set(receipt) != required
            or receipt.get("schema_version") != 1
            or receipt.get("record_type") != DISPATCH_RECEIPT_TYPE
            or receipt.get("source_commit") != bootstrap["source_commit"]
            or receipt.get("operation") != operation
            or receipt.get("intent_digest") != intent_digest
            or receipt.get("request_digest") != request_digest
            or re.fullmatch(
                r"sha256:[a-f0-9]{64}",
                str(receipt.get("authorization_digest", "")),
            )
            is None
            or not isinstance(verifier, Mapping)
            or set(verifier) != {"account_id", "caller_arn", "profile", "region"}
            or verifier.get("account_id") != expected_account
            or verifier.get("profile") != expected_profile
            or verifier.get("region") != contract.REGION
            or caller_pattern.fullmatch(str(verifier.get("caller_arn", "")))
            is None
            or not isinstance(stack_name, str)
            or not isinstance(change_set_name, str)
            or stack_pattern.fullmatch(str(receipt.get("stack_id", ""))) is None
            or change_set_pattern.fullmatch(
                str(receipt.get("change_set_id", ""))
            )
            is None
            or _REQUEST_ID.fullmatch(str(receipt.get("request_id", ""))) is None
            or receipt.get("aws_calls")
            != 2
            + (
                int(cleanup_retire.get("terminal_revalidation_aws_calls", 0))
                if operation == "bridge-cleanup-retire"
                and cleanup_retire is not None
                else 0
            )
            or receipt.get("aws_mutations") != 1
            or receipt.get("retry_permitted") is not False
            or receipt.get("production_authorized") is not False
            or receipt.get("production_status") != contract.PRODUCTION_STATUS
            or contract.digest_value(
                {key: item for key, item in receipt.items() if key != "receipt_digest"}
            )
            != receipt.get("receipt_digest")
        ):
            _fail("DISPATCH_RECEIPT_INVALID")
        if operation == "bridge-cleanup-retire":
            if cleanup_retire is None:
                _fail("DISPATCH_RECEIPT_INVALID")
            ConnectedArtifactBootstrapProvider._validate_cleanup_retire_receipt_time(
                receipt.get("dispatched_at"),
                cleanup_retire=cleanup_retire,
                code="DISPATCH_RECEIPT_INVALID",
            )
        else:
            if cleanup_retire is not None:
                _fail("DISPATCH_RECEIPT_INVALID")
            ConnectedArtifactBootstrapProvider._validate_receipt_time(
                receipt.get("dispatched_at"),
                bootstrap=bootstrap,
                read_only=False,
                code="DISPATCH_RECEIPT_INVALID",
            )
        return json.loads(contract.canonical_json(dict(receipt)))

    def _validate_causal_dispatch_receipt(
        self,
        receipt: Mapping[str, Any],
        *,
        bootstrap: Mapping[str, Any],
        operation: str,
        intent_digest: str,
        request_digest: str,
        request: Mapping[str, Any],
        mutation_authorization: bool,
        cleanup_retire: Mapping[str, Any] | None = None,
    ) -> tuple[dict[str, Any], int]:
        """Prove a dispatch from its immutable claim and CreateChangeSet event."""

        dispatch = self._validate_dispatch_receipt(
            receipt,
            bootstrap=bootstrap,
            operation=operation,
            intent_digest=intent_digest,
            request_digest=request_digest,
            request=request,
            cleanup_retire=cleanup_retire,
        )
        claim = self._claims.read_exact(
            operation=f"{operation}-dispatch",
            digest=request_digest,
        )
        verifier = dispatch["verifier"]
        if (
            claim.get("target_digest") != request_digest
            or claim.get("request_digest") != request_digest
            or claim.get("request_token") != request.get("ClientToken")
            or claim.get("authorization_digest")
            != dispatch["authorization_digest"]
            or claim.get("caller_arn") != verifier["caller_arn"]
            or claim.get("preflight_digest") is not None
            or claim.get("preflight_calls") is not None
            or claim.get("mutation_nonce") is not None
            or claim.get("causal_claim_digest") is not None
        ):
            _fail("DISPATCH_CAUSAL_CLAIM_MISMATCH")
        self._validate_original_claim_authorization(
            bootstrap=bootstrap,
            operation=f"{operation}:dispatch",
            target_digest=intent_digest,
            claim=claim,
            mutation_authorization=mutation_authorization,
            cleanup_retire=cleanup_retire,
        )
        expected_account = (
            contract.AUTHORITY_ACCOUNT_ID
            if operation in {"foundation-create", "foundation-access-update"}
            else contract.MANAGEMENT_ACCOUNT_ID
        )
        current_account, _current_caller, _sts_request_id = self._identity()
        if current_account != expected_account:
            _fail("DISPATCH_VERIFIER_INVALID")
        event, event_calls = self._lookup_create_change_set_event(
            bootstrap=bootstrap,
            account=expected_account,
            request=request,
            claim=claim,
            cleanup_retire=cleanup_retire,
        )
        if (
            event["stack_id"] != dispatch["stack_id"]
            or event["change_set_id"] != dispatch["change_set_id"]
            or event["request_id"] != dispatch["request_id"]
            or dispatch["dispatched_at"]
            not in {claim.get("claimed_at"), event["event_time"]}
        ):
            _fail("DISPATCH_CLOUDTRAIL_MISMATCH")
        return dispatch, 1 + event_calls

    @staticmethod
    def _validate_object_dispatch_receipt(
        receipt: Mapping[str, Any],
        *,
        bootstrap: Mapping[str, Any],
        intent: Mapping[str, Any],
    ) -> dict[str, Any]:
        required = {
            "schema_version",
            "record_type",
            "source_commit",
            "bootstrap_intent_digest",
            "object_intent_digest",
            "effect_digest",
            "mutation_nonce",
            "causal_claim_digest",
            "authorization_digest",
            "preflight_absence_digest",
            "preflight_calls",
            "verifier",
            "bucket",
            "key",
            "version",
            "provider_request_id",
            "recovery_evidence_type",
            "recovery_evidence_digest",
            "dispatched_at",
            "aws_calls",
            "aws_mutations",
            "retry_permitted",
            "production_authorized",
            "production_status",
            "receipt_digest",
        }
        verifier = receipt.get("verifier") if isinstance(receipt, Mapping) else None
        request_id = (
            receipt.get("provider_request_id")
            if isinstance(receipt, Mapping)
            else None
        )
        evidence_type = (
            receipt.get("recovery_evidence_type")
            if isinstance(receipt, Mapping)
            else None
        )
        if (
            not isinstance(receipt, Mapping)
            or set(receipt) != required
            or receipt.get("schema_version") != 1
            or receipt.get("record_type") != OBJECT_DISPATCH_TYPE
            or receipt.get("source_commit") != bootstrap["source_commit"]
            or receipt.get("bootstrap_intent_digest") != bootstrap["intent_digest"]
            or receipt.get("object_intent_digest") != intent["intent_digest"]
            or receipt.get("effect_digest") != intent["effect_digest"]
            or receipt.get("mutation_nonce") != intent["mutation_nonce"]
            or receipt.get("causal_claim_digest")
            != intent["causal_claim_digest"]
            or re.fullmatch(
                r"sha256:[a-f0-9]{64}",
                str(receipt.get("authorization_digest", "")),
            )
            is None
            or not isinstance(verifier, Mapping)
            or set(verifier) != {"account_id", "caller_arn", "profile", "region"}
            or verifier.get("account_id") != contract.AUTHORITY_ACCOUNT_ID
            or verifier.get("profile") != contract.AUTHORITY_PROFILE
            or verifier.get("region") != contract.REGION
            or _AUTH_CALLER.fullmatch(str(verifier.get("caller_arn", ""))) is None
            or receipt.get("bucket") != intent["request"]["Bucket"]
            or receipt.get("key") != intent["request"]["Key"]
            or _VERSION.fullmatch(str(receipt.get("version", ""))) is None
            or re.fullmatch(
                r"sha256:[a-f0-9]{64}",
                str(receipt.get("preflight_absence_digest", "")),
            )
            is None
            or type(receipt.get("preflight_calls")) is not int
            or not 1 <= receipt["preflight_calls"] <= 100
            or (
                evidence_type == "S3_PUT_RESPONSE"
                and (
                    not isinstance(request_id, str)
                    or (
                        _REQUEST_ID.fullmatch(request_id) is None
                        and _S3_REQUEST_ID.fullmatch(request_id) is None
                    )
                    or receipt.get("recovery_evidence_digest") is not None
                )
            )
            or (
                evidence_type == "S3_DATA_PLANE_CAUSAL_RECOVERY"
                and (
                    request_id is not None
                    or re.fullmatch(
                        r"sha256:[a-f0-9]{64}",
                        str(receipt.get("recovery_evidence_digest", "")),
                    )
                    is None
                )
            )
            or evidence_type
            not in {"S3_PUT_RESPONSE", "S3_DATA_PLANE_CAUSAL_RECOVERY"}
            or receipt.get("aws_calls") != receipt["preflight_calls"] + 2
            or receipt.get("aws_mutations") != 1
            or receipt.get("retry_permitted") is not False
            or receipt.get("production_authorized") is not False
            or receipt.get("production_status") != contract.PRODUCTION_STATUS
            or contract.digest_value(
                {
                    key: value
                    for key, value in receipt.items()
                    if key != "receipt_digest"
                }
            )
            != receipt.get("receipt_digest")
        ):
            _fail("OBJECT_DISPATCH_RECEIPT_INVALID")
        ConnectedArtifactBootstrapProvider._validate_receipt_time(
            receipt.get("dispatched_at"),
            bootstrap=bootstrap,
            read_only=False,
            code="OBJECT_DISPATCH_RECEIPT_INVALID",
        )
        return json.loads(contract.canonical_json(dict(receipt)))

    @staticmethod
    def _validate_signing_dispatch_receipt(
        receipt: Mapping[str, Any],
        *,
        bootstrap: Mapping[str, Any],
        intent: Mapping[str, Any],
    ) -> dict[str, Any]:
        required = {
            "schema_version",
            "record_type",
            "source_commit",
            "bootstrap_intent_digest",
            "signing_intent_digest",
            "authorization_digest",
            "verifier",
            "job_id",
            "job_arn",
            "request_id",
            "dispatched_at",
            "aws_calls",
            "aws_mutations",
            "retry_permitted",
            "production_authorized",
            "production_status",
            "receipt_digest",
        }
        verifier = receipt.get("verifier") if isinstance(receipt, Mapping) else None
        job_id = receipt.get("job_id") if isinstance(receipt, Mapping) else None
        if (
            not isinstance(receipt, Mapping)
            or set(receipt) != required
            or receipt.get("schema_version") != 1
            or receipt.get("record_type") != SIGNING_DISPATCH_TYPE
            or receipt.get("source_commit") != bootstrap["source_commit"]
            or receipt.get("bootstrap_intent_digest") != bootstrap["intent_digest"]
            or receipt.get("signing_intent_digest") != intent["intent_digest"]
            or re.fullmatch(
                r"sha256:[a-f0-9]{64}",
                str(receipt.get("authorization_digest", "")),
            )
            is None
            or not isinstance(verifier, Mapping)
            or set(verifier) != {"account_id", "caller_arn", "profile", "region"}
            or verifier.get("account_id") != contract.AUTHORITY_ACCOUNT_ID
            or verifier.get("profile") != contract.AUTHORITY_PROFILE
            or verifier.get("region") != contract.REGION
            or _AUTH_CALLER.fullmatch(str(verifier.get("caller_arn", ""))) is None
            or not isinstance(job_id, str)
            or _JOB.fullmatch(job_id) is None
            or receipt.get("job_arn")
            != (
                "arn:aws:signer:us-east-1:042360977644:/signing-jobs/"
                f"{job_id}"
            )
            or _REQUEST_ID.fullmatch(str(receipt.get("request_id", ""))) is None
            or receipt.get("aws_calls") != 3
            or receipt.get("aws_mutations") != 1
            or receipt.get("retry_permitted") is not False
            or receipt.get("production_authorized") is not False
            or receipt.get("production_status") != contract.PRODUCTION_STATUS
            or contract.digest_value(
                {
                    key: value
                    for key, value in receipt.items()
                    if key != "receipt_digest"
                }
            )
            != receipt.get("receipt_digest")
        ):
            _fail("SIGNING_DISPATCH_RECEIPT_INVALID")
        ConnectedArtifactBootstrapProvider._validate_receipt_time(
            receipt.get("dispatched_at"),
            bootstrap=bootstrap,
            read_only=False,
            code="SIGNING_DISPATCH_RECEIPT_INVALID",
        )
        return json.loads(contract.canonical_json(dict(receipt)))

    @staticmethod
    def _execution_effect_digest(
        *,
        operation: str,
        intent_digest: str,
        request_digest: str,
        dispatch: Mapping[str, Any],
    ) -> str:
        """Identify one CloudFormation effect without receipt/auth freshness."""

        return contract.digest_value(
            {
                "operation": operation,
                "intent_digest": intent_digest,
                "request_digest": request_digest,
                "stack_id": dispatch["stack_id"],
                "change_set_id": dispatch["change_set_id"],
            }
        )

    @staticmethod
    def _parse_claim_time(value: object, *, code: str) -> datetime:
        if not isinstance(value, str) or not value.endswith("Z"):
            _fail(code)
        try:
            parsed = datetime.fromisoformat(value[:-1] + "+00:00")
        except ValueError as exc:
            raise ConnectedArtifactBootstrapError(code) from exc
        if parsed.tzinfo is None or parsed.utcoffset() is None:
            _fail(code)
        return parsed.astimezone(timezone.utc).replace(microsecond=0)

    @staticmethod
    def _validate_attestation_chronology(
        attestation: Mapping[str, Any],
        *,
        not_before: object,
        not_after: object,
    ) -> None:
        """Bind one attestation to the causal dispatch and execute interval."""

        attested = ConnectedArtifactBootstrapProvider._parse_claim_time(
            attestation.get("attested_at"),
            code="CHANGE_SET_ATTESTATION_CHRONOLOGY_INVALID",
        )
        lower = ConnectedArtifactBootstrapProvider._parse_claim_time(
            not_before,
            code="CHANGE_SET_ATTESTATION_CHRONOLOGY_INVALID",
        )
        if isinstance(not_after, datetime):
            if not_after.tzinfo is None or not_after.utcoffset() is None:
                _fail("CHANGE_SET_ATTESTATION_CHRONOLOGY_INVALID")
            upper = not_after.astimezone(timezone.utc).replace(microsecond=0)
        else:
            upper = ConnectedArtifactBootstrapProvider._parse_claim_time(
                not_after,
                code="CHANGE_SET_ATTESTATION_CHRONOLOGY_INVALID",
            )
        if not lower <= attested <= upper:
            _fail("CHANGE_SET_ATTESTATION_CHRONOLOGY_INVALID")

    def _read_execution_claim_for_attestation(
        self,
        *,
        operation: str,
        intent_digest: str,
        request_digest: str,
        dispatch: Mapping[str, Any],
        attestation: Mapping[str, Any],
    ) -> dict[str, Any]:
        """Open the immutable execute claim and enforce causal chronology locally."""

        execution_digest = self._execution_effect_digest(
            operation=operation,
            intent_digest=intent_digest,
            request_digest=request_digest,
            dispatch=dispatch,
        )
        claim = self._claims.read_exact(
            operation=f"{operation}-execute", digest=execution_digest
        )
        self._validate_attestation_chronology(
            attestation,
            not_before=dispatch["dispatched_at"],
            not_after=claim.get("claimed_at"),
        )
        return claim

    @staticmethod
    def _validate_original_claim_authorization(
        *,
        bootstrap: Mapping[str, Any],
        operation: str,
        target_digest: str,
        claim: Mapping[str, Any],
        mutation_authorization: bool,
        cleanup_retire: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Validate the sealed pre-mutation authorization at claim time."""

        record = claim.get("authorization_record")
        if not isinstance(record, Mapping):
            _fail("CLAIM_AUTHORIZATION_REQUIRED")
        claimed = ConnectedArtifactBootstrapProvider._parse_claim_time(
            claim.get("claimed_at"), code="CLAIM_RECORD_INVALID"
        )
        if cleanup_retire is not None:
            validated = contract.validate_bridge_cleanup_retire_authorization(
                record,
                cleanup_retire=cleanup_retire,
                operation=operation.rsplit(":", 1)[-1],
                now=claimed,
            )
        elif mutation_authorization:
            validated = contract.validate_mutation_authorization(
                record,
                bootstrap_intent=bootstrap,
                operation=operation,
                target_digest=target_digest,
                now=claimed,
            )
        else:
            validated = contract.validate_authorization(
                record,
                intent=bootstrap,
                operation=operation,
                now=claimed,
            )
        if validated["authorization_digest"] != claim.get(
            "authorization_digest"
        ):
            _fail("CLAIM_AUTHORIZATION_MISMATCH")
        return validated

    def _lookup_create_change_set_event(
        self,
        *,
        bootstrap: Mapping[str, Any],
        account: str,
        request: Mapping[str, Any],
        claim: Mapping[str, Any],
        cleanup_retire: Mapping[str, Any] | None = None,
    ) -> tuple[dict[str, Any], int]:
        if self._clients.cloudtrail is None:
            _fail("CLOUDFORMATION_RECOVERY_UNAVAILABLE")
        claimed = self._parse_claim_time(
            claim.get("claimed_at"), code="CLAIM_RECORD_INVALID"
        )
        if cleanup_retire is None:
            window_start = self._parse_claim_time(
                bootstrap["access_not_before"], code="WINDOW_INVALID"
            )
            window_end: datetime | None = self._parse_claim_time(
                bootstrap["access_not_after"], code="WINDOW_INVALID"
            )
        else:
            window_start = self._parse_claim_time(
                cleanup_retire["evaluated_at"], code="WINDOW_INVALID"
            )
            window_end = (
                self._parse_claim_time(
                    cleanup_retire["cleanup_not_after"], code="WINDOW_INVALID"
                )
                if cleanup_retire.get("mode") == "SUCCESS"
                else None
            )
        current = self._clock()
        if current.tzinfo is None or current.utcoffset() is None:
            _fail("CLOCK_INVALID")
        current_end = current.astimezone(timezone.utc).replace(microsecond=0)
        end = min(current_end, window_end) if window_end is not None else current_end
        start = max(window_start, claimed)
        if (
            not start <= claimed <= end
            or (window_end is not None and not claimed < window_end)
        ):
            _fail("CLAIM_TIME_INVALID")
        expected_request = _cloudtrail_cfn_request(request)
        matches: dict[str, dict[str, Any]] = {}
        token: str | None = None
        seen_tokens: set[str] = set()
        calls = 0
        for _page in range(10):
            lookup: dict[str, Any] = {
                "LookupAttributes": [
                    {
                        "AttributeKey": "EventName",
                        "AttributeValue": "CreateChangeSet",
                    }
                ],
                "StartTime": start,
                "EndTime": end,
                "MaxResults": 50,
            }
            if token is not None:
                lookup["NextToken"] = token
            response = _call(
                self._clients.cloudtrail.lookup_events,
                code="CLOUDFORMATION_RECOVERY_EVENT_LOOKUP_FAILED",
                **lookup,
            )
            calls += 1
            _response_id(response, "CLOUDFORMATION_RECOVERY_EVENT_LOOKUP_FAILED")
            events = response.get("Events")
            if not isinstance(events, list):
                _fail("CLOUDFORMATION_RECOVERY_EVENT_INVALID")
            for event in events:
                if not isinstance(event, Mapping):
                    _fail("CLOUDFORMATION_RECOVERY_EVENT_INVALID")
                try:
                    payload = json.loads(event["CloudTrailEvent"])
                except (KeyError, TypeError, json.JSONDecodeError) as exc:
                    raise ConnectedArtifactBootstrapError(
                        "CLOUDFORMATION_RECOVERY_EVENT_INVALID"
                    ) from exc
                response_elements = payload.get("responseElements")
                identity = payload.get("userIdentity")
                event_id = payload.get("eventID")
                request_id = payload.get("requestID")
                event_time = self._parse_claim_time(
                    payload.get("eventTime"),
                    code="CLOUDFORMATION_RECOVERY_EVENT_INVALID",
                )
                if (
                    payload.get("eventSource") == "cloudformation.amazonaws.com"
                    and payload.get("eventName") == "CreateChangeSet"
                    and payload.get("awsRegion") == contract.REGION
                    and payload.get("recipientAccountId") == account
                    and payload.get("readOnly") is False
                    and payload.get("managementEvent") is True
                    and payload.get("errorCode") is None
                    and payload.get("errorMessage") is None
                    and isinstance(identity, Mapping)
                    and identity.get("arn") == claim.get("caller_arn")
                    and payload.get("requestParameters") == expected_request
                    and isinstance(response_elements, Mapping)
                    and set(response_elements) == {"id", "stackId"}
                    and isinstance(response_elements.get("id"), str)
                    and isinstance(response_elements.get("stackId"), str)
                    and isinstance(event_id, str)
                    and _REQUEST_ID.fullmatch(event_id) is not None
                    and isinstance(request_id, str)
                    and _REQUEST_ID.fullmatch(request_id) is not None
                    and claimed <= event_time <= end
                    and (window_end is None or event_time < window_end)
                ):
                    matches[event_id] = {
                        "event_id": event_id,
                        "request_id": request_id,
                        "event_time": _stamp(event_time),
                        "change_set_id": response_elements["id"],
                        "stack_id": response_elements["stackId"],
                    }
            next_token = response.get("NextToken")
            if next_token is None:
                break
            if (
                not isinstance(next_token, str)
                or not next_token
                or next_token in seen_tokens
            ):
                _fail("CLOUDFORMATION_RECOVERY_PAGINATION_INVALID")
            seen_tokens.add(next_token)
            token = next_token
        else:
            _fail("CLOUDFORMATION_RECOVERY_PAGE_LIMIT")
        if len(matches) != 1:
            _fail("CLOUDFORMATION_RECOVERY_EVENT_AMBIGUOUS")
        return next(iter(matches.values())), calls

    def _lookup_execute_change_set_event(
        self,
        *,
        bootstrap: Mapping[str, Any],
        account: str,
        request: Mapping[str, Any],
        claim: Mapping[str, Any],
        cleanup_retire: Mapping[str, Any] | None = None,
    ) -> tuple[dict[str, Any], int]:
        """Find the single original ExecuteChangeSet management event."""

        if self._clients.cloudtrail is None:
            _fail("CLOUDFORMATION_EXECUTION_RECOVERY_UNAVAILABLE")
        claimed = self._parse_claim_time(
            claim.get("claimed_at"), code="CLAIM_RECORD_INVALID"
        )
        if cleanup_retire is None:
            window_start = self._parse_claim_time(
                bootstrap["access_not_before"], code="WINDOW_INVALID"
            )
            window_end: datetime | None = self._parse_claim_time(
                bootstrap["access_not_after"], code="WINDOW_INVALID"
            )
        else:
            window_start = self._parse_claim_time(
                cleanup_retire["evaluated_at"], code="WINDOW_INVALID"
            )
            window_end = (
                self._parse_claim_time(
                    cleanup_retire["cleanup_not_after"], code="WINDOW_INVALID"
                )
                if cleanup_retire.get("mode") == "SUCCESS"
                else None
            )
        current = self._clock()
        if current.tzinfo is None or current.utcoffset() is None:
            _fail("CLOCK_INVALID")
        current_end = current.astimezone(timezone.utc).replace(microsecond=0)
        end = min(current_end, window_end) if window_end is not None else current_end
        start = max(window_start, claimed)
        if (
            not start <= claimed <= end
            or (window_end is not None and not claimed < window_end)
        ):
            _fail("CLAIM_TIME_INVALID")
        expected_request = _cloudtrail_execute_request(request)
        matches: dict[str, dict[str, Any]] = {}
        token: str | None = None
        seen_tokens: set[str] = set()
        calls = 0
        for _page in range(10):
            lookup: dict[str, Any] = {
                "LookupAttributes": [
                    {
                        "AttributeKey": "EventName",
                        "AttributeValue": "ExecuteChangeSet",
                    }
                ],
                "StartTime": start,
                "EndTime": end,
                "MaxResults": 50,
            }
            if token is not None:
                lookup["NextToken"] = token
            response = _call(
                self._clients.cloudtrail.lookup_events,
                code="CLOUDFORMATION_EXECUTION_RECOVERY_LOOKUP_FAILED",
                **lookup,
            )
            calls += 1
            _response_id(
                response, "CLOUDFORMATION_EXECUTION_RECOVERY_LOOKUP_FAILED"
            )
            events = response.get("Events")
            if not isinstance(events, list):
                _fail("CLOUDFORMATION_EXECUTION_RECOVERY_EVENT_INVALID")
            for event in events:
                if not isinstance(event, Mapping):
                    _fail("CLOUDFORMATION_EXECUTION_RECOVERY_EVENT_INVALID")
                try:
                    payload = json.loads(event["CloudTrailEvent"])
                except (KeyError, TypeError, json.JSONDecodeError) as exc:
                    raise ConnectedArtifactBootstrapError(
                        "CLOUDFORMATION_EXECUTION_RECOVERY_EVENT_INVALID"
                    ) from exc
                identity = payload.get("userIdentity")
                event_id = payload.get("eventID")
                request_id = payload.get("requestID")
                event_time = self._parse_claim_time(
                    payload.get("eventTime"),
                    code="CLOUDFORMATION_EXECUTION_RECOVERY_EVENT_INVALID",
                )
                if (
                    payload.get("eventSource") == "cloudformation.amazonaws.com"
                    and payload.get("eventName") == "ExecuteChangeSet"
                    and payload.get("awsRegion") == contract.REGION
                    and payload.get("recipientAccountId") == account
                    and payload.get("readOnly") is False
                    and payload.get("managementEvent") is True
                    and payload.get("errorCode") is None
                    and payload.get("errorMessage") is None
                    and payload.get("responseElements") is None
                    and isinstance(identity, Mapping)
                    and identity.get("arn") == claim.get("caller_arn")
                    and payload.get("requestParameters") == expected_request
                    and isinstance(event_id, str)
                    and _REQUEST_ID.fullmatch(event_id) is not None
                    and isinstance(request_id, str)
                    and _REQUEST_ID.fullmatch(request_id) is not None
                    and claimed <= event_time <= end
                    and (window_end is None or event_time < window_end)
                ):
                    matches[event_id] = {
                        "event_id": event_id,
                        "request_id": request_id,
                        "event_time": _stamp(event_time),
                    }
            next_token = response.get("NextToken")
            if next_token is None:
                break
            if (
                not isinstance(next_token, str)
                or not next_token
                or next_token in seen_tokens
            ):
                _fail("CLOUDFORMATION_EXECUTION_RECOVERY_PAGINATION_INVALID")
            seen_tokens.add(next_token)
            token = next_token
        else:
            _fail("CLOUDFORMATION_EXECUTION_RECOVERY_PAGE_LIMIT")
        if len(matches) != 1:
            _fail("CLOUDFORMATION_EXECUTION_RECOVERY_EVENT_AMBIGUOUS")
        return next(iter(matches.values())), calls

    def _recover_execution_receipt(
        self,
        *,
        bootstrap: Mapping[str, Any],
        operation: str,
        intent_digest: str,
        request_digest: str,
        dispatch: Mapping[str, Any],
        attestation: Mapping[str, Any],
        account: str,
        execution_claim: Mapping[str, Any],
        cleanup_retire: Mapping[str, Any] | None = None,
    ) -> tuple[dict[str, Any], int]:
        execution_digest = self._execution_effect_digest(
            operation=operation,
            intent_digest=intent_digest,
            request_digest=request_digest,
            dispatch=dispatch,
        )
        execute_request = {
            "ChangeSetName": dispatch["change_set_id"],
            "StackName": dispatch["stack_id"],
            "ClientRequestToken": "gug376-" + execution_digest[7:55],
        }
        claim = execution_claim
        self._validate_attestation_chronology(
            attestation,
            not_before=dispatch["dispatched_at"],
            not_after=claim.get("claimed_at"),
        )
        caller_pattern = (
            _AUTH_CALLER
            if account == contract.AUTHORITY_ACCOUNT_ID
            else _MGMT_CALLER
        )
        if (
            claim.get("request_digest") != contract.digest_value(execute_request)
            or claim.get("request_token") != execute_request["ClientRequestToken"]
            or claim.get("preflight_digest")
            != self._execution_preflight_digest(
                dispatch=dispatch, attestation=attestation
            )
            or type(claim.get("preflight_calls")) is not int
            or not 5 <= claim["preflight_calls"] <= 20
            or caller_pattern.fullmatch(str(claim.get("caller_arn", ""))) is None
            or re.fullmatch(
                r"sha256:[a-f0-9]{64}",
                str(claim.get("authorization_digest", "")),
            )
            is None
        ):
            _fail("EXECUTION_CAUSAL_CLAIM_MISMATCH")
        self._validate_original_claim_authorization(
            bootstrap=bootstrap,
            operation=f"{operation}:execute",
            target_digest=intent_digest,
            claim=claim,
            mutation_authorization=operation
            in {"bridge-pin", "foundation-access-update"},
            cleanup_retire=cleanup_retire,
        )
        self._identity()
        event, event_calls = self._lookup_execute_change_set_event(
            bootstrap=bootstrap,
            account=account,
            request=execute_request,
            claim=claim,
            cleanup_retire=cleanup_retire,
        )
        receipt: dict[str, Any] = {
            "schema_version": 1,
            "record_type": EXECUTION_RECEIPT_TYPE,
            "source_commit": bootstrap["source_commit"],
            "operation": operation,
            "intent_digest": intent_digest,
            "dispatch_receipt_digest": dispatch["receipt_digest"],
            "change_set_attestation_digest": attestation["attestation_digest"],
            "authorization_digest": claim["authorization_digest"],
            "verifier": self._verifier(account, claim["caller_arn"]),
            "request_id": event["request_id"],
            "dispatched_at": claim["claimed_at"],
            "aws_calls": claim["preflight_calls"] + 1,
            "aws_mutations": 1,
            "retry_permitted": False,
            "production_authorized": False,
            "production_status": contract.PRODUCTION_STATUS,
        }
        receipt["receipt_digest"] = contract.digest_value(receipt)
        return receipt, 1 + event_calls

    def _recover_cfn_dispatch(
        self,
        *,
        bootstrap: Mapping[str, Any],
        operation: str,
        intent_digest: str,
        request_digest: str,
        request: Mapping[str, Any],
        account: str,
        cleanup_retire: Mapping[str, Any] | None = None,
    ) -> tuple[dict[str, Any], int]:
        claim = self._claims.read_exact(
            operation=f"{operation}-dispatch",
            digest=request_digest,
        )
        if (
            claim.get("request_digest") != request_digest
            or claim.get("request_token") != request.get("ClientToken")
            or not isinstance(claim.get("caller_arn"), str)
            or not isinstance(claim.get("authorization_digest"), str)
        ):
            _fail("CAUSAL_CLAIM_MISMATCH")
        self._validate_original_claim_authorization(
            bootstrap=bootstrap,
            operation=f"{operation}:dispatch",
            target_digest=intent_digest,
            claim=claim,
            mutation_authorization=operation
            in {"bridge-pin", "foundation-access-update"},
            cleanup_retire=cleanup_retire,
        )
        _current_account, _current_caller, _sts_request_id = self._identity()
        event, event_calls = self._lookup_create_change_set_event(
            bootstrap=bootstrap,
            account=account,
            request=request,
            claim=claim,
            cleanup_retire=cleanup_retire,
        )
        response = _call(
            self._clients.cloudformation.describe_change_set,
            code="DESCRIBE_CHANGE_SET_FAILED",
            StackName=request["StackName"],
            ChangeSetName=request["ChangeSetName"],
            IncludePropertyValues=True,
        )
        _response_id(response, "DESCRIBE_CHANGE_SET_FAILED")
        _response_id(response, "CHANGE_SET_RECOVERY_MISMATCH")
        if (
            response.get("StackName") != request["StackName"]
            or response.get("ChangeSetName") != request["ChangeSetName"]
            or response.get("Status") != "CREATE_COMPLETE"
            or response.get("ExecutionStatus") != "AVAILABLE"
            or response.get("StackId") != event["stack_id"]
            or response.get("ChangeSetId") != event["change_set_id"]
        ):
            _fail("CHANGE_SET_RECOVERY_MISMATCH")
        dispatch: dict[str, Any] = {
            "schema_version": 1,
            "record_type": DISPATCH_RECEIPT_TYPE,
            "source_commit": bootstrap["source_commit"],
            "operation": operation,
            "intent_digest": intent_digest,
            "request_digest": request_digest,
            "authorization_digest": claim["authorization_digest"],
            "verifier": self._verifier(account, claim["caller_arn"]),
            "stack_id": event["stack_id"],
            "change_set_id": event["change_set_id"],
            "request_id": event["request_id"],
            "dispatched_at": event["event_time"],
            "aws_calls": 2,
            "aws_mutations": 1,
            "retry_permitted": False,
            "production_authorized": False,
            "production_status": contract.PRODUCTION_STATUS,
        }
        dispatch["receipt_digest"] = contract.digest_value(dispatch)
        return dispatch, 2 + event_calls

    def _list_exact_object_versions(
        self,
        *,
        bucket: str,
        key: str,
        code: str,
    ) -> tuple[list[Mapping[str, Any]], list[Mapping[str, Any]], dict[str, Any]]:
        if self._clients.s3 is None:
            _fail("OPERATION_PROFILE_INVALID")
        versions: list[Mapping[str, Any]] = []
        deletes: list[Mapping[str, Any]] = []
        token: tuple[str, str] | None = None
        seen_tokens: set[tuple[str, str]] = set()
        request_ids: list[str] = []
        for page in range(1, 101):
            request: dict[str, Any] = {
                "Bucket": bucket,
                "Prefix": key,
                "ExpectedBucketOwner": contract.AUTHORITY_ACCOUNT_ID,
            }
            if token is not None:
                request["KeyMarker"], request["VersionIdMarker"] = token
            response = _call(
                self._clients.s3.list_object_versions,
                code=code,
                **request,
            )
            request_ids.append(_response_id(response, code, service="s3"))
            page_versions = response.get("Versions", [])
            page_deletes = response.get("DeleteMarkers", [])
            if not isinstance(page_versions, list) or not isinstance(
                page_deletes, list
            ):
                _fail(code)
            versions.extend(
                item
                for item in page_versions
                if isinstance(item, Mapping) and item.get("Key") == key
            )
            deletes.extend(
                item
                for item in page_deletes
                if isinstance(item, Mapping) and item.get("Key") == key
            )
            if response.get("IsTruncated") is False:
                evidence = {
                    "bucket": bucket,
                    "key": key,
                    "pages": page,
                    "request_ids": request_ids,
                    "exact_version_count": len(versions),
                    "exact_delete_marker_count": len(deletes),
                    "observed_at": _stamp(self._clock()),
                }
                evidence["evidence_digest"] = contract.digest_value(evidence)
                return versions, deletes, evidence
            next_key = response.get("NextKeyMarker")
            next_version = response.get("NextVersionIdMarker")
            next_token = (next_key, next_version)
            if (
                not all(isinstance(item, str) and item for item in next_token)
                or next_token in seen_tokens
            ):
                _fail(f"{code}_PAGINATION_INVALID")
            seen_tokens.add(next_token)
            token = next_token
        _fail(f"{code}_PAGE_LIMIT")

    def _list_stack_resources_exact(
        self, *, stack_name: str, code: str
    ) -> tuple[list[Mapping[str, Any]], int]:
        """Read the complete stack resource set with bounded token handling."""

        resources: list[Mapping[str, Any]] = []
        token: str | None = None
        seen: set[str] = set()
        for page_count in range(1, 101):
            request: dict[str, Any] = {"StackName": stack_name}
            if token is not None:
                request["NextToken"] = token
            response = _call(
                self._clients.cloudformation.list_stack_resources,
                code=code,
                **request,
            )
            raw = response.get("StackResourceSummaries")
            if not isinstance(raw, list) or any(
                not isinstance(item, Mapping) for item in raw
            ):
                _fail(code)
            resources.extend(raw)
            next_token = response.get("NextToken")
            if next_token is None:
                return resources, page_count
            if (
                not isinstance(next_token, str)
                or not next_token
                or next_token in seen
            ):
                _fail(f"{code}_PAGINATION_INVALID")
            seen.add(next_token)
            token = next_token
        _fail(f"{code}_PAGE_LIMIT")

    def attest_change_set(
        self,
        *,
        bootstrap_intent: Mapping[str, Any],
        operation: str,
        dispatch_receipt: Mapping[str, Any],
        source_root: Path,
        access_update: Mapping[str, Any] | None = None,
        route_template_receipt: Mapping[str, Any] | None = None,
        delegation_template_receipt: Mapping[str, Any] | None = None,
        bridge_pin: Mapping[str, Any] | None = None,
        foundation_readback: Mapping[str, Any] | None = None,
        cleanup_retire: Mapping[str, Any] | None = None,
        bridge_revoke_readback: Mapping[str, Any] | None = None,
        bootstrap_route_release: Mapping[str, Any] | None = None,
        seed_intent: Mapping[str, Any] | None = None,
        terminal_readbacks: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Attest one exact reviewed change set without executing it."""

        bootstrap = contract.validate_bootstrap_intent(bootstrap_intent)
        cleanup_revalidation_calls = 0
        if operation != "bridge-cleanup-retire":
            self._require_window(bootstrap, read_only=True)
        reviewed = self._reviewed_sources(
            source_root=source_root, bootstrap=bootstrap
        )
        if operation == "bridge-cleanup-retire":
            if cleanup_retire is None or bridge_revoke_readback is None:
                _fail("CLEANUP_RETIRE_REQUIRED")
            retire = contract.validate_bridge_cleanup_retire(
                cleanup_retire,
                bootstrap_intent=bootstrap,
                bridge_revoke_readback=bridge_revoke_readback,
                bootstrap_route_release=bootstrap_route_release,
                seed_intent=seed_intent,
                terminal_readbacks=terminal_readbacks,
            )
            self._require_cleanup_retire_clock(retire, admission=True)
            request = retire["request"]
            intent_digest = retire["intent_digest"]
            request_digest = retire["request_digest"]
            expected_profile = contract.MANAGEMENT_PROFILE
        elif operation == "foundation-access-update":
            if (
                access_update is None
                or route_template_receipt is None
                or delegation_template_receipt is None
                or bridge_pin is not None
                or foundation_readback is None
            ):
                _fail("ACCESS_UPDATE_REQUIRED")
            update = contract.validate_foundation_access_update(
                access_update,
                bootstrap_intent=bootstrap,
                foundation_readback=foundation_readback,
                route_template_receipt=route_template_receipt,
                delegation_template_receipt=delegation_template_receipt,
                reviewed_sources=reviewed,
            )
            request = update["request"]
            intent_digest = update["intent_digest"]
            request_digest = update["request_digest"]
            expected_profile = contract.AUTHORITY_PROFILE
        elif operation == "bridge-pin":
            if (
                bridge_pin is None
                or foundation_readback is None
                or access_update is not None
                or route_template_receipt is not None
                or delegation_template_receipt is not None
            ):
                _fail("BRIDGE_PIN_REQUIRED")
            pin = contract.validate_bridge_pin(
                bridge_pin,
                bootstrap_intent=bootstrap,
                foundation_readback=foundation_readback,
            )
            request = pin["request"]
            intent_digest = pin["intent_digest"]
            request_digest = pin["request_digest"]
            expected_profile = contract.MANAGEMENT_PROFILE
        else:
            if (
                operation not in bootstrap["requests"]
                or access_update is not None
                or route_template_receipt is not None
                or delegation_template_receipt is not None
                or bridge_pin is not None
                or foundation_readback is not None
            ):
                _fail("ATTESTATION_OPERATION_INVALID")
            request = bootstrap["requests"][operation]
            intent_digest = bootstrap["intent_digest"]
            request_digest = bootstrap["request_digests"][operation]
            expected_profile = (
                contract.AUTHORITY_PROFILE
                if operation == "foundation-create"
                else contract.MANAGEMENT_PROFILE
            )
        if self._profile != expected_profile:
            _fail("OPERATION_PROFILE_INVALID")
        dispatch = self._validate_dispatch_receipt(
            dispatch_receipt,
            bootstrap=bootstrap,
            operation=operation,
            intent_digest=intent_digest,
            request_digest=request_digest,
            request=request,
            cleanup_retire=(retire if operation == "bridge-cleanup-retire" else None),
        )
        if operation == "bridge-cleanup-retire":
            cleanup_revalidation_calls = self._revalidate_cleanup_success(
                cleanup_retire=retire,
                seed_intent=seed_intent,
                terminal_readbacks=terminal_readbacks,
            )
        account, caller, _sts_request_id = self._identity()
        response = _call(
            self._clients.cloudformation.describe_change_set,
            code="DESCRIBE_CHANGE_SET_FAILED",
            ChangeSetName=dispatch["change_set_id"],
            StackName=dispatch["stack_id"],
            IncludePropertyValues=True,
        )
        if (
            response.get("ChangeSetId") != dispatch["change_set_id"]
            or response.get("StackId") != dispatch["stack_id"]
            or response.get("ChangeSetName") != request["ChangeSetName"]
            or response.get("StackName") != request["StackName"]
            or response.get("ChangeSetType") != request["ChangeSetType"]
            or response.get("Status") != "CREATE_COMPLETE"
            or response.get("ExecutionStatus") != "AVAILABLE"
            or response.get("Description") != request["Description"]
            or response.get("RoleARN") is not None
            or response.get("Capabilities", []) != request.get("Capabilities", [])
            or response.get("Tags", []) != request["Tags"]
            or response.get("IncludeNestedStacks", False)
            != request["IncludeNestedStacks"]
            or response.get("NotificationARNs", []) != request["NotificationARNs"]
            or response.get("RollbackConfiguration", {})
            != request["RollbackConfiguration"]
            or response.get("OnStackFailure") != request.get("OnStackFailure")
            or response.get("ImportExistingResources") not in {None, False}
            or response.get("ParentChangeSetId") is not None
            or response.get("RootChangeSetId") is not None
        ):
            _fail("CHANGE_SET_ATTESTATION_MISMATCH")
        observed_parameters = _exact_parameter_values(
            response.get("Parameters"), code="CHANGE_SET_PARAMETER_MISMATCH"
        )
        expected_parameters = {
            item["ParameterKey"]: item["ParameterValue"]
            for item in request["Parameters"]
        }
        if observed_parameters != expected_parameters:
            _fail("CHANGE_SET_PARAMETER_MISMATCH")
        template = _call(
            self._clients.cloudformation.get_template,
            code="GET_CHANGE_SET_TEMPLATE_FAILED",
            ChangeSetName=dispatch["change_set_id"],
            StackName=dispatch["stack_id"],
            TemplateStage="Original",
        )
        _response_id(template, "GET_CHANGE_SET_TEMPLATE_FAILED")
        body = template.get("TemplateBody")
        if (
            not isinstance(body, str)
            or contract.bytes_digest(body.encode("utf-8"))
            != (
                bootstrap["template_digests"]["bridge"]
                if operation in {
                    "bridge-create",
                    "bridge-pin",
                    "bridge-revoke",
                    "bridge-cleanup-retire",
                }
                else bootstrap["template_digests"]["foundation"]
            )
        ):
            _fail("CHANGE_SET_TEMPLATE_MISMATCH")
        expected_changes = {
            "bridge-create": {
                ("ArtifactBootstrapPermissionSet", "AWS::SSO::PermissionSet", "Add"),
                ("ArtifactBootstrapAssignment", "AWS::SSO::Assignment", "Add"),
                ("RouteSeedCleanupPermissionSet", "AWS::SSO::PermissionSet", "Add"),
                ("RouteSeedCleanupAssignment", "AWS::SSO::Assignment", "Add"),
                ("BrokerSeedCleanupPermissionSet", "AWS::SSO::PermissionSet", "Add"),
                ("BrokerSeedCleanupAssignment", "AWS::SSO::Assignment", "Add"),
                ("ManagementRecoveryRole", "AWS::IAM::Role", "Add"),
            },
            "foundation-create": {
                ("ArtifactKey", "AWS::KMS::Key", "Add"),
                ("ArtifactKeyAlias", "AWS::KMS::Alias", "Add"),
                ("ArtifactBucket", "AWS::S3::Bucket", "Add"),
                ("ArtifactBucketPolicy", "AWS::S3::BucketPolicy", "Add"),
                ("SigningProfile", "AWS::Signer::SigningProfile", "Add"),
                ("CodeSigningConfig", "AWS::Lambda::CodeSigningConfig", "Add"),
            },
            "foundation-access-update": {
                ("ArtifactKey", "AWS::KMS::Key", "Modify"),
                ("ArtifactBucketPolicy", "AWS::S3::BucketPolicy", "Modify"),
            },
            "bridge-pin": {
                ("ArtifactBootstrapPermissionSet", "AWS::SSO::PermissionSet", "Modify"),
            },
            "bridge-revoke": {
                ("ArtifactBootstrapPermissionSet", "AWS::SSO::PermissionSet", "Modify"),
                ("ArtifactBootstrapAssignment", "AWS::SSO::Assignment", "Remove"),
            },
            "bridge-cleanup-retire": {
                ("BrokerSeedCleanupAssignment", "AWS::SSO::Assignment", "Remove"),
                ("BrokerSeedCleanupPermissionSet", "AWS::SSO::PermissionSet", "Remove"),
                ("ManagementRecoveryRole", "AWS::IAM::Role", "Remove"),
                ("RouteSeedCleanupAssignment", "AWS::SSO::Assignment", "Remove"),
                ("RouteSeedCleanupPermissionSet", "AWS::SSO::PermissionSet", "Remove"),
            },
        }[operation]
        changes = response.get("Changes")
        if not isinstance(changes, list):
            _fail("CHANGE_SET_CHANGES_INVALID")
        expected_modified_properties = {
            "foundation-access-update": {
                "ArtifactKey": "KeyPolicy",
                "ArtifactBucketPolicy": "PolicyDocument",
            },
            "bridge-pin": {"ArtifactBootstrapPermissionSet": "InlinePolicy"},
            "bridge-revoke": {"ArtifactBootstrapPermissionSet": "InlinePolicy"},
        }
        expected_parameter_references = {
            "foundation-access-update": {
                ("ArtifactKey", "KeyPolicy"): {"CrossAccountAccessEnabled"},
                ("ArtifactBucketPolicy", "PolicyDocument"): {
                    "CrossAccountAccessEnabled",
                    "RouteTemplateVersion",
                    "DelegationTemplateVersion",
                },
            },
            "bridge-pin": {
                ("ArtifactBootstrapPermissionSet", "InlinePolicy"): {
                    "SigningProfileVersion"
                },
            },
            "bridge-revoke": {
                ("ArtifactBootstrapPermissionSet", "InlinePolicy"): {
                    "SigningProfileVersion"
                },
            },
        }
        observed_changes: set[tuple[str, str, str]] = set()
        semantic_changes: list[dict[str, Any]] = []
        for item in changes:
            if not isinstance(item, Mapping) or item.get("Type") not in {
                None,
                "Resource",
            }:
                _fail("CHANGE_SET_SEMANTIC_DRIFT")
            resource = item.get("ResourceChange")
            if not isinstance(resource, Mapping):
                _fail("CHANGE_SET_SEMANTIC_DRIFT")
            logical = resource.get("LogicalResourceId")
            resource_type = resource.get("ResourceType")
            action = resource.get("Action")
            observed_changes.add((logical, resource_type, action))
            replacement = resource.get("Replacement")
            if replacement in {True, "True", "Conditional"}:
                _fail("CHANGE_SET_REPLACEMENT_FORBIDDEN")
            scope = resource.get("Scope", [])
            details = resource.get("Details", [])
            if action == "Modify":
                expected_property = expected_modified_properties.get(
                    operation, {}
                ).get(logical)
                if (
                    replacement not in {None, False, "False"}
                    or scope != ["Properties"]
                    or not isinstance(details, list)
                    or not details
                ):
                    _fail("CHANGE_SET_SEMANTIC_DRIFT")
                expected_refs = expected_parameter_references.get(operation, {}).get(
                    (logical, expected_property), set()
                )
                observed_refs: set[str] = set()
                direct_modification = False
                for detail in details:
                    target = (
                        detail.get("Target") if isinstance(detail, Mapping) else None
                    )
                    if (
                        not isinstance(detail, Mapping)
                        or detail.get("Evaluation") not in {"Static", "Dynamic"}
                        or not isinstance(target, Mapping)
                        or target.get("Attribute") != "Properties"
                        or target.get("Name") != expected_property
                        or target.get("RequiresRecreation") != "Never"
                    ):
                        _fail("CHANGE_SET_SEMANTIC_DRIFT")
                    source = detail.get("ChangeSource")
                    causing = detail.get("CausingEntity")
                    if source == "DirectModification" and causing is None:
                        if len(details) != 1:
                            _fail("CHANGE_SET_SEMANTIC_DRIFT")
                        direct_modification = True
                    elif (
                        source == "ParameterReference"
                        and isinstance(causing, str)
                        and causing in expected_refs
                        and causing not in observed_refs
                    ):
                        observed_refs.add(causing)
                    else:
                        _fail("CHANGE_SET_SEMANTIC_DRIFT")
                if not direct_modification and observed_refs != expected_refs:
                    _fail("CHANGE_SET_SEMANTIC_DRIFT")
            elif (
                replacement is not None
                or scope not in (None, [])
                or details not in (None, [])
            ):
                _fail("CHANGE_SET_SEMANTIC_DRIFT")
            semantic_changes.append(
                {
                    "logical_resource_id": logical,
                    "resource_type": resource_type,
                    "action": action,
                    "replacement": replacement,
                    "scope": scope or [],
                    "details_digest": contract.digest_value(details or []),
                }
            )
        if observed_changes != expected_changes or len(changes) != len(expected_changes):
            _fail("CHANGE_SET_SEMANTIC_DRIFT")
        record: dict[str, Any] = {
            "schema_version": 1,
            "record_type": CHANGE_SET_ATTESTATION_TYPE,
            "source_commit": bootstrap["source_commit"],
            "operation": operation,
            "intent_digest": intent_digest,
            "request_digest": request_digest,
            "dispatch_receipt_digest": dispatch["receipt_digest"],
            "verifier": self._verifier(account, caller),
            "stack_id": dispatch["stack_id"],
            "change_set_id": dispatch["change_set_id"],
            "template_digest": contract.bytes_digest(body.encode("utf-8")),
            "parameters_digest": contract.digest_value(expected_parameters),
            "changes": sorted(
                semantic_changes,
                key=lambda item: (
                    item["logical_resource_id"],
                    item["resource_type"],
                    item["action"],
                ),
            ),
            "attested_at": _stamp(
                self._require_cleanup_retire_clock(retire, admission=True)
                if operation == "bridge-cleanup-retire"
                else self._require_window(bootstrap, read_only=True)
            ),
            "aws_calls": 3 + cleanup_revalidation_calls,
            "aws_mutations": 0,
            "production_authorized": False,
            "production_status": contract.PRODUCTION_STATUS,
        }
        record["attestation_digest"] = contract.digest_value(record)
        return record

    @staticmethod
    def _validate_attestation(
        value: Mapping[str, Any],
        *,
        bootstrap: Mapping[str, Any],
        operation: str,
        intent_digest: str,
        request_digest: str,
        request: Mapping[str, Any],
        dispatch: Mapping[str, Any],
        cleanup_retire: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        required = {
            "schema_version",
            "record_type",
            "source_commit",
            "operation",
            "intent_digest",
            "request_digest",
            "dispatch_receipt_digest",
            "verifier",
            "stack_id",
            "change_set_id",
            "template_digest",
            "parameters_digest",
            "changes",
            "attested_at",
            "aws_calls",
            "aws_mutations",
            "production_authorized",
            "production_status",
            "attestation_digest",
        }
        authority_operation = operation in {
            "foundation-create",
            "foundation-access-update",
        }
        expected_account = (
            contract.AUTHORITY_ACCOUNT_ID
            if authority_operation
            else contract.MANAGEMENT_ACCOUNT_ID
        )
        expected_profile = (
            contract.AUTHORITY_PROFILE
            if authority_operation
            else contract.MANAGEMENT_PROFILE
        )
        caller_pattern = _AUTH_CALLER if authority_operation else _MGMT_CALLER
        verifier = value.get("verifier") if isinstance(value, Mapping) else None
        expected_parameters = {
            item["ParameterKey"]: item["ParameterValue"]
            for item in request.get("Parameters", [])
            if isinstance(item, Mapping)
            and set(item) == {"ParameterKey", "ParameterValue"}
        }
        expected_template_digest = bootstrap["template_digests"][
            "bridge"
            if operation in {
                "bridge-create",
                "bridge-pin",
                "bridge-revoke",
                "bridge-cleanup-retire",
            }
            else "foundation"
        ]
        changes = value.get("changes") if isinstance(value, Mapping) else None
        if (
            not isinstance(value, Mapping)
            or set(value) != required
            or value.get("schema_version") != 1
            or value.get("record_type") != CHANGE_SET_ATTESTATION_TYPE
            or value.get("source_commit") != bootstrap["source_commit"]
            or value.get("operation") != operation
            or value.get("intent_digest") != intent_digest
            or value.get("request_digest") != request_digest
            or value.get("dispatch_receipt_digest") != dispatch["receipt_digest"]
            or not isinstance(verifier, Mapping)
            or set(verifier) != {"account_id", "caller_arn", "profile", "region"}
            or verifier.get("account_id") != expected_account
            or verifier.get("profile") != expected_profile
            or verifier.get("region") != contract.REGION
            or caller_pattern.fullmatch(str(verifier.get("caller_arn", "")))
            is None
            or value.get("stack_id") != dispatch["stack_id"]
            or value.get("change_set_id") != dispatch["change_set_id"]
            or value.get("template_digest") != expected_template_digest
            or value.get("parameters_digest")
            != contract.digest_value(expected_parameters)
            or not isinstance(changes, list)
            or any(
                not isinstance(item, Mapping)
                or set(item)
                != {
                    "logical_resource_id",
                    "resource_type",
                    "action",
                    "replacement",
                    "scope",
                    "details_digest",
                }
                or re.fullmatch(
                    r"sha256:[a-f0-9]{64}", str(item.get("details_digest", ""))
                )
                is None
                for item in changes
            )
            or value.get("aws_calls")
            != 3
            + (
                int(cleanup_retire.get("terminal_revalidation_aws_calls", 0))
                if operation == "bridge-cleanup-retire"
                and cleanup_retire is not None
                else 0
            )
            or value.get("aws_mutations") != 0
            or value.get("production_authorized") is not False
            or value.get("production_status") != contract.PRODUCTION_STATUS
            or contract.digest_value(
                {
                    key: item
                    for key, item in value.items()
                    if key != "attestation_digest"
                }
            )
            != value.get("attestation_digest")
        ):
            _fail("CHANGE_SET_ATTESTATION_INVALID")
        expected_changes = {
            "bridge-create": {
                ("ArtifactBootstrapPermissionSet", "AWS::SSO::PermissionSet", "Add"),
                ("ArtifactBootstrapAssignment", "AWS::SSO::Assignment", "Add"),
                ("RouteSeedCleanupPermissionSet", "AWS::SSO::PermissionSet", "Add"),
                ("RouteSeedCleanupAssignment", "AWS::SSO::Assignment", "Add"),
                ("BrokerSeedCleanupPermissionSet", "AWS::SSO::PermissionSet", "Add"),
                ("BrokerSeedCleanupAssignment", "AWS::SSO::Assignment", "Add"),
                ("ManagementRecoveryRole", "AWS::IAM::Role", "Add"),
            },
            "foundation-create": {
                ("ArtifactKey", "AWS::KMS::Key", "Add"),
                ("ArtifactKeyAlias", "AWS::KMS::Alias", "Add"),
                ("ArtifactBucket", "AWS::S3::Bucket", "Add"),
                ("ArtifactBucketPolicy", "AWS::S3::BucketPolicy", "Add"),
                ("SigningProfile", "AWS::Signer::SigningProfile", "Add"),
                ("CodeSigningConfig", "AWS::Lambda::CodeSigningConfig", "Add"),
            },
            "foundation-access-update": {
                ("ArtifactKey", "AWS::KMS::Key", "Modify"),
                ("ArtifactBucketPolicy", "AWS::S3::BucketPolicy", "Modify"),
            },
            "bridge-pin": {
                ("ArtifactBootstrapPermissionSet", "AWS::SSO::PermissionSet", "Modify"),
            },
            "bridge-revoke": {
                ("ArtifactBootstrapPermissionSet", "AWS::SSO::PermissionSet", "Modify"),
                ("ArtifactBootstrapAssignment", "AWS::SSO::Assignment", "Remove"),
            },
            "bridge-cleanup-retire": {
                ("BrokerSeedCleanupAssignment", "AWS::SSO::Assignment", "Remove"),
                ("BrokerSeedCleanupPermissionSet", "AWS::SSO::PermissionSet", "Remove"),
                ("ManagementRecoveryRole", "AWS::IAM::Role", "Remove"),
                ("RouteSeedCleanupAssignment", "AWS::SSO::Assignment", "Remove"),
                ("RouteSeedCleanupPermissionSet", "AWS::SSO::PermissionSet", "Remove"),
            },
        }.get(operation)
        properties = {
            ("foundation-access-update", "ArtifactKey"): (
                "KeyPolicy",
                frozenset({"CrossAccountAccessEnabled"}),
            ),
            ("foundation-access-update", "ArtifactBucketPolicy"): (
                "PolicyDocument",
                frozenset(
                    {
                        "CrossAccountAccessEnabled",
                        "RouteTemplateVersion",
                        "DelegationTemplateVersion",
                    }
                ),
            ),
            ("bridge-pin", "ArtifactBootstrapPermissionSet"): (
                "InlinePolicy",
                frozenset({"SigningProfileVersion"}),
            ),
            ("bridge-revoke", "ArtifactBootstrapPermissionSet"): (
                "InlinePolicy",
                frozenset({"SigningProfileVersion"}),
            ),
        }
        observed_changes = {
            (
                item["logical_resource_id"],
                item["resource_type"],
                item["action"],
            )
            for item in changes
        }
        if (
            expected_changes is None
            or len(changes) != len(expected_changes)
            or observed_changes != expected_changes
        ):
            _fail("CHANGE_SET_ATTESTATION_INVALID")
        empty_details = contract.digest_value([])
        for item in changes:
            if item["action"] == "Modify":
                expected_property = properties.get(
                    (operation, item["logical_resource_id"])
                )
                if (
                    expected_property is None
                    or item["replacement"] not in {None, False, "False"}
                    or item["scope"] != ["Properties"]
                    or item["details_digest"]
                    not in _allowed_change_detail_digests(
                        property_name=expected_property[0],
                        references=expected_property[1],
                    )
                ):
                    _fail("CHANGE_SET_ATTESTATION_INVALID")
            elif (
                item["replacement"] is not None
                or item["scope"] != []
                or item["details_digest"] != empty_details
            ):
                _fail("CHANGE_SET_ATTESTATION_INVALID")
        if operation == "bridge-cleanup-retire":
            if cleanup_retire is None:
                _fail("CHANGE_SET_ATTESTATION_INVALID")
            ConnectedArtifactBootstrapProvider._validate_cleanup_retire_receipt_time(
                value.get("attested_at"),
                cleanup_retire=cleanup_retire,
                code="CHANGE_SET_ATTESTATION_INVALID",
            )
        else:
            if cleanup_retire is not None:
                _fail("CHANGE_SET_ATTESTATION_INVALID")
            ConnectedArtifactBootstrapProvider._validate_receipt_time(
                value.get("attested_at"),
                bootstrap=bootstrap,
                read_only=True,
                code="CHANGE_SET_ATTESTATION_INVALID",
            )
        return json.loads(contract.canonical_json(dict(value)))

    @staticmethod
    def _compare_live_attestation(
        supplied: Mapping[str, Any], live: Mapping[str, Any]
    ) -> None:
        """Require every immutable attestation fact to match a fresh AWS read."""

        freshness = {"verifier", "attested_at", "attestation_digest"}
        supplied_immutable = {
            key: value for key, value in supplied.items() if key not in freshness
        }
        live_immutable = {
            key: value for key, value in live.items() if key not in freshness
        }
        if supplied_immutable != live_immutable:
            _fail("CHANGE_SET_LIVE_ATTESTATION_MISMATCH")

    @staticmethod
    def _execution_preflight_digest(
        *, dispatch: Mapping[str, Any], attestation: Mapping[str, Any]
    ) -> str:
        return contract.digest_value(
            {
                "dispatch_receipt_digest": dispatch["receipt_digest"],
                "change_set_attestation_digest": attestation[
                    "attestation_digest"
                ],
            }
        )

    def dispatch_change_set_once(
        self,
        *,
        bootstrap_intent: Mapping[str, Any],
        source_root: Path,
        operation: str,
        authorization: Mapping[str, Any],
        cleanup_retire: Mapping[str, Any] | None = None,
        bridge_revoke_readback: Mapping[str, Any] | None = None,
        bootstrap_route_release: Mapping[str, Any] | None = None,
        seed_intent: Mapping[str, Any] | None = None,
        terminal_readbacks: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        intent = contract.validate_bootstrap_intent(bootstrap_intent)
        retire: dict[str, Any] | None = None
        cleanup_revalidation_calls = 0
        if operation == "bridge-cleanup-retire":
            if cleanup_retire is None or bridge_revoke_readback is None:
                _fail("CLEANUP_RETIRE_REQUIRED")
            retire = contract.validate_bridge_cleanup_retire(
                cleanup_retire,
                bootstrap_intent=intent,
                bridge_revoke_readback=bridge_revoke_readback,
                bootstrap_route_release=bootstrap_route_release,
                seed_intent=seed_intent,
                terminal_readbacks=terminal_readbacks,
            )
            self._require_cleanup_retire_clock(retire, admission=True)
            request = retire["request"]
            intent_digest = retire["intent_digest"]
            request_digest = retire["request_digest"]
            contract.validate_bridge_cleanup_retire_authorization(
                authorization,
                cleanup_retire=retire,
                operation="dispatch",
                now=self._clock(),
            )
            cleanup_revalidation_calls = self._revalidate_cleanup_success(
                cleanup_retire=retire,
                seed_intent=seed_intent,
                terminal_readbacks=terminal_readbacks,
            )
        else:
            if any(
                item is not None
                for item in (
                    cleanup_retire,
                    bridge_revoke_readback,
                    bootstrap_route_release,
                    seed_intent,
                    terminal_readbacks,
                )
            ):
                _fail("CLEANUP_RETIRE_INPUT_INVALID")
            self._require_window(intent, read_only=False)
            if operation not in intent["requests"]:
                _fail("OPERATION_PROFILE_INVALID")
            request = intent["requests"][operation]
            intent_digest = intent["intent_digest"]
            request_digest = intent["request_digests"][operation]
            contract.validate_authorization(
                authorization,
                intent=intent,
                operation=f"{operation}:dispatch",
                now=self._clock(),
            )
        self._reviewed_sources(source_root=source_root, bootstrap=intent)
        expected_profile = (
            contract.AUTHORITY_PROFILE
            if operation == "foundation-create"
            else contract.MANAGEMENT_PROFILE
        )
        if self._profile != expected_profile:
            _fail("OPERATION_PROFILE_INVALID")
        account, caller, _sts_request_id = self._identity()
        claim_current = (
            self._require_cleanup_retire_clock(retire, admission=True)
            if retire is not None
            else self._require_window(intent, read_only=False)
        )
        if retire is not None:
            contract.validate_bridge_cleanup_retire_authorization(
                authorization,
                cleanup_retire=retire,
                operation="dispatch",
                now=claim_current,
            )
        else:
            contract.validate_authorization(
                authorization,
                intent=intent,
                operation=f"{operation}:dispatch",
                now=claim_current,
            )
        claimed_at = _stamp(claim_current)
        self._claims.reserve(
            operation=f"{operation}-dispatch",
            digest=request_digest,
            claimed_at=claimed_at,
            caller_arn=caller,
            request_digest=request_digest,
            authorization_digest=authorization["authorization_digest"],
            authorization_record=authorization,
            request_token=request["ClientToken"],
        )
        response = _call(
            self._clients.cloudformation.create_change_set,
            mutation=True,
            code="CREATE_CHANGE_SET_UNCERTAIN",
            **request,
        )
        stack_id = response.get("StackId")
        change_set_id = response.get("Id")
        expected_account = (
            contract.AUTHORITY_ACCOUNT_ID
            if operation == "foundation-create"
            else contract.MANAGEMENT_ACCOUNT_ID
        )
        if (
            not isinstance(stack_id, str)
            or f":{expected_account}:stack/" not in stack_id
            or not isinstance(change_set_id, str)
            or f":{expected_account}:changeSet/" not in change_set_id
        ):
            _fail("CREATE_CHANGE_SET_RESPONSE_INVALID", uncertain=True)
        receipt: dict[str, Any] = {
            "schema_version": 1,
            "record_type": DISPATCH_RECEIPT_TYPE,
            "source_commit": intent["source_commit"],
            "operation": operation,
            "intent_digest": intent_digest,
            "request_digest": request_digest,
            "authorization_digest": authorization["authorization_digest"],
            "verifier": self._verifier(account, caller),
            "stack_id": stack_id,
            "change_set_id": change_set_id,
            "request_id": _response_id(response, "CREATE_CHANGE_SET_RESPONSE_INVALID"),
            "dispatched_at": claimed_at,
            "aws_calls": 2 + cleanup_revalidation_calls,
            "aws_mutations": 1,
            "retry_permitted": False,
            "production_authorized": False,
            "production_status": contract.PRODUCTION_STATUS,
        }
        receipt["receipt_digest"] = contract.digest_value(receipt)
        return self._validate_dispatch_receipt(
            receipt,
            bootstrap=intent,
            operation=operation,
            intent_digest=intent_digest,
            request_digest=request_digest,
            request=request,
            cleanup_retire=retire,
        )

    def recover_change_set(
        self,
        *,
        bootstrap_intent: Mapping[str, Any],
        source_root: Path,
        operation: str,
        cleanup_retire: Mapping[str, Any] | None = None,
        bridge_revoke_readback: Mapping[str, Any] | None = None,
        bootstrap_route_release: Mapping[str, Any] | None = None,
        seed_intent: Mapping[str, Any] | None = None,
        terminal_readbacks: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        intent = contract.validate_bootstrap_intent(bootstrap_intent)
        retire: dict[str, Any] | None = None
        cleanup_revalidation_calls = 0
        if operation == "bridge-cleanup-retire":
            if cleanup_retire is None or bridge_revoke_readback is None:
                _fail("CLEANUP_RETIRE_REQUIRED")
            retire = contract.validate_bridge_cleanup_retire(
                cleanup_retire,
                bootstrap_intent=intent,
                bridge_revoke_readback=bridge_revoke_readback,
                bootstrap_route_release=bootstrap_route_release,
                seed_intent=seed_intent,
                terminal_readbacks=terminal_readbacks,
            )
            self._require_cleanup_retire_clock(retire, admission=False)
            cleanup_revalidation_calls = self._revalidate_cleanup_success(
                cleanup_retire=retire,
                seed_intent=seed_intent,
                terminal_readbacks=terminal_readbacks,
            )
            request = retire["request"]
            intent_digest = retire["intent_digest"]
            request_digest = retire["request_digest"]
        else:
            if any(
                item is not None
                for item in (
                    cleanup_retire,
                    bridge_revoke_readback,
                    bootstrap_route_release,
                    seed_intent,
                    terminal_readbacks,
                )
            ):
                _fail("CLEANUP_RETIRE_INPUT_INVALID")
            self._require_window(intent, read_only=True)
            if operation not in intent["requests"]:
                _fail("OPERATION_PROFILE_INVALID")
            request = intent["requests"][operation]
            intent_digest = intent["intent_digest"]
            request_digest = intent["request_digests"][operation]
        self._reviewed_sources(source_root=source_root, bootstrap=intent)
        expected_profile = (
            contract.AUTHORITY_PROFILE
            if operation == "foundation-create"
            else contract.MANAGEMENT_PROFILE
        )
        if self._profile != expected_profile:
            _fail("OPERATION_PROFILE_INVALID")
        expected_account = (
            contract.AUTHORITY_ACCOUNT_ID
            if operation == "foundation-create"
            else contract.MANAGEMENT_ACCOUNT_ID
        )
        dispatch, recovery_calls = self._recover_cfn_dispatch(
            bootstrap=intent,
            operation=operation,
            intent_digest=intent_digest,
            request_digest=request_digest,
            request=request,
            account=expected_account,
            cleanup_retire=retire,
        )
        attestation = self.attest_change_set(
            bootstrap_intent=intent,
            source_root=source_root,
            operation=operation,
            dispatch_receipt=dispatch,
            cleanup_retire=retire,
            bridge_revoke_readback=bridge_revoke_readback,
            bootstrap_route_release=bootstrap_route_release,
            seed_intent=seed_intent,
            terminal_readbacks=terminal_readbacks,
        )
        return {
            "status": "RECOVERED_AND_ATTESTED",
            "dispatch_receipt": dispatch,
            "change_set_attestation": attestation,
            "aws_calls": (
                cleanup_revalidation_calls
                + recovery_calls
                + attestation["aws_calls"]
            ),
            "aws_mutations": 0,
            "retry_permitted": False,
            "production_authorized": False,
            "production_status": contract.PRODUCTION_STATUS,
        }

    def execute_change_set_once(
        self,
        *,
        bootstrap_intent: Mapping[str, Any],
        source_root: Path,
        operation: str,
        dispatch_receipt: Mapping[str, Any],
        change_set_attestation: Mapping[str, Any],
        authorization: Mapping[str, Any],
        cleanup_retire: Mapping[str, Any] | None = None,
        bridge_revoke_readback: Mapping[str, Any] | None = None,
        bootstrap_route_release: Mapping[str, Any] | None = None,
        seed_intent: Mapping[str, Any] | None = None,
        terminal_readbacks: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        intent = contract.validate_bootstrap_intent(bootstrap_intent)
        retire: dict[str, Any] | None = None
        if operation == "bridge-cleanup-retire":
            if cleanup_retire is None or bridge_revoke_readback is None:
                _fail("CLEANUP_RETIRE_REQUIRED")
            retire = contract.validate_bridge_cleanup_retire(
                cleanup_retire,
                bootstrap_intent=intent,
                bridge_revoke_readback=bridge_revoke_readback,
                bootstrap_route_release=bootstrap_route_release,
                seed_intent=seed_intent,
                terminal_readbacks=terminal_readbacks,
            )
            execution_current = self._require_cleanup_retire_clock(
                retire, admission=True
            )
            request = retire["request"]
            intent_digest = retire["intent_digest"]
            request_digest = retire["request_digest"]
            contract.validate_bridge_cleanup_retire_authorization(
                authorization,
                cleanup_retire=retire,
                operation="execute",
                now=self._clock(),
            )
        else:
            if any(
                item is not None
                for item in (
                    cleanup_retire,
                    bridge_revoke_readback,
                    bootstrap_route_release,
                    seed_intent,
                    terminal_readbacks,
                )
            ):
                _fail("CLEANUP_RETIRE_INPUT_INVALID")
            execution_current = self._require_window(intent, read_only=False)
            if operation not in intent["requests"]:
                _fail("EXECUTION_INPUT_INVALID")
            request = intent["requests"][operation]
            intent_digest = intent["intent_digest"]
            request_digest = intent["request_digests"][operation]
            contract.validate_authorization(
                authorization,
                intent=intent,
                operation=f"{operation}:execute",
                now=self._clock(),
            )
        self._reviewed_sources(source_root=source_root, bootstrap=intent)
        expected_profile = (
            contract.AUTHORITY_PROFILE
            if operation == "foundation-create"
            else contract.MANAGEMENT_PROFILE
        )
        if self._profile != expected_profile:
            _fail("EXECUTION_INPUT_INVALID")
        dispatch = self._validate_dispatch_receipt(
            dispatch_receipt,
            bootstrap=intent,
            operation=operation,
            intent_digest=intent_digest,
            request_digest=request_digest,
            request=request,
            cleanup_retire=retire,
        )
        attestation = self._validate_attestation(
            change_set_attestation,
            bootstrap=intent,
            operation=operation,
            intent_digest=intent_digest,
            request_digest=request_digest,
            request=request,
            dispatch=dispatch,
            cleanup_retire=retire,
        )
        self._validate_attestation_chronology(
            attestation,
            not_before=dispatch["dispatched_at"],
            not_after=execution_current,
        )
        dispatch, causal_calls = self._validate_causal_dispatch_receipt(
            dispatch,
            bootstrap=intent,
            operation=operation,
            intent_digest=intent_digest,
            request_digest=request_digest,
            request=request,
            mutation_authorization=False,
            cleanup_retire=retire,
        )
        live_attestation = self.attest_change_set(
            bootstrap_intent=intent,
            source_root=source_root,
            operation=operation,
            dispatch_receipt=dispatch,
            cleanup_retire=retire,
            bridge_revoke_readback=bridge_revoke_readback,
            bootstrap_route_release=bootstrap_route_release,
            seed_intent=seed_intent,
            terminal_readbacks=terminal_readbacks,
        )
        self._compare_live_attestation(attestation, live_attestation)
        account, caller, _sts_request_id = self._identity()
        claim_current = (
            self._require_cleanup_retire_clock(retire, admission=True)
            if retire is not None
            else self._require_window(intent, read_only=False)
        )
        self._validate_attestation_chronology(
            attestation,
            not_before=dispatch["dispatched_at"],
            not_after=claim_current,
        )
        if retire is not None:
            contract.validate_bridge_cleanup_retire_authorization(
                authorization,
                cleanup_retire=retire,
                operation="execute",
                now=claim_current,
            )
        else:
            contract.validate_authorization(
                authorization,
                intent=intent,
                operation=f"{operation}:execute",
                now=claim_current,
            )
        dispatched_at = _stamp(claim_current)
        execution_digest = self._execution_effect_digest(
            operation=operation,
            intent_digest=intent_digest,
            request_digest=request_digest,
            dispatch=dispatch,
        )
        execute_request = {
            "ChangeSetName": dispatch["change_set_id"],
            "StackName": dispatch["stack_id"],
            "ClientRequestToken": "gug376-" + execution_digest[7:55],
        }
        self._claims.reserve(
            operation=f"{operation}-execute",
            digest=execution_digest,
            claimed_at=dispatched_at,
            caller_arn=caller,
            request_digest=contract.digest_value(execute_request),
            authorization_digest=authorization["authorization_digest"],
            authorization_record=authorization,
            request_token=execute_request["ClientRequestToken"],
            preflight_digest=self._execution_preflight_digest(
                dispatch=dispatch, attestation=attestation
            ),
            preflight_calls=causal_calls + live_attestation["aws_calls"] + 1,
        )
        response = _call(
            self._clients.cloudformation.execute_change_set,
            mutation=True,
            code="EXECUTE_CHANGE_SET_UNCERTAIN",
            **execute_request,
        )
        receipt: dict[str, Any] = {
            "schema_version": 1,
            "record_type": EXECUTION_RECEIPT_TYPE,
            "source_commit": intent["source_commit"],
            "operation": operation,
            "intent_digest": intent_digest,
            "dispatch_receipt_digest": dispatch["receipt_digest"],
            "change_set_attestation_digest": attestation["attestation_digest"],
            "authorization_digest": authorization["authorization_digest"],
            "verifier": self._verifier(account, caller),
            "request_id": _response_id(response, "EXECUTE_CHANGE_SET_RESPONSE_INVALID"),
            "dispatched_at": dispatched_at,
            "aws_calls": causal_calls + live_attestation["aws_calls"] + 2,
            "aws_mutations": 1,
            "retry_permitted": False,
            "production_authorized": False,
            "production_status": contract.PRODUCTION_STATUS,
        }
        receipt["receipt_digest"] = contract.digest_value(receipt)
        return receipt

    def recover_change_set_execution(
        self,
        *,
        bootstrap_intent: Mapping[str, Any],
        source_root: Path,
        operation: str,
        dispatch_receipt: Mapping[str, Any],
        change_set_attestation: Mapping[str, Any],
        cleanup_retire: Mapping[str, Any] | None = None,
        bridge_revoke_readback: Mapping[str, Any] | None = None,
        bootstrap_route_release: Mapping[str, Any] | None = None,
        seed_intent: Mapping[str, Any] | None = None,
        terminal_readbacks: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Recover one ambiguous generic ExecuteChangeSet and terminal state."""

        intent = contract.validate_bootstrap_intent(bootstrap_intent)
        retire: dict[str, Any] | None = None
        cleanup_revalidation_calls = 0
        if operation == "bridge-cleanup-retire":
            if cleanup_retire is None or bridge_revoke_readback is None:
                _fail("CLEANUP_RETIRE_REQUIRED")
            retire = contract.validate_bridge_cleanup_retire(
                cleanup_retire,
                bootstrap_intent=intent,
                bridge_revoke_readback=bridge_revoke_readback,
                bootstrap_route_release=bootstrap_route_release,
                seed_intent=seed_intent,
                terminal_readbacks=terminal_readbacks,
            )
            self._require_cleanup_retire_clock(retire, admission=False)
            cleanup_revalidation_calls = self._revalidate_cleanup_success(
                cleanup_retire=retire,
                seed_intent=seed_intent,
                terminal_readbacks=terminal_readbacks,
            )
            request_digest = retire["request_digest"]
            request = retire["request"]
            intent_digest = retire["intent_digest"]
        else:
            if any(
                item is not None
                for item in (
                    cleanup_retire,
                    bridge_revoke_readback,
                    bootstrap_route_release,
                    seed_intent,
                    terminal_readbacks,
                )
            ):
                _fail("CLEANUP_RETIRE_INPUT_INVALID")
            self._require_window(intent, read_only=True)
            if operation not in intent["requests"]:
                _fail("EXECUTION_INPUT_INVALID")
            request_digest = intent["request_digests"][operation]
            request = intent["requests"][operation]
            intent_digest = intent["intent_digest"]
        self._reviewed_sources(source_root=source_root, bootstrap=intent)
        expected_profile = (
            contract.AUTHORITY_PROFILE
            if operation == "foundation-create"
            else contract.MANAGEMENT_PROFILE
        )
        if self._profile != expected_profile:
            _fail("EXECUTION_INPUT_INVALID")
        dispatch = self._validate_dispatch_receipt(
            dispatch_receipt,
            bootstrap=intent,
            operation=operation,
            intent_digest=intent_digest,
            request_digest=request_digest,
            request=request,
            cleanup_retire=retire,
        )
        attestation = self._validate_attestation(
            change_set_attestation,
            bootstrap=intent,
            operation=operation,
            intent_digest=intent_digest,
            request_digest=request_digest,
            request=request,
            dispatch=dispatch,
            cleanup_retire=retire,
        )
        execution_claim = self._read_execution_claim_for_attestation(
            operation=operation,
            intent_digest=intent_digest,
            request_digest=request_digest,
            dispatch=dispatch,
            attestation=attestation,
        )
        dispatch, causal_calls = self._validate_causal_dispatch_receipt(
            dispatch,
            bootstrap=intent,
            operation=operation,
            intent_digest=intent_digest,
            request_digest=request_digest,
            request=request,
            mutation_authorization=False,
            cleanup_retire=retire,
        )
        account = (
            contract.AUTHORITY_ACCOUNT_ID
            if operation == "foundation-create"
            else contract.MANAGEMENT_ACCOUNT_ID
        )
        execution, recovery_calls = self._recover_execution_receipt(
            bootstrap=intent,
            operation=operation,
            intent_digest=intent_digest,
            request_digest=request_digest,
            dispatch=dispatch,
            attestation=attestation,
            account=account,
            execution_claim=execution_claim,
            cleanup_retire=retire,
        )
        terminal = self.readback_stack(
            bootstrap_intent=intent,
            source_root=source_root,
            operation=operation,
            cleanup_retire=retire,
            bridge_revoke_readback=bridge_revoke_readback,
            bootstrap_route_release=bootstrap_route_release,
            seed_intent=seed_intent,
            terminal_readbacks=terminal_readbacks,
        )
        return {
            "status": "EXECUTION_RECOVERED_AND_TERMINAL",
            "execution_receipt": execution,
            "stack_readback": terminal,
            "aws_calls": (
                cleanup_revalidation_calls
                + causal_calls
                + recovery_calls
                + terminal["aws_calls"]
            ),
            "aws_mutations": 0,
            "retry_permitted": False,
            "production_authorized": False,
            "production_status": contract.PRODUCTION_STATUS,
        }

    def dispatch_bridge_pin_once(
        self,
        *,
        bootstrap_intent: Mapping[str, Any],
        source_root: Path,
        foundation_readback: Mapping[str, Any],
        bridge_pin: Mapping[str, Any],
        authorization: Mapping[str, Any],
    ) -> dict[str, Any]:
        if self._profile != contract.MANAGEMENT_PROFILE:
            _fail("OPERATION_PROFILE_INVALID")
        bootstrap = contract.validate_bootstrap_intent(bootstrap_intent)
        self._require_window(bootstrap, read_only=False)
        self._reviewed_sources(source_root=source_root, bootstrap=bootstrap)
        pin = contract.validate_bridge_pin(
            bridge_pin,
            bootstrap_intent=bootstrap,
            foundation_readback=foundation_readback,
        )
        contract.validate_mutation_authorization(
            authorization,
            bootstrap_intent=bootstrap,
            operation="bridge-pin:dispatch",
            target_digest=pin["intent_digest"],
            now=self._clock(),
        )
        account, caller, _sts_request_id = self._identity()
        claim_current = self._require_window(bootstrap, read_only=False)
        contract.validate_mutation_authorization(
            authorization,
            bootstrap_intent=bootstrap,
            operation="bridge-pin:dispatch",
            target_digest=pin["intent_digest"],
            now=claim_current,
        )
        claimed_at = _stamp(claim_current)
        self._claims.reserve(
            operation="bridge-pin-dispatch",
            digest=pin["request_digest"],
            claimed_at=claimed_at,
            caller_arn=caller,
            request_digest=pin["request_digest"],
            authorization_digest=authorization["authorization_digest"],
            authorization_record=authorization,
            request_token=pin["request"]["ClientToken"],
        )
        response = _call(
            self._clients.cloudformation.create_change_set,
            mutation=True,
            code="BRIDGE_PIN_CREATE_UNCERTAIN",
            **pin["request"],
        )
        stack_id = response.get("StackId")
        change_set_id = response.get("Id")
        if (
            not isinstance(stack_id, str)
            or f":{contract.MANAGEMENT_ACCOUNT_ID}:stack/{contract.BRIDGE_STACK_NAME}/"
            not in stack_id
            or not isinstance(change_set_id, str)
            or f":{contract.MANAGEMENT_ACCOUNT_ID}:changeSet/" not in change_set_id
        ):
            _fail("BRIDGE_PIN_RESPONSE_INVALID", uncertain=True)
        receipt: dict[str, Any] = {
            "schema_version": 1,
            "record_type": DISPATCH_RECEIPT_TYPE,
            "source_commit": bootstrap["source_commit"],
            "operation": "bridge-pin",
            "intent_digest": pin["intent_digest"],
            "request_digest": pin["request_digest"],
            "authorization_digest": authorization["authorization_digest"],
            "verifier": self._verifier(account, caller),
            "stack_id": stack_id,
            "change_set_id": change_set_id,
            "request_id": _response_id(response, "BRIDGE_PIN_RESPONSE_INVALID"),
            "dispatched_at": claimed_at,
            "aws_calls": 2,
            "aws_mutations": 1,
            "retry_permitted": False,
            "production_authorized": False,
            "production_status": contract.PRODUCTION_STATUS,
        }
        receipt["receipt_digest"] = contract.digest_value(receipt)
        return self._validate_dispatch_receipt(
            receipt,
            bootstrap=bootstrap,
            operation="bridge-pin",
            intent_digest=pin["intent_digest"],
            request_digest=pin["request_digest"],
            request=pin["request"],
        )

    def execute_bridge_pin_once(
        self,
        *,
        bootstrap_intent: Mapping[str, Any],
        source_root: Path,
        foundation_readback: Mapping[str, Any],
        bridge_pin: Mapping[str, Any],
        dispatch_receipt: Mapping[str, Any],
        change_set_attestation: Mapping[str, Any],
        authorization: Mapping[str, Any],
    ) -> dict[str, Any]:
        if self._profile != contract.MANAGEMENT_PROFILE:
            _fail("OPERATION_PROFILE_INVALID")
        bootstrap = contract.validate_bootstrap_intent(bootstrap_intent)
        execution_current = self._require_window(bootstrap, read_only=False)
        self._reviewed_sources(source_root=source_root, bootstrap=bootstrap)
        pin = contract.validate_bridge_pin(
            bridge_pin,
            bootstrap_intent=bootstrap,
            foundation_readback=foundation_readback,
        )
        contract.validate_mutation_authorization(
            authorization,
            bootstrap_intent=bootstrap,
            operation="bridge-pin:execute",
            target_digest=pin["intent_digest"],
            now=self._clock(),
        )
        dispatch = self._validate_dispatch_receipt(
            dispatch_receipt,
            bootstrap=bootstrap,
            operation="bridge-pin",
            intent_digest=pin["intent_digest"],
            request_digest=pin["request_digest"],
            request=pin["request"],
        )
        attestation = self._validate_attestation(
            change_set_attestation,
            bootstrap=bootstrap,
            operation="bridge-pin",
            intent_digest=pin["intent_digest"],
            request_digest=pin["request_digest"],
            request=pin["request"],
            dispatch=dispatch,
        )
        self._validate_attestation_chronology(
            attestation,
            not_before=dispatch["dispatched_at"],
            not_after=execution_current,
        )
        dispatch, causal_calls = self._validate_causal_dispatch_receipt(
            dispatch,
            bootstrap=bootstrap,
            operation="bridge-pin",
            intent_digest=pin["intent_digest"],
            request_digest=pin["request_digest"],
            request=pin["request"],
            mutation_authorization=True,
        )
        live_attestation = self.attest_change_set(
            bootstrap_intent=bootstrap,
            source_root=source_root,
            operation="bridge-pin",
            dispatch_receipt=dispatch,
            bridge_pin=pin,
            foundation_readback=foundation_readback,
        )
        self._compare_live_attestation(attestation, live_attestation)
        account, caller, _sts_request_id = self._identity()
        execution_digest = self._execution_effect_digest(
            operation="bridge-pin",
            intent_digest=pin["intent_digest"],
            request_digest=pin["request_digest"],
            dispatch=dispatch,
        )
        claim_current = self._require_window(bootstrap, read_only=False)
        self._validate_attestation_chronology(
            attestation,
            not_before=dispatch["dispatched_at"],
            not_after=claim_current,
        )
        contract.validate_mutation_authorization(
            authorization,
            bootstrap_intent=bootstrap,
            operation="bridge-pin:execute",
            target_digest=pin["intent_digest"],
            now=claim_current,
        )
        dispatched_at = _stamp(claim_current)
        execute_request = {
            "ChangeSetName": dispatch["change_set_id"],
            "StackName": dispatch["stack_id"],
            "ClientRequestToken": "gug376-" + execution_digest[7:55],
        }
        self._claims.reserve(
            operation="bridge-pin-execute",
            digest=execution_digest,
            claimed_at=dispatched_at,
            caller_arn=caller,
            request_digest=contract.digest_value(execute_request),
            authorization_digest=authorization["authorization_digest"],
            authorization_record=authorization,
            request_token=execute_request["ClientRequestToken"],
            preflight_digest=self._execution_preflight_digest(
                dispatch=dispatch, attestation=attestation
            ),
            preflight_calls=causal_calls + live_attestation["aws_calls"] + 1,
        )
        response = _call(
            self._clients.cloudformation.execute_change_set,
            mutation=True,
            code="BRIDGE_PIN_EXECUTE_UNCERTAIN",
            **execute_request,
        )
        receipt: dict[str, Any] = {
            "schema_version": 1,
            "record_type": EXECUTION_RECEIPT_TYPE,
            "source_commit": bootstrap["source_commit"],
            "operation": "bridge-pin",
            "intent_digest": pin["intent_digest"],
            "dispatch_receipt_digest": dispatch["receipt_digest"],
            "change_set_attestation_digest": attestation["attestation_digest"],
            "authorization_digest": authorization["authorization_digest"],
            "verifier": self._verifier(account, caller),
            "request_id": _response_id(response, "BRIDGE_PIN_EXECUTE_RESPONSE_INVALID"),
            "dispatched_at": dispatched_at,
            "aws_calls": causal_calls + live_attestation["aws_calls"] + 2,
            "aws_mutations": 1,
            "retry_permitted": False,
            "production_authorized": False,
            "production_status": contract.PRODUCTION_STATUS,
        }
        receipt["receipt_digest"] = contract.digest_value(receipt)
        return receipt

    def recover_bridge_pin_execution(
        self,
        *,
        bootstrap_intent: Mapping[str, Any],
        source_root: Path,
        foundation_readback: Mapping[str, Any],
        bridge_pin: Mapping[str, Any],
        dispatch_receipt: Mapping[str, Any],
        change_set_attestation: Mapping[str, Any],
    ) -> dict[str, Any]:
        """Recover an ambiguous bridge-pin execution without a second execute."""

        if self._profile != contract.MANAGEMENT_PROFILE:
            _fail("OPERATION_PROFILE_INVALID")
        bootstrap = contract.validate_bootstrap_intent(bootstrap_intent)
        self._require_window(bootstrap, read_only=True)
        self._reviewed_sources(source_root=source_root, bootstrap=bootstrap)
        pin = contract.validate_bridge_pin(
            bridge_pin,
            bootstrap_intent=bootstrap,
            foundation_readback=foundation_readback,
        )
        dispatch = self._validate_dispatch_receipt(
            dispatch_receipt,
            bootstrap=bootstrap,
            operation="bridge-pin",
            intent_digest=pin["intent_digest"],
            request_digest=pin["request_digest"],
            request=pin["request"],
        )
        attestation = self._validate_attestation(
            change_set_attestation,
            bootstrap=bootstrap,
            operation="bridge-pin",
            intent_digest=pin["intent_digest"],
            request_digest=pin["request_digest"],
            request=pin["request"],
            dispatch=dispatch,
        )
        execution_claim = self._read_execution_claim_for_attestation(
            operation="bridge-pin",
            intent_digest=pin["intent_digest"],
            request_digest=pin["request_digest"],
            dispatch=dispatch,
            attestation=attestation,
        )
        dispatch, causal_calls = self._validate_causal_dispatch_receipt(
            dispatch,
            bootstrap=bootstrap,
            operation="bridge-pin",
            intent_digest=pin["intent_digest"],
            request_digest=pin["request_digest"],
            request=pin["request"],
            mutation_authorization=True,
        )
        execution, recovery_calls = self._recover_execution_receipt(
            bootstrap=bootstrap,
            operation="bridge-pin",
            intent_digest=pin["intent_digest"],
            request_digest=pin["request_digest"],
            dispatch=dispatch,
            attestation=attestation,
            account=contract.MANAGEMENT_ACCOUNT_ID,
            execution_claim=execution_claim,
        )
        terminal = self.readback_stack(
            bootstrap_intent=bootstrap,
            source_root=source_root,
            operation="bridge-pin",
            bridge_pin=pin,
            foundation_readback=foundation_readback,
        )
        return {
            "status": "EXECUTION_RECOVERED_AND_TERMINAL",
            "execution_receipt": execution,
            "stack_readback": terminal,
            "aws_calls": causal_calls + recovery_calls + terminal["aws_calls"],
            "aws_mutations": 0,
            "retry_permitted": False,
            "production_authorized": False,
            "production_status": contract.PRODUCTION_STATUS,
        }

    def recover_bridge_pin(
        self,
        *,
        bootstrap_intent: Mapping[str, Any],
        source_root: Path,
        foundation_readback: Mapping[str, Any],
        bridge_pin: Mapping[str, Any],
    ) -> dict[str, Any]:
        if self._profile != contract.MANAGEMENT_PROFILE:
            _fail("OPERATION_PROFILE_INVALID")
        bootstrap = contract.validate_bootstrap_intent(bootstrap_intent)
        self._require_window(bootstrap, read_only=True)
        self._reviewed_sources(source_root=source_root, bootstrap=bootstrap)
        pin = contract.validate_bridge_pin(
            bridge_pin,
            bootstrap_intent=bootstrap,
            foundation_readback=foundation_readback,
        )
        dispatch, recovery_calls = self._recover_cfn_dispatch(
            bootstrap=bootstrap,
            operation="bridge-pin",
            intent_digest=pin["intent_digest"],
            request_digest=pin["request_digest"],
            request=pin["request"],
            account=contract.MANAGEMENT_ACCOUNT_ID,
        )
        attestation = self.attest_change_set(
            bootstrap_intent=bootstrap,
            source_root=source_root,
            operation="bridge-pin",
            dispatch_receipt=dispatch,
            bridge_pin=pin,
            foundation_readback=foundation_readback,
        )
        return {
            "status": "RECOVERED_AND_ATTESTED",
            "dispatch_receipt": dispatch,
            "change_set_attestation": attestation,
            "aws_calls": recovery_calls + attestation["aws_calls"],
            "aws_mutations": 0,
            "retry_permitted": False,
            "production_authorized": False,
            "production_status": contract.PRODUCTION_STATUS,
        }

    def dispatch_foundation_access_update_once(
        self,
        *,
        bootstrap_intent: Mapping[str, Any],
        foundation_readback: Mapping[str, Any],
        access_update: Mapping[str, Any],
        route_template_receipt: Mapping[str, Any],
        delegation_template_receipt: Mapping[str, Any],
        source_root: Path,
        authorization: Mapping[str, Any],
    ) -> dict[str, Any]:
        if self._profile != contract.AUTHORITY_PROFILE:
            _fail("OPERATION_PROFILE_INVALID")
        bootstrap = contract.validate_bootstrap_intent(bootstrap_intent)
        self._require_window(bootstrap, read_only=False)
        reviewed_sources = self._reviewed_sources(
            source_root=source_root, bootstrap=bootstrap
        )
        update = contract.validate_foundation_access_update(
            access_update,
            bootstrap_intent=bootstrap,
            foundation_readback=foundation_readback,
            route_template_receipt=route_template_receipt,
            delegation_template_receipt=delegation_template_receipt,
            reviewed_sources=reviewed_sources,
        )
        contract.validate_mutation_authorization(
            authorization,
            bootstrap_intent=bootstrap,
            operation="foundation-access-update:dispatch",
            target_digest=update["intent_digest"],
            now=self._clock(),
        )
        account, caller, _sts_request_id = self._identity()
        claim_current = self._require_window(bootstrap, read_only=False)
        contract.validate_mutation_authorization(
            authorization,
            bootstrap_intent=bootstrap,
            operation="foundation-access-update:dispatch",
            target_digest=update["intent_digest"],
            now=claim_current,
        )
        claimed_at = _stamp(claim_current)
        self._claims.reserve(
            operation="foundation-access-update-dispatch",
            digest=update["request_digest"],
            claimed_at=claimed_at,
            caller_arn=caller,
            request_digest=update["request_digest"],
            authorization_digest=authorization["authorization_digest"],
            authorization_record=authorization,
            request_token=update["request"]["ClientToken"],
        )
        response = _call(
            self._clients.cloudformation.create_change_set,
            mutation=True,
            code="FOUNDATION_ACCESS_UPDATE_CREATE_UNCERTAIN",
            **update["request"],
        )
        stack_id = response.get("StackId")
        change_set_id = response.get("Id")
        if (
            not isinstance(stack_id, str)
            or f":{contract.AUTHORITY_ACCOUNT_ID}:stack/{contract.FOUNDATION_STACK_NAME}/"
            not in stack_id
            or not isinstance(change_set_id, str)
            or f":{contract.AUTHORITY_ACCOUNT_ID}:changeSet/" not in change_set_id
        ):
            _fail("FOUNDATION_ACCESS_UPDATE_RESPONSE_INVALID", uncertain=True)
        receipt: dict[str, Any] = {
            "schema_version": 1,
            "record_type": DISPATCH_RECEIPT_TYPE,
            "source_commit": bootstrap["source_commit"],
            "operation": "foundation-access-update",
            "intent_digest": update["intent_digest"],
            "request_digest": update["request_digest"],
            "authorization_digest": authorization["authorization_digest"],
            "verifier": self._verifier(account, caller),
            "stack_id": stack_id,
            "change_set_id": change_set_id,
            "request_id": _response_id(
                response, "FOUNDATION_ACCESS_UPDATE_RESPONSE_INVALID"
            ),
            "dispatched_at": claimed_at,
            "aws_calls": 2,
            "aws_mutations": 1,
            "retry_permitted": False,
            "production_authorized": False,
            "production_status": contract.PRODUCTION_STATUS,
        }
        receipt["receipt_digest"] = contract.digest_value(receipt)
        return self._validate_dispatch_receipt(
            receipt,
            bootstrap=bootstrap,
            operation="foundation-access-update",
            intent_digest=update["intent_digest"],
            request_digest=update["request_digest"],
            request=update["request"],
        )

    def execute_foundation_access_update_once(
        self,
        *,
        bootstrap_intent: Mapping[str, Any],
        foundation_readback: Mapping[str, Any],
        access_update: Mapping[str, Any],
        route_template_receipt: Mapping[str, Any],
        delegation_template_receipt: Mapping[str, Any],
        source_root: Path,
        dispatch_receipt: Mapping[str, Any],
        change_set_attestation: Mapping[str, Any],
        authorization: Mapping[str, Any],
    ) -> dict[str, Any]:
        if self._profile != contract.AUTHORITY_PROFILE:
            _fail("OPERATION_PROFILE_INVALID")
        bootstrap = contract.validate_bootstrap_intent(bootstrap_intent)
        execution_current = self._require_window(bootstrap, read_only=False)
        reviewed_sources = self._reviewed_sources(
            source_root=source_root, bootstrap=bootstrap
        )
        update = contract.validate_foundation_access_update(
            access_update,
            bootstrap_intent=bootstrap,
            foundation_readback=foundation_readback,
            route_template_receipt=route_template_receipt,
            delegation_template_receipt=delegation_template_receipt,
            reviewed_sources=reviewed_sources,
        )
        contract.validate_mutation_authorization(
            authorization,
            bootstrap_intent=bootstrap,
            operation="foundation-access-update:execute",
            target_digest=update["intent_digest"],
            now=self._clock(),
        )
        dispatch = self._validate_dispatch_receipt(
            dispatch_receipt,
            bootstrap=bootstrap,
            operation="foundation-access-update",
            intent_digest=update["intent_digest"],
            request_digest=update["request_digest"],
            request=update["request"],
        )
        attestation = self._validate_attestation(
            change_set_attestation,
            bootstrap=bootstrap,
            operation="foundation-access-update",
            intent_digest=update["intent_digest"],
            request_digest=update["request_digest"],
            request=update["request"],
            dispatch=dispatch,
        )
        self._validate_attestation_chronology(
            attestation,
            not_before=dispatch["dispatched_at"],
            not_after=execution_current,
        )
        dispatch, causal_calls = self._validate_causal_dispatch_receipt(
            dispatch,
            bootstrap=bootstrap,
            operation="foundation-access-update",
            intent_digest=update["intent_digest"],
            request_digest=update["request_digest"],
            request=update["request"],
            mutation_authorization=True,
        )
        live_attestation = self.attest_change_set(
            bootstrap_intent=bootstrap,
            source_root=source_root,
            operation="foundation-access-update",
            dispatch_receipt=dispatch,
            access_update=update,
            route_template_receipt=route_template_receipt,
            delegation_template_receipt=delegation_template_receipt,
            foundation_readback=foundation_readback,
        )
        self._compare_live_attestation(attestation, live_attestation)
        account, caller, _sts_request_id = self._identity()
        execution_digest = self._execution_effect_digest(
            operation="foundation-access-update",
            intent_digest=update["intent_digest"],
            request_digest=update["request_digest"],
            dispatch=dispatch,
        )
        claim_current = self._require_window(bootstrap, read_only=False)
        self._validate_attestation_chronology(
            attestation,
            not_before=dispatch["dispatched_at"],
            not_after=claim_current,
        )
        contract.validate_mutation_authorization(
            authorization,
            bootstrap_intent=bootstrap,
            operation="foundation-access-update:execute",
            target_digest=update["intent_digest"],
            now=claim_current,
        )
        dispatched_at = _stamp(claim_current)
        execute_request = {
            "ChangeSetName": dispatch["change_set_id"],
            "StackName": dispatch["stack_id"],
            "ClientRequestToken": "gug376-" + execution_digest[7:55],
        }
        self._claims.reserve(
            operation="foundation-access-update-execute",
            digest=execution_digest,
            claimed_at=dispatched_at,
            caller_arn=caller,
            request_digest=contract.digest_value(execute_request),
            authorization_digest=authorization["authorization_digest"],
            authorization_record=authorization,
            request_token=execute_request["ClientRequestToken"],
            preflight_digest=self._execution_preflight_digest(
                dispatch=dispatch, attestation=attestation
            ),
            preflight_calls=causal_calls + live_attestation["aws_calls"] + 1,
        )
        response = _call(
            self._clients.cloudformation.execute_change_set,
            mutation=True,
            code="FOUNDATION_ACCESS_UPDATE_EXECUTE_UNCERTAIN",
            **execute_request,
        )
        receipt: dict[str, Any] = {
            "schema_version": 1,
            "record_type": EXECUTION_RECEIPT_TYPE,
            "source_commit": bootstrap["source_commit"],
            "operation": "foundation-access-update",
            "intent_digest": update["intent_digest"],
            "dispatch_receipt_digest": dispatch["receipt_digest"],
            "change_set_attestation_digest": attestation["attestation_digest"],
            "authorization_digest": authorization["authorization_digest"],
            "verifier": self._verifier(account, caller),
            "request_id": _response_id(
                response, "FOUNDATION_ACCESS_UPDATE_EXECUTE_RESPONSE_INVALID"
            ),
            "dispatched_at": dispatched_at,
            "aws_calls": causal_calls + live_attestation["aws_calls"] + 2,
            "aws_mutations": 1,
            "retry_permitted": False,
            "production_authorized": False,
            "production_status": contract.PRODUCTION_STATUS,
        }
        receipt["receipt_digest"] = contract.digest_value(receipt)
        return receipt

    def recover_foundation_access_update_execution(
        self,
        *,
        bootstrap_intent: Mapping[str, Any],
        foundation_readback: Mapping[str, Any],
        access_update: Mapping[str, Any],
        route_template_receipt: Mapping[str, Any],
        delegation_template_receipt: Mapping[str, Any],
        source_root: Path,
        dispatch_receipt: Mapping[str, Any],
        change_set_attestation: Mapping[str, Any],
    ) -> dict[str, Any]:
        """Recover the exact access-update execution and its terminal readback."""

        if self._profile != contract.AUTHORITY_PROFILE:
            _fail("OPERATION_PROFILE_INVALID")
        bootstrap = contract.validate_bootstrap_intent(bootstrap_intent)
        self._require_window(bootstrap, read_only=True)
        reviewed_sources = self._reviewed_sources(
            source_root=source_root, bootstrap=bootstrap
        )
        update = contract.validate_foundation_access_update(
            access_update,
            bootstrap_intent=bootstrap,
            foundation_readback=foundation_readback,
            route_template_receipt=route_template_receipt,
            delegation_template_receipt=delegation_template_receipt,
            reviewed_sources=reviewed_sources,
        )
        dispatch = self._validate_dispatch_receipt(
            dispatch_receipt,
            bootstrap=bootstrap,
            operation="foundation-access-update",
            intent_digest=update["intent_digest"],
            request_digest=update["request_digest"],
            request=update["request"],
        )
        attestation = self._validate_attestation(
            change_set_attestation,
            bootstrap=bootstrap,
            operation="foundation-access-update",
            intent_digest=update["intent_digest"],
            request_digest=update["request_digest"],
            request=update["request"],
            dispatch=dispatch,
        )
        execution_claim = self._read_execution_claim_for_attestation(
            operation="foundation-access-update",
            intent_digest=update["intent_digest"],
            request_digest=update["request_digest"],
            dispatch=dispatch,
            attestation=attestation,
        )
        dispatch, causal_calls = self._validate_causal_dispatch_receipt(
            dispatch,
            bootstrap=bootstrap,
            operation="foundation-access-update",
            intent_digest=update["intent_digest"],
            request_digest=update["request_digest"],
            request=update["request"],
            mutation_authorization=True,
        )
        execution, recovery_calls = self._recover_execution_receipt(
            bootstrap=bootstrap,
            operation="foundation-access-update",
            intent_digest=update["intent_digest"],
            request_digest=update["request_digest"],
            dispatch=dispatch,
            attestation=attestation,
            account=contract.AUTHORITY_ACCOUNT_ID,
            execution_claim=execution_claim,
        )
        terminal = self.readback_foundation_access_update(
            bootstrap_intent=bootstrap,
            foundation_readback=foundation_readback,
            access_update=update,
            route_template_receipt=route_template_receipt,
            delegation_template_receipt=delegation_template_receipt,
            source_root=source_root,
        )
        return {
            "status": "EXECUTION_RECOVERED_AND_TERMINAL",
            "execution_receipt": execution,
            "foundation_access_readback": terminal,
            "aws_calls": causal_calls + recovery_calls + terminal["aws_calls"],
            "aws_mutations": 0,
            "retry_permitted": False,
            "production_authorized": False,
            "production_status": contract.PRODUCTION_STATUS,
        }

    def recover_foundation_access_update(
        self,
        *,
        bootstrap_intent: Mapping[str, Any],
        foundation_readback: Mapping[str, Any],
        access_update: Mapping[str, Any],
        route_template_receipt: Mapping[str, Any],
        delegation_template_receipt: Mapping[str, Any],
        source_root: Path,
    ) -> dict[str, Any]:
        """Recover and attest an uncertain access-update dispatch read-only."""

        if self._profile != contract.AUTHORITY_PROFILE:
            _fail("OPERATION_PROFILE_INVALID")
        bootstrap = contract.validate_bootstrap_intent(bootstrap_intent)
        self._require_window(bootstrap, read_only=True)
        reviewed_sources = self._reviewed_sources(
            source_root=source_root, bootstrap=bootstrap
        )
        update = contract.validate_foundation_access_update(
            access_update,
            bootstrap_intent=bootstrap,
            foundation_readback=foundation_readback,
            route_template_receipt=route_template_receipt,
            delegation_template_receipt=delegation_template_receipt,
            reviewed_sources=reviewed_sources,
        )
        dispatch, recovery_calls = self._recover_cfn_dispatch(
            bootstrap=bootstrap,
            operation="foundation-access-update",
            intent_digest=update["intent_digest"],
            request_digest=update["request_digest"],
            request=update["request"],
            account=contract.AUTHORITY_ACCOUNT_ID,
        )
        attestation = self.attest_change_set(
            bootstrap_intent=bootstrap,
            source_root=source_root,
            operation="foundation-access-update",
            dispatch_receipt=dispatch,
            access_update=update,
            route_template_receipt=route_template_receipt,
            delegation_template_receipt=delegation_template_receipt,
            foundation_readback=foundation_readback,
        )
        return {
            "status": "RECOVERED_AND_ATTESTED",
            "dispatch_receipt": dispatch,
            "change_set_attestation": attestation,
            "aws_calls": recovery_calls + attestation["aws_calls"],
            "aws_mutations": 0,
            "retry_permitted": False,
            "production_authorized": False,
            "production_status": contract.PRODUCTION_STATUS,
        }

    def readback_foundation_access_update(
        self,
        *,
        bootstrap_intent: Mapping[str, Any],
        foundation_readback: Mapping[str, Any],
        access_update: Mapping[str, Any],
        route_template_receipt: Mapping[str, Any],
        delegation_template_receipt: Mapping[str, Any],
        source_root: Path,
    ) -> dict[str, Any]:
        """Prove exact version-bound S3 and direct KMS reader grants."""

        if (
            self._profile != contract.AUTHORITY_PROFILE
            or self._clients.s3 is None
            or self._clients.kms is None
        ):
            _fail("OPERATION_PROFILE_INVALID")
        bootstrap = contract.validate_bootstrap_intent(bootstrap_intent)
        self._require_window(bootstrap, read_only=True)
        reviewed_sources = self._reviewed_sources(
            source_root=source_root, bootstrap=bootstrap
        )
        update = contract.validate_foundation_access_update(
            access_update,
            bootstrap_intent=bootstrap,
            foundation_readback=foundation_readback,
            route_template_receipt=route_template_receipt,
            delegation_template_receipt=delegation_template_receipt,
            reviewed_sources=reviewed_sources,
        )
        account, caller, _sts_request_id = self._identity()
        stacks = _call(
            self._clients.cloudformation.describe_stacks,
            code="FOUNDATION_ACCESS_READBACK_FAILED",
            StackName=contract.FOUNDATION_STACK_NAME,
        )
        raw = stacks.get("Stacks")
        if (
            not isinstance(raw, list)
            or len(raw) != 1
            or raw[0].get("StackStatus") != "UPDATE_COMPLETE"
        ):
            _fail("FOUNDATION_ACCESS_STACK_NOT_TERMINAL")
        outputs = {
            item.get("OutputKey"): item.get("OutputValue")
            for item in raw[0].get("Outputs", [])
            if isinstance(item, Mapping)
        }
        if (
            set(outputs)
            != {
                "ArtifactBucketName",
                "ArtifactBucketArn",
                "ArtifactKmsKeyArn",
                "ArtifactKmsAlias",
                "SigningProfileName",
                "SigningProfileVersionArn",
                "CodeSigningConfigArn",
                "CrossAccountAccessMode",
                "ProductionAuthorized",
            }
            or outputs.get("ArtifactBucketName")
            != bootstrap["names"]["artifact_bucket"]
            or outputs.get("ArtifactBucketArn")
            != f"arn:aws:s3:::{bootstrap['names']['artifact_bucket']}"
            or outputs.get("ArtifactKmsAlias")
            != bootstrap["names"]["artifact_kms_alias"]
            or outputs.get("SigningProfileName")
            != bootstrap["names"]["signing_profile_name"]
            or outputs.get("CrossAccountAccessMode") != "true"
            or outputs.get("ProductionAuthorized") != "false"
            or outputs.get("ArtifactKmsKeyArn") != update["artifact_kms_key_arn"]
        ):
            _fail("FOUNDATION_ACCESS_OUTPUT_MISMATCH")
        expected_parameters = {
            item["ParameterKey"]: item["ParameterValue"]
            for item in update["request"]["Parameters"]
        }
        observed_parameters = _exact_parameter_values(
            raw[0].get("Parameters"),
            code="FOUNDATION_ACCESS_PARAMETER_MISMATCH",
        )
        if observed_parameters != expected_parameters:
            _fail("FOUNDATION_ACCESS_PARAMETER_MISMATCH")
        template_response = _call(
            self._clients.cloudformation.get_template,
            code="FOUNDATION_ACCESS_READBACK_FAILED",
            StackName=contract.FOUNDATION_STACK_NAME,
            TemplateStage="Original",
        )
        template_body = template_response.get("TemplateBody")
        if (
            not isinstance(template_body, str)
            or contract.bytes_digest(template_body.encode("utf-8"))
            != bootstrap["template_digests"]["foundation"]
        ):
            _fail("FOUNDATION_ACCESS_TEMPLATE_MISMATCH")
        resources, stack_resource_calls = self._list_stack_resources_exact(
            stack_name=contract.FOUNDATION_STACK_NAME,
            code="FOUNDATION_ACCESS_READBACK_FAILED",
        )
        expected_resources = {
            ("ArtifactKey", "AWS::KMS::Key"),
            ("ArtifactKeyAlias", "AWS::KMS::Alias"),
            ("ArtifactBucket", "AWS::S3::Bucket"),
            ("ArtifactBucketPolicy", "AWS::S3::BucketPolicy"),
            ("SigningProfile", "AWS::Signer::SigningProfile"),
            ("CodeSigningConfig", "AWS::Lambda::CodeSigningConfig"),
        }
        observed = {
            (item.get("LogicalResourceId"), item.get("ResourceType"))
            for item in resources or []
            if isinstance(item, Mapping)
        }
        if observed != expected_resources or len(resources or []) != 6:
            _fail("FOUNDATION_ACCESS_RESOURCE_SET_MISMATCH")
        bucket = bootstrap["names"]["artifact_bucket"]
        bucket_policy_response = _call(
            self._clients.s3.get_bucket_policy,
            code="FOUNDATION_ACCESS_READBACK_FAILED",
            Bucket=bucket,
            ExpectedBucketOwner=contract.AUTHORITY_ACCOUNT_ID,
        )
        key_policy_response = _call(
            self._clients.kms.get_key_policy,
            code="FOUNDATION_ACCESS_READBACK_FAILED",
            KeyId=update["artifact_kms_key_arn"],
            PolicyName="default",
        )
        try:
            bucket_policy = json.loads(bucket_policy_response["Policy"])
            key_policy = json.loads(key_policy_response["Policy"])
        except (KeyError, TypeError, json.JSONDecodeError) as exc:
            raise ConnectedArtifactBootstrapError(
                "FOUNDATION_ACCESS_POLICY_INVALID"
            ) from exc
        bucket_statements = {
            item.get("Sid"): item
            for item in bucket_policy.get("Statement", [])
            if isinstance(item, Mapping)
        }
        key_statements = {
            item.get("Sid"): item
            for item in key_policy.get("Statement", [])
            if isinstance(item, Mapping)
        }
        parameters = {
            item["ParameterKey"]: item["ParameterValue"]
            for item in update["request"]["Parameters"]
        }
        route = bucket_statements.get(
            "AllowManagementExactRouteTemplateVersion"
        )
        delegation = bucket_statements.get(
            "AllowManagementCreatorExactDelegationTemplateVersion"
        )
        bucket_context = f"arn:aws:s3:::{bucket}"
        route_key = (
            f"{contract.ARTIFACT_PREFIX}templates/{bootstrap['source_commit']}/"
            "cfn-platform-authority-gug376-temporary-change-set-route.yaml"
        )
        delegation_key = (
            f"{contract.ARTIFACT_PREFIX}templates/{bootstrap['source_commit']}/"
            "cfn-platform-authority-bootstrap-plan-repair-delegation.yaml"
        )
        management_admin = (
            "arn:aws:iam::839393571433:role/aws-reserved/sso.amazonaws.com/"
            "AWSReservedSSO_AWSAdministratorAccess_*"
        )
        management_creator = (
            "arn:aws:iam::839393571433:role/scanalyze/platform-authority/"
            "ScanalyzeGug376RouteBrokerCreator"
        )
        expected_route = {
            "Sid": "AllowManagementExactRouteTemplateVersion",
            "Effect": "Allow",
            "Principal": {"AWS": "arn:aws:iam::839393571433:root"},
            "Action": "s3:GetObjectVersion",
            "Resource": f"arn:aws:s3:::{bucket}/{route_key}",
            "Condition": {
                "ArnLike": {
                    "aws:PrincipalArn": [management_admin, management_creator]
                },
                "StringEquals": {
                    "s3:VersionId": parameters["RouteTemplateVersion"]
                },
            },
        }
        expected_delegation = {
            "Sid": "AllowManagementCreatorExactDelegationTemplateVersion",
            "Effect": "Allow",
            "Principal": {"AWS": "arn:aws:iam::839393571433:root"},
            "Action": "s3:GetObjectVersion",
            "Resource": f"arn:aws:s3:::{bucket}/{delegation_key}",
            "Condition": {
                "ArnEquals": {"aws:PrincipalArn": management_creator},
                "StringEquals": {
                    "s3:VersionId": parameters["DelegationTemplateVersion"]
                },
            },
        }
        expected_delegated_principals = [
            f"arn:aws:iam::{contract.AUTHORITY_ACCOUNT_ID}:root",
            "arn:aws:iam::839393571433:root",
        ]
        expected_delegated_arns = [
            management_admin,
            management_creator,
            f"arn:aws:iam::{contract.AUTHORITY_ACCOUNT_ID}:role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_ScanalyzeGug376ArtifactBootstrap_*",
            f"arn:aws:iam::{contract.AUTHORITY_ACCOUNT_ID}:role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_ScanalyzeGug376BrokerSeedCreator_*",
            f"arn:aws:iam::{contract.AUTHORITY_ACCOUNT_ID}:role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_ScanalyzeGug376BrokerSeedExec_*",
            f"arn:aws:iam::{contract.AUTHORITY_ACCOUNT_ID}:role/ScanalyzeGug376RouteBrokerCreator",
            f"arn:aws:iam::{contract.AUTHORITY_ACCOUNT_ID}:role/ScanalyzeGug376RouteBrokerExecutor",
        ]
        delegated = key_statements.get(
            "AllowExactGug376ReadersThroughBucketKeyS3Only"
        )
        if (
            set(bucket_statements)
            != {
                "DenyInsecureTransport",
                "DenyUnencryptedObjectWrites",
                "DenyWrongKmsKey",
                "AllowSignerSourceAndDestination",
                "AllowManagementExactRouteTemplateVersion",
                "AllowManagementCreatorExactDelegationTemplateVersion",
            }
            or not isinstance(route, Mapping)
            or route != expected_route
            or not isinstance(delegation, Mapping)
            or delegation != expected_delegation
            or not isinstance(delegated, Mapping)
            or set(key_statements)
            != {
                "PreserveAccountAdministration",
                "AllowOnlyTemporaryBootstrapRoleThroughExactS3",
                "AllowSignerServiceThroughExactBucket",
                "AllowExactGug376ReadersThroughBucketKeyS3Only",
            }
            or delegated.get("Effect") != "Allow"
            or delegated.get("Principal", {}).get("AWS")
            != expected_delegated_principals
            or delegated.get("Action") != "kms:Decrypt"
            or delegated.get("Resource") != "*"
            or delegated.get("Condition", {}).get("ArnLike", {}).get(
                "aws:PrincipalArn"
            )
            != expected_delegated_arns
            or delegated.get("Condition", {}).get("StringEquals")
            != {
                "aws:RequestedRegion": "us-east-1",
                "kms:ViaService": "s3.us-east-1.amazonaws.com",
                "kms:EncryptionContext:aws:s3:arn": bucket_context,
            }
            or "AllowExactReadersWithoutIdentityKmsDecrypt" in key_statements
        ):
            _fail("FOUNDATION_ACCESS_POLICY_MISMATCH")
        receipt: dict[str, Any] = {
            "schema_version": 1,
            "record_type": contract.FOUNDATION_ACCESS_READBACK_TYPE,
            "source_commit": bootstrap["source_commit"],
            "bootstrap_intent_digest": bootstrap["intent_digest"],
            "access_update_intent_digest": update["intent_digest"],
            "verifier": self._verifier(account, caller),
            "route_template_receipt_digest": update[
                "route_template_receipt_digest"
            ],
            "delegation_template_receipt_digest": update[
                "delegation_template_receipt_digest"
            ],
            "route_template_sha256": update["route_template_sha256"],
            "delegation_template_sha256": update[
                "delegation_template_sha256"
            ],
            "route_template_version_digest": update[
                "route_template_version_digest"
            ],
            "delegation_template_version_digest": update[
                "delegation_template_version_digest"
            ],
            "template_digest": bootstrap["template_digests"]["foundation"],
            "parameters_digest": contract.digest_value(expected_parameters),
            "bucket_policy_digest": contract.digest_value(bucket_policy),
            "key_policy_digest": contract.digest_value(key_policy),
            "direct_kms_grant_proven": True,
            "exact_resource_count": 6,
            "source_marker": "AWS_STS_CLOUDFORMATION_S3_KMS_EXACT_ACCESS_READBACK",
            "read_at": _stamp(
                self._require_window(bootstrap, read_only=True)
            ),
            "aws_calls": 5 + stack_resource_calls,
            "aws_mutations": 0,
            "production_authorized": False,
            "production_status": contract.PRODUCTION_STATUS,
        }
        receipt["readback_digest"] = contract.digest_value(receipt)
        contract.validate_foundation_access_readback(
            receipt,
            bootstrap_intent=bootstrap,
            foundation_readback=foundation_readback,
            access_update=update,
            route_template_receipt=route_template_receipt,
            delegation_template_receipt=delegation_template_receipt,
            reviewed_sources=reviewed_sources,
        )
        return receipt

    def readback_stack(
        self, *, bootstrap_intent: Mapping[str, Any],
        source_root: Path, operation: str,
        bridge_pin: Mapping[str, Any] | None = None,
        foundation_readback: Mapping[str, Any] | None = None,
        cleanup_retire: Mapping[str, Any] | None = None,
        bridge_revoke_readback: Mapping[str, Any] | None = None,
        bootstrap_route_release: Mapping[str, Any] | None = None,
        seed_intent: Mapping[str, Any] | None = None,
        terminal_readbacks: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Prove exact logical-resource inventory with no extra resources."""

        intent = contract.validate_bootstrap_intent(bootstrap_intent)
        retire: dict[str, Any] | None = None
        cleanup_revalidation_calls = 0
        if operation == "bridge-cleanup-retire":
            if cleanup_retire is None or bridge_revoke_readback is None:
                _fail("CLEANUP_RETIRE_REQUIRED")
            retire = contract.validate_bridge_cleanup_retire(
                cleanup_retire,
                bootstrap_intent=intent,
                bridge_revoke_readback=bridge_revoke_readback,
                bootstrap_route_release=bootstrap_route_release,
                seed_intent=seed_intent,
                terminal_readbacks=terminal_readbacks,
            )
            self._require_cleanup_retire_clock(retire, admission=False)
        else:
            if any(
                item is not None
                for item in (
                    cleanup_retire,
                    bridge_revoke_readback,
                    bootstrap_route_release,
                    seed_intent,
                    terminal_readbacks,
                )
            ):
                _fail("CLEANUP_RETIRE_INPUT_INVALID")
            self._require_window(intent, read_only=True)
        self._reviewed_sources(source_root=source_root, bootstrap=intent)
        if operation == "bridge-cleanup-retire":
            if bridge_pin is not None or foundation_readback is not None:
                _fail("STACK_READBACK_INPUT_INVALID")
            assert retire is not None
            request = retire["request"]
            readback_intent_digest = retire["intent_digest"]
            cleanup_revalidation_calls = self._revalidate_cleanup_success(
                cleanup_retire=retire,
                seed_intent=seed_intent,
                terminal_readbacks=terminal_readbacks,
            )
        elif operation == "bridge-pin":
            if bridge_pin is None or foundation_readback is None:
                _fail("BRIDGE_PIN_REQUIRED")
            pin = contract.validate_bridge_pin(
                bridge_pin,
                bootstrap_intent=intent,
                foundation_readback=foundation_readback,
            )
            request = pin["request"]
            readback_intent_digest = pin["intent_digest"]
        else:
            if bridge_pin is not None or foundation_readback is not None:
                _fail("STACK_READBACK_INPUT_INVALID")
            if operation not in intent["requests"]:
                _fail("STACK_READBACK_INPUT_INVALID")
            request = intent["requests"][operation]
            readback_intent_digest = intent["intent_digest"]
        expected_profile = (
            contract.AUTHORITY_PROFILE
            if operation == "foundation-create"
            else contract.MANAGEMENT_PROFILE
        )
        if self._profile != expected_profile:
            _fail("OPERATION_PROFILE_INVALID")
        account, caller, _sts_request_id = self._identity()
        stacks = _call(
            self._clients.cloudformation.describe_stacks,
            code="DESCRIBE_STACK_FAILED",
            StackName=request["StackName"],
        )
        raw_stacks = stacks.get("Stacks")
        if not isinstance(raw_stacks, list) or len(raw_stacks) != 1:
            _fail("STACK_READBACK_INVALID")
        stack = raw_stacks[0]
        expected_status = (
            "UPDATE_COMPLETE"
            if operation in {
                "bridge-pin",
                "bridge-revoke",
                "bridge-cleanup-retire",
            }
            else "CREATE_COMPLETE"
        )
        if not isinstance(stack, Mapping) or stack.get("StackStatus") != expected_status:
            _fail("STACK_NOT_TERMINAL")
        stack_completed = (
            stack.get("LastUpdatedTime")
            if operation in {
                "bridge-pin",
                "bridge-revoke",
                "bridge-cleanup-retire",
            }
            else stack.get("CreationTime")
        )
        if not isinstance(stack_completed, datetime):
            _fail("STACK_COMPLETION_TIME_INVALID")
        template = _call(
            self._clients.cloudformation.get_template,
            code="GET_TEMPLATE_FAILED",
            StackName=request["StackName"],
            TemplateStage="Original",
        )
        body = template.get("TemplateBody")
        expected_template = "foundation" if operation == "foundation-create" else "bridge"
        if (
            not isinstance(body, str)
            or contract.bytes_digest(body.encode("utf-8"))
            != intent["template_digests"][expected_template]
        ):
            _fail("STACK_TEMPLATE_MISMATCH")
        resources, stack_resource_calls = self._list_stack_resources_exact(
            stack_name=request["StackName"],
            code="LIST_STACK_RESOURCES_FAILED",
        )
        observed = {
            (item.get("LogicalResourceId"), item.get("ResourceType"))
            for item in resources
            if isinstance(item, Mapping)
        }
        bridge_create = {
            ("ArtifactBootstrapPermissionSet", "AWS::SSO::PermissionSet"),
            ("ArtifactBootstrapAssignment", "AWS::SSO::Assignment"),
            ("RouteSeedCleanupPermissionSet", "AWS::SSO::PermissionSet"),
            ("RouteSeedCleanupAssignment", "AWS::SSO::Assignment"),
            ("BrokerSeedCleanupPermissionSet", "AWS::SSO::PermissionSet"),
            ("BrokerSeedCleanupAssignment", "AWS::SSO::Assignment"),
            ("ManagementRecoveryRole", "AWS::IAM::Role"),
        }
        bridge_revoke = bridge_create - {
            ("ArtifactBootstrapAssignment", "AWS::SSO::Assignment")
        }
        bridge_retired = {
            ("ArtifactBootstrapPermissionSet", "AWS::SSO::PermissionSet")
        }
        foundation = {
            ("ArtifactKey", "AWS::KMS::Key"),
            ("ArtifactKeyAlias", "AWS::KMS::Alias"),
            ("ArtifactBucket", "AWS::S3::Bucket"),
            ("ArtifactBucketPolicy", "AWS::S3::BucketPolicy"),
            ("SigningProfile", "AWS::Signer::SigningProfile"),
            ("CodeSigningConfig", "AWS::Lambda::CodeSigningConfig"),
        }
        expected = (
            foundation
            if operation == "foundation-create"
            else bridge_create
            if operation in {"bridge-create", "bridge-pin"}
            else bridge_revoke
            if operation == "bridge-revoke"
            else bridge_retired
        )
        if observed != expected or len(resources) != len(expected):
            _fail("STACK_RESOURCE_SET_MISMATCH")
        outputs = {
            item.get("OutputKey"): item.get("OutputValue")
            for item in stack.get("Outputs", [])
            if isinstance(item, Mapping)
        }
        expected_mode = (
            "false"
            if operation in {"bridge-revoke", "bridge-cleanup-retire"}
            else "true"
        )
        base_bridge_outputs = {
                "ArtifactBootstrapPermissionSetArn",
                "AssignmentMode",
                "CleanupAssignmentMode",
                "CleanupNotAfter",
                "AuthorityProfileName",
                "ProductionAuthorized",
        }
        cleanup_bridge_outputs = {
            "ManagementRecoveryRoleArn",
            "ManagementRecoveryRoleName",
            "RouteSeedCleanupPermissionSetArn",
            "BrokerSeedCleanupPermissionSetArn",
            "RouteSeedCleanupProfileName",
            "BrokerSeedCleanupProfileName",
        }
        cleanup_active = operation not in {
            "foundation-create",
            "bridge-cleanup-retire",
        }
        if operation != "foundation-create" and (
            set(outputs)
            != base_bridge_outputs
            | (cleanup_bridge_outputs if cleanup_active else set())
            or outputs.get("AssignmentMode") != expected_mode
            or outputs.get("CleanupAssignmentMode")
            != ("true" if cleanup_active else "false")
            or outputs.get("CleanupNotAfter") != intent["cleanup_not_after"]
            or outputs.get("AuthorityProfileName") != contract.AUTHORITY_PROFILE
            or outputs.get("ProductionAuthorized") != "false"
            or (
                cleanup_active
                and (
                    outputs.get("ManagementRecoveryRoleArn")
                    != "arn:aws:iam::839393571433:role/scanalyze/platform-authority/ScanalyzeGug376RouteBrokerRecovery"
                    or outputs.get("ManagementRecoveryRoleName")
                    != "ScanalyzeGug376RouteBrokerRecovery"
                    or outputs.get("RouteSeedCleanupProfileName")
                    != "839393571433_ScanalyzeGug376RouteSeedCleanup"
                    or outputs.get("BrokerSeedCleanupProfileName")
                    != "042360977644_ScanalyzeGug376BrokerSeedCleanup"
                )
            )
        ):
            _fail("BRIDGE_OUTPUT_MISMATCH")
        sso_calls = 0
        credential_window_expired = False
        permission_set_arn_digest: str | None = None
        permission_set_policy_digest: str | None = None
        permission_set_tags_digest: str | None = None
        permission_set_provisioned: bool | None = None
        managed_policy_count: int | None = None
        customer_policy_count: int | None = None
        permissions_boundary_absent: bool | None = None
        permission_set_metadata_exact: bool | None = None
        cleanup_assignment_count: int | None = None
        cleanup_permission_set_count: int | None = None
        cleanup_permission_sets_digest: str | None = None
        management_recovery_role_present: bool | None = None
        management_recovery_role_digest: str | None = None
        cleanup_authority_active: bool | None = None
        iam_calls = 0
        if operation in {
            "bridge-create",
            "bridge-pin",
            "bridge-revoke",
            "bridge-cleanup-retire",
        }:
            if self._clients.sso_admin is None or self._clients.iam is None:
                _fail("SSO_READBACK_CLIENT_MISSING")
            parameters = {
                item["ParameterKey"]: item["ParameterValue"]
                for item in request["Parameters"]
            }
            permission_set_arn = outputs.get("ArtifactBootstrapPermissionSetArn")
            if not isinstance(permission_set_arn, str):
                _fail("BRIDGE_PERMISSION_SET_OUTPUT_INVALID")
            exact_permission_request = {
                "InstanceArn": parameters["IdentityCenterInstanceArn"],
                "PermissionSetArn": permission_set_arn,
            }
            described_response = _call(
                self._clients.sso_admin.describe_permission_set,
                code="SSO_PERMISSION_SET_READBACK_FAILED",
                **exact_permission_request,
            )
            sso_calls += 1
            described = described_response.get("PermissionSet")
            permission_set_metadata_exact = bool(
                isinstance(described, Mapping)
                and described.get("PermissionSetArn") == permission_set_arn
                and described.get("Name") == "ScanalyzeGug376ArtifactBootstrap"
                and described.get("Description")
                == (
                    "GUG-376 temporary artifact-foundation bootstrap; "
                    "no production authority"
                )
                and described.get("SessionDuration") == "PT1H"
                and described.get("RelayState") in {None, ""}
            )
            if not permission_set_metadata_exact:
                _fail("SSO_PERMISSION_SET_METADATA_MISMATCH")
            inline_response = _call(
                self._clients.sso_admin.get_inline_policy_for_permission_set,
                code="SSO_PERMISSION_SET_READBACK_FAILED",
                **exact_permission_request,
            )
            sso_calls += 1
            inline_policy = _parse_policy(
                inline_response.get("InlinePolicy"),
                code="SSO_PERMISSION_SET_POLICY_INVALID",
            )
            expected_policy = _resolve_bridge_policy(
                template_body=request["TemplateBody"],
                parameters=parameters,
            )
            if inline_policy != expected_policy:
                _fail("SSO_PERMISSION_SET_POLICY_MISMATCH")

            def paginate(method: Any, *, key: str, request: dict[str, Any]) -> list[Any]:
                nonlocal sso_calls
                items: list[Any] = []
                page_token: str | None = None
                seen_tokens: set[str] = set()
                for _ in range(100):
                    page_request = dict(request)
                    page_request["MaxResults"] = 100
                    if page_token is not None:
                        page_request["NextToken"] = page_token
                    page = _call(
                        method,
                        code="SSO_PERMISSION_SET_READBACK_FAILED",
                        **page_request,
                    )
                    sso_calls += 1
                    raw_items = page.get(key)
                    if not isinstance(raw_items, list):
                        _fail("SSO_PERMISSION_SET_READBACK_FAILED")
                    items.extend(raw_items)
                    next_token = page.get("NextToken")
                    if next_token is None:
                        return items
                    if (
                        not isinstance(next_token, str)
                        or not next_token
                        or next_token in seen_tokens
                    ):
                        _fail("SSO_PERMISSION_SET_PAGINATION_INVALID")
                    seen_tokens.add(next_token)
                    page_token = next_token
                _fail("SSO_PERMISSION_SET_PAGE_LIMIT")

            tags = paginate(
                self._clients.sso_admin.list_tags_for_resource,
                key="Tags",
                request={
                    "InstanceArn": parameters["IdentityCenterInstanceArn"],
                    "ResourceArn": permission_set_arn,
                },
            )
            expected_tags = {
                "managed_by": "cloudformation",
                "service": "scanalyze-platform-authority",
                "work_package": "GUG-376",
                "source_commit": intent["source_commit"],
            }
            observed_tags = {
                item.get("Key"): item.get("Value")
                for item in tags
                if isinstance(item, Mapping)
            }
            if len(observed_tags) != len(tags) or observed_tags != expected_tags:
                _fail("SSO_PERMISSION_SET_TAGS_MISMATCH")
            managed = paginate(
                self._clients.sso_admin.list_managed_policies_in_permission_set,
                key="AttachedManagedPolicies",
                request=exact_permission_request,
            )
            customer = paginate(
                self._clients.sso_admin.list_customer_managed_policy_references_in_permission_set,
                key="CustomerManagedPolicyReferences",
                request=exact_permission_request,
            )
            try:
                sso_calls += 1
                boundary_response = _call(
                    self._clients.sso_admin.get_permissions_boundary_for_permission_set,
                    code="SSO_PERMISSION_SET_BOUNDARY_READBACK_FAILED",
                    **exact_permission_request,
                )
                boundary = boundary_response.get("PermissionsBoundary")
            except ConnectedArtifactBootstrapError as exc:
                if _aws_error_code(exc.__cause__ or exc) not in {
                    "ResourceNotFound",
                    "ResourceNotFoundException",
                }:
                    raise
                boundary = None
            managed_policy_count = len(managed)
            customer_policy_count = len(customer)
            permissions_boundary_absent = boundary is None
            if managed or customer or boundary is not None:
                _fail("SSO_PERMISSION_SET_FOREIGN_AUTHORITY")
            permission_set_arn_digest = contract.digest_value(permission_set_arn)
            permission_set_policy_digest = contract.digest_value(inline_policy)
            permission_set_tags_digest = contract.digest_value(expected_tags)
            assignments: list[Mapping[str, Any]] = []
            token: str | None = None
            seen: set[str] = set()
            for _page in range(100):
                page_request: dict[str, Any] = {
                    "InstanceArn": parameters["IdentityCenterInstanceArn"],
                    "AccountId": contract.AUTHORITY_ACCOUNT_ID,
                    "PermissionSetArn": permission_set_arn,
                    "MaxResults": 100,
                }
                if token is not None:
                    page_request["NextToken"] = token
                page = _call(
                    self._clients.sso_admin.list_account_assignments,
                    code="SSO_ASSIGNMENT_READBACK_FAILED",
                    **page_request,
                )
                sso_calls += 1
                raw_assignments = page.get("AccountAssignments")
                if not isinstance(raw_assignments, list):
                    _fail("SSO_ASSIGNMENT_READBACK_FAILED")
                assignments.extend(
                    item for item in raw_assignments if isinstance(item, Mapping)
                )
                next_token = page.get("NextToken")
                if next_token is None:
                    break
                if (
                    not isinstance(next_token, str)
                    or not next_token
                    or next_token in seen
                ):
                    _fail("SSO_ASSIGNMENT_PAGINATION_INVALID")
                seen.add(next_token)
                token = next_token
            else:
                _fail("SSO_ASSIGNMENT_PAGE_LIMIT")
            expected_assignment = {
                "AccountId": contract.AUTHORITY_ACCOUNT_ID,
                "PermissionSetArn": permission_set_arn,
                "PrincipalId": parameters["BootstrapPrincipalId"],
                "PrincipalType": "USER",
            }
            if operation in {"bridge-create", "bridge-pin"}:
                if assignments != [expected_assignment]:
                    _fail("SSO_ASSIGNMENT_MISMATCH")
            elif assignments:
                _fail("SSO_ASSIGNMENT_REVOCATION_INCOMPLETE")
            provisioned: list[str] = []
            token = None
            seen.clear()
            for _page in range(100):
                page_request = {
                    "InstanceArn": parameters["IdentityCenterInstanceArn"],
                    "AccountId": contract.AUTHORITY_ACCOUNT_ID,
                    "MaxResults": 100,
                }
                if operation in {"bridge-create", "bridge-pin"}:
                    page_request["ProvisioningStatus"] = (
                        "LATEST_PERMISSION_SET_PROVISIONED"
                    )
                if token is not None:
                    page_request["NextToken"] = token
                page = _call(
                    self._clients.sso_admin.list_permission_sets_provisioned_to_account,
                    code="SSO_PROVISIONING_READBACK_FAILED",
                    **page_request,
                )
                sso_calls += 1
                raw_permission_sets = page.get("PermissionSets")
                if not isinstance(raw_permission_sets, list) or any(
                    not isinstance(item, str) for item in raw_permission_sets
                ):
                    _fail("SSO_PROVISIONING_READBACK_FAILED")
                provisioned.extend(raw_permission_sets)
                next_token = page.get("NextToken")
                if next_token is None:
                    break
                if (
                    not isinstance(next_token, str)
                    or not next_token
                    or next_token in seen
                ):
                    _fail("SSO_PROVISIONING_PAGINATION_INVALID")
                seen.add(next_token)
                token = next_token
            else:
                _fail("SSO_PROVISIONING_PAGE_LIMIT")
            permission_set_provisioned = permission_set_arn in provisioned
            if operation in {"bridge-create", "bridge-pin"} and not permission_set_provisioned:
                _fail("SSO_PROVISIONING_STATE_MISMATCH")
            if operation == "bridge-revoke":
                expiry = datetime.fromisoformat(
                    intent["access_not_after"][:-1] + "+00:00"
                )
                session_expiry = stack_completed.astimezone(timezone.utc) + timedelta(
                    hours=1
                )
                expiry = max(expiry, session_expiry)
                observed = self._clock()
                if observed.tzinfo is None or observed.utcoffset() is None:
                    _fail("CLOCK_INVALID")
                credential_window_expired = (
                    observed.astimezone(timezone.utc).replace(microsecond=0)
                    >= expiry
                )
                if not credential_window_expired:
                    _fail("REVOCATION_CREDENTIAL_WINDOW_ACTIVE")

            cleanup_specs = (
                (
                    "RouteSeedCleanupPermissionSet",
                    "RouteSeedCleanupPermissionSetArn",
                    "ScanalyzeGug376RouteSeedCleanup",
                    contract.MANAGEMENT_ACCOUNT_ID,
                ),
                (
                    "BrokerSeedCleanupPermissionSet",
                    "BrokerSeedCleanupPermissionSetArn",
                    "ScanalyzeGug376BrokerSeedCleanup",
                    contract.AUTHORITY_ACCOUNT_ID,
                ),
            )
            cleanup_projections: list[dict[str, Any]] = []
            if cleanup_active:
                for logical_id, output_key, name, target_account in cleanup_specs:
                    cleanup_arn = outputs.get(output_key)
                    if not isinstance(cleanup_arn, str):
                        _fail("CLEANUP_PERMISSION_SET_OUTPUT_INVALID")
                    cleanup_request = {
                        "InstanceArn": parameters["IdentityCenterInstanceArn"],
                        "PermissionSetArn": cleanup_arn,
                    }
                    described_response = _call(
                        self._clients.sso_admin.describe_permission_set,
                        code="CLEANUP_PERMISSION_SET_READBACK_FAILED",
                        **cleanup_request,
                    )
                    sso_calls += 1
                    described_cleanup = described_response.get("PermissionSet")
                    inline_response = _call(
                        self._clients.sso_admin.get_inline_policy_for_permission_set,
                        code="CLEANUP_PERMISSION_SET_READBACK_FAILED",
                        **cleanup_request,
                    )
                    sso_calls += 1
                    cleanup_policy = _parse_policy(
                        inline_response.get("InlinePolicy"),
                        code="CLEANUP_PERMISSION_SET_POLICY_INVALID",
                    )
                    expected_cleanup_policy = _resolve_bridge_policy(
                        template_body=request["TemplateBody"],
                        parameters=parameters,
                        logical_id=logical_id,
                    )
                    cleanup_tags = paginate(
                        self._clients.sso_admin.list_tags_for_resource,
                        key="Tags",
                        request={
                            "InstanceArn": parameters["IdentityCenterInstanceArn"],
                            "ResourceArn": cleanup_arn,
                        },
                    )
                    cleanup_managed = paginate(
                        self._clients.sso_admin.list_managed_policies_in_permission_set,
                        key="AttachedManagedPolicies",
                        request=cleanup_request,
                    )
                    cleanup_customer = paginate(
                        self._clients.sso_admin.list_customer_managed_policy_references_in_permission_set,
                        key="CustomerManagedPolicyReferences",
                        request=cleanup_request,
                    )
                    try:
                        sso_calls += 1
                        cleanup_boundary_response = _call(
                            self._clients.sso_admin.get_permissions_boundary_for_permission_set,
                            code="CLEANUP_PERMISSION_SET_READBACK_FAILED",
                            **cleanup_request,
                        )
                        cleanup_boundary = cleanup_boundary_response.get(
                            "PermissionsBoundary"
                        )
                    except ConnectedArtifactBootstrapError as exc:
                        if _aws_error_code(exc.__cause__ or exc) not in {
                            "ResourceNotFound",
                            "ResourceNotFoundException",
                        }:
                            raise
                        cleanup_boundary = None
                    expected_cleanup_tags = [
                        {"Key": "managed_by", "Value": "cloudformation"},
                        {"Key": "source_commit", "Value": intent["source_commit"]},
                        {"Key": "work_package", "Value": "GUG-376"},
                    ]
                    if (
                        not isinstance(described_cleanup, Mapping)
                        or described_cleanup.get("PermissionSetArn") != cleanup_arn
                        or described_cleanup.get("Name") != name
                        or described_cleanup.get("SessionDuration") != "PT1H"
                        or described_cleanup.get("Description") not in {None, ""}
                        or described_cleanup.get("RelayState") not in {None, ""}
                        or cleanup_policy != expected_cleanup_policy
                        or sorted(cleanup_tags, key=lambda item: item.get("Key", ""))
                        != expected_cleanup_tags
                        or cleanup_managed != []
                        or cleanup_customer != []
                        or cleanup_boundary is not None
                    ):
                        _fail("CLEANUP_PERMISSION_SET_READBACK_MISMATCH")
                    cleanup_assignments = paginate(
                        self._clients.sso_admin.list_account_assignments,
                        key="AccountAssignments",
                        request={
                            "InstanceArn": parameters["IdentityCenterInstanceArn"],
                            "AccountId": target_account,
                            "PermissionSetArn": cleanup_arn,
                        },
                    )
                    expected_cleanup_assignment = {
                        "AccountId": target_account,
                        "PermissionSetArn": cleanup_arn,
                        "PrincipalId": parameters["BootstrapPrincipalId"],
                        "PrincipalType": "USER",
                    }
                    provisioned_cleanup = paginate(
                        self._clients.sso_admin.list_permission_sets_provisioned_to_account,
                        key="PermissionSets",
                        request={
                            "InstanceArn": parameters["IdentityCenterInstanceArn"],
                            "AccountId": target_account,
                        },
                    )
                    if (
                        cleanup_assignments != [expected_cleanup_assignment]
                        or cleanup_arn not in provisioned_cleanup
                    ):
                        _fail("CLEANUP_ASSIGNMENT_READBACK_MISMATCH")
                    cleanup_projections.append(
                        {
                            "logical_id": logical_id,
                            "account_id": target_account,
                            "permission_set_arn_digest": contract.digest_value(cleanup_arn),
                            "policy_digest": contract.digest_value(cleanup_policy),
                            "tags_digest": contract.digest_value(expected_cleanup_tags),
                            "assigned": True,
                            "provisioned": True,
                        }
                    )
                cleanup_assignment_count = 2
                cleanup_permission_set_count = 2
                cleanup_authority_active = True
            else:
                permission_set_arns = paginate(
                    self._clients.sso_admin.list_permission_sets,
                    key="PermissionSets",
                    request={"InstanceArn": parameters["IdentityCenterInstanceArn"]},
                )
                forbidden_names = {
                    "ScanalyzeGug376RouteSeedCleanup",
                    "ScanalyzeGug376BrokerSeedCleanup",
                }
                for permission_arn in permission_set_arns:
                    if not isinstance(permission_arn, str):
                        _fail("CLEANUP_PERMISSION_SET_ABSENCE_INVALID")
                    description = _call(
                        self._clients.sso_admin.describe_permission_set,
                        code="CLEANUP_PERMISSION_SET_ABSENCE_INVALID",
                        InstanceArn=parameters["IdentityCenterInstanceArn"],
                        PermissionSetArn=permission_arn,
                    )
                    sso_calls += 1
                    item = description.get("PermissionSet")
                    if not isinstance(item, Mapping) or item.get("Name") in forbidden_names:
                        _fail("CLEANUP_PERMISSION_SET_ABSENCE_INVALID")
                cleanup_assignment_count = 0
                cleanup_permission_set_count = 0
                cleanup_authority_active = False
            cleanup_permission_sets_digest = contract.digest_value(
                cleanup_projections
            )

            expected_role = _resolve_bridge_role_contract(
                template_body=request["TemplateBody"], parameters=parameters
            )
            if cleanup_active:
                role_response = _call(
                    self._clients.iam.get_role,
                    code="MANAGEMENT_RECOVERY_ROLE_READBACK_FAILED",
                    RoleName="ScanalyzeGug376RouteBrokerRecovery",
                )
                iam_calls += 1
                role = role_response.get("Role")
                policies_response = _call(
                    self._clients.iam.list_role_policies,
                    code="MANAGEMENT_RECOVERY_ROLE_READBACK_FAILED",
                    RoleName="ScanalyzeGug376RouteBrokerRecovery",
                )
                iam_calls += 1
                attached_response = _call(
                    self._clients.iam.list_attached_role_policies,
                    code="MANAGEMENT_RECOVERY_ROLE_READBACK_FAILED",
                    RoleName="ScanalyzeGug376RouteBrokerRecovery",
                )
                iam_calls += 1
                tags_response = _call(
                    self._clients.iam.list_role_tags,
                    code="MANAGEMENT_RECOVERY_ROLE_READBACK_FAILED",
                    RoleName="ScanalyzeGug376RouteBrokerRecovery",
                )
                iam_calls += 1
                expected_inline = expected_role["Policies"][0]
                policy_response = _call(
                    self._clients.iam.get_role_policy,
                    code="MANAGEMENT_RECOVERY_ROLE_READBACK_FAILED",
                    RoleName="ScanalyzeGug376RouteBrokerRecovery",
                    PolicyName=expected_inline["PolicyName"],
                )
                iam_calls += 1
                expected_role_tags = sorted(
                    expected_role["Tags"], key=lambda item: item["Key"]
                )
                if (
                    not isinstance(role, Mapping)
                    or role.get("RoleName") != expected_role["RoleName"]
                    or role.get("Arn") != outputs.get("ManagementRecoveryRoleArn")
                    or role.get("Path") != expected_role["Path"]
                    or role.get("MaxSessionDuration")
                    != expected_role["MaxSessionDuration"]
                    or role.get("AssumeRolePolicyDocument")
                    != expected_role["AssumeRolePolicyDocument"]
                    or role.get("PermissionsBoundary") is not None
                    or policies_response.get("IsTruncated") is True
                    or policies_response.get("PolicyNames")
                    != [expected_inline["PolicyName"]]
                    or attached_response.get("IsTruncated") is True
                    or attached_response.get("AttachedPolicies") != []
                    or sorted(
                        tags_response.get("Tags", []), key=lambda item: item.get("Key", "")
                    )
                    != expected_role_tags
                    or policy_response.get("PolicyName")
                    != expected_inline["PolicyName"]
                    or policy_response.get("PolicyDocument")
                    != expected_inline["PolicyDocument"]
                ):
                    _fail("MANAGEMENT_RECOVERY_ROLE_READBACK_MISMATCH")
                role_projection = {
                    "arn": role["Arn"],
                    "trust_digest": contract.digest_value(
                        expected_role["AssumeRolePolicyDocument"]
                    ),
                    "policy_digest": contract.digest_value(
                        expected_inline["PolicyDocument"]
                    ),
                    "tags_digest": contract.digest_value(expected_role_tags),
                }
                management_recovery_role_present = True
            else:
                try:
                    _call(
                        self._clients.iam.get_role,
                        code="MANAGEMENT_RECOVERY_ROLE_ABSENCE_FAILED",
                        RoleName="ScanalyzeGug376RouteBrokerRecovery",
                    )
                except ConnectedArtifactBootstrapError as exc:
                    iam_calls += 1
                    if _aws_error_code(exc.__cause__ or exc) not in {
                        "NoSuchEntity",
                        "NoSuchEntityException",
                    }:
                        raise
                else:
                    _fail("MANAGEMENT_RECOVERY_ROLE_STILL_PRESENT")
                role_projection = None
                management_recovery_role_present = False
            management_recovery_role_digest = contract.digest_value(
                role_projection
            )
            if operation == "bridge-cleanup-retire":
                credential_window_expired = True
        receipt: dict[str, Any] = {
            "schema_version": 1,
            "record_type": STACK_READBACK_TYPE,
            "source_commit": intent["source_commit"],
            "operation": operation,
            "intent_digest": readback_intent_digest,
            "verifier": self._verifier(account, caller),
            "stack_status": expected_status,
            "stack_completed_at": _stamp(stack_completed),
            "template_digest": intent["template_digests"][expected_template],
            "resources": [
                {"logical_resource_id": item[0], "resource_type": item[1]}
                for item in sorted(expected)
            ],
            "outputs_digest": contract.digest_value(outputs),
            "sso_assignment_count": (
                0
                if operation in {"bridge-revoke", "bridge-cleanup-retire"}
                else 1
                if operation in {"bridge-create", "bridge-pin"} else None
            ),
            "permission_set_provisioned": (
                permission_set_provisioned
                if operation
                in {
                    "bridge-create",
                    "bridge-pin",
                    "bridge-revoke",
                    "bridge-cleanup-retire",
                }
                else None
            ),
            "permission_set_arn_digest": permission_set_arn_digest,
            "permission_set_policy_digest": permission_set_policy_digest,
            "permission_set_tags_digest": permission_set_tags_digest,
            "permission_set_metadata_exact": permission_set_metadata_exact,
            "managed_policy_count": managed_policy_count,
            "customer_managed_policy_count": customer_policy_count,
            "permissions_boundary_absent": permissions_boundary_absent,
            "signing_profile_version_digest": (
                contract.digest_value(parameters["SigningProfileVersion"])
                if operation
                in {
                    "bridge-create",
                    "bridge-pin",
                    "bridge-revoke",
                    "bridge-cleanup-retire",
                }
                else None
            ),
            "temporary_principal_authorized": (
                operation in {"bridge-create", "bridge-pin"}
                if operation
                in {
                    "bridge-create",
                    "bridge-pin",
                    "bridge-revoke",
                    "bridge-cleanup-retire",
                }
                else None
            ),
            "cleanup_assignment_count": cleanup_assignment_count,
            "cleanup_permission_set_count": cleanup_permission_set_count,
            "cleanup_permission_sets_digest": cleanup_permission_sets_digest,
            "management_recovery_role_present": management_recovery_role_present,
            "management_recovery_role_digest": management_recovery_role_digest,
            "cleanup_authority_active": cleanup_authority_active,
            "credential_window_expired": credential_window_expired,
            "read_at": _stamp(
                self._require_cleanup_retire_clock(retire, admission=False)
                if retire is not None
                else self._require_window(intent, read_only=True)
            ),
            "aws_calls": (
                cleanup_revalidation_calls
                + 3
                + stack_resource_calls
                + sso_calls
                + iam_calls
            ),
            "aws_mutations": 0,
            "production_authorized": False,
            "production_status": contract.PRODUCTION_STATUS,
        }
        receipt["readback_digest"] = contract.digest_value(receipt)
        contract.validate_stack_readback(
            receipt,
            bootstrap_intent=intent,
            operation=operation,
            bridge_pin=bridge_pin,
            foundation_readback=foundation_readback,
            cleanup_retire=retire,
            bridge_revoke_readback=bridge_revoke_readback,
            bootstrap_route_release=bootstrap_route_release,
            seed_intent=seed_intent,
            terminal_readbacks=terminal_readbacks,
        )
        return receipt

    def readback_foundation(
        self, *, bootstrap_intent: Mapping[str, Any],
        source_root: Path
    ) -> dict[str, Any]:
        """Verify every foundation resource property after exact stack readback."""

        if self._profile != contract.AUTHORITY_PROFILE:
            _fail("OPERATION_PROFILE_INVALID")
        intent = contract.validate_bootstrap_intent(bootstrap_intent)
        self._require_window(intent, read_only=True)
        self._reviewed_sources(source_root=source_root, bootstrap=intent)
        account, caller, _sts_request_id = self._identity()
        if any(
            client is None
            for client in (
                self._clients.kms,
                self._clients.s3,
                self._clients.signer,
                self._clients.lambda_client,
            )
        ):
            _fail("FOUNDATION_CLIENTS_MISSING")
        stacks = _call(
            self._clients.cloudformation.describe_stacks,
            code="DESCRIBE_STACK_FAILED",
            StackName=contract.FOUNDATION_STACK_NAME,
        )
        raw = stacks.get("Stacks")
        if not isinstance(raw, list) or len(raw) != 1 or raw[0].get("StackStatus") != "CREATE_COMPLETE":
            _fail("FOUNDATION_STACK_NOT_TERMINAL")
        template_response = _call(
            self._clients.cloudformation.get_template,
            code="FOUNDATION_TEMPLATE_READBACK_FAILED",
            StackName=contract.FOUNDATION_STACK_NAME,
            TemplateStage="Original",
        )
        template_body = template_response.get("TemplateBody")
        if (
            not isinstance(template_body, str)
            or contract.bytes_digest(template_body.encode("utf-8"))
            != intent["template_digests"]["foundation"]
        ):
            _fail("FOUNDATION_TEMPLATE_MISMATCH")
        resources, stack_resource_calls = self._list_stack_resources_exact(
            stack_name=contract.FOUNDATION_STACK_NAME,
            code="FOUNDATION_RESOURCE_READBACK_FAILED",
        )
        expected_resources = {
            ("ArtifactKey", "AWS::KMS::Key"),
            ("ArtifactKeyAlias", "AWS::KMS::Alias"),
            ("ArtifactBucket", "AWS::S3::Bucket"),
            ("ArtifactBucketPolicy", "AWS::S3::BucketPolicy"),
            ("SigningProfile", "AWS::Signer::SigningProfile"),
            ("CodeSigningConfig", "AWS::Lambda::CodeSigningConfig"),
        }
        observed_resources = {
            (item.get("LogicalResourceId"), item.get("ResourceType"))
            for item in resources or []
            if isinstance(item, Mapping)
        }
        if observed_resources != expected_resources or len(resources or []) != 6:
            _fail("FOUNDATION_RESOURCE_SET_MISMATCH")
        outputs = {
            item.get("OutputKey"): item.get("OutputValue")
            for item in raw[0].get("Outputs", [])
            if isinstance(item, Mapping)
        }
        required_outputs = {
            "ArtifactBucketName",
            "ArtifactBucketArn",
            "ArtifactKmsKeyArn",
            "ArtifactKmsAlias",
            "SigningProfileName",
            "SigningProfileVersionArn",
            "CodeSigningConfigArn",
            "CrossAccountAccessMode",
            "ProductionAuthorized",
        }
        names = intent["names"]
        if (
            set(outputs) != required_outputs
            or outputs.get("ArtifactBucketName") != names["artifact_bucket"]
            or outputs.get("ArtifactBucketArn")
            != f"arn:aws:s3:::{names['artifact_bucket']}"
            or outputs.get("ArtifactKmsAlias") != names["artifact_kms_alias"]
            or outputs.get("SigningProfileName") != names["signing_profile_name"]
            or outputs.get("CrossAccountAccessMode") != "false"
            or outputs.get("ProductionAuthorized") != "false"
        ):
            _fail("FOUNDATION_OUTPUT_MISMATCH")
        key_arn = outputs["ArtifactKmsKeyArn"]
        key = _call(
            self._clients.kms.describe_key,
            code="KMS_READBACK_FAILED",
            KeyId=key_arn,
        )
        metadata = key.get("KeyMetadata")
        rotation = _call(
            self._clients.kms.get_key_rotation_status,
            code="KMS_READBACK_FAILED",
            KeyId=key_arn,
        )
        key_tags = _call(
            self._clients.kms.list_resource_tags,
            code="KMS_READBACK_FAILED",
            KeyId=key_arn,
        )
        key_policy_response = _call(
            self._clients.kms.get_key_policy,
            code="KMS_READBACK_FAILED",
            KeyId=key_arn,
            PolicyName="default",
        )
        aliases = _call(
            self._clients.kms.list_aliases,
            code="KMS_READBACK_FAILED",
            KeyId=key_arn,
            Limit=100,
        )
        expected_tags = {
            "managed_by": "gug376-artifact-bootstrap",
            "service": "scanalyze-platform-authority",
            "work_package": "GUG-376",
            "source_commit": intent["source_commit"],
        }
        observed_key_tags = {
            item.get("TagKey"): item.get("TagValue")
            for item in key_tags.get("Tags", [])
            if isinstance(item, Mapping)
        }
        try:
            key_policy = json.loads(key_policy_response["Policy"])
        except (KeyError, TypeError, json.JSONDecodeError) as exc:
            raise ConnectedArtifactBootstrapError("KMS_POLICY_INVALID") from exc
        key_statements = {
            item.get("Sid"): item
            for item in key_policy.get("Statement", [])
            if isinstance(item, Mapping)
        }
        exact_aliases = [
            item
            for item in aliases.get("Aliases", [])
            if isinstance(item, Mapping)
            and item.get("AliasName") == names["artifact_kms_alias"]
        ]
        bucket_context = f"arn:aws:s3:::{names['artifact_bucket']}"
        if (
            not isinstance(metadata, Mapping)
            or metadata.get("Arn") != key_arn
            or metadata.get("AWSAccountId") != contract.AUTHORITY_ACCOUNT_ID
            or metadata.get("Enabled") is not True
            or metadata.get("KeyState") != "Enabled"
            or metadata.get("KeyUsage") != "ENCRYPT_DECRYPT"
            or metadata.get("KeySpec") != "SYMMETRIC_DEFAULT"
            or metadata.get("Origin") != "AWS_KMS"
            or metadata.get("MultiRegion") is not False
            or rotation.get("KeyRotationEnabled") is not True
            or observed_key_tags != expected_tags
            or set(key_statements)
            != {
                "PreserveAccountAdministration",
                "AllowOnlyTemporaryBootstrapRoleThroughExactS3",
                "AllowSignerServiceThroughExactBucket",
            }
            or key_statements[
                "AllowOnlyTemporaryBootstrapRoleThroughExactS3"
            ].get("Condition", {}).get("StringLike", {}).get(
                "kms:EncryptionContext:aws:s3:arn"
            )
            != bucket_context
            or key_statements["AllowSignerServiceThroughExactBucket"].get(
                "Condition", {}
            ).get("StringLike", {}).get("kms:EncryptionContext:aws:s3:arn")
            != bucket_context
            or aliases.get("Truncated") not in {False, None}
            or len(exact_aliases) != 1
            or exact_aliases[0].get("TargetKeyId") != metadata.get("KeyId")
        ):
            _fail("KMS_FOUNDATION_MISMATCH")
        bucket = names["artifact_bucket"]
        versioning = _call(
            self._clients.s3.get_bucket_versioning,
            code="S3_READBACK_FAILED",
            Bucket=bucket,
            ExpectedBucketOwner=contract.AUTHORITY_ACCOUNT_ID,
        )
        encryption = _call(
            self._clients.s3.get_bucket_encryption,
            code="S3_READBACK_FAILED",
            Bucket=bucket,
            ExpectedBucketOwner=contract.AUTHORITY_ACCOUNT_ID,
        )
        ownership = _call(
            self._clients.s3.get_bucket_ownership_controls,
            code="S3_READBACK_FAILED",
            Bucket=bucket,
            ExpectedBucketOwner=contract.AUTHORITY_ACCOUNT_ID,
        )
        public = _call(
            self._clients.s3.get_public_access_block,
            code="S3_READBACK_FAILED",
            Bucket=bucket,
            ExpectedBucketOwner=contract.AUTHORITY_ACCOUNT_ID,
        )
        bucket_tags = _call(
            self._clients.s3.get_bucket_tagging,
            code="S3_READBACK_FAILED",
            Bucket=bucket,
            ExpectedBucketOwner=contract.AUTHORITY_ACCOUNT_ID,
        )
        bucket_policy_response = _call(
            self._clients.s3.get_bucket_policy,
            code="S3_READBACK_FAILED",
            Bucket=bucket,
            ExpectedBucketOwner=contract.AUTHORITY_ACCOUNT_ID,
        )
        rules = encryption.get("ServerSideEncryptionConfiguration", {}).get("Rules", [])
        defaults = rules[0].get("ApplyServerSideEncryptionByDefault", {}) if len(rules) == 1 else {}
        observed_bucket_tags = {
            item.get("Key"): item.get("Value")
            for item in bucket_tags.get("TagSet", [])
            if isinstance(item, Mapping)
        }
        pab = public.get("PublicAccessBlockConfiguration")
        try:
            bucket_policy = json.loads(bucket_policy_response["Policy"])
        except (KeyError, TypeError, json.JSONDecodeError) as exc:
            raise ConnectedArtifactBootstrapError("S3_POLICY_INVALID") from exc
        bucket_statements = {
            item.get("Sid"): item
            for item in bucket_policy.get("Statement", [])
            if isinstance(item, Mapping)
        }
        if (
            versioning.get("Status") != "Enabled"
            or len(rules) != 1
            or rules[0].get("BucketKeyEnabled") is not True
            or defaults.get("SSEAlgorithm") != "aws:kms"
            or defaults.get("KMSMasterKeyID") != key_arn
            or ownership.get("OwnershipControls", {}).get("Rules")
            != [{"ObjectOwnership": "BucketOwnerEnforced"}]
            or not isinstance(pab, Mapping)
            or set(pab.values()) != {True}
            or set(pab) != {
                "BlockPublicAcls",
                "IgnorePublicAcls",
                "BlockPublicPolicy",
                "RestrictPublicBuckets",
            }
            or observed_bucket_tags != expected_tags
            or set(bucket_statements)
            != {
                "DenyInsecureTransport",
                "DenyUnencryptedObjectWrites",
                "DenyWrongKmsKey",
                "AllowSignerSourceAndDestination",
            }
            or any(
                bucket_statements[sid].get("NotPrincipal")
                != {"Service": "signer.amazonaws.com"}
                for sid in ("DenyUnencryptedObjectWrites", "DenyWrongKmsKey")
            )
        ):
            _fail("S3_FOUNDATION_MISMATCH")
        profile = _call(
            self._clients.signer.get_signing_profile,
            code="SIGNER_READBACK_FAILED",
            profileName=names["signing_profile_name"],
            profileOwner=contract.AUTHORITY_ACCOUNT_ID,
        )
        expected_profile_arn = (
            f"arn:aws:signer:{contract.REGION}:{contract.AUTHORITY_ACCOUNT_ID}:"
            f"/signing-profiles/{names['signing_profile_name']}"
        )
        profile_tags = _call(
            self._clients.signer.list_tags_for_resource,
            code="SIGNER_READBACK_FAILED",
            resourceArn=expected_profile_arn,
        )
        if (
            profile.get("profileName") != names["signing_profile_name"]
            or profile.get("arn") != expected_profile_arn
            or profile.get("profileVersionArn") != outputs["SigningProfileVersionArn"]
            or profile.get("platformId") != "AWSLambda-SHA384-ECDSA"
            or profile.get("status") != "Active"
            or profile.get("revocationRecord") is not None
            or profile_tags.get("tags") != expected_tags
        ):
            _fail("SIGNER_FOUNDATION_MISMATCH")
        csc = _call(
            self._clients.lambda_client.get_code_signing_config,
            code="CSC_READBACK_FAILED",
            CodeSigningConfigArn=outputs["CodeSigningConfigArn"],
        ).get("CodeSigningConfig")
        csc_tags = _call(
            self._clients.lambda_client.list_tags,
            code="CSC_READBACK_FAILED",
            Resource=outputs["CodeSigningConfigArn"],
        )
        if (
            not isinstance(csc, Mapping)
            or csc.get("CodeSigningConfigArn") != outputs["CodeSigningConfigArn"]
            or csc.get("AllowedPublishers")
            != {"SigningProfileVersionArns": [outputs["SigningProfileVersionArn"]]}
            or csc.get("CodeSigningPolicies")
            != {"UntrustedArtifactOnDeployment": "Enforce"}
            or csc_tags.get("Tags") != expected_tags
        ):
            _fail("CSC_FOUNDATION_MISMATCH")
        receipt: dict[str, Any] = {
            "schema_version": 1,
            "record_type": FOUNDATION_READBACK_TYPE,
            "source_commit": intent["source_commit"],
            "bootstrap_intent_digest": intent["intent_digest"],
            "verifier": self._verifier(account, caller),
            "artifact_bucket": bucket,
            "artifact_kms_key_arn": key_arn,
            "artifact_kms_alias": names["artifact_kms_alias"],
            "signing_profile_name": names["signing_profile_name"],
            "signing_profile_version_arn": outputs["SigningProfileVersionArn"],
            "code_signing_config_arn": outputs["CodeSigningConfigArn"],
            "source_marker": "AWS_STS_KMS_S3_SIGNER_LAMBDA_EXACT_READBACK",
            "read_at": _stamp(self._require_window(intent, read_only=True)),
            "aws_calls": 18 + stack_resource_calls,
            "aws_mutations": 0,
            "production_authorized": False,
            "production_status": contract.PRODUCTION_STATUS,
        }
        receipt["readback_digest"] = contract.digest_value(receipt)
        return receipt

    def publish_object_once(
        self,
        *,
        bootstrap_intent: Mapping[str, Any],
        source_root: Path,
        foundation_readback: Mapping[str, Any],
        object_intent: Mapping[str, Any],
        body: bytes,
        authorization: Mapping[str, Any],
    ) -> dict[str, Any]:
        if self._profile != contract.AUTHORITY_PROFILE or self._clients.s3 is None:
            _fail("OPERATION_PROFILE_INVALID")
        bootstrap = contract.validate_bootstrap_intent(bootstrap_intent)
        self._require_window(bootstrap, read_only=False)
        self._reviewed_sources(source_root=source_root, bootstrap=bootstrap)
        intent = contract.validate_object_intent(
            object_intent,
            bootstrap_intent=bootstrap,
            foundation_readback=foundation_readback,
        )
        contract.validate_mutation_authorization(
            authorization,
            bootstrap_intent=bootstrap,
            operation="publish-object",
            target_digest=intent["intent_digest"],
            now=self._clock(),
        )
        if (
            not isinstance(body, bytes)
            or len(body) != intent["request"]["ContentLength"]
            or contract.bytes_digest(body) != intent["object_sha256"]
            or base64.b64encode(sha256(body).digest()).decode("ascii")
            != intent["request"]["ChecksumSHA256"]
        ):
            _fail("OBJECT_BODY_MISMATCH")
        account, caller, _sts_request_id = self._identity()
        existing_versions, existing_deletes, absence = (
            self._list_exact_object_versions(
                bucket=intent["request"]["Bucket"],
                key=intent["request"]["Key"],
                code="OBJECT_PREFLIGHT_FAILED",
            )
        )
        if existing_versions or existing_deletes:
            _fail("OBJECT_KEY_NOT_ABSENT")
        claim_current = self._require_window(bootstrap, read_only=False)
        contract.validate_mutation_authorization(
            authorization,
            bootstrap_intent=bootstrap,
            operation="publish-object",
            target_digest=intent["intent_digest"],
            now=claim_current,
        )
        claimed_at = _stamp(claim_current)
        self._claims.reserve(
            operation="publish-object",
            digest=intent["effect_digest"],
            claimed_at=claimed_at,
            caller_arn=caller,
            request_digest=intent["request_digest"],
            authorization_digest=authorization["authorization_digest"],
            authorization_record=authorization,
            preflight_digest=absence["evidence_digest"],
            preflight_calls=absence["pages"],
            mutation_nonce=intent["mutation_nonce"],
            causal_claim_digest=intent["causal_claim_digest"],
        )
        response = _call(
            self._clients.s3.put_object,
            mutation=True,
            code="PUT_OBJECT_UNCERTAIN",
            Body=body,
            ExpectedBucketOwner=contract.AUTHORITY_ACCOUNT_ID,
            **intent["request"],
        )
        version = response.get("VersionId")
        if (
            not isinstance(version, str)
            or _VERSION.fullmatch(version) is None
            or version.casefold() == "null"
            or response.get("ServerSideEncryption") != "aws:kms"
            or response.get("SSEKMSKeyId") != intent["request"]["SSEKMSKeyId"]
            or response.get("ChecksumSHA256") != intent["request"]["ChecksumSHA256"]
        ):
            _fail("PUT_OBJECT_RESPONSE_INVALID", uncertain=True)
        receipt: dict[str, Any] = {
            "schema_version": 1,
            "record_type": OBJECT_DISPATCH_TYPE,
            "source_commit": bootstrap["source_commit"],
            "bootstrap_intent_digest": bootstrap["intent_digest"],
            "object_intent_digest": intent["intent_digest"],
            "effect_digest": intent["effect_digest"],
            "mutation_nonce": intent["mutation_nonce"],
            "causal_claim_digest": intent["causal_claim_digest"],
            "authorization_digest": authorization["authorization_digest"],
            "preflight_absence_digest": absence["evidence_digest"],
            "preflight_calls": absence["pages"],
            "verifier": self._verifier(account, caller),
            "bucket": intent["request"]["Bucket"],
            "key": intent["request"]["Key"],
            "version": version,
            "provider_request_id": _response_id(
                response, "PUT_OBJECT_RESPONSE_INVALID", service="s3"
            ),
            "recovery_evidence_type": "S3_PUT_RESPONSE",
            "recovery_evidence_digest": None,
            "dispatched_at": claimed_at,
            "aws_calls": absence["pages"] + 2,
            "aws_mutations": 1,
            "retry_permitted": False,
            "production_authorized": False,
            "production_status": contract.PRODUCTION_STATUS,
        }
        receipt["receipt_digest"] = contract.digest_value(receipt)
        return receipt

    def readback_object(
        self,
        *,
        bootstrap_intent: Mapping[str, Any],
        source_root: Path,
        foundation_readback: Mapping[str, Any],
        object_intent: Mapping[str, Any],
        dispatch_receipt: Mapping[str, Any],
    ) -> dict[str, Any]:
        if self._profile != contract.AUTHORITY_PROFILE or self._clients.s3 is None:
            _fail("OPERATION_PROFILE_INVALID")
        bootstrap = contract.validate_bootstrap_intent(bootstrap_intent)
        self._require_window(bootstrap, read_only=True)
        self._reviewed_sources(source_root=source_root, bootstrap=bootstrap)
        intent = contract.validate_object_intent(
            object_intent,
            bootstrap_intent=bootstrap,
            foundation_readback=foundation_readback,
        )
        dispatch = self._validate_object_dispatch_receipt(
            dispatch_receipt,
            bootstrap=bootstrap,
            intent=intent,
        )
        claim = self._claims.read_exact(
            operation="publish-object", digest=intent["effect_digest"]
        )
        if (
            claim.get("request_digest") != intent["request_digest"]
            or claim.get("authorization_digest")
            != dispatch["authorization_digest"]
            or claim.get("caller_arn")
            != dispatch["verifier"]["caller_arn"]
            or claim.get("preflight_digest")
            != dispatch["preflight_absence_digest"]
            or claim.get("preflight_calls") != dispatch["preflight_calls"]
            or claim.get("mutation_nonce") != intent["mutation_nonce"]
            or claim.get("causal_claim_digest")
            != intent["causal_claim_digest"]
        ):
            _fail("OBJECT_DISPATCH_CLAIM_MISMATCH")
        self._validate_original_claim_authorization(
            bootstrap=bootstrap,
            operation="publish-object",
            target_digest=intent["intent_digest"],
            claim=claim,
            mutation_authorization=True,
        )
        account, caller, _sts_request_id = self._identity()
        request = intent["request"]
        bucket = request["Bucket"]
        key = request["Key"]
        version = dispatch["version"]
        versioning = _call(
            self._clients.s3.get_bucket_versioning,
            code="OBJECT_READBACK_FAILED",
            Bucket=bucket,
            ExpectedBucketOwner=contract.AUTHORITY_ACCOUNT_ID,
        )
        head = _call(
            self._clients.s3.head_object,
            code="OBJECT_READBACK_FAILED",
            Bucket=bucket,
            Key=key,
            VersionId=version,
            ChecksumMode="ENABLED",
            ExpectedBucketOwner=contract.AUTHORITY_ACCOUNT_ID,
        )
        attributes = _call(
            self._clients.s3.get_object_attributes,
            code="OBJECT_READBACK_FAILED",
            Bucket=bucket,
            Key=key,
            VersionId=version,
            ObjectAttributes=["Checksum", "ObjectSize", "StorageClass"],
            ExpectedBucketOwner=contract.AUTHORITY_ACCOUNT_ID,
        )
        tagging = _call(
            self._clients.s3.get_object_tagging,
            code="OBJECT_READBACK_FAILED",
            Bucket=bucket,
            Key=key,
            VersionId=version,
            ExpectedBucketOwner=contract.AUTHORITY_ACCOUNT_ID,
        )
        downloaded = _call(
            self._clients.s3.get_object,
            code="OBJECT_READBACK_FAILED",
            Bucket=bucket,
            Key=key,
            VersionId=version,
            ChecksumMode="ENABLED",
            ExpectedBucketOwner=contract.AUTHORITY_ACCOUNT_ID,
        )
        payload = _read_bounded_stream(
            downloaded.get("Body"), code="OBJECT_BODY_READBACK_INVALID"
        )
        observed_tags = {
            item.get("Key"): item.get("Value")
            for item in tagging.get("TagSet", [])
            if isinstance(item, Mapping)
        }
        expected_tags = {
            "managed_by": "gug376-artifact-bootstrap",
            "service": "scanalyze-platform-authority",
            "work_package": "GUG-376",
            "source_commit": bootstrap["source_commit"],
            "mutation_nonce": intent["mutation_nonce"],
            "effect_digest": intent["effect_digest"],
            "causal_claim_digest": intent["causal_claim_digest"],
        }
        checksum = request["ChecksumSHA256"]
        if (
            versioning.get("Status") != "Enabled"
            or len(payload) != request["ContentLength"]
            or contract.bytes_digest(payload) != intent["object_sha256"]
            or head.get("VersionId") != version
            or head.get("ContentLength") != len(payload)
            or head.get("ContentType") != request["ContentType"]
            or head.get("ServerSideEncryption") != "aws:kms"
            or head.get("SSEKMSKeyId") != request["SSEKMSKeyId"]
            or head.get("BucketKeyEnabled") is not True
            or head.get("Metadata") != request["Metadata"]
            or head.get("ChecksumSHA256") != checksum
            or head.get("ChecksumType") != "FULL_OBJECT"
            or attributes.get("VersionId") != version
            or attributes.get("ObjectSize") != len(payload)
            or attributes.get("Checksum", {}).get("ChecksumSHA256") != checksum
            or attributes.get("Checksum", {}).get("ChecksumType") != "FULL_OBJECT"
            or downloaded.get("VersionId") != version
            or downloaded.get("ServerSideEncryption") != "aws:kms"
            or downloaded.get("SSEKMSKeyId") != request["SSEKMSKeyId"]
            or downloaded.get("Metadata") != request["Metadata"]
            or downloaded.get("ChecksumSHA256") != checksum
            or downloaded.get("ChecksumType") != "FULL_OBJECT"
            or observed_tags != expected_tags
        ):
            _fail("OBJECT_READBACK_MISMATCH")
        receipt: dict[str, Any] = {
            "schema_version": 1,
            "record_type": contract.OBJECT_RECEIPT_TYPE,
            "source_commit": bootstrap["source_commit"],
            "bootstrap_intent_digest": bootstrap["intent_digest"],
            "foundation_readback_digest": intent["foundation_readback_digest"],
            "object_intent_digest": intent["intent_digest"],
            "dispatch_receipt_digest": dispatch["receipt_digest"],
            "effect_digest": intent["effect_digest"],
            "mutation_nonce": intent["mutation_nonce"],
            "causal_claim_digest": intent["causal_claim_digest"],
            "verifier": self._verifier(account, caller),
            "bucket": bucket,
            "key": key,
            "version": version,
            "object_sha256": intent["object_sha256"],
            "checksum_sha256": checksum,
            "content_length": len(payload),
            "content_type": request["ContentType"],
            "sse_algorithm": "aws:kms",
            "sse_kms_key_arn": request["SSEKMSKeyId"],
            "bucket_key_enabled": True,
            "metadata": request["Metadata"],
            "tags": expected_tags,
            "source_marker": "AWS_STS_S3_VERSIONED_SSE_KMS_OBJECT_READBACK",
            "read_at": _stamp(
                self._require_window(bootstrap, read_only=True)
            ),
            "aws_calls": 6,
            "aws_mutations": 0,
            "production_authorized": False,
            "production_status": contract.PRODUCTION_STATUS,
        }
        receipt["receipt_digest"] = contract.digest_value(receipt)
        contract.validate_object_receipt(
            receipt,
            bootstrap_intent=bootstrap,
            foundation_readback=foundation_readback,
        )
        return receipt

    def recover_object_publish(
        self,
        *,
        bootstrap_intent: Mapping[str, Any],
        source_root: Path,
        foundation_readback: Mapping[str, Any],
        object_intent: Mapping[str, Any],
    ) -> dict[str, Any]:
        """Recover one uncertain immutable PutObject without another mutation."""

        if self._profile != contract.AUTHORITY_PROFILE or self._clients.s3 is None:
            _fail("OPERATION_PROFILE_INVALID")
        bootstrap = contract.validate_bootstrap_intent(bootstrap_intent)
        self._require_window(bootstrap, read_only=True)
        self._reviewed_sources(source_root=source_root, bootstrap=bootstrap)
        intent = contract.validate_object_intent(
            object_intent,
            bootstrap_intent=bootstrap,
            foundation_readback=foundation_readback,
        )
        claim = self._claims.read_exact(
            operation="publish-object",
            digest=intent["effect_digest"],
        )
        if (
            claim.get("request_digest") != intent["request_digest"]
            or claim.get("mutation_nonce") != intent["mutation_nonce"]
            or claim.get("causal_claim_digest")
            != intent["causal_claim_digest"]
            or not isinstance(claim.get("preflight_digest"), str)
            or type(claim.get("preflight_calls")) is not int
            or not isinstance(claim.get("caller_arn"), str)
            or not isinstance(claim.get("authorization_digest"), str)
        ):
            _fail("OBJECT_RECOVERY_CLAIM_MISMATCH")
        self._validate_original_claim_authorization(
            bootstrap=bootstrap,
            operation="publish-object",
            target_digest=intent["intent_digest"],
            claim=claim,
            mutation_authorization=True,
        )
        account, _caller, _sts_request_id = self._identity()
        versions, deletes, observation = self._list_exact_object_versions(
            bucket=intent["request"]["Bucket"],
            key=intent["request"]["Key"],
            code="OBJECT_RECOVERY_FAILED",
        )
        calls = 1 + observation["pages"]
        if len(versions) != 1 or deletes:
            _fail("OBJECT_RECOVERY_AMBIGUOUS")
        item = versions[0]
        version = item.get("VersionId")
        modified = item.get("LastModified")
        claimed = self._parse_claim_time(
            claim["claimed_at"], code="OBJECT_RECOVERY_CLAIM_MISMATCH"
        )
        window_end = self._parse_claim_time(
            bootstrap["access_not_after"], code="WINDOW_INVALID"
        )
        if (
            not isinstance(version, str)
            or _VERSION.fullmatch(version) is None
            or not isinstance(modified, datetime)
            or modified.tzinfo is None
            or modified.utcoffset() is None
            or not claimed
            <= modified.astimezone(timezone.utc).replace(microsecond=0)
            < window_end
            or item.get("IsLatest") is not True
            or item.get("Size") != intent["request"]["ContentLength"]
            or not isinstance(item.get("ETag"), str)
            or not item["ETag"]
            or not isinstance(item.get("StorageClass"), str)
        ):
            _fail("OBJECT_RECOVERY_AMBIGUOUS")
        recovery_evidence: dict[str, Any] = {
            "evidence_type": "S3_DATA_PLANE_CAUSAL_RECOVERY",
            "claim_digest": claim["claim_digest"],
            "effect_digest": intent["effect_digest"],
            "causal_claim_digest": intent["causal_claim_digest"],
            "preflight_absence_digest": claim["preflight_digest"],
            "observation_digest": observation["evidence_digest"],
            "version": version,
            "last_modified": _stamp(modified),
            "size": item["Size"],
            "etag": item["ETag"],
            "storage_class": item["StorageClass"],
        }
        recovery_evidence_digest = contract.digest_value(recovery_evidence)
        dispatch: dict[str, Any] = {
            "schema_version": 1,
            "record_type": OBJECT_DISPATCH_TYPE,
            "source_commit": bootstrap["source_commit"],
            "bootstrap_intent_digest": bootstrap["intent_digest"],
            "object_intent_digest": intent["intent_digest"],
            "effect_digest": intent["effect_digest"],
            "mutation_nonce": intent["mutation_nonce"],
            "causal_claim_digest": intent["causal_claim_digest"],
            "authorization_digest": claim["authorization_digest"],
            "preflight_absence_digest": claim["preflight_digest"],
            "preflight_calls": claim["preflight_calls"],
            "verifier": self._verifier(account, claim["caller_arn"]),
            "bucket": intent["request"]["Bucket"],
            "key": intent["request"]["Key"],
            "version": version,
            "provider_request_id": None,
            "recovery_evidence_type": "S3_DATA_PLANE_CAUSAL_RECOVERY",
            "recovery_evidence_digest": recovery_evidence_digest,
            "dispatched_at": _stamp(modified),
            "aws_calls": claim["preflight_calls"] + 2,
            "aws_mutations": 1,
            "retry_permitted": False,
            "production_authorized": False,
            "production_status": contract.PRODUCTION_STATUS,
        }
        dispatch["receipt_digest"] = contract.digest_value(dispatch)
        readback = self.readback_object(
            bootstrap_intent=bootstrap,
            source_root=source_root,
            foundation_readback=foundation_readback,
            object_intent=intent,
            dispatch_receipt=dispatch,
        )
        return {
            "status": "RECOVERED_AND_ATTESTED",
            "dispatch_receipt": dispatch,
            "object_readback": readback,
            "aws_calls": calls + readback["aws_calls"],
            "aws_mutations": 0,
            "retry_permitted": False,
            "production_authorized": False,
            "production_status": contract.PRODUCTION_STATUS,
        }

    def start_signing_job_once(
        self,
        *,
        bootstrap_intent: Mapping[str, Any],
        source_root: Path,
        foundation_readback: Mapping[str, Any],
        bridge_pin: Mapping[str, Any],
        bridge_pin_readback: Mapping[str, Any],
        unsigned_receipt: Mapping[str, Any],
        signing_intent: Mapping[str, Any],
        authorization: Mapping[str, Any],
    ) -> dict[str, Any]:
        if self._profile != contract.AUTHORITY_PROFILE or self._clients.signer is None:
            _fail("OPERATION_PROFILE_INVALID")
        bootstrap = contract.validate_bootstrap_intent(bootstrap_intent)
        self._require_window(bootstrap, read_only=False)
        self._reviewed_sources(source_root=source_root, bootstrap=bootstrap)
        intent = contract.validate_signing_intent(
            signing_intent,
            bootstrap_intent=bootstrap,
            foundation_readback=foundation_readback,
            bridge_pin=bridge_pin,
            bridge_pin_readback=bridge_pin_readback,
            unsigned_receipt=unsigned_receipt,
        )
        contract.validate_mutation_authorization(
            authorization,
            bootstrap_intent=bootstrap,
            operation="start-signing-job",
            target_digest=intent["intent_digest"],
            now=self._clock(),
        )
        account, caller, _sts_request_id = self._identity()
        profile = _call(
            self._clients.signer.get_signing_profile,
            code="SIGNING_PROFILE_PREFLIGHT_FAILED",
            profileName=intent["request"]["profileName"],
            profileOwner=contract.AUTHORITY_ACCOUNT_ID,
        )
        if (
            profile.get("status") != "Active"
            or profile.get("revocationRecord") is not None
            or profile.get("profileVersionArn")
            != intent["signing_profile_version_arn"]
        ):
            _fail("SIGNING_PROFILE_VERSION_DRIFT")
        claim_current = self._require_window(bootstrap, read_only=False)
        contract.validate_mutation_authorization(
            authorization,
            bootstrap_intent=bootstrap,
            operation="start-signing-job",
            target_digest=intent["intent_digest"],
            now=claim_current,
        )
        claimed_at = _stamp(claim_current)
        self._claims.reserve(
            operation="start-signing-job",
            digest=intent["intent_digest"],
            claimed_at=claimed_at,
            caller_arn=caller,
            request_digest=intent["request_digest"],
            authorization_digest=authorization["authorization_digest"],
            authorization_record=authorization,
            request_token=intent["request"]["clientRequestToken"],
        )
        response = _call(
            self._clients.signer.start_signing_job,
            mutation=True,
            code="START_SIGNING_JOB_UNCERTAIN",
            **intent["request"],
        )
        job_id = response.get("jobId")
        if not isinstance(job_id, str) or _JOB.fullmatch(job_id) is None:
            _fail("START_SIGNING_JOB_RESPONSE_INVALID", uncertain=True)
        receipt: dict[str, Any] = {
            "schema_version": 1,
            "record_type": SIGNING_DISPATCH_TYPE,
            "source_commit": bootstrap["source_commit"],
            "bootstrap_intent_digest": bootstrap["intent_digest"],
            "signing_intent_digest": intent["intent_digest"],
            "authorization_digest": authorization["authorization_digest"],
            "verifier": self._verifier(account, caller),
            "job_id": job_id,
            "job_arn": f"arn:aws:signer:us-east-1:{account}:/signing-jobs/{job_id}",
            "request_id": _response_id(response, "START_SIGNING_JOB_RESPONSE_INVALID"),
            "dispatched_at": claimed_at,
            "aws_calls": 3,
            "aws_mutations": 1,
            "retry_permitted": False,
            "production_authorized": False,
            "production_status": contract.PRODUCTION_STATUS,
        }
        receipt["receipt_digest"] = contract.digest_value(receipt)
        return receipt

    def readback_signing_job(
        self,
        *,
        bootstrap_intent: Mapping[str, Any],
        source_root: Path,
        foundation_readback: Mapping[str, Any],
        bridge_pin: Mapping[str, Any],
        bridge_pin_readback: Mapping[str, Any],
        unsigned_receipt: Mapping[str, Any],
        signing_intent: Mapping[str, Any],
        dispatch_receipt: Mapping[str, Any],
    ) -> dict[str, Any]:
        """One terminal observation only; this method never polls."""

        if (
            self._profile != contract.AUTHORITY_PROFILE
            or self._clients.signer is None
            or self._clients.s3 is None
        ):
            _fail("OPERATION_PROFILE_INVALID")
        bootstrap = contract.validate_bootstrap_intent(bootstrap_intent)
        self._require_window(bootstrap, read_only=True)
        self._reviewed_sources(source_root=source_root, bootstrap=bootstrap)
        intent = contract.validate_signing_intent(
            signing_intent,
            bootstrap_intent=bootstrap,
            foundation_readback=foundation_readback,
            bridge_pin=bridge_pin,
            bridge_pin_readback=bridge_pin_readback,
            unsigned_receipt=unsigned_receipt,
        )
        dispatch = self._validate_signing_dispatch_receipt(
            dispatch_receipt,
            bootstrap=bootstrap,
            intent=intent,
        )
        claim = self._claims.read_exact(
            operation="start-signing-job", digest=intent["intent_digest"]
        )
        if (
            claim.get("request_digest") != intent["request_digest"]
            or claim.get("authorization_digest")
            != dispatch["authorization_digest"]
            or claim.get("caller_arn")
            != dispatch["verifier"]["caller_arn"]
            or claim.get("request_token")
            != intent["request"]["clientRequestToken"]
        ):
            _fail("SIGNING_DISPATCH_CLAIM_MISMATCH")
        self._validate_original_claim_authorization(
            bootstrap=bootstrap,
            operation="start-signing-job",
            target_digest=intent["intent_digest"],
            claim=claim,
            mutation_authorization=True,
        )
        job_id = dispatch["job_id"]
        account, caller, _sts_request_id = self._identity()
        job = _call(
            self._clients.signer.describe_signing_job,
            code="SIGNING_JOB_READBACK_FAILED",
            jobId=job_id,
        )
        if job.get("status") != "Succeeded":
            _fail("SIGNING_JOB_NOT_TERMINAL")
        profile = _call(
            self._clients.signer.get_signing_profile,
            code="SIGNING_PROFILE_TERMINAL_READBACK_FAILED",
            profileName=intent["request"]["profileName"],
            profileOwner=contract.AUTHORITY_ACCOUNT_ID,
        )
        expected_profile_arn = (
            f"arn:aws:signer:{contract.REGION}:{contract.AUTHORITY_ACCOUNT_ID}:"
            f"/signing-profiles/{intent['request']['profileName']}"
        )
        profile_tags = _call(
            self._clients.signer.list_tags_for_resource,
            code="SIGNING_PROFILE_TERMINAL_READBACK_FAILED",
            resourceArn=expected_profile_arn,
        )
        expected_tags = {
            "managed_by": "cloudformation",
            "service": "scanalyze-platform-authority",
            "work_package": "GUG-376",
            "source_commit": bootstrap["source_commit"],
        }
        if (
            profile.get("profileName") != intent["request"]["profileName"]
            or profile.get("arn") != expected_profile_arn
            or profile.get("profileVersionArn")
            != intent["signing_profile_version_arn"]
            or profile.get("platformId") != "AWSLambda-SHA384-ECDSA"
            or profile.get("status") != "Active"
            or profile.get("revocationRecord") is not None
            or profile_tags.get("tags") != expected_tags
        ):
            _fail("SIGNING_PROFILE_TERMINAL_DRIFT")
        source = job.get("source", {}).get("s3")
        signed = job.get("signedObject", {}).get("s3")
        expected_source = intent["request"]["source"]["s3"]
        expected_destination = intent["request"]["destination"]["s3"]
        if (
            source != expected_source
            or not isinstance(signed, Mapping)
            or signed.get("bucketName") != expected_destination["bucketName"]
            or not str(signed.get("key", "")).startswith(expected_destination["prefix"])
            or job.get("profileName") != intent["request"]["profileName"]
            or job.get("profileVersion")
            != intent["signing_profile_version_arn"].rsplit("/", 1)[-1]
            or job.get("jobOwner") != contract.AUTHORITY_ACCOUNT_ID
            or job.get("jobInvoker") != contract.AUTHORITY_ACCOUNT_ID
            or job.get("platformId") != "AWSLambda-SHA384-ECDSA"
            or job.get("revocationRecord") is not None
        ):
            _fail("SIGNING_JOB_READBACK_MISMATCH")
        versions = _call(
            self._clients.s3.list_object_versions,
            code="SIGNED_OBJECT_READBACK_FAILED",
            Bucket=signed["bucketName"],
            Prefix=signed["key"],
            ExpectedBucketOwner=contract.AUTHORITY_ACCOUNT_ID,
        )
        exact = [
            item
            for item in versions.get("Versions", [])
            if isinstance(item, Mapping) and item.get("Key") == signed["key"]
        ]
        deletes = [
            item
            for item in versions.get("DeleteMarkers", [])
            if isinstance(item, Mapping) and item.get("Key") == signed["key"]
        ]
        if versions.get("IsTruncated") is not False or len(exact) != 1 or deletes:
            _fail("SIGNED_OBJECT_VERSION_NOT_UNIQUE")
        version = exact[0].get("VersionId")
        if not isinstance(version, str) or _VERSION.fullmatch(version) is None:
            _fail("SIGNED_OBJECT_VERSION_INVALID")
        head = _call(
            self._clients.s3.head_object,
            code="SIGNED_OBJECT_READBACK_FAILED",
            Bucket=signed["bucketName"],
            Key=signed["key"],
            VersionId=version,
            ChecksumMode="ENABLED",
            ExpectedBucketOwner=contract.AUTHORITY_ACCOUNT_ID,
        )
        downloaded = _call(
            self._clients.s3.get_object,
            code="SIGNED_OBJECT_READBACK_FAILED",
            Bucket=signed["bucketName"],
            Key=signed["key"],
            VersionId=version,
            ChecksumMode="ENABLED",
            ExpectedBucketOwner=contract.AUTHORITY_ACCOUNT_ID,
        )
        payload = _read_bounded_stream(
            downloaded.get("Body"), code="SIGNED_OBJECT_BODY_INVALID"
        )
        kms_key_arn = head.get("SSEKMSKeyId")
        checksum = base64.b64encode(sha256(payload).digest()).decode("ascii")
        head_checksum = head.get("ChecksumSHA256")
        downloaded_checksum = downloaded.get("ChecksumSHA256")
        if (
            not payload
            or head.get("VersionId") != version
            or head.get("ContentLength") != len(payload)
            or head.get("ServerSideEncryption") != "aws:kms"
            or not isinstance(kms_key_arn, str)
            or kms_key_arn != intent["sse_kms_key_arn"]
            or kms_key_arn != downloaded.get("SSEKMSKeyId")
            or head.get("BucketKeyEnabled") is not True
            or (
                head_checksum is not None
                and (
                    head_checksum != checksum
                    or head.get("ChecksumType") != "FULL_OBJECT"
                )
            )
            or downloaded.get("VersionId") != version
            or downloaded.get("ServerSideEncryption") != "aws:kms"
            or (
                downloaded_checksum is not None
                and (
                    downloaded_checksum != checksum
                    or downloaded.get("ChecksumType") != "FULL_OBJECT"
                )
            )
        ):
            _fail("SIGNED_OBJECT_ENCRYPTION_MISMATCH")
        receipt: dict[str, Any] = {
            "schema_version": 1,
            "record_type": SIGNING_READBACK_TYPE,
            "source_commit": bootstrap["source_commit"],
            "bootstrap_intent_digest": bootstrap["intent_digest"],
            "signing_intent_digest": intent["intent_digest"],
            "dispatch_receipt_digest": dispatch["receipt_digest"],
            "verifier": self._verifier(account, caller),
            "job_id": job_id,
            "status": "Succeeded",
            "profile_name": job["profileName"],
            "profile_version": job.get("profileVersion"),
            "profile_version_arn": intent["signing_profile_version_arn"],
            "profile_arn": expected_profile_arn,
            "profile_tags": expected_tags,
            "signed_artifact": {
                "bucket": signed["bucketName"],
                "key": signed["key"],
                "version": version,
                "sha256": contract.bytes_digest(payload),
                "checksum_sha256": checksum,
                "bytes": len(payload),
                "sse_algorithm": "aws:kms",
                "sse_kms_key_arn": kms_key_arn,
                "bucket_key_enabled": True,
            },
            "source_marker": "AWS_STS_SIGNER_AND_VERSIONED_SSE_KMS_OBJECT_READBACK",
            "read_at": _stamp(
                self._require_window(bootstrap, read_only=True)
            ),
            "aws_calls": 7,
            "aws_mutations": 0,
            "production_authorized": False,
            "production_status": contract.PRODUCTION_STATUS,
        }
        receipt["readback_digest"] = contract.digest_value(receipt)
        return receipt

    def recover_signing_job(
        self,
        *,
        bootstrap_intent: Mapping[str, Any],
        source_root: Path,
        foundation_readback: Mapping[str, Any],
        bridge_pin: Mapping[str, Any],
        bridge_pin_readback: Mapping[str, Any],
        unsigned_receipt: Mapping[str, Any],
        signing_intent: Mapping[str, Any],
    ) -> dict[str, Any]:
        """Recover an uncertain StartSigningJob from exact CloudTrail evidence."""

        if (
            self._profile != contract.AUTHORITY_PROFILE
            or self._clients.cloudtrail is None
            or self._clients.signer is None
            or self._clients.s3 is None
        ):
            _fail("OPERATION_PROFILE_INVALID")
        bootstrap = contract.validate_bootstrap_intent(bootstrap_intent)
        self._require_window(bootstrap, read_only=True)
        self._reviewed_sources(source_root=source_root, bootstrap=bootstrap)
        intent = contract.validate_signing_intent(
            signing_intent,
            bootstrap_intent=bootstrap,
            foundation_readback=foundation_readback,
            bridge_pin=bridge_pin,
            bridge_pin_readback=bridge_pin_readback,
            unsigned_receipt=unsigned_receipt,
        )
        claim = self._claims.read_exact(
            operation="start-signing-job",
            digest=intent["intent_digest"],
        )
        if (
            claim.get("request_digest") != intent["request_digest"]
            or claim.get("request_token")
            != intent["request"]["clientRequestToken"]
            or not isinstance(claim.get("caller_arn"), str)
            or not isinstance(claim.get("authorization_digest"), str)
        ):
            _fail("SIGNING_RECOVERY_CLAIM_MISMATCH")
        self._validate_original_claim_authorization(
            bootstrap=bootstrap,
            operation="start-signing-job",
            target_digest=intent["intent_digest"],
            claim=claim,
            mutation_authorization=True,
        )
        account, _caller, _sts_request_id = self._identity()
        start = datetime.fromisoformat(
            bootstrap["access_not_before"][:-1] + "+00:00"
        )
        window_end = datetime.fromisoformat(
            bootstrap["access_not_after"][:-1] + "+00:00"
        )
        end = min(
            self._clock().astimezone(timezone.utc).replace(microsecond=0),
            window_end,
        )
        token: str | None = None
        seen_tokens: set[str] = set()
        matches: dict[str, dict[str, Any]] = {}
        calls = 1
        for _page in range(10):
            request: dict[str, Any] = {
                "LookupAttributes": [
                    {"AttributeKey": "EventName", "AttributeValue": "StartSigningJob"}
                ],
                "StartTime": start,
                "EndTime": end,
                "MaxResults": 50,
            }
            if token is not None:
                request["NextToken"] = token
            response = _call(
                self._clients.cloudtrail.lookup_events,
                code="SIGNING_RECOVERY_FAILED",
                **request,
            )
            calls += 1
            events = response.get("Events")
            if not isinstance(events, list):
                _fail("SIGNING_RECOVERY_FAILED")
            for event in events:
                if not isinstance(event, Mapping):
                    _fail("SIGNING_RECOVERY_FAILED")
                try:
                    payload = json.loads(event["CloudTrailEvent"])
                except (KeyError, TypeError, json.JSONDecodeError) as exc:
                    raise ConnectedArtifactBootstrapError(
                        "SIGNING_RECOVERY_EVENT_INVALID"
                    ) from exc
                request_parameters = payload.get("requestParameters")
                response_elements = payload.get("responseElements")
                identity = payload.get("userIdentity")
                job_id = (
                    response_elements.get("jobId")
                    if isinstance(response_elements, Mapping)
                    else None
                )
                if (
                    payload.get("eventSource") == "signer.amazonaws.com"
                    and payload.get("eventName") == "StartSigningJob"
                    and payload.get("awsRegion") == contract.REGION
                    and payload.get("recipientAccountId") == account
                    and isinstance(identity, Mapping)
                    and identity.get("arn") == claim["caller_arn"]
                    and request_parameters == intent["request"]
                    and isinstance(job_id, str)
                    and _JOB.fullmatch(job_id) is not None
                    and payload.get("errorCode") is None
                    and payload.get("errorMessage") is None
                ):
                    event_id = payload.get("eventID")
                    event_request_id = payload.get("requestID")
                    event_time = self._parse_claim_time(
                        payload.get("eventTime"),
                        code="SIGNING_RECOVERY_EVENT_INVALID",
                    )
                    claimed = self._parse_claim_time(
                        claim["claimed_at"],
                        code="SIGNING_RECOVERY_CLAIM_MISMATCH",
                    )
                    if (
                        isinstance(event_id, str)
                        and _REQUEST_ID.fullmatch(event_id) is not None
                        and isinstance(event_request_id, str)
                        and _REQUEST_ID.fullmatch(event_request_id) is not None
                        and claimed <= event_time <= end
                        and event_time < window_end
                    ):
                        matches[event_id] = {
                            "job_id": job_id,
                            "request_id": event_request_id,
                            "event_time": _stamp(event_time),
                        }
            next_token = response.get("NextToken")
            if next_token is None:
                _response_id(response, "SIGNING_RECOVERY_FAILED")
                break
            if (
                not isinstance(next_token, str)
                or not next_token
                or next_token in seen_tokens
            ):
                _fail("SIGNING_RECOVERY_PAGINATION_INVALID")
            seen_tokens.add(next_token)
            token = next_token
        else:
            _fail("SIGNING_RECOVERY_PAGE_LIMIT")
        if len(matches) != 1:
            _fail("SIGNING_RECOVERY_AMBIGUOUS")
        mutation = next(iter(matches.values()))
        job_id = mutation["job_id"]
        dispatch: dict[str, Any] = {
            "schema_version": 1,
            "record_type": SIGNING_DISPATCH_TYPE,
            "source_commit": bootstrap["source_commit"],
            "bootstrap_intent_digest": bootstrap["intent_digest"],
            "signing_intent_digest": intent["intent_digest"],
            "authorization_digest": claim["authorization_digest"],
            "verifier": self._verifier(account, claim["caller_arn"]),
            "job_id": job_id,
            "job_arn": f"arn:aws:signer:us-east-1:{account}:/signing-jobs/{job_id}",
            "request_id": mutation["request_id"],
            "dispatched_at": mutation["event_time"],
            "aws_calls": 3,
            "aws_mutations": 1,
            "retry_permitted": False,
            "production_authorized": False,
            "production_status": contract.PRODUCTION_STATUS,
        }
        dispatch["receipt_digest"] = contract.digest_value(dispatch)
        readback = self.readback_signing_job(
            bootstrap_intent=bootstrap,
            source_root=source_root,
            foundation_readback=foundation_readback,
            bridge_pin=bridge_pin,
            bridge_pin_readback=bridge_pin_readback,
            unsigned_receipt=unsigned_receipt,
            signing_intent=intent,
            dispatch_receipt=dispatch,
        )
        return {
            "status": "RECOVERED_AND_ATTESTED",
            "dispatch_receipt": dispatch,
            "signing_readback": readback,
            "aws_calls": calls + readback["aws_calls"],
            "aws_mutations": 0,
            "retry_permitted": False,
            "production_authorized": False,
            "production_status": contract.PRODUCTION_STATUS,
        }


def validate_aws_environment(
    *, expected_profile: str, environment: Mapping[str, str] | None = None
) -> None:
    """Reject every ambient credential, endpoint, proxy, CA, and region drift."""

    values = os.environ if environment is None else environment
    if expected_profile not in _EXPECTED_SSO_PROFILES:
        _fail("AWS_PROFILE_INVALID")
    if any(values.get(key) for key in _AMBIENT_AWS_FORBIDDEN) or any(
        value
        and (key == "AWS_ENDPOINT_URL" or key.startswith("AWS_ENDPOINT_URL_"))
        for key, value in values.items()
    ):
        _fail("AMBIENT_AWS_CONFIGURATION_FORBIDDEN")
    for key in ("AWS_PROFILE", "AWS_DEFAULT_PROFILE"):
        if values.get(key) not in {None, "", expected_profile}:
            _fail("AMBIENT_PROFILE_INVALID")
    for key in ("AWS_REGION", "AWS_DEFAULT_REGION"):
        if values.get(key) not in {None, "", contract.REGION}:
            _fail("AMBIENT_REGION_INVALID")


def _validate_sso_start_url(value: object) -> None:
    parsed = urlsplit(value) if isinstance(value, str) else None
    if (
        parsed is None
        or parsed.scheme != "https"
        or parsed.username is not None
        or parsed.password is not None
        or parsed.port is not None
        or parsed.query
        or parsed.fragment
        or re.fullmatch(
            r"[a-z0-9-]+\.awsapps\.com(?:\.cn)?",
            str(parsed.hostname or ""),
        )
        is None
    ):
        _fail("AWS_SSO_CONFIGURATION_INVALID")


def validate_aws_session(session: Any, *, expected_profile: str) -> None:
    """Require one exact direct SSO profile and its credential provider."""

    expected = _EXPECTED_SSO_PROFILES.get(expected_profile)
    if (
        expected is None
        or getattr(session, "profile_name", None) != expected_profile
        or getattr(session, "region_name", None) != contract.REGION
    ):
        _fail("AWS_SESSION_INVALID")
    internal = getattr(session, "_session", None)
    full_config = getattr(internal, "full_config", None)
    profiles = full_config.get("profiles") if isinstance(full_config, Mapping) else None
    document = (
        profiles.get(expected_profile) if isinstance(profiles, Mapping) else None
    )
    expected_account, expected_role = expected
    if (
        not isinstance(document, Mapping)
        or not set(document).issubset(_PROFILE_CONFIGURATION_KEYS)
        or document.get("region") != contract.REGION
        or document.get("sso_account_id") != expected_account
        or document.get("sso_role_name") != expected_role
    ):
        _fail("AWS_SSO_CONFIGURATION_INVALID")
    session_name = document.get("sso_session")
    if session_name is None:
        if document.get("sso_region") != contract.REGION:
            _fail("AWS_SSO_CONFIGURATION_INVALID")
        _validate_sso_start_url(document.get("sso_start_url"))
    else:
        sessions = (
            full_config.get("sso_sessions")
            if isinstance(full_config, Mapping)
            else None
        )
        sso_document = (
            sessions.get(session_name)
            if isinstance(session_name, str) and isinstance(sessions, Mapping)
            else None
        )
        if (
            not isinstance(sso_document, Mapping)
            or not set(sso_document).issubset(_SSO_SESSION_CONFIGURATION_KEYS)
            or sso_document.get("sso_region") != contract.REGION
            or document.get("sso_region") is not None
            or document.get("sso_start_url") is not None
        ):
            _fail("AWS_SSO_CONFIGURATION_INVALID")
        _validate_sso_start_url(sso_document.get("sso_start_url"))
    try:
        credentials = session.get_credentials()
    except Exception as exc:
        raise ConnectedArtifactBootstrapError(
            "AWS_SSO_CREDENTIALS_UNAVAILABLE"
        ) from exc
    if credentials is None or getattr(credentials, "method", None) != "sso":
        _fail("AWS_CREDENTIAL_SOURCE_INVALID")


def sdk_client_config(config_type: Any) -> Any:
    """Return the sole no-retry, no-endpoint-override SDK configuration."""

    return config_type(
        connect_timeout=3,
        read_timeout=8,
        retries={"total_max_attempts": 1, "mode": "standard"},
        ignore_configured_endpoint_urls=True,
        s3={"us_east_1_regional_endpoint": "regional"},
    )


def _bounded_client(session: Any, service: str, config: Any) -> Any:
    client = session.client(service, region_name=contract.REGION, config=config)
    metadata = getattr(client, "meta", None)
    endpoint = getattr(metadata, "endpoint_url", None)
    parsed = urlsplit(endpoint) if isinstance(endpoint, str) else None
    expected_host = {
        "sts": f"sts.{contract.REGION}.amazonaws.com",
        "cloudformation": f"cloudformation.{contract.REGION}.amazonaws.com",
        "cloudtrail": f"cloudtrail.{contract.REGION}.amazonaws.com",
        "sso-admin": f"sso.{contract.REGION}.amazonaws.com",
        "kms": f"kms.{contract.REGION}.amazonaws.com",
        "s3": f"s3.{contract.REGION}.amazonaws.com",
        "signer": f"signer.{contract.REGION}.amazonaws.com",
        "lambda": f"lambda.{contract.REGION}.amazonaws.com",
        "iam": "iam.amazonaws.com",
    }[service]
    if (
        metadata is None
        or getattr(metadata, "region_name", None)
        != ("aws-global" if service == "iam" else contract.REGION)
        or parsed is None
        or parsed.scheme != "https"
        or parsed.hostname != expected_host
        or parsed.username is not None
        or parsed.password is not None
        or parsed.port is not None
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
    ):
        _fail("AWS_CLIENT_BOUNDARY_INVALID")
    return client


def clients_from_session(
    session: Any,
    config: Any,
    *,
    environment: Mapping[str, str] | None = None,
) -> Clients:
    """Build exact direct-SSO clients with retries and endpoints closed."""

    expected_profile = str(getattr(session, "profile_name", ""))
    validate_aws_environment(
        expected_profile=expected_profile, environment=environment
    )
    validate_aws_session(session, expected_profile=expected_profile)
    retries = getattr(config, "retries", None)
    if (
        not isinstance(retries, Mapping)
        or retries.get("mode") != "standard"
        or retries.get("total_max_attempts") != 1
        or getattr(config, "ignore_configured_endpoint_urls", None) is not True
        or getattr(config, "s3", None)
        != {"us_east_1_regional_endpoint": "regional"}
    ):
        _fail("AWS_CLIENT_CONFIG_INVALID")
    authority = expected_profile == contract.AUTHORITY_PROFILE
    return Clients(
        sts=_bounded_client(session, "sts", config),
        cloudformation=_bounded_client(session, "cloudformation", config),
        cloudtrail=_bounded_client(session, "cloudtrail", config),
        sso_admin=(
            None if authority else _bounded_client(session, "sso-admin", config)
        ),
        kms=_bounded_client(session, "kms", config) if authority else None,
        s3=_bounded_client(session, "s3", config) if authority else None,
        signer=_bounded_client(session, "signer", config) if authority else None,
        lambda_client=(
            _bounded_client(session, "lambda", config) if authority else None
        ),
        iam=None if authority else _bounded_client(session, "iam", config),
    )


__all__ = [
    "CHANGE_SET_ATTESTATION_TYPE",
    "Clients",
    "ConnectedArtifactBootstrapError",
    "ConnectedArtifactBootstrapProvider",
    "DISPATCH_RECEIPT_TYPE",
    "EXECUTION_RECEIPT_TYPE",
    "FOUNDATION_READBACK_TYPE",
    "OBJECT_DISPATCH_TYPE",
    "OExclClaimStore",
    "SIGNING_DISPATCH_TYPE",
    "SIGNING_READBACK_TYPE",
    "STACK_READBACK_TYPE",
    "attest_clean_reviewed_sources",
    "clients_from_session",
    "read_clean_reviewed_source_bytes",
    "sdk_client_config",
    "validate_aws_environment",
    "validate_aws_session",
]
