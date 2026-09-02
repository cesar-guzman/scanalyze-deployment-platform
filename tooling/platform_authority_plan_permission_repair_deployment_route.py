"""Offline, closed materializer for the GUG-376 bootstrap seed route.

Only two initial administrative stacks are represented here: the temporary
management-account route and the authority-account route broker.  The broker
is created recoverably with its ledger deletion protection disabled and is
then advanced by one separately authorized, exact UPDATE change set that
enables protection before the broker may be used.  Every later delegation,
PEP, and revocation operation belongs exclusively to the deployed broker and
cannot be expressed by this module.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from hashlib import sha256
import json
from pathlib import Path, PurePosixPath
import re
import subprocess
from typing import Any, Mapping, Protocol, Sequence
from urllib.parse import parse_qs, quote, urlsplit


MANAGEMENT_ACCOUNT_ID = "839393571433"
AUTHORITY_ACCOUNT_ID = "042360977644"
REGION = "us-east-1"
MAX_CLOUDFORMATION_TEMPLATE_URL_LENGTH = 5_120
ROUTE_STACK_NAME = "scanalyze-platform-authority-gug376-temporary-change-set-route"
BROKER_STACK_NAME = "scanalyze-platform-authority-gug376-route-broker"
ROUTE_CHANGE_SET_NAME = "gug376-temporary-route-create"
BROKER_CHANGE_SET_NAME = "gug376-route-broker-create"
BROKER_PROTECTION_CHANGE_SET_NAME = (
    "gug376-route-broker-protection-enable"
)
BROKER_PROTECTION_TARGET = "broker-protection"
TARGETS = ("route", "broker", BROKER_PROTECTION_TARGET)
MIN_ROUTE_WINDOW_SECONDS = 3_600
MUTATION_COMPLETION_RESERVE_SECONDS = 1_800
ROUTE_TEMPLATE_PATH = "bootstrap/cfn-platform-authority-gug376-temporary-change-set-route.yaml"
DELEGATION_TEMPLATE_PATH = "bootstrap/cfn-platform-authority-bootstrap-plan-repair-delegation.yaml"
BROKER_TEMPLATE_PATH = "bootstrap/cfn-platform-authority-gug376-route-broker-seed.template.yaml"
RECORD_TYPE_INPUT = (
    "scanalyze.platform_authority.plan_permission_repair_seed_input.v1"
)
RECORD_TYPE_INTENT = (
    "scanalyze.platform_authority.plan_permission_repair_seed_intent.v1"
)
RECORD_TYPE_CREATE_ATTESTATION = (
    "scanalyze.platform_authority.plan_permission_repair_seed_create_attestation.v1"
)
RECORD_TYPE_CREATION_AUTHORIZATION = (
    "scanalyze.platform_authority.plan_permission_repair_seed_creation_authorization.v1"
)
RECORD_TYPE_EXECUTION_AUTHORIZATION = (
    "scanalyze.platform_authority.plan_permission_repair_seed_execution_authorization.v1"
)
RECORD_TYPE_EXECUTION_INTENT = (
    "scanalyze.platform_authority.plan_permission_repair_seed_execution_intent.v1"
)
PRODUCTION_STATUS = "NO-GO"
EXACT_TAGS = [
    {"Key": "managed_by", "Value": "cloudformation"},
    {"Key": "service", "Value": "scanalyze-platform-authority"},
    {"Key": "work_package", "Value": "GUG-376"},
]
ROUTE_RESOURCE_COUNT = 9
ROUTE_ASSIGNMENT_COUNT = 3

ROUTE_PARAMETER_KEYS = (
    "ManagementAccountId",
    "AuthorityAccountId",
    "SourceCommit",
    "IdentityCenterInstanceArn",
    "BootstrapPrincipalId",
    "SeedAssignmentsEnabled",
    "BrokerInvokerAssignmentEnabled",
    "RouteNotBefore",
    "RouteNotAfter",
    "RecoveryNotAfter",
    "ArtifactKmsKeyArn",
    "RouteTemplateBucket",
    "RouteTemplateKey",
    "RouteTemplateVersion",
    "RouteTemplateUrl",
    "DelegationTemplateBucket",
    "DelegationTemplateKey",
    "DelegationTemplateVersion",
    "DelegationTemplateUrl",
    "BrokerSeedTemplateBucket",
    "BrokerSeedTemplateKey",
    "BrokerSeedTemplateVersion",
    "BrokerSeedTemplateUrl",
    "BrokerProtectionTemplateBucket",
    "BrokerProtectionTemplateKey",
    "BrokerProtectionTemplateVersion",
    "BrokerProtectionTemplateUrl",
    "BrokerCodeBucket",
    "BrokerCodeKey",
    "BrokerCodeVersion",
    "BrokerSigningProfileVersionArn",
)
# The route accepts only non-secret identifiers and immutable artifact
# coordinates.  Keeping every value readable is an execution-safety boundary:
# connected readback must compare the exact values before any effect.
ROUTE_NO_ECHO_PARAMETER_KEYS: frozenset[str] = frozenset()

_INPUT_FIELDS = frozenset(
    {
        "schema_version",
        "record_type",
        "source_commit",
        "management_account_id",
        "authority_account_id",
        "region",
        "route_not_before",
        "route_not_after",
        "identity_center_instance_arn",
        "bootstrap_principal_id",
        "artifact_bootstrap_intent",
        "bootstrap_route_release",
        "artifacts",
        "broker_seed_input",
        "production_authorized",
        "input_digest",
    }
)
_TEMPLATE_ARTIFACT_FIELDS = frozenset(
    {
        "schema_version",
        "record_type",
        "source_commit",
        "source_path",
        "source_sha256",
        "bucket",
        "key",
        "version",
        "template_url",
        "artifact_sha256",
        "content_length",
        "sse_algorithm",
        "sse_kms_key_arn",
        "upstream_storage_binding",
        "materialization_receipt",
        "verifier",
        "observed_at",
        "source_marker",
        "aws_calls",
        "aws_mutations",
        "receipt_digest",
    }
)
_TEMPLATE_VERIFIER_FIELDS = frozenset(
    {"account_id", "caller_arn", "profile", "region"}
)
_TEMPLATE_STORAGE_BINDING_FIELDS = frozenset(
    {
        "schema_version",
        "record_type",
        "gug363_plan_digest",
        "gug363_artifact_signing_contract_digest",
        "gug365_plan_digest",
        "gug365_ledger_factory_artifact_signing_contract_digest",
        "gug365_signed_artifact_binding_digest",
        "bucket",
        "sse_algorithm",
        "sse_kms_key_arn",
        "source_marker",
        "binding_digest",
    }
)
_INTENT_FIELDS = frozenset(
    {
        "schema_version",
        "record_type",
        "source_commit",
        "management_account_id",
        "authority_account_id",
        "region",
        "route_not_before",
        "route_not_after",
        "recovery_not_after",
        "cleanup_not_after",
        "identity_center_instance_arn",
        "bootstrap_principal_id",
        "identity_center_instance_arn_digest",
        "bootstrap_principal_id_digest",
        "artifact_bootstrap_release_digest",
        "foundation_storage_binding_digest",
        "delegation_source_template_digest",
        "targets",
        "aws_calls",
        "aws_mutations",
        "deployment_authorized",
        "production_authorized",
        "production_status",
        "intent_digest",
    }
)
_TARGET_FIELDS = frozenset(
    {
        "account_id",
        "stack_name",
        "change_set_name",
        "creator_role_name",
        "executor_role_name",
        "template_digest",
        "source_template_digest",
        "expected_resources",
        "expected_changes",
        "expected_outputs",
        "expected_assignment_count",
        "broker_code_sha256",
        "broker_signing_profile_version_arn",
        "broker_signing_receipt_digest",
        "broker_config_digest",
        "broker_effective_policy_projection",
        "create_request",
        "create_request_digest",
    }
)
_CREATE_COMMON_FIELDS = frozenset(
    {
        "StackName",
        "ChangeSetName",
        "ChangeSetType",
        "Description",
        "TemplateURL",
        "Parameters",
        "Capabilities",
        "Tags",
        "IncludeNestedStacks",
        "NotificationARNs",
        "RollbackConfiguration",
        "ClientToken",
    }
)
_CREATE_FIELDS = _CREATE_COMMON_FIELDS | frozenset({"OnStackFailure"})
_UPDATE_FIELDS = _CREATE_COMMON_FIELDS
_ATTESTATION_FIELDS = frozenset(
    {
        "schema_version",
        "record_type",
        "source_commit",
        "target",
        "intent_digest",
        "create_request_digest",
        "account_id",
        "stack_arn",
        "change_set_arn",
        "create_request_id",
        "cloudtrail_event_digest",
        "describe_change_set_digest",
        "template_digest",
        "changes_digest",
        "status",
        "execution_status",
        "attested_at",
        "aws_mutations",
        "retry_permitted",
        "production_authorized",
        "production_status",
        "attestation_digest",
    }
)
_CREATION_AUTHORIZATION_FIELDS = frozenset(
    {
        "schema_version",
        "record_type",
        "source_commit",
        "target",
        "intent_digest",
        "create_request_digest",
        "authorization",
        "authorized_at",
        "expires_at",
        "production_authorized",
        "authorization_digest",
    }
)
_AUTHORIZATION_FIELDS = frozenset(
    {
        "schema_version",
        "record_type",
        "source_commit",
        "target",
        "intent_digest",
        "create_attestation_digest",
        "stack_arn",
        "change_set_arn",
        "authorization",
        "authorized_at",
        "expires_at",
        "production_authorized",
        "authorization_digest",
    }
)
_EXECUTION_INTENT_FIELDS = frozenset(
    {
        "schema_version",
        "record_type",
        "source_commit",
        "target",
        "account_id",
        "route_not_before",
        "route_not_after",
        "recovery_not_after",
        "authorization_not_before",
        "authorization_expires_at",
        "parent_intent_digest",
        "create_attestation_digest",
        "authorization_digest",
        "execute_operation_digest",
        "execute_request",
        "execute_request_digest",
        "aws_calls",
        "aws_mutations",
        "execution_authorized",
        "retry_permitted",
        "production_authorized",
        "production_status",
        "execution_intent_digest",
    }
)

_COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-"
    r"[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)
_INSTANCE_RE = re.compile(r"^arn:aws[a-z-]*:sso:::instance/ssoins-[A-Za-z0-9]{16}$")
_PRINCIPAL_RE = re.compile(
    r"^(?:[0-9a-f]{10}-)?[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$"
)
_SIGNING_RE = re.compile(
    r"^arn:aws:signer:us-east-1:042360977644:/signing-profiles/"
    r"[A-Za-z0-9_-]{2,64}/[A-Za-z0-9]{10}$"
)
_ARTIFACT_BOOTSTRAP_CALLER_RE = re.compile(
    r"^arn:aws:sts::042360977644:assumed-role/"
    r"AWSReservedSSO_ScanalyzeGug376ArtifactBootstrap_[0-9A-Fa-f]{16}/"
    r"[A-Za-z0-9+=,.@_-]{1,64}$"
)
_AUTHORITY_KMS_KEY_RE = re.compile(
    r"^arn:aws[a-z-]*:kms:us-east-1:042360977644:key/"
    r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$"
)
_TEMPLATE_KEY_PATTERNS = {
    "route_template": re.compile(
        r"^scanalyze/platform-authority/gug-376/plan-policy-repair/templates/"
        r"(?P<commit>[0-9a-f]{40})/"
        r"cfn-platform-authority-gug376-temporary-change-set-route\.yaml$"
    ),
    "delegation_template": re.compile(
        r"^scanalyze/platform-authority/gug-376/plan-policy-repair/templates/"
        r"(?P<commit>[0-9a-f]{40})/"
        r"cfn-platform-authority-bootstrap-plan-repair-delegation\.yaml$"
    ),
    "broker_template": re.compile(
        r"^scanalyze/platform-authority/gug-376/plan-policy-repair/private/"
        r"(?P<commit>[0-9a-f]{40})/"
        r"cfn-platform-authority-gug376-route-broker\.yaml$"
    ),
    "broker_protection_template": re.compile(
        r"^scanalyze/platform-authority/gug-376/plan-policy-repair/private/"
        r"(?P<commit>[0-9a-f]{40})/"
        r"cfn-platform-authority-gug376-route-broker-protection\.yaml$"
    ),
}


class RouteSeedError(RuntimeError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(f"GUG376_SEED_BLOCKED:{code}")


def canonical_json(value: Any) -> str:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    )


def digest_value(value: Any) -> str:
    return "sha256:" + sha256(canonical_json(value).encode("utf-8")).hexdigest()


def bytes_digest(value: bytes) -> str:
    return "sha256:" + sha256(value).hexdigest()


def seal(value: Mapping[str, Any], field: str) -> dict[str, Any]:
    result = dict(value)
    result[field] = digest_value(dict(value))
    return result


def _verify_seal(value: Mapping[str, Any], field: str, code: str) -> str:
    claimed = value.get(field)
    if not isinstance(claimed, str) or _DIGEST_RE.fullmatch(claimed) is None:
        raise RouteSeedError(code)
    if digest_value({key: item for key, item in value.items() if key != field}) != claimed:
        raise RouteSeedError(code)
    return claimed


def _parse_time(value: Any, code: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise RouteSeedError(code)
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise RouteSeedError(code) from exc
    if parsed.microsecond:
        raise RouteSeedError(code)
    return parsed


def _timestamp(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        raise RouteSeedError("CLOCK_INVALID")
    return (
        value.astimezone(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def _versioned_url(artifact: Mapping[str, Any]) -> None:
    template_url = artifact.get("template_url")
    if (
        not isinstance(template_url, str)
        or not 1 <= len(template_url) <= MAX_CLOUDFORMATION_TEMPLATE_URL_LENGTH
    ):
        raise RouteSeedError("ARTIFACT_URL_INVALID")
    parsed = urlsplit(template_url)
    query = parse_qs(parsed.query, keep_blank_values=True, strict_parsing=True)
    expected_host = f"{artifact.get('bucket')}.s3.{REGION}.amazonaws.com"
    expected_path = "/" + quote(str(artifact.get("key", "")), safe="/-_.~")
    if (
        parsed.scheme != "https"
        or parsed.hostname != expected_host
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
        or parsed.path != expected_path
        or set(query) != {"versionId"}
        or query["versionId"] != [artifact.get("version")]
    ):
        raise RouteSeedError("ARTIFACT_URL_INVALID")


class GitPort(Protocol):
    def root(self) -> Path: ...

    def branch(self) -> str: ...

    def head(self) -> str: ...

    def origin_main(self) -> str: ...

    def status(self) -> str: ...

    def read_at(self, commit: str, path: str) -> bytes: ...

    def tree_at(self, commit: str) -> str: ...

    def render_broker_seed(
        self, private_input: Mapping[str, Any], *, protection_enabled: bool
    ) -> bytes: ...


class SubprocessGit:
    """Shell-free, read-only Git adapter."""

    def __init__(self, source_root: Path) -> None:
        self._root = source_root.resolve(strict=True)

    def _run(self, *args: str) -> bytes:
        result = subprocess.run(
            ["git", "-C", str(self._root), *args],
            check=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        if result.returncode != 0:
            raise RouteSeedError("GIT_READ_FAILED")
        return result.stdout

    def root(self) -> Path:
        return Path(self._run("rev-parse", "--show-toplevel").decode().strip()).resolve()

    def branch(self) -> str:
        return self._run("symbolic-ref", "--short", "HEAD").decode().strip()

    def head(self) -> str:
        return self._run("rev-parse", "HEAD").decode().strip()

    def origin_main(self) -> str:
        return self._run("rev-parse", "origin/main").decode().strip()

    def status(self) -> str:
        return self._run("status", "--porcelain=v1", "--untracked-files=all").decode()

    def read_at(self, commit: str, path: str) -> bytes:
        return self._run("show", f"{commit}:{path}")

    def tree_at(self, commit: str) -> str:
        value = self._run("rev-parse", f"{commit}^{{tree}}").decode().strip()
        if re.fullmatch(r"[0-9a-f]{40}", value) is None:
            raise RouteSeedError("GIT_READ_FAILED")
        return value

    def render_broker_seed(
        self, private_input: Mapping[str, Any], *, protection_enabled: bool
    ) -> bytes:
        try:
            from tooling.platform_authority_plan_permission_repair_broker_seed import (
                BrokerSeedError,
                render_template,
            )
        except ImportError as exc:
            raise RouteSeedError("BROKER_REPRODUCIBILITY_INVALID") from exc
        try:
            return render_template(
                source_root=self._root,
                private_input=private_input,
                protection_enabled=protection_enabled,
            )
        except BrokerSeedError as exc:
            raise RouteSeedError("BROKER_REPRODUCIBILITY_INVALID") from exc


def _template_inventory(template: bytes) -> list[dict[str, str]]:
    try:
        lines = template.decode("utf-8").splitlines()
    except UnicodeDecodeError as exc:
        raise RouteSeedError("TEMPLATE_UTF8_INVALID") from exc
    in_resources = False
    logical_id: str | None = None
    inventory: list[dict[str, str]] = []
    for line in lines:
        if line == "Resources:":
            in_resources = True
            continue
        if in_resources and re.fullmatch(r"[A-Za-z][A-Za-z0-9]*:", line):
            break
        if not in_resources:
            continue
        match = re.fullmatch(r"  ([A-Za-z][A-Za-z0-9]+):", line)
        if match:
            logical_id = match.group(1)
            continue
        type_match = re.fullmatch(r"    Type: ([A-Za-z0-9:._-]+)", line)
        if type_match and logical_id is not None:
            inventory.append(
                {
                    "logical_resource_id": logical_id,
                    "resource_type": type_match.group(1),
                }
            )
            logical_id = None
    if not inventory or len({item["logical_resource_id"] for item in inventory}) != len(
        inventory
    ):
        raise RouteSeedError("TEMPLATE_INVENTORY_INVALID")
    return sorted(inventory, key=lambda item: item["logical_resource_id"])


def _broker_protection_change_inventory(
    template: bytes,
) -> list[dict[str, str]]:
    """Derive the closed protection delta from the reviewed source template."""

    inventory = {
        item["logical_resource_id"]: item["resource_type"]
        for item in _template_inventory(template)
    }
    try:
        lines = template.decode("utf-8").splitlines()
    except UnicodeDecodeError as exc:
        raise RouteSeedError("TEMPLATE_UTF8_INVALID") from exc
    current: str | None = None
    protected: set[str] = set()
    ledger_property: set[str] = set()
    for line in lines:
        match = re.fullmatch(r"  ([A-Za-z][A-Za-z0-9]+):", line)
        if match:
            current = match.group(1)
            continue
        if current is None:
            continue
        if line == "    DeletionPolicy: @@BROKER_DELETION_POLICY@@":
            protected.add(current)
        if (
            line
            == "      DeletionProtectionEnabled: "
            "@@BROKER_LEDGER_PROTECTION_BOOLEAN@@"
        ):
            ledger_property.add(current)
    expected = {
        "BrokerLedgerKey",
        "BrokerLedger",
        "CreatorLogGroup",
        "ExecutorLogGroup",
        "CreateDispatchRecoveryLogGroup",
        "ExecuteDispatchRecoveryLogGroup",
        "CreatorVersion",
        "ExecutorVersion",
        "CreateDispatchRecoveryVersion",
        "ExecuteDispatchRecoveryVersion",
    }
    if (
        protected != expected
        or ledger_property != {"BrokerLedger"}
        or any(name not in inventory for name in expected)
        or template.count(b"@@BROKER_UPDATE_REPLACE_POLICY@@") != len(expected)
    ):
        raise RouteSeedError("BROKER_PROTECTION_DELTA_INVALID")
    return sorted(
        (
            {"logical_resource_id": name, "resource_type": inventory[name]}
            for name in expected
        ),
        key=lambda item: item["logical_resource_id"],
    )


@dataclass(frozen=True, slots=True)
class ValidatedInput:
    value: dict[str, Any]
    route_source: bytes
    delegation_source: bytes
    broker_source: bytes


def validate_input(
    value: Mapping[str, Any], *, git: GitPort, now: datetime | None = None
) -> ValidatedInput:
    if not isinstance(value, Mapping) or set(value) != _INPUT_FIELDS:
        raise RouteSeedError("INPUT_FIELDS_INVALID")
    _verify_seal(value, "input_digest", "INPUT_DIGEST_INVALID")
    if value.get("schema_version") != 1 or value.get("record_type") != RECORD_TYPE_INPUT:
        raise RouteSeedError("INPUT_TYPE_INVALID")
    source_commit = value.get("source_commit")
    if not isinstance(source_commit, str) or _COMMIT_RE.fullmatch(source_commit) is None:
        raise RouteSeedError("SOURCE_COMMIT_INVALID")
    if (
        value.get("management_account_id") != MANAGEMENT_ACCOUNT_ID
        or value.get("authority_account_id") != AUTHORITY_ACCOUNT_ID
        or value.get("region") != REGION
        or value.get("production_authorized") is not False
    ):
        raise RouteSeedError("EXECUTION_BOUNDARY_INVALID")
    not_before = _parse_time(value.get("route_not_before"), "ROUTE_WINDOW_INVALID")
    not_after = _parse_time(value.get("route_not_after"), "ROUTE_WINDOW_INVALID")
    route_window_seconds = (not_after - not_before).total_seconds()
    if not MIN_ROUTE_WINDOW_SECONDS <= route_window_seconds <= 7200:
        raise RouteSeedError("ROUTE_WINDOW_INVALID")
    if (
        _INSTANCE_RE.fullmatch(str(value.get("identity_center_instance_arn", "")))
        is None
        or _PRINCIPAL_RE.fullmatch(str(value.get("bootstrap_principal_id", "")))
        is None
    ):
        raise RouteSeedError("PRIVATE_COORDINATE_INVALID")
    supplied_now = now or datetime.now(timezone.utc)
    if supplied_now.tzinfo is None or supplied_now.utcoffset() is None:
        raise RouteSeedError("CLOCK_INVALID")
    evaluated = supplied_now.astimezone(timezone.utc).replace(microsecond=0)
    try:
        from tooling import (
            platform_authority_plan_permission_repair_artifact_bootstrap as artifact_bootstrap,
        )

        bootstrap_intent = artifact_bootstrap.validate_bootstrap_intent(
            value.get("artifact_bootstrap_intent")
        )
        bootstrap_release = artifact_bootstrap.validate_route_release(
            value.get("bootstrap_route_release"),
            bootstrap_intent=bootstrap_intent,
            now=evaluated,
        )
    except Exception as exc:
        raise RouteSeedError("ARTIFACT_BOOTSTRAP_RELEASE_INVALID") from exc
    if (
        bootstrap_intent.get("source_commit") != source_commit
        or bootstrap_release.get("source_commit") != source_commit
        or bootstrap_release.get("cleanup_not_after")
        != bootstrap_intent.get("cleanup_not_after")
        or bootstrap_release.get("cleanup_not_after_digest")
        != digest_value(bootstrap_intent.get("cleanup_not_after"))
        or _parse_time(
            _recovery_not_after(value["route_not_after"]),
            "ARTIFACT_BOOTSTRAP_RELEASE_INVALID",
        )
        > _parse_time(
            bootstrap_release.get("cleanup_not_after"),
            "ARTIFACT_BOOTSTRAP_RELEASE_INVALID",
        )
        or not_before
        < _parse_time(
            bootstrap_release.get("normal_route_not_before"),
            "ARTIFACT_BOOTSTRAP_RELEASE_INVALID",
        )
    ):
        raise RouteSeedError("ARTIFACT_BOOTSTRAP_RELEASE_INVALID")
    expected_foundation_storage = bootstrap_release["storage_binding"]
    release_publication = bootstrap_release["publication_evidence"]
    artifacts = value.get("artifacts")
    if not isinstance(artifacts, Mapping) or set(artifacts) != {
        "route_template",
        "delegation_template",
        "broker_template",
        "broker_protection_template",
        "broker_code",
    }:
        raise RouteSeedError("ARTIFACT_FIELDS_INVALID")
    try:
        from tooling.platform_authority_plan_permission_repair_broker_seed import (
            BrokerSeedError,
            derive_effective_policy_projection,
            validate_broker_seed_receipt,
            validate_archived_broker_signing_receipt,
            validate_input as validate_broker_seed_input,
        )
    except ImportError as exc:
        raise RouteSeedError("BROKER_SEED_VALIDATOR_UNAVAILABLE") from exc
    for name in (
        "route_template",
        "delegation_template",
        "broker_template",
        "broker_protection_template",
    ):
        artifact = artifacts[name]
        if not isinstance(artifact, Mapping) or set(artifact) != _TEMPLATE_ARTIFACT_FIELDS:
            raise RouteSeedError("ARTIFACT_FIELDS_INVALID")
        if any(
            not isinstance(artifact.get(field), str) or not artifact.get(field)
            for field in ("source_path", "bucket", "key", "version")
        ):
            raise RouteSeedError("ARTIFACT_FIELDS_INVALID")
        for field in ("source_sha256", "artifact_sha256"):
            if _DIGEST_RE.fullmatch(str(artifact.get(field, ""))) is None:
                raise RouteSeedError("ARTIFACT_DIGEST_INVALID")
        verifier = artifact.get("verifier")
        storage = artifact.get("upstream_storage_binding")
        foundation_storage = (
            isinstance(storage, Mapping)
            and storage == expected_foundation_storage
            and storage.get("record_type")
            == artifact_bootstrap.FOUNDATION_STORAGE_BINDING_TYPE
            and storage.get("source_commit") == source_commit
            and storage.get("source_marker")
            == "VALIDATED_GUG376_FOUNDATION_PUBLISH_AUTHORITY"
            and digest_value(
                {
                    key: item
                    for key, item in storage.items()
                    if key != "binding_digest"
                }
            )
            == storage.get("binding_digest")
        )
        if (
            not foundation_storage
            or storage.get("bucket") != artifact.get("bucket")
            or storage.get("sse_algorithm") != "aws:kms"
            or storage.get("sse_algorithm") != artifact.get("sse_algorithm")
            or storage.get("sse_kms_key_arn")
            != artifact.get("sse_kms_key_arn")
        ):
            raise RouteSeedError("TEMPLATE_STORAGE_BINDING_INVALID")
        _verify_seal(storage, "binding_digest", "TEMPLATE_STORAGE_BINDING_DIGEST_INVALID")
        if (
            artifact.get("schema_version") != 1
            or artifact.get("record_type")
            != "scanalyze.platform_authority.plan_permission_repair_template_readback.v1"
            or artifact.get("source_commit") != source_commit
            or artifact.get("source_marker")
            != "AWS_STS_S3_VERSIONED_OBJECT_READBACK"
            or artifact.get("aws_calls") != 4
            or artifact.get("aws_mutations") != 0
            or type(artifact.get("content_length")) is not int
            or not 0 < artifact["content_length"] <= 4 * 1024 * 1024
            or artifact.get("sse_algorithm") != "aws:kms"
            or _AUTHORITY_KMS_KEY_RE.fullmatch(
                str(artifact.get("sse_kms_key_arn", ""))
            )
            is None
            or not isinstance(verifier, Mapping)
            or set(verifier) != _TEMPLATE_VERIFIER_FIELDS
            or verifier.get("account_id") != AUTHORITY_ACCOUNT_ID
            or verifier.get("profile")
            != "042360977644_ScanalyzeGug376ArtifactBootstrap"
            or verifier.get("region") != REGION
            or _ARTIFACT_BOOTSTRAP_CALLER_RE.fullmatch(
                str(verifier.get("caller_arn", ""))
            )
            is None
        ):
            raise RouteSeedError("TEMPLATE_RECEIPT_INVALID")
        _verify_seal(artifact, "receipt_digest", "TEMPLATE_RECEIPT_DIGEST_INVALID")
        observed = _parse_time(
            artifact.get("observed_at"), "TEMPLATE_RECEIPT_INVALID"
        )
        if artifact != release_publication["template_readbacks"].get(name):
            raise RouteSeedError("ARTIFACT_BOOTSTRAP_RELEASE_EVIDENCE_MISMATCH")
        path = PurePosixPath(artifact["source_path"])
        if path.is_absolute() or ".." in path.parts:
            raise RouteSeedError("ARTIFACT_PATH_INVALID")
        _versioned_url(artifact)
        match = _TEMPLATE_KEY_PATTERNS[name].fullmatch(str(artifact["key"]))
        if match is None or match.group("commit") != source_commit:
            raise RouteSeedError("TEMPLATE_KEY_INVALID")
        materialization = artifact.get("materialization_receipt")
        if name in {"broker_template", "broker_protection_template"}:
            try:
                materialization = validate_broker_seed_receipt(
                    materialization,
                    expected_protection_enabled=(
                        name == "broker_protection_template"
                    ),
                )
            except BrokerSeedError as exc:
                raise RouteSeedError(
                    "BROKER_MATERIALIZATION_RECEIPT_INVALID"
                ) from exc
            if materialization.get("template_sha256") != artifact.get(
                "artifact_sha256"
            ):
                raise RouteSeedError("BROKER_MATERIALIZATION_RECEIPT_INVALID")
            artifact = dict(artifact)
            artifact["materialization_receipt"] = materialization
            artifacts = dict(artifacts)
            artifacts[name] = artifact
        elif (
            materialization is not None
            or artifact.get("source_sha256") != artifact.get("artifact_sha256")
        ):
            raise RouteSeedError("TEMPLATE_RECEIPT_INVALID")
    storage_bindings = [
        artifacts[name]["upstream_storage_binding"]
        for name in (
            "route_template",
            "delegation_template",
            "broker_template",
            "broker_protection_template",
        )
    ]
    if any(binding != storage_bindings[0] for binding in storage_bindings[1:]):
        raise RouteSeedError("TEMPLATE_STORAGE_BINDING_MISMATCH")
    try:
        broker_receipt = validate_archived_broker_signing_receipt(
            artifacts["broker_code"],
            source_commit=source_commit,
            bootstrap_intent=bootstrap_intent,
            foundation_publish_binding=expected_foundation_storage,
            valid_through=not_after,
        )
    except BrokerSeedError as exc:
        raise RouteSeedError("BROKER_SIGNING_RECEIPT_INVALID") from exc
    artifacts = dict(artifacts)
    artifacts["broker_code"] = broker_receipt
    if broker_receipt.get("upstream_storage_binding") != expected_foundation_storage:
        raise RouteSeedError("BROKER_FOUNDATION_STORAGE_BINDING_MISMATCH")
    broker_materializations = {
        name: artifacts[name]["materialization_receipt"]
        for name in ("broker_template", "broker_protection_template")
    }
    for materialization in broker_materializations.values():
        if (
            materialization.get("signing_receipt_digest")
            != broker_receipt["receipt_digest"]
            or materialization.get("unsigned_package_sha256")
            != broker_receipt["unsigned_artifact"]["sha256"]
            or materialization.get("signed_package_sha256")
            != broker_receipt["signed_artifact"]["sha256"]
            or materialization.get("signed_package_code_sha256")
            != broker_receipt["signed_artifact"]["code_sha256"]
        ):
            raise RouteSeedError("BROKER_MATERIALIZATION_BINDING_INVALID")
    materialization = broker_materializations["broker_template"]
    raw_broker_seed_input = value.get("broker_seed_input")
    try:
        broker_seed_input = validate_broker_seed_input(raw_broker_seed_input)
    except BrokerSeedError as exc:
        raise RouteSeedError("BROKER_REPRODUCIBILITY_INPUT_INVALID") from exc
    if (
        broker_seed_input != release_publication["broker_seed_input"]
        or broker_materializations
        != release_publication["broker_seed_receipts"]
        or broker_receipt
        != release_publication["broker_seed_input"]["broker_code"]
        or
        broker_seed_input.get("source_commit") != source_commit
        or broker_seed_input.get("management_account_id") != MANAGEMENT_ACCOUNT_ID
        or broker_seed_input.get("authority_account_id") != AUTHORITY_ACCOUNT_ID
        or broker_seed_input.get("region") != REGION
        or broker_seed_input.get("route_not_before") != value["route_not_before"]
        or broker_seed_input.get("route_not_after") != value["route_not_after"]
        or broker_seed_input.get("broker_config", {}).get(
            "recovery_not_after"
        )
        != _recovery_not_after(value["route_not_after"])
        or broker_seed_input.get("broker_code") != broker_receipt
        or broker_seed_input.get("source_template")
        != {
            "path": BROKER_TEMPLATE_PATH,
            "sha256": artifacts["broker_template"]["source_sha256"],
        }
        or broker_seed_input.get("pep_runtime_binding", {}).get("binding_digest")
        != materialization.get("pep_runtime_binding_digest")
        or broker_seed_input.get("broker_config", {}).get("config_digest")
        is None
    ):
        raise RouteSeedError("BROKER_REPRODUCIBILITY_BINDING_INVALID")

    if (
        git.root() != git.root().resolve()
        or git.branch() != "main"
        or git.head() != source_commit
        or git.origin_main() != source_commit
        or git.status() != ""
    ):
        raise RouteSeedError("CLEAN_MAIN_REQUIRED")
    expected_paths = {
        "route_template": ROUTE_TEMPLATE_PATH,
        "delegation_template": DELEGATION_TEMPLATE_PATH,
        "broker_template": BROKER_TEMPLATE_PATH,
        "broker_protection_template": BROKER_TEMPLATE_PATH,
    }
    sources: dict[str, bytes] = {}
    for name, expected_path in expected_paths.items():
        artifact = artifacts[name]
        if artifact["source_path"] != expected_path:
            raise RouteSeedError("TEMPLATE_PATH_INVALID")
        body = git.read_at(source_commit, expected_path)
        if (
            bytes_digest(body) != artifact["source_sha256"]
            or (
                name not in {"broker_template", "broker_protection_template"}
                and artifact["content_length"] != len(body)
            )
        ):
            raise RouteSeedError("TEMPLATE_GIT_DIGEST_INVALID")
        sources[name] = body
    try:
        reproduced_broker = git.render_broker_seed(
            broker_seed_input, protection_enabled=False
        )
        reproduced_broker_protection = git.render_broker_seed(
            broker_seed_input, protection_enabled=True
        )
    except RouteSeedError:
        raise
    except Exception as exc:
        raise RouteSeedError("BROKER_REPRODUCIBILITY_INVALID") from exc
    if (
        type(reproduced_broker) is not bytes
        or bytes_digest(reproduced_broker)
        != artifacts["broker_template"]["artifact_sha256"]
        or len(reproduced_broker)
        != artifacts["broker_template"]["content_length"]
        or len(reproduced_broker) != materialization["template_bytes"]
        or bytes_digest(reproduced_broker_protection)
        != artifacts["broker_protection_template"]["artifact_sha256"]
        or len(reproduced_broker_protection)
        != artifacts["broker_protection_template"]["content_length"]
        or len(reproduced_broker_protection)
        != broker_materializations["broker_protection_template"][
            "template_bytes"
        ]
    ):
        raise RouteSeedError("BROKER_REPRODUCIBILITY_DIGEST_MISMATCH")
    try:
        reproduced_projection = derive_effective_policy_projection(
            rendered_template=reproduced_broker,
            source_commit=source_commit,
        )
    except BrokerSeedError as exc:
        raise RouteSeedError("BROKER_EFFECTIVE_POLICY_INVALID") from exc
    if reproduced_projection != materialization["effective_policy_projection"]:
        raise RouteSeedError("BROKER_EFFECTIVE_POLICY_MISMATCH")
    try:
        reproduced_protection_projection = derive_effective_policy_projection(
            rendered_template=reproduced_broker_protection,
            source_commit=source_commit,
        )
    except BrokerSeedError as exc:
        raise RouteSeedError("BROKER_EFFECTIVE_POLICY_INVALID") from exc
    if (
        reproduced_protection_projection
        != broker_materializations["broker_protection_template"][
            "effective_policy_projection"
        ]
    ):
        raise RouteSeedError("BROKER_EFFECTIVE_POLICY_MISMATCH")
    normalized = dict(value)
    normalized["artifact_bootstrap_intent"] = bootstrap_intent
    normalized["bootstrap_route_release"] = bootstrap_release
    normalized["artifacts"] = artifacts
    normalized["broker_seed_input"] = json.loads(
        canonical_json(broker_seed_input)
    )
    return ValidatedInput(
        normalized,
        sources["route_template"],
        sources["delegation_template"],
        sources["broker_template"],
    )


def _parameter_list(values: Mapping[str, str]) -> list[dict[str, str]]:
    if tuple(values) != ROUTE_PARAMETER_KEYS:
        raise RouteSeedError("ROUTE_PARAMETERS_INVALID")
    return [
        {"ParameterKey": key, "ParameterValue": values[key]}
        for key in ROUTE_PARAMETER_KEYS
    ]


def _recovery_not_after(route_not_after: str) -> str:
    """Derive the one and only read-only recovery horizon."""

    return _timestamp(
        _parse_time(route_not_after, "RECOVERY_WINDOW_INVALID")
        + timedelta(hours=24)
    )


def _target_authorization_token(target: str) -> str:
    if target not in TARGETS:
        raise RouteSeedError("TARGET_INVALID")
    return target.upper().replace("-", "_")


def _target_account_id(target: str) -> str:
    if target == "route":
        return MANAGEMENT_ACCOUNT_ID
    if target in {"broker", BROKER_PROTECTION_TARGET}:
        return AUTHORITY_ACCOUNT_ID
    raise RouteSeedError("TARGET_INVALID")


def _request_fields(
    change_set_type: str, *, has_parameters: bool = True
) -> frozenset[str]:
    common = (
        _CREATE_COMMON_FIELDS
        if has_parameters
        else _CREATE_COMMON_FIELDS - {"Parameters"}
    )
    if change_set_type == "CREATE":
        return common | {"OnStackFailure"}
    if change_set_type == "UPDATE":
        return common
    raise RouteSeedError("CREATE_REQUEST_INVALID")


def _create_request(
    *,
    stack_name: str,
    change_set_name: str,
    change_set_type: str,
    description: str,
    template_url: str,
    parameters: list[dict[str, str]] | None,
    token_seed: Any,
) -> dict[str, Any]:
    request = {
        "StackName": stack_name,
        "ChangeSetName": change_set_name,
        "ChangeSetType": change_set_type,
        "Description": description,
        "TemplateURL": template_url,
        "Capabilities": ["CAPABILITY_NAMED_IAM"],
        "Tags": EXACT_TAGS,
        "IncludeNestedStacks": False,
        "NotificationARNs": [],
        "RollbackConfiguration": {"MonitoringTimeInMinutes": 0, "RollbackTriggers": []},
        "ClientToken": "gug376-" + digest_value(token_seed)[7:55],
    }
    if parameters is not None:
        request["Parameters"] = parameters
    if change_set_type == "CREATE":
        # The immutable CREATE variants use Delete policies for every
        # fixed-name resource.  Retention is introduced only by the separately
        # attested protection UPDATE after the initial stack is healthy.
        request["OnStackFailure"] = "DELETE"
    if (
        set(request)
        != _request_fields(
            change_set_type, has_parameters=parameters is not None
        )
        or "RoleARN" in request
    ):
        raise RouteSeedError("CREATE_REQUEST_INVALID")
    return request


def materialize_seed_intent(
    value: Mapping[str, Any], *, git: GitPort, now: datetime | None = None
) -> dict[str, Any]:
    validated = validate_input(value, git=git, now=now)
    source = validated.value
    artifacts = source["artifacts"]
    route = artifacts["route_template"]
    delegation = artifacts["delegation_template"]
    broker_template = artifacts["broker_template"]
    broker_protection_template = artifacts["broker_protection_template"]
    broker_code_receipt = artifacts["broker_code"]
    broker_code = broker_code_receipt["signed_artifact"]
    signing_job = broker_code_receipt["signing_job"]
    recovery_not_after = _recovery_not_after(source["route_not_after"])
    route_parameters = _parameter_list(
        {
            "ManagementAccountId": MANAGEMENT_ACCOUNT_ID,
            "AuthorityAccountId": AUTHORITY_ACCOUNT_ID,
            "SourceCommit": source["source_commit"],
            "IdentityCenterInstanceArn": source["identity_center_instance_arn"],
            "BootstrapPrincipalId": source["bootstrap_principal_id"],
            "SeedAssignmentsEnabled": "true",
            "BrokerInvokerAssignmentEnabled": "true",
            "RouteNotBefore": source["route_not_before"],
            "RouteNotAfter": source["route_not_after"],
            "RecoveryNotAfter": recovery_not_after,
            "ArtifactKmsKeyArn": route["sse_kms_key_arn"],
            "RouteTemplateBucket": route["bucket"],
            "RouteTemplateKey": route["key"],
            "RouteTemplateVersion": route["version"],
            "RouteTemplateUrl": route["template_url"],
            "DelegationTemplateBucket": delegation["bucket"],
            "DelegationTemplateKey": delegation["key"],
            "DelegationTemplateVersion": delegation["version"],
            "DelegationTemplateUrl": delegation["template_url"],
            "BrokerSeedTemplateBucket": broker_template["bucket"],
            "BrokerSeedTemplateKey": broker_template["key"],
            "BrokerSeedTemplateVersion": broker_template["version"],
            "BrokerSeedTemplateUrl": broker_template["template_url"],
            "BrokerProtectionTemplateBucket": broker_protection_template[
                "bucket"
            ],
            "BrokerProtectionTemplateKey": broker_protection_template["key"],
            "BrokerProtectionTemplateVersion": broker_protection_template[
                "version"
            ],
            "BrokerProtectionTemplateUrl": broker_protection_template[
                "template_url"
            ],
            "BrokerCodeBucket": broker_code["bucket"],
            "BrokerCodeKey": broker_code["key"],
            "BrokerCodeVersion": broker_code["version"],
            "BrokerSigningProfileVersionArn": signing_job["profile_version_arn"],
        }
    )
    route_request = _create_request(
        stack_name=ROUTE_STACK_NAME,
        change_set_name=ROUTE_CHANGE_SET_NAME,
        change_set_type="CREATE",
        description="GUG-376 reviewed initial administrative seed",
        template_url=route["template_url"],
        parameters=route_parameters,
        token_seed={"target": "route", "source_commit": source["source_commit"], "input_digest": source["input_digest"]},
    )
    broker_request = _create_request(
        stack_name=BROKER_STACK_NAME,
        change_set_name=BROKER_CHANGE_SET_NAME,
        change_set_type="CREATE",
        description="GUG-376 reviewed initial administrative seed",
        template_url=broker_template["template_url"],
        parameters=None,
        token_seed={"target": "broker", "source_commit": source["source_commit"], "input_digest": source["input_digest"]},
    )
    broker_protection_request = _create_request(
        stack_name=BROKER_STACK_NAME,
        change_set_name=BROKER_PROTECTION_CHANGE_SET_NAME,
        change_set_type="UPDATE",
        description="GUG-376 enable route broker ledger deletion protection",
        template_url=broker_protection_template["template_url"],
        parameters=None,
        token_seed={
            "target": BROKER_PROTECTION_TARGET,
            "source_commit": source["source_commit"],
            "input_digest": source["input_digest"],
        },
    )
    route_outputs = sorted(
        [
            "ManagementBrokerCreatorRoleArn",
            "ManagementBrokerExecutorRoleArn",
            "BrokerSeedCreatorPermissionSetArn",
            "BrokerSeedExecutorPermissionSetArn",
            "BrokerInvokerPermissionSetArn",
            "SeedAssignmentMode",
            "BrokerInvokerAssignmentMode",
            "CleanupOrder",
            "BrokerStackName",
            "ProductionAuthorized",
        ]
    )
    broker_outputs = sorted(
        [
            "BrokerLedgerName",
            "CreatorFunctionArn",
            "ExecutorFunctionArn",
            "CreateDispatchRecoveryAliasArn",
            "ExecuteDispatchRecoveryAliasArn",
            "ManagementCreatorRoleArn",
            "ManagementExecutorRoleArn",
            "ManagementRecoveryRoleArn",
            "ParametersAccepted",
            "BrokerLedgerDeletionProtectionMode",
            "ProductionAuthorized",
        ]
    )
    targets = {
        "route": {
            "account_id": MANAGEMENT_ACCOUNT_ID,
            "stack_name": ROUTE_STACK_NAME,
            "change_set_name": ROUTE_CHANGE_SET_NAME,
            "creator_role_name": "AWSAdministratorAccess",
            "executor_role_name": "AWSAdministratorAccess",
            "template_digest": route["artifact_sha256"],
            "source_template_digest": route["source_sha256"],
            "expected_resources": _template_inventory(validated.route_source),
            "expected_changes": _template_inventory(validated.route_source),
            "expected_outputs": route_outputs,
            "expected_assignment_count": ROUTE_ASSIGNMENT_COUNT,
            "broker_code_sha256": None,
            "broker_signing_profile_version_arn": None,
            "broker_signing_receipt_digest": None,
            "broker_config_digest": None,
            "broker_effective_policy_projection": None,
            "create_request": route_request,
            "create_request_digest": digest_value(route_request),
        },
        "broker": {
            "account_id": AUTHORITY_ACCOUNT_ID,
            "stack_name": BROKER_STACK_NAME,
            "change_set_name": BROKER_CHANGE_SET_NAME,
            "creator_role_name": "ScanalyzeGug376BrokerSeedCreator",
            "executor_role_name": "ScanalyzeGug376BrokerSeedExec",
            "template_digest": broker_template["artifact_sha256"],
            "source_template_digest": broker_template["source_sha256"],
            "expected_resources": _template_inventory(validated.broker_source),
            "expected_changes": _template_inventory(validated.broker_source),
            "expected_outputs": broker_outputs,
            "expected_assignment_count": 0,
            "broker_code_sha256": broker_code["code_sha256"],
            "broker_signing_profile_version_arn": signing_job[
                "profile_version_arn"
            ],
            "broker_signing_receipt_digest": broker_code_receipt[
                "receipt_digest"
            ],
            "broker_config_digest": source["broker_seed_input"][
                "broker_config"
            ]["config_digest"],
            "broker_effective_policy_projection": broker_template[
                "materialization_receipt"
            ]["effective_policy_projection"],
            "create_request": broker_request,
            "create_request_digest": digest_value(broker_request),
        },
        BROKER_PROTECTION_TARGET: {
            "account_id": AUTHORITY_ACCOUNT_ID,
            "stack_name": BROKER_STACK_NAME,
            "change_set_name": BROKER_PROTECTION_CHANGE_SET_NAME,
            "creator_role_name": "ScanalyzeGug376BrokerSeedCreator",
            "executor_role_name": "ScanalyzeGug376BrokerSeedExec",
            "template_digest": broker_protection_template["artifact_sha256"],
            "source_template_digest": broker_protection_template["source_sha256"],
            "expected_resources": _template_inventory(validated.broker_source),
            "expected_changes": _broker_protection_change_inventory(
                validated.broker_source
            ),
            "expected_outputs": broker_outputs,
            "expected_assignment_count": 0,
            "broker_code_sha256": broker_code["code_sha256"],
            "broker_signing_profile_version_arn": signing_job[
                "profile_version_arn"
            ],
            "broker_signing_receipt_digest": broker_code_receipt[
                "receipt_digest"
            ],
            "broker_config_digest": source["broker_seed_input"][
                "broker_config"
            ]["config_digest"],
            "broker_effective_policy_projection": broker_protection_template[
                "materialization_receipt"
            ]["effective_policy_projection"],
            "create_request": broker_protection_request,
            "create_request_digest": digest_value(broker_protection_request),
        },
    }
    if len(targets["route"]["expected_resources"]) != ROUTE_RESOURCE_COUNT:
        raise RouteSeedError("ROUTE_RESOURCE_INVENTORY_INVALID")
    intent = {
        "schema_version": 1,
        "record_type": RECORD_TYPE_INTENT,
        "source_commit": source["source_commit"],
        "management_account_id": MANAGEMENT_ACCOUNT_ID,
        "authority_account_id": AUTHORITY_ACCOUNT_ID,
        "region": REGION,
        "route_not_before": source["route_not_before"],
        "route_not_after": source["route_not_after"],
        "recovery_not_after": recovery_not_after,
        "cleanup_not_after": source["bootstrap_route_release"][
            "cleanup_not_after"
        ],
        "identity_center_instance_arn": source["identity_center_instance_arn"],
        "bootstrap_principal_id": source["bootstrap_principal_id"],
        "identity_center_instance_arn_digest": digest_value(source["identity_center_instance_arn"]),
        "bootstrap_principal_id_digest": digest_value(source["bootstrap_principal_id"]),
        "artifact_bootstrap_release_digest": source[
            "bootstrap_route_release"
        ]["release_digest"],
        "foundation_storage_binding_digest": source[
            "bootstrap_route_release"
        ]["storage_binding"]["binding_digest"],
        "delegation_source_template_digest": delegation["source_sha256"],
        "targets": targets,
        "aws_calls": 0,
        "aws_mutations": 0,
        "deployment_authorized": False,
        "production_authorized": False,
        "production_status": PRODUCTION_STATUS,
    }
    return seal(intent, "intent_digest")


def validate_seed_intent(value: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != _INTENT_FIELDS:
        raise RouteSeedError("INTENT_FIELDS_INVALID")
    _verify_seal(value, "intent_digest", "INTENT_DIGEST_INVALID")
    if (
        value.get("schema_version") != 1
        or value.get("record_type") != RECORD_TYPE_INTENT
        or value.get("management_account_id") != MANAGEMENT_ACCOUNT_ID
        or value.get("authority_account_id") != AUTHORITY_ACCOUNT_ID
        or value.get("region") != REGION
        or _INSTANCE_RE.fullmatch(str(value.get("identity_center_instance_arn", "")))
        is None
        or value.get("identity_center_instance_arn_digest")
        != digest_value(value.get("identity_center_instance_arn"))
        or value.get("bootstrap_principal_id_digest")
        != digest_value(value.get("bootstrap_principal_id"))
        or _DIGEST_RE.fullmatch(
            str(value.get("artifact_bootstrap_release_digest", ""))
        )
        is None
        or _DIGEST_RE.fullmatch(
            str(value.get("foundation_storage_binding_digest", ""))
        )
        is None
        or _DIGEST_RE.fullmatch(
            str(value.get("delegation_source_template_digest", ""))
        )
        is None
        or set(value.get("targets", {})) != set(TARGETS)
        or value.get("aws_calls") != 0
        or value.get("aws_mutations") != 0
        or value.get("deployment_authorized") is not False
        or value.get("production_authorized") is not False
        or value.get("production_status") != PRODUCTION_STATUS
    ):
        raise RouteSeedError("INTENT_INVALID")
    not_before = _parse_time(value.get("route_not_before"), "INTENT_INVALID")
    not_after = _parse_time(value.get("route_not_after"), "INTENT_INVALID")
    recovery_not_after = _parse_time(
        value.get("recovery_not_after"), "INTENT_INVALID"
    )
    cleanup_not_after = _parse_time(
        value.get("cleanup_not_after"), "INTENT_INVALID"
    )
    if (
        not MIN_ROUTE_WINDOW_SECONDS
        <= (not_after - not_before).total_seconds()
        <= 7200
        or recovery_not_after != not_after + timedelta(hours=24)
        or recovery_not_after > cleanup_not_after
    ):
        raise RouteSeedError("INTENT_INVALID")
    for target, expected in (
        (
            "route",
            {
                "account_id": MANAGEMENT_ACCOUNT_ID,
                "stack_name": ROUTE_STACK_NAME,
                "change_set_name": ROUTE_CHANGE_SET_NAME,
                "creator_role_name": "AWSAdministratorAccess",
                "executor_role_name": "AWSAdministratorAccess",
                "expected_outputs": sorted(
                    [
                        "ManagementBrokerCreatorRoleArn",
                        "ManagementBrokerExecutorRoleArn",
                        "BrokerSeedCreatorPermissionSetArn",
                        "BrokerSeedExecutorPermissionSetArn",
                        "BrokerInvokerPermissionSetArn",
                        "SeedAssignmentMode",
                        "BrokerInvokerAssignmentMode",
                        "CleanupOrder",
                        "BrokerStackName",
                        "ProductionAuthorized",
                    ]
                ),
                "expected_assignment_count": ROUTE_ASSIGNMENT_COUNT,
                "broker_code_sha256": None,
                "broker_signing_profile_version_arn": None,
                "broker_signing_receipt_digest": None,
                "broker_config_digest": None,
                "broker_effective_policy_projection": None,
            },
        ),
        (
            "broker",
            {
                "account_id": AUTHORITY_ACCOUNT_ID,
                "stack_name": BROKER_STACK_NAME,
                "change_set_name": BROKER_CHANGE_SET_NAME,
                "creator_role_name": "ScanalyzeGug376BrokerSeedCreator",
                "executor_role_name": "ScanalyzeGug376BrokerSeedExec",
                "expected_outputs": sorted(
                    [
                        "BrokerLedgerName",
                        "CreatorFunctionArn",
                        "ExecutorFunctionArn",
                        "CreateDispatchRecoveryAliasArn",
                        "ExecuteDispatchRecoveryAliasArn",
                        "ManagementCreatorRoleArn",
                        "ManagementExecutorRoleArn",
                        "ManagementRecoveryRoleArn",
                        "ParametersAccepted",
                        "BrokerLedgerDeletionProtectionMode",
                        "ProductionAuthorized",
                    ]
                ),
                "expected_assignment_count": 0,
            },
        ),
        (
            BROKER_PROTECTION_TARGET,
            {
                "account_id": AUTHORITY_ACCOUNT_ID,
                "stack_name": BROKER_STACK_NAME,
                "change_set_name": BROKER_PROTECTION_CHANGE_SET_NAME,
                "creator_role_name": "ScanalyzeGug376BrokerSeedCreator",
                "executor_role_name": "ScanalyzeGug376BrokerSeedExec",
                "expected_outputs": sorted(
                    [
                        "BrokerLedgerName",
                        "CreatorFunctionArn",
                        "ExecutorFunctionArn",
                        "CreateDispatchRecoveryAliasArn",
                        "ExecuteDispatchRecoveryAliasArn",
                        "ManagementCreatorRoleArn",
                        "ManagementExecutorRoleArn",
                        "ManagementRecoveryRoleArn",
                        "ParametersAccepted",
                        "BrokerLedgerDeletionProtectionMode",
                        "ProductionAuthorized",
                    ]
                ),
                "expected_assignment_count": 0,
            },
        ),
    ):
        item = value["targets"][target]
        if not isinstance(item, Mapping) or set(item) != _TARGET_FIELDS:
            raise RouteSeedError("TARGET_INVALID")
        request = item.get("create_request")
        if (
            any(item.get(key) != expected_value for key, expected_value in expected.items())
            or not isinstance(request, Mapping)
            or set(request)
            != _request_fields(
                str(request.get("ChangeSetType")),
                has_parameters="Parameters" in request,
            )
            or "RoleARN" in request
            or item.get("create_request_digest") != digest_value(request)
            or request.get("StackName") != expected["stack_name"]
            or request.get("ChangeSetName") != expected["change_set_name"]
            or request.get("ChangeSetType")
            != (
                "UPDATE"
                if target == BROKER_PROTECTION_TARGET
                else "CREATE"
            )
            or request.get("Description")
            != (
                "GUG-376 enable route broker ledger deletion protection"
                if target == BROKER_PROTECTION_TARGET
                else "GUG-376 reviewed initial administrative seed"
            )
            or request.get("Capabilities") != ["CAPABILITY_NAMED_IAM"]
            or request.get("Tags") != EXACT_TAGS
            or request.get("IncludeNestedStacks") is not False
            or request.get("NotificationARNs") != []
            or request.get("RollbackConfiguration")
            != {"MonitoringTimeInMinutes": 0, "RollbackTriggers": []}
            or (
                request.get("OnStackFailure") != "DELETE"
                if target != BROKER_PROTECTION_TARGET
                else "OnStackFailure" in request
            )
            or re.fullmatch(r"gug376-[0-9a-f]{48}", str(request.get("ClientToken", "")))
            is None
            or not isinstance(item.get("expected_resources"), list)
            or not item["expected_resources"]
            or not isinstance(item.get("expected_changes"), list)
            or item["expected_changes"]
            != (
                sorted(
                    [
                        {
                            "logical_resource_id": "BrokerLedgerKey",
                            "resource_type": "AWS::KMS::Key",
                        },
                        {
                            "logical_resource_id": "BrokerLedger",
                            "resource_type": "AWS::DynamoDB::Table",
                        },
                        {
                            "logical_resource_id": "CreatorLogGroup",
                            "resource_type": "AWS::Logs::LogGroup",
                        },
                        {
                            "logical_resource_id": "ExecutorLogGroup",
                            "resource_type": "AWS::Logs::LogGroup",
                        },
                        {
                            "logical_resource_id": "CreateDispatchRecoveryLogGroup",
                            "resource_type": "AWS::Logs::LogGroup",
                        },
                        {
                            "logical_resource_id": "ExecuteDispatchRecoveryLogGroup",
                            "resource_type": "AWS::Logs::LogGroup",
                        },
                        {
                            "logical_resource_id": "CreatorVersion",
                            "resource_type": "AWS::Lambda::Version",
                        },
                        {
                            "logical_resource_id": "ExecutorVersion",
                            "resource_type": "AWS::Lambda::Version",
                        },
                        {
                            "logical_resource_id": "CreateDispatchRecoveryVersion",
                            "resource_type": "AWS::Lambda::Version",
                        },
                        {
                            "logical_resource_id": "ExecuteDispatchRecoveryVersion",
                            "resource_type": "AWS::Lambda::Version",
                        },
                    ],
                    key=lambda change: change["logical_resource_id"],
                )
                if target == BROKER_PROTECTION_TARGET
                else item["expected_resources"]
            )
            or _DIGEST_RE.fullmatch(str(item.get("template_digest", ""))) is None
            or _DIGEST_RE.fullmatch(str(item.get("source_template_digest", "")))
            is None
        ):
            raise RouteSeedError("TARGET_INVALID")
        if target in {"broker", BROKER_PROTECTION_TARGET}:
            if (
                "Parameters" in request
                or len(item["expected_resources"]) == 0
                or re.fullmatch(
                    r"[A-Za-z0-9+/]{43}=",
                    str(item.get("broker_code_sha256", "")),
                )
                is None
                or _SIGNING_RE.fullmatch(
                    str(item.get("broker_signing_profile_version_arn", ""))
                )
                is None
                or _DIGEST_RE.fullmatch(
                    str(item.get("broker_signing_receipt_digest", ""))
                )
                is None
                or _DIGEST_RE.fullmatch(
                    str(item.get("broker_config_digest", ""))
                )
                is None
                or not isinstance(
                    item.get("broker_effective_policy_projection"), Mapping
                )
            ):
                raise RouteSeedError("BROKER_PARAMETERS_INVALID")
            try:
                from tooling.platform_authority_plan_permission_repair_broker_seed import (
                    BrokerSeedError,
                    validate_effective_policy_projection,
                )
            except ImportError as exc:
                raise RouteSeedError("BROKER_EFFECTIVE_POLICY_INVALID") from exc
            try:
                projection = validate_effective_policy_projection(
                    item["broker_effective_policy_projection"],
                    source_commit=value["source_commit"],
                )
            except BrokerSeedError as exc:
                raise RouteSeedError("BROKER_EFFECTIVE_POLICY_INVALID") from exc
            if projection != item["broker_effective_policy_projection"]:
                raise RouteSeedError("BROKER_EFFECTIVE_POLICY_INVALID")
        else:
            parameters = request.get("Parameters")
            if (
                not isinstance(parameters, list)
                or tuple(entry.get("ParameterKey") for entry in parameters)
                != ROUTE_PARAMETER_KEYS
                or any(
                    not isinstance(entry, Mapping)
                    or set(entry) != {"ParameterKey", "ParameterValue"}
                    or not isinstance(entry.get("ParameterValue"), str)
                    for entry in parameters
                )
                or len(item["expected_resources"]) != ROUTE_RESOURCE_COUNT
            ):
                raise RouteSeedError("ROUTE_PARAMETERS_INVALID")
            parameter_map = {
                entry["ParameterKey"]: entry["ParameterValue"] for entry in parameters
            }
            if (
                parameter_map["ManagementAccountId"] != MANAGEMENT_ACCOUNT_ID
                or parameter_map["AuthorityAccountId"] != AUTHORITY_ACCOUNT_ID
                or parameter_map["SourceCommit"] != value["source_commit"]
                or parameter_map["IdentityCenterInstanceArn"]
                != value["identity_center_instance_arn"]
                or parameter_map["BootstrapPrincipalId"]
                != value["bootstrap_principal_id"]
                or parameter_map["SeedAssignmentsEnabled"] != "true"
                or parameter_map["BrokerInvokerAssignmentEnabled"] != "true"
                or parameter_map["RouteNotBefore"] != value["route_not_before"]
                or parameter_map["RouteNotAfter"] != value["route_not_after"]
                or parameter_map["RecoveryNotAfter"]
                != value["recovery_not_after"]
            ):
                raise RouteSeedError("ROUTE_PARAMETERS_INVALID")
    return json.loads(canonical_json(value))


def validate_seed_intent_against_git(
    value: Mapping[str, Any], *, git: GitPort
) -> dict[str, Any]:
    """Revalidate a sealed intent against the exact clean canonical source tree."""

    intent = validate_seed_intent(value)
    source_commit = intent["source_commit"]
    if (
        git.root() != git.root().resolve()
        or git.branch() != "main"
        or git.head() != source_commit
        or git.origin_main() != source_commit
        or git.status() != ""
    ):
        raise RouteSeedError("CLEAN_MAIN_REQUIRED")
    expected = {
        ROUTE_TEMPLATE_PATH: intent["targets"]["route"][
            "source_template_digest"
        ],
        DELEGATION_TEMPLATE_PATH: intent["delegation_source_template_digest"],
        BROKER_TEMPLATE_PATH: intent["targets"]["broker"][
            "source_template_digest"
        ],
    }
    for source_path, expected_digest in expected.items():
        if bytes_digest(git.read_at(source_commit, source_path)) != expected_digest:
            raise RouteSeedError("TEMPLATE_GIT_DIGEST_INVALID")
    return intent


def validate_seed_intent_against_input(
    value: Mapping[str, Any],
    *,
    seed_input: Mapping[str, Any],
    git: GitPort,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Reconstruct and compare the complete seed intent from causal input.

    ``intent_digest`` is an integrity checksum, not an authorization signature.
    A connected mutation therefore must not accept a merely re-sealed intent.
    Re-materializing from the full artifact-bootstrap release and its versioned
    readbacks preserves the exact TemplateURL, parameters, tags, template
    digests, windows, and deterministic client tokens admitted offline.
    """

    observed = validate_seed_intent(value)
    expected = materialize_seed_intent(seed_input, git=git, now=now)
    if observed != expected:
        raise RouteSeedError("INTENT_INPUT_BINDING_INVALID")
    return observed


def _full_arn(value: Any, *, account_id: str, kind: str, name: str) -> str:
    if not isinstance(value, str):
        raise RouteSeedError("PROVIDER_ARN_INVALID")
    prefix = f"arn:aws:cloudformation:{REGION}:{account_id}:{kind}/{name}/"
    suffix = value.removeprefix(prefix)
    if not value.startswith(prefix) or _UUID_RE.fullmatch(suffix) is None:
        raise RouteSeedError("PROVIDER_ARN_INVALID")
    return value


def validate_create_attestation(
    value: Mapping[str, Any], *, intent: Mapping[str, Any], target: str
) -> dict[str, Any]:
    validated_intent = validate_seed_intent(intent)
    if not isinstance(value, Mapping) or set(value) != _ATTESTATION_FIELDS:
        raise RouteSeedError("CREATE_ATTESTATION_FIELDS_INVALID")
    _verify_seal(value, "attestation_digest", "CREATE_ATTESTATION_DIGEST_INVALID")
    spec = validated_intent["targets"].get(target)
    if not isinstance(spec, Mapping):
        raise RouteSeedError("TARGET_INVALID")
    if (
        value.get("schema_version") != 1
        or value.get("record_type") != RECORD_TYPE_CREATE_ATTESTATION
        or value.get("source_commit") != validated_intent["source_commit"]
        or value.get("target") != target
        or value.get("intent_digest") != validated_intent["intent_digest"]
        or value.get("create_request_digest") != spec["create_request_digest"]
        or value.get("account_id") != spec["account_id"]
        or value.get("template_digest") != spec["template_digest"]
        or value.get("changes_digest")
        != digest_value(spec["expected_changes"])
        or value.get("status") != "CREATE_COMPLETE"
        or value.get("execution_status") != "AVAILABLE"
        or value.get("aws_mutations") != 0
        or value.get("retry_permitted") is not False
        or value.get("production_authorized") is not False
        or value.get("production_status") != PRODUCTION_STATUS
    ):
        raise RouteSeedError("CREATE_ATTESTATION_INVALID")
    for field in (
        "create_request_id",
        "cloudtrail_event_digest",
        "describe_change_set_digest",
        "changes_digest",
    ):
        raw = value.get(field)
        if field == "create_request_id":
            if not isinstance(raw, str) or _UUID_RE.fullmatch(raw) is None:
                raise RouteSeedError("CREATE_ATTESTATION_INVALID")
        elif not isinstance(raw, str) or _DIGEST_RE.fullmatch(raw) is None:
            raise RouteSeedError("CREATE_ATTESTATION_INVALID")
    _full_arn(value.get("stack_arn"), account_id=spec["account_id"], kind="stack", name=spec["stack_name"])
    _full_arn(value.get("change_set_arn"), account_id=spec["account_id"], kind="changeSet", name=spec["change_set_name"])
    attested = _parse_time(value.get("attested_at"), "CREATE_ATTESTATION_INVALID")
    if not _parse_time(validated_intent["route_not_before"], "INTENT_INVALID") <= attested < _parse_time(validated_intent["recovery_not_after"], "INTENT_INVALID"):
        raise RouteSeedError("CREATE_ATTESTATION_INVALID")
    return json.loads(canonical_json(value))


def materialize_execution_authorization(
    *,
    seed_intent: Mapping[str, Any],
    create_attestation: Mapping[str, Any],
    authorization: str,
    authorized_at: str,
    expires_at: str,
) -> dict[str, Any]:
    """Bind one explicit, short-lived human authorization to an attested set."""

    intent = validate_seed_intent(seed_intent)
    target = create_attestation.get("target")
    if target not in TARGETS:
        raise RouteSeedError("TARGET_INVALID")
    attestation = validate_create_attestation(
        create_attestation,
        intent=intent,
        target=str(target),
    )
    expected_phrase = (
        f"I_AUTHORIZE_GUG376_{_target_authorization_token(str(target))}"
        "_SEED_EXECUTION"
    )
    authorized = _parse_time(authorized_at, "AUTHORIZATION_INVALID")
    expires = _parse_time(expires_at, "AUTHORIZATION_INVALID")
    attested = _parse_time(attestation["attested_at"], "AUTHORIZATION_INVALID")
    route_not_before = _parse_time(
        intent["route_not_before"], "AUTHORIZATION_INVALID"
    )
    route_not_after = _parse_time(
        intent["route_not_after"], "AUTHORIZATION_INVALID"
    )
    admission_not_after = route_not_after - timedelta(
        seconds=MUTATION_COMPLETION_RESERVE_SECONDS
    )
    duration = (expires - authorized).total_seconds()
    if (
        authorization != expected_phrase
        or not route_not_before
        <= attested
        <= authorized
        < expires
        <= admission_not_after
        or not 60 <= duration <= 900
    ):
        raise RouteSeedError("AUTHORIZATION_INVALID")
    result = seal(
        {
            "schema_version": 1,
            "record_type": RECORD_TYPE_EXECUTION_AUTHORIZATION,
            "source_commit": intent["source_commit"],
            "target": target,
            "intent_digest": intent["intent_digest"],
            "create_attestation_digest": attestation["attestation_digest"],
            "stack_arn": attestation["stack_arn"],
            "change_set_arn": attestation["change_set_arn"],
            "authorization": authorization,
            "authorized_at": authorized_at,
            "expires_at": expires_at,
            "production_authorized": False,
        },
        "authorization_digest",
    )
    # Reuse the closed consumer as the producer's final contract check.
    materialize_execution_intent(
        seed_intent=intent,
        create_attestation=attestation,
        authorization=result,
    )
    return result


def validate_execution_authorization(
    value: Mapping[str, Any],
    *,
    seed_intent: Mapping[str, Any],
    create_attestation: Mapping[str, Any],
    now: datetime | None = None,
) -> dict[str, Any]:
    """Validate one exact execution grant, optionally requiring it to be active."""

    intent = validate_seed_intent(seed_intent)
    if not isinstance(value, Mapping) or set(value) != _AUTHORIZATION_FIELDS:
        raise RouteSeedError("AUTHORIZATION_FIELDS_INVALID")
    _verify_seal(value, "authorization_digest", "AUTHORIZATION_DIGEST_INVALID")
    target = value.get("target")
    if target not in TARGETS:
        raise RouteSeedError("TARGET_INVALID")
    attestation = validate_create_attestation(
        create_attestation,
        intent=intent,
        target=str(target),
    )
    expected_phrase = (
        f"I_AUTHORIZE_GUG376_{_target_authorization_token(str(target))}"
        "_SEED_EXECUTION"
    )
    authorized = _parse_time(value.get("authorized_at"), "AUTHORIZATION_INVALID")
    expires = _parse_time(value.get("expires_at"), "AUTHORIZATION_INVALID")
    attested = _parse_time(attestation["attested_at"], "AUTHORIZATION_INVALID")
    route_not_before = _parse_time(
        intent["route_not_before"], "AUTHORIZATION_INVALID"
    )
    route_not_after = _parse_time(
        intent["route_not_after"], "AUTHORIZATION_INVALID"
    )
    admission_not_after = route_not_after - timedelta(
        seconds=MUTATION_COMPLETION_RESERVE_SECONDS
    )
    duration = (expires - authorized).total_seconds()
    if (
        value.get("schema_version") != 1
        or value.get("record_type") != RECORD_TYPE_EXECUTION_AUTHORIZATION
        or value.get("source_commit") != intent["source_commit"]
        or value.get("intent_digest") != intent["intent_digest"]
        or value.get("create_attestation_digest")
        != attestation["attestation_digest"]
        or value.get("stack_arn") != attestation["stack_arn"]
        or value.get("change_set_arn") != attestation["change_set_arn"]
        or value.get("authorization") != expected_phrase
        or value.get("production_authorized") is not False
        or not route_not_before
        <= attested
        <= authorized
        < expires
        <= admission_not_after
        or not 60 <= duration <= 900
    ):
        raise RouteSeedError("AUTHORIZATION_INVALID")
    if now is not None:
        if now.tzinfo is None or now.utcoffset() is None:
            raise RouteSeedError("CLOCK_INVALID")
        current = now.astimezone(timezone.utc).replace(microsecond=0)
        if current < authorized:
            raise RouteSeedError("AUTHORIZATION_NOT_ACTIVE")
        if current >= expires:
            raise RouteSeedError("AUTHORIZATION_EXPIRED")
    return json.loads(canonical_json(value))


def materialize_creation_authorization(
    *,
    seed_intent: Mapping[str, Any],
    target: str,
    authorization: str,
    authorized_at: str,
    expires_at: str,
) -> dict[str, Any]:
    """Bind one short-lived human authorization to one exact create request."""

    intent = validate_seed_intent(seed_intent)
    if target not in TARGETS:
        raise RouteSeedError("TARGET_INVALID")
    spec = intent["targets"][target]
    expected_phrase = (
        f"I_AUTHORIZE_GUG376_{_target_authorization_token(target)}"
        "_SEED_CREATION"
    )
    authorized = _parse_time(authorized_at, "CREATION_AUTHORIZATION_INVALID")
    expires = _parse_time(expires_at, "CREATION_AUTHORIZATION_INVALID")
    route_not_before = _parse_time(
        intent["route_not_before"], "CREATION_AUTHORIZATION_INVALID"
    )
    route_not_after = _parse_time(
        intent["route_not_after"], "CREATION_AUTHORIZATION_INVALID"
    )
    admission_not_after = route_not_after - timedelta(
        seconds=MUTATION_COMPLETION_RESERVE_SECONDS
    )
    duration = (expires - authorized).total_seconds()
    if (
        authorization != expected_phrase
        or not route_not_before <= authorized < expires <= admission_not_after
        or not 60 <= duration <= 900
    ):
        raise RouteSeedError("CREATION_AUTHORIZATION_INVALID")
    result = seal(
        {
            "schema_version": 1,
            "record_type": RECORD_TYPE_CREATION_AUTHORIZATION,
            "source_commit": intent["source_commit"],
            "target": target,
            "intent_digest": intent["intent_digest"],
            "create_request_digest": spec["create_request_digest"],
            "authorization": authorization,
            "authorized_at": authorized_at,
            "expires_at": expires_at,
            "production_authorized": False,
        },
        "authorization_digest",
    )
    validate_creation_authorization(
        result,
        seed_intent=intent,
        target=target,
        now=authorized,
    )
    return result


def validate_creation_authorization(
    value: Mapping[str, Any],
    *,
    seed_intent: Mapping[str, Any],
    target: str,
    now: datetime,
) -> dict[str, Any]:
    """Validate one active authorization without deriving provider identity."""

    intent = validate_seed_intent(seed_intent)
    if target not in TARGETS:
        raise RouteSeedError("TARGET_INVALID")
    if not isinstance(value, Mapping) or set(value) != _CREATION_AUTHORIZATION_FIELDS:
        raise RouteSeedError("CREATION_AUTHORIZATION_FIELDS_INVALID")
    _verify_seal(
        value,
        "authorization_digest",
        "CREATION_AUTHORIZATION_DIGEST_INVALID",
    )
    if now.tzinfo is None or now.utcoffset() is None:
        raise RouteSeedError("CLOCK_INVALID")
    current = now.astimezone(timezone.utc).replace(microsecond=0)
    authorized = _parse_time(
        value.get("authorized_at"), "CREATION_AUTHORIZATION_INVALID"
    )
    expires = _parse_time(
        value.get("expires_at"), "CREATION_AUTHORIZATION_INVALID"
    )
    route_not_before = _parse_time(
        intent["route_not_before"], "CREATION_AUTHORIZATION_INVALID"
    )
    route_not_after = _parse_time(
        intent["route_not_after"], "CREATION_AUTHORIZATION_INVALID"
    )
    admission_not_after = route_not_after - timedelta(
        seconds=MUTATION_COMPLETION_RESERVE_SECONDS
    )
    spec = intent["targets"][target]
    duration = (expires - authorized).total_seconds()
    if (
        value.get("schema_version") != 1
        or value.get("record_type") != RECORD_TYPE_CREATION_AUTHORIZATION
        or value.get("source_commit") != intent["source_commit"]
        or value.get("target") != target
        or value.get("intent_digest") != intent["intent_digest"]
        or value.get("create_request_digest") != spec["create_request_digest"]
        or value.get("authorization")
        != (
            f"I_AUTHORIZE_GUG376_{_target_authorization_token(target)}"
            "_SEED_CREATION"
        )
        or value.get("production_authorized") is not False
        or not route_not_before
        <= authorized
        <= current
        < expires
        <= admission_not_after
        or not 60 <= duration <= 900
    ):
        raise RouteSeedError("CREATION_AUTHORIZATION_INVALID")
    return json.loads(canonical_json(value))


def materialize_execution_intent(
    *,
    seed_intent: Mapping[str, Any],
    create_attestation: Mapping[str, Any],
    authorization: Mapping[str, Any],
) -> dict[str, Any]:
    intent = validate_seed_intent(seed_intent)
    authorization = validate_execution_authorization(
        authorization,
        seed_intent=intent,
        create_attestation=create_attestation,
    )
    target = authorization["target"]
    attestation = validate_create_attestation(
        create_attestation,
        intent=intent,
        target=target,
    )
    spec = intent["targets"][target]
    execute_operation_digest = digest_value(
        {
            "record_type": (
                "scanalyze.platform_authority."
                "plan_permission_repair_execute_operation.v1"
            ),
            "source_commit": intent["source_commit"],
            "target": target,
            "account_id": spec["account_id"],
            "stack_arn": attestation["stack_arn"],
            "change_set_arn": attestation["change_set_arn"],
        }
    )
    request = {
        "StackName": attestation["stack_arn"],
        "ChangeSetName": attestation["change_set_arn"],
        "ClientRequestToken": "gug376-" + execute_operation_digest[7:55],
    }
    if target == BROKER_PROTECTION_TARGET:
        request["DisableRollback"] = False
    result = {
        "schema_version": 1,
        "record_type": RECORD_TYPE_EXECUTION_INTENT,
        "source_commit": intent["source_commit"],
        "target": target,
        "account_id": spec["account_id"],
        "route_not_before": intent["route_not_before"],
        "route_not_after": intent["route_not_after"],
        "recovery_not_after": intent["recovery_not_after"],
        "authorization_not_before": authorization["authorized_at"],
        "authorization_expires_at": authorization["expires_at"],
        "parent_intent_digest": intent["intent_digest"],
        "create_attestation_digest": attestation["attestation_digest"],
        "authorization_digest": authorization["authorization_digest"],
        "execute_operation_digest": execute_operation_digest,
        "execute_request": request,
        "execute_request_digest": digest_value(request),
        "aws_calls": 0,
        "aws_mutations": 0,
        "execution_authorized": True,
        "retry_permitted": False,
        "production_authorized": False,
        "production_status": PRODUCTION_STATUS,
    }
    return seal(result, "execution_intent_digest")


def validate_execution_intent(value: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != _EXECUTION_INTENT_FIELDS:
        raise RouteSeedError("EXECUTION_INTENT_FIELDS_INVALID")
    _verify_seal(value, "execution_intent_digest", "EXECUTION_INTENT_DIGEST_INVALID")
    if (
        value.get("schema_version") != 1
        or value.get("record_type") != RECORD_TYPE_EXECUTION_INTENT
        or _COMMIT_RE.fullmatch(str(value.get("source_commit", ""))) is None
        or value.get("target") not in TARGETS
        or value.get("account_id")
        != _target_account_id(str(value.get("target")))
        or value.get("execute_request_digest") != digest_value(value.get("execute_request"))
        or value.get("aws_calls") != 0
        or value.get("aws_mutations") != 0
        or value.get("execution_authorized") is not True
        or value.get("retry_permitted") is not False
        or value.get("production_authorized") is not False
        or value.get("production_status") != PRODUCTION_STATUS
    ):
        raise RouteSeedError("EXECUTION_INTENT_INVALID")
    not_before = _parse_time(value.get("route_not_before"), "EXECUTION_INTENT_INVALID")
    not_after = _parse_time(value.get("route_not_after"), "EXECUTION_INTENT_INVALID")
    recovery_not_after = _parse_time(
        value.get("recovery_not_after"), "EXECUTION_INTENT_INVALID"
    )
    expires_at = _parse_time(
        value.get("authorization_expires_at"), "EXECUTION_INTENT_INVALID"
    )
    authorized_at = _parse_time(
        value.get("authorization_not_before"), "EXECUTION_INTENT_INVALID"
    )
    request = value.get("execute_request")
    target = str(value["target"])
    account_id = str(value["account_id"])
    if (
        recovery_not_after != not_after + timedelta(hours=24)
        or not not_before
        <= authorized_at
        < expires_at
        <= not_after - timedelta(seconds=MUTATION_COMPLETION_RESERVE_SECONDS)
        or not 60 <= (expires_at - authorized_at).total_seconds() <= 900
        or not isinstance(request, Mapping)
        or set(request)
        != (
            {
                "StackName",
                "ChangeSetName",
                "ClientRequestToken",
                "DisableRollback",
            }
            if target == BROKER_PROTECTION_TARGET
            else {"StackName", "ChangeSetName", "ClientRequestToken"}
        )
        or (
            target == BROKER_PROTECTION_TARGET
            and request.get("DisableRollback") is not False
        )
        or re.fullmatch(
            r"gug376-[0-9a-f]{48}", str(request.get("ClientRequestToken", ""))
        )
        is None
    ):
        raise RouteSeedError("EXECUTION_INTENT_INVALID")
    expected_operation_digest = digest_value(
        {
            "record_type": (
                "scanalyze.platform_authority."
                "plan_permission_repair_execute_operation.v1"
            ),
            "source_commit": value["source_commit"],
            "target": target,
            "account_id": account_id,
            "stack_arn": request["StackName"],
            "change_set_arn": request["ChangeSetName"],
        }
    )
    if (
        value.get("execute_operation_digest") != expected_operation_digest
        or request.get("ClientRequestToken")
        != "gug376-" + expected_operation_digest[7:55]
    ):
        raise RouteSeedError("EXECUTION_INTENT_INVALID")
    stack_name = ROUTE_STACK_NAME if target == "route" else BROKER_STACK_NAME
    change_set_name = {
        "route": ROUTE_CHANGE_SET_NAME,
        "broker": BROKER_CHANGE_SET_NAME,
        BROKER_PROTECTION_TARGET: BROKER_PROTECTION_CHANGE_SET_NAME,
    }[target]
    _full_arn(
        request.get("StackName"),
        account_id=account_id,
        kind="stack",
        name=stack_name,
    )
    _full_arn(
        request.get("ChangeSetName"),
        account_id=account_id,
        kind="changeSet",
        name=change_set_name,
    )
    return json.loads(canonical_json(value))


def validate_execution_intent_against_causal_records(
    value: Mapping[str, Any],
    *,
    seed_intent: Mapping[str, Any],
    create_attestation: Mapping[str, Any],
    authorization: Mapping[str, Any],
) -> dict[str, Any]:
    """Reconstruct one execute intent from its exact attestation and grant.

    This prevents a re-sealed execute intent from substituting a different
    same-name change-set ARN while retaining a superficially valid token and
    parent digest.
    """

    observed = validate_execution_intent(value)
    expected = materialize_execution_intent(
        seed_intent=seed_intent,
        create_attestation=create_attestation,
        authorization=authorization,
    )
    if observed != expected:
        raise RouteSeedError("EXECUTION_CAUSAL_BINDING_INVALID")
    return observed


__all__ = [
    "AUTHORITY_ACCOUNT_ID",
    "BROKER_CHANGE_SET_NAME",
    "BROKER_PROTECTION_CHANGE_SET_NAME",
    "BROKER_PROTECTION_TARGET",
    "BROKER_STACK_NAME",
    "BROKER_TEMPLATE_PATH",
    "DELEGATION_TEMPLATE_PATH",
    "EXACT_TAGS",
    "GitPort",
    "MANAGEMENT_ACCOUNT_ID",
    "MIN_ROUTE_WINDOW_SECONDS",
    "MUTATION_COMPLETION_RESERVE_SECONDS",
    "PRODUCTION_STATUS",
    "RECORD_TYPE_CREATE_ATTESTATION",
    "RECORD_TYPE_CREATION_AUTHORIZATION",
    "RECORD_TYPE_EXECUTION_AUTHORIZATION",
    "RECORD_TYPE_EXECUTION_INTENT",
    "RECORD_TYPE_INPUT",
    "RECORD_TYPE_INTENT",
    "REGION",
    "ROUTE_ASSIGNMENT_COUNT",
    "ROUTE_CHANGE_SET_NAME",
    "ROUTE_PARAMETER_KEYS",
    "ROUTE_RESOURCE_COUNT",
    "ROUTE_STACK_NAME",
    "ROUTE_TEMPLATE_PATH",
    "RouteSeedError",
    "SubprocessGit",
    "TARGETS",
    "bytes_digest",
    "canonical_json",
    "digest_value",
    "materialize_execution_authorization",
    "materialize_creation_authorization",
    "materialize_execution_intent",
    "materialize_seed_intent",
    "seal",
    "validate_create_attestation",
    "validate_creation_authorization",
    "validate_execution_authorization",
    "validate_execution_intent",
    "validate_execution_intent_against_causal_records",
    "validate_input",
    "validate_seed_intent",
    "validate_seed_intent_against_git",
    "validate_seed_intent_against_input",
]
