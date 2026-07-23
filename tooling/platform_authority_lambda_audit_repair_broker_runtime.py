"""AWS adapters and orchestration for the private GUG-221 repair broker.

This module intentionally exposes one content-free Lambda handler.  It never
uses request data to select accounts, principals, permission sets, roles,
policies, modes, or effects.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import time
from typing import Any, Callable, Mapping, Protocol
from urllib.parse import unquote

try:  # Support both package-style tests and direct tooling imports.
    from .platform_authority_lambda_audit_repair_broker import (
        AUTHORITY_ACCOUNT_ID,
        COLLECTOR_INLINE_POLICY_NAME,
        COLLECTOR_PERMISSION_SET_NAME,
        COLLECTOR_ROLE_PREFIX,
        MANAGEMENT_ACCOUNT_ID,
        PLAN_FUNCTION_NAME,
        PROVIDER_DERIVED_FUNCTION_VERSION,
        PRIVATE_LEDGER_TYPE,
        READ_FUNCTION_NAME,
        REPAIR_FUNCTION_NAME,
        REPAIR_INVOKER_ROLE_PREFIX,
        REGION,
        SCHEMA_VERSION,
        Assignment,
        BrokerLiveSnapshot,
        BrokerConfig,
        BrokerContractError,
        CollectorRole,
        LiveSnapshot,
        RepairInvokerSnapshot,
        build_private_intent,
        build_private_ledger_claim,
        build_public_receipt,
        canonical_digest,
        canonical_json,
        sanitized_blocked_state_digest,
        parse_utc_timestamp,
        utc_timestamp,
        validate_empty_event,
        validate_invocation,
        validate_repair_invoker_snapshot,
        validate_snapshot,
        validate_time,
    )
    from .platform_authority_lambda_invocation_authority import (
        AuthorityInventoryError,
        AwsReadOnlyInventoryAdapter,
        TargetBinding,
        digest_text,
    )
    from .platform_authority_lambda_audit_repair_invocation_authority import (
        RepairInvocationAuthorityBinding,
        VerifiedRepairInvocationAuthority,
        collect_provider_invocation_snapshots,
        require_stable_authority,
        verify_provider_invocation_authority,
    )
    from .platform_authority_lambda_invocation_materializer import (
        BROKER_FUNCTION_NAME as COLLECTOR_TARGET_FUNCTION_NAME,
        LambdaAuthorityMaterializationError,
        render_collector_inline_policy,
    )
    from .platform_authority_lambda_audit_repair_iam_verifier import (
        AwsIamEffectiveVerifier,
        IamEffectiveSnapshot,
        IamEffectiveVerifierPort,
        validate_iam_effective_snapshot,
    )
except ImportError:  # pragma: no cover - exercised by deployment entrypoints.
    from platform_authority_lambda_audit_repair_broker import (  # type: ignore
        AUTHORITY_ACCOUNT_ID,
        COLLECTOR_INLINE_POLICY_NAME,
        COLLECTOR_PERMISSION_SET_NAME,
        COLLECTOR_ROLE_PREFIX,
        MANAGEMENT_ACCOUNT_ID,
        PLAN_FUNCTION_NAME,
        PROVIDER_DERIVED_FUNCTION_VERSION,
        PRIVATE_LEDGER_TYPE,
        READ_FUNCTION_NAME,
        REPAIR_FUNCTION_NAME,
        REPAIR_INVOKER_ROLE_PREFIX,
        REGION,
        SCHEMA_VERSION,
        Assignment,
        BrokerLiveSnapshot,
        BrokerConfig,
        BrokerContractError,
        CollectorRole,
        LiveSnapshot,
        RepairInvokerSnapshot,
        build_private_intent,
        build_private_ledger_claim,
        build_public_receipt,
        canonical_digest,
        canonical_json,
        sanitized_blocked_state_digest,
        parse_utc_timestamp,
        utc_timestamp,
        validate_empty_event,
        validate_invocation,
        validate_repair_invoker_snapshot,
        validate_snapshot,
        validate_time,
    )
    from platform_authority_lambda_invocation_authority import (  # type: ignore
        AuthorityInventoryError,
        AwsReadOnlyInventoryAdapter,
        TargetBinding,
        digest_text,
    )
    from platform_authority_lambda_audit_repair_invocation_authority import (  # type: ignore
        RepairInvocationAuthorityBinding,
        VerifiedRepairInvocationAuthority,
        collect_provider_invocation_snapshots,
        require_stable_authority,
        verify_provider_invocation_authority,
    )
    from platform_authority_lambda_invocation_materializer import (  # type: ignore
        BROKER_FUNCTION_NAME as COLLECTOR_TARGET_FUNCTION_NAME,
        LambdaAuthorityMaterializationError,
        render_collector_inline_policy,
    )
    from platform_authority_lambda_audit_repair_iam_verifier import (  # type: ignore
        AwsIamEffectiveVerifier,
        IamEffectiveSnapshot,
        IamEffectiveVerifierPort,
        validate_iam_effective_snapshot,
    )


COLLECTOR_POLICY_RELATIVE_PATH = Path(
    "policies/iam/platform-authority-lambda-invocation-inventory-role.json"
)
REPAIR_INVOKER_POLICY_RELATIVE_PATH = Path(
    "policies/iam/platform-authority-lambda-audit-repair-invoker-role.json"
)
RUNTIME_LOCK_RELATIVE_PATH = Path("gug221_runtime_lock.json")
RUNTIME_LOCK_RECORD_TYPE = (
    "scanalyze.platform_authority.lambda_audit_repair_runtime_lock.v1"
)
EFFECTS = (
    "PUT_INLINE_POLICY",
    "CREATE_ACCOUNT_ASSIGNMENT",
    "PROVISION_PERMISSION_SET",
)
SDK_CONNECT_TIMEOUT_SECONDS = 3
SDK_READ_TIMEOUT_SECONDS = 8
FUNCTION_TIMEOUT_SECONDS = {
    "plan": 300,
    "repair": 600,
    "reconcile": 300,
}
FUNCTION_MEMORY_SIZE_MB = 1024
INVENTORY_PROVIDER_CALL_RESERVE_MS = 60_000
LAMBDA_POLLING_RESERVE_MS = 60_000
LAMBDA_MUTATION_DISPATCH_MIN_REMAINING_MS = 75_000
REPAIR_CLAIM_MIN_REMAINING_MS = 480_000
MUTATION_WINDOW_MIN_REMAINING_SECONDS = 75
REPAIR_START_MIN_WINDOW_REMAINING_SECONDS = 660
SYNC_CLIENT_CONTEXT_CUSTOM = {
    "scanalyze_transport": "REQUEST_RESPONSE",
    "scanalyze_work_package": "GUG-221",
}
_PUBLIC_ERROR_CODE_RE = re.compile(r"^[A-Z][A-Z0-9_]{0,63}$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_FUNCTION_VERSION_RE = re.compile(r"^[1-9][0-9]*$")
_KMS_KEY_ID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
)
REPAIR_FUNCTION_DESCRIPTION = (
    "GUG-221 exact one-shot Lambda audit provisioning repair PEP"
)
PLAN_FUNCTION_DESCRIPTION = (
    "GUG-221 read-only plan proof and create-only ledger gate"
)
READ_FUNCTION_DESCRIPTION = "GUG-221 read-only reconciliation PEP"
REPAIR_FUNCTION_VERSION_DESCRIPTION = "GUG-221 reviewed immutable repair version"
PLAN_FUNCTION_VERSION_DESCRIPTION = "GUG-221 reviewed immutable plan version"
READ_FUNCTION_VERSION_DESCRIPTION = "GUG-221 reviewed immutable reconcile version"
REPAIR_FUNCTION_HANDLER = (
    "tooling.platform_authority_lambda_audit_repair_broker_runtime.repair_handler"
)
PLAN_FUNCTION_HANDLER = (
    "tooling.platform_authority_lambda_audit_repair_broker_runtime.plan_handler"
)
READ_FUNCTION_HANDLER = (
    "tooling.platform_authority_lambda_audit_repair_broker_runtime.reconcile_handler"
)
REPAIR_EXECUTION_ROLE_ARN = (
    "arn:aws:iam::042360977644:role/ScanalyzeLambdaAuditRepairExecution"
)
PLAN_EXECUTION_ROLE_ARN = (
    "arn:aws:iam::042360977644:role/ScanalyzeLambdaAuditRepairPlan"
)
READ_EXECUTION_ROLE_ARN = (
    "arn:aws:iam::042360977644:role/ScanalyzeLambdaAuditRepairReconcile"
)
INVOCATION_INSPECTOR_ROLE_NAME = (
    "ScanalyzeLambdaAuditRepairAuthorityInspector"
)
INVOCATION_INSPECTOR_ROLE_ARN = (
    "arn:aws:iam::042360977644:role/scanalyze/platform-authority/"
    f"{INVOCATION_INSPECTOR_ROLE_NAME}"
)
UNSUPPORTED_LEDGER_WRITE_ACTIONS = (
    "dynamodb:BatchWriteItem",
    "dynamodb:DeleteItem",
    "dynamodb:PartiQLDelete",
    "dynamodb:PartiQLInsert",
    "dynamodb:PartiQLUpdate",
    "dynamodb:TransactWriteItems",
)
PLAN_LEDGER_WRITE_ACTIONS = ("dynamodb:PutItem",)
REPAIR_LEDGER_WRITE_ACTIONS = ("dynamodb:UpdateItem",)
REPAIR_LEDGER_KEY_ALIAS = (
    "alias/scanalyze/platform-authority/gug221-repair-ledger"
)
REPAIR_LEDGER_KEY_TAGS = {
    "environment": "non-production",
    "managed_by": "cloudformation",
    "production": "false",
    "service": "scanalyze-platform-authority",
    "work_package": "GUG-221",
}


def _expected_repair_ledger_key_policy() -> dict[str, Any]:
    authority_root = f"arn:aws:iam::{AUTHORITY_ACCOUNT_ID}:root"
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "DelegateAdministrationToExactAuthorityAccount",
                "Effect": "Allow",
                "Principal": {"AWS": authority_root},
                "Action": "kms:*",
                "Resource": "*",
            },
            {
                "Sid": "PermitDynamoDbCryptographicUseOnlyFromAuthorityAccount",
                "Effect": "Allow",
                "Principal": {"AWS": authority_root},
                "Action": [
                    "kms:Decrypt",
                    "kms:DescribeKey",
                    "kms:Encrypt",
                    "kms:GenerateDataKey*",
                    "kms:ReEncrypt*",
                ],
                "Resource": "*",
                "Condition": {
                    "StringEquals": {
                        "kms:CallerAccount": AUTHORITY_ACCOUNT_ID,
                        "kms:ViaService": "dynamodb.us-east-1.amazonaws.com",
                        "kms:EncryptionContext:aws:dynamodb:tableName": (
                            "scanalyze-platform-authority-gug221-repair-ledger"
                        ),
                        "kms:EncryptionContext:aws:dynamodb:subscriberId": (
                            AUTHORITY_ACCOUNT_ID
                        ),
                    }
                },
            },
            {
                "Sid": "PermitDynamoDbGrantOnlyForAwsResource",
                "Effect": "Allow",
                "Principal": {"AWS": authority_root},
                "Action": "kms:CreateGrant",
                "Resource": "*",
                "Condition": {
                    "Bool": {"kms:GrantIsForAWSResource": "true"},
                    "StringEquals": {
                        "kms:CallerAccount": AUTHORITY_ACCOUNT_ID,
                        "kms:ViaService": "dynamodb.us-east-1.amazonaws.com",
                    },
                },
            },
        ],
    }


class ProviderResponseAmbiguous(RuntimeError):
    """A provider response cannot prove whether an effect occurred."""


class PublicBrokerFailure(RuntimeError):
    """Stable, sanitized Lambda error that contains no provider payload."""

    def __init__(self, code: str) -> None:
        super().__init__(f"GUG221_BROKER_BLOCKED:{code}")


class IdentityCenterPort(Protocol):
    def snapshot(
        self,
        config: BrokerConfig,
        collector_policy: Mapping[str, Any],
        repair_invoker_policy: Mapping[str, Any],
    ) -> BrokerLiveSnapshot: ...

    def put_inline_policy(self, config: BrokerConfig, policy_json: str) -> None: ...

    def create_account_assignment(self, config: BrokerConfig) -> "OperationResult": ...

    def describe_account_assignment(self, request_id: str) -> str: ...

    def provision_permission_set(self, config: BrokerConfig) -> "OperationResult": ...

    def describe_provisioning(self, request_id: str) -> str: ...


class LocalControlPlanePort(Protocol):
    def snapshot(self, config: BrokerConfig) -> "LocalControlPlaneSnapshot": ...


class InvocationAuthorityPort(Protocol):
    """Provider-derived proof of the complete GUG-221 invocation graph."""

    def snapshot(
        self, config: BrokerConfig, invoker: RepairInvokerSnapshot
    ) -> VerifiedRepairInvocationAuthority: ...


class LedgerPort(Protocol):
    def claim(self, claim: Mapping[str, Any]) -> None: ...

    def read(self, repair_id: str) -> Mapping[str, Any] | None: ...

    def transition(
        self,
        *,
        repair_id: str,
        intent_digest: str,
        ledger_digest: str,
        expected_ledger: Mapping[str, Any],
        expected_status: str,
        new_status: str,
        stage: str,
        effects_attempted: int,
        effects_completed: int,
        state_digest: str,
        updated_at: datetime,
        claimed_at: datetime | None = None,
    ) -> None: ...


@dataclass(frozen=True)
class LocalControlPlaneSnapshot:
    """Normalized proof of every local control-plane read granted to the PEP."""

    repair_function_version: str
    plan_function_version: str
    reconcile_function_version: str
    artifact_code_sha256: str
    code_signing_config_arn: str
    signing_profile_version_arn: str
    ledger_table_arn: str
    ledger_kms_key_arn: str
    lambda_controls_digest: str
    ledger_controls_digest: str
    kms_controls_digest: str

    def digest(self) -> str:
        return canonical_digest(
            {
                "repair_function_version": self.repair_function_version,
                "plan_function_version": self.plan_function_version,
                "reconcile_function_version": self.reconcile_function_version,
                "artifact_code_sha256": self.artifact_code_sha256,
                "code_signing_config_arn": self.code_signing_config_arn,
                "signing_profile_version_arn": self.signing_profile_version_arn,
                "ledger_table_arn": self.ledger_table_arn,
                "ledger_kms_key_arn": self.ledger_kms_key_arn,
                "lambda_controls_digest": self.lambda_controls_digest,
                "ledger_controls_digest": self.ledger_controls_digest,
                "kms_controls_digest": self.kms_controls_digest,
            }
        )


@dataclass(frozen=True)
class VerifiedBrokerLiveSnapshot:
    """Identity state plus an independently re-read local PEP control plane."""

    identity: BrokerLiveSnapshot
    local: LocalControlPlaneSnapshot
    iam: IamEffectiveSnapshot
    invocation_authority: VerifiedRepairInvocationAuthority

    @property
    def invoker(self) -> RepairInvokerSnapshot:
        return self.identity.invoker

    @property
    def collector(self) -> LiveSnapshot:
        return self.identity.collector

    def digest(self) -> str:
        return canonical_digest(
            {
                "identity_state_digest": self.identity.digest(),
                "local_control_plane_digest": self.local.digest(),
                "iam_effective_state_digest": self.iam.digest(),
                "invocation_authority_graph_digest": (
                    self.invocation_authority.authority_graph_digest
                ),
            }
        )


def validate_local_control_plane_snapshot(
    config: BrokerConfig, snapshot: LocalControlPlaneSnapshot
) -> None:
    expected_table_arn = (
        f"arn:aws:dynamodb:{REGION}:{AUTHORITY_ACCOUNT_ID}:"
        f"table/{config.ledger_table_name}"
    )
    exact = (
        (snapshot.repair_function_version, config.repair_function_version),
        (snapshot.artifact_code_sha256, config.expected_artifact_code_sha256),
        (snapshot.code_signing_config_arn, config.expected_code_signing_config_arn),
        (
            snapshot.signing_profile_version_arn,
            config.expected_signing_profile_version_arn,
        ),
        (snapshot.ledger_table_arn, expected_table_arn),
        (snapshot.ledger_kms_key_arn, config.repair_ledger_kms_key_arn),
    )
    if any(observed != expected for observed, expected in exact):
        raise BrokerContractError(
            "LOCAL_CONTROL_PLANE_MISMATCH",
            "local PEP control-plane binding differs from immutable configuration",
        )
    if config.mode == "plan" and snapshot.plan_function_version != config.function_version:
        raise BrokerContractError(
            "LOCAL_FUNCTION_VERSION_MISMATCH",
            "the executing plan version differs from the private Plan alias",
        )
    if (
        config.mode == "reconcile"
        and snapshot.reconcile_function_version != config.function_version
    ):
        raise BrokerContractError(
            "LOCAL_FUNCTION_VERSION_MISMATCH",
            "the executing reconcile version differs from the private Reconcile alias",
        )
    if config.mode == "repair" and config.function_version != config.repair_function_version:
        raise BrokerContractError(
            "LOCAL_FUNCTION_VERSION_MISMATCH",
            "the executing repair version differs from the immutable repair version",
        )
    if not all(
        _FUNCTION_VERSION_RE.fullmatch(item)
        for item in (
            snapshot.repair_function_version,
            snapshot.plan_function_version,
            snapshot.reconcile_function_version,
        )
    ):
        raise BrokerContractError(
            "LOCAL_FUNCTION_VERSION_MISMATCH",
            "all private aliases must target published numeric versions",
        )
    if any(
        not _SHA256_RE.fullmatch(item)
        for item in (
            snapshot.lambda_controls_digest,
            snapshot.ledger_controls_digest,
            snapshot.kms_controls_digest,
        )
    ):
        raise BrokerContractError(
            "LOCAL_CONTROL_PLANE_MALFORMED",
            "local PEP control-plane evidence digest is malformed",
        )


@dataclass(frozen=True)
class OperationResult:
    request_id: str
    status: str


def _provider_code(error: BaseException) -> str | None:
    response = getattr(error, "response", None)
    if isinstance(response, Mapping):
        details = response.get("Error")
        if isinstance(details, Mapping) and isinstance(details.get("Code"), str):
            return details["Code"]
    return None


def _normalize_policy(value: Any) -> Mapping[str, Any]:
    if isinstance(value, str):
        text = unquote(value)
        try:
            value = json.loads(text)
        except json.JSONDecodeError as exc:
            raise BrokerContractError("MALFORMED_POLICY", "provider policy is malformed") from exc
    if not isinstance(value, Mapping):
        raise BrokerContractError("MALFORMED_POLICY", "provider policy must be an object")
    return dict(value)


def _load_bundled_policy(relative_path: Path, repo_root: Path | None = None) -> Mapping[str, Any]:
    root = repo_root or Path(__file__).resolve().parents[1]
    path = root / relative_path
    try:
        raw = path.read_text(encoding="utf-8")
        value = json.loads(raw)
    except (OSError, json.JSONDecodeError) as exc:
        raise BrokerContractError("BUNDLED_POLICY_UNREADABLE", "bundled collector policy is unavailable") from exc
    if not isinstance(value, dict):
        raise BrokerContractError("MALFORMED_POLICY", "bundled collector policy must be an object")
    return value


def load_bundled_collector_policy(repo_root: Path | None = None) -> Mapping[str, Any]:
    """Render the reviewed GUG-219 collector policy for the exact live target.

    The repository policy is deliberately a template.  Hashing or submitting
    it before rendering would either authorize unusable literal placeholders
    or make the configured digest describe a different document than the one
    delivered to Identity Center.
    """

    root = repo_root or Path(__file__).resolve().parents[1]
    try:
        return render_collector_inline_policy(
            binding=TargetBinding(
                authority_account_id=AUTHORITY_ACCOUNT_ID,
                region=REGION,
                function_name=COLLECTOR_TARGET_FUNCTION_NAME,
            ),
            repo_root=root,
        )
    except (AuthorityInventoryError, LambdaAuthorityMaterializationError) as exc:
        raise BrokerContractError(
            "BUNDLED_POLICY_UNREADABLE",
            "bundled collector policy cannot be rendered for the reviewed target",
        ) from exc


def load_bundled_repair_invoker_policy(repo_root: Path | None = None) -> Mapping[str, Any]:
    """Read exactly the reviewed human invoker policy bundled with the artifact."""

    return _load_bundled_policy(REPAIR_INVOKER_POLICY_RELATIVE_PATH, repo_root)


def expected_runtime_lock(config: BrokerConfig) -> dict[str, Any]:
    """Return the only runtime dependency lock accepted by this artifact."""

    return {
        "schema_version": 1,
        "record_type": RUNTIME_LOCK_RECORD_TYPE,
        "source_commit": config.source_commit,
        "expected_boto3_version": config.expected_boto3_version,
        "expected_botocore_version": config.expected_botocore_version,
    }


def validate_runtime_lock(
    config: BrokerConfig, *, repo_root: Path | None = None
) -> None:
    """Prove env dependency pins came from the immutable Lambda ZIP."""

    root = repo_root or Path(__file__).resolve().parents[1]
    path = root / RUNTIME_LOCK_RELATIVE_PATH

    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise BrokerContractError(
                    "RUNTIME_LOCK_INVALID", "runtime dependency lock is malformed"
                )
            result[key] = value
        return result

    try:
        value = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=reject_duplicates,
        )
    except BrokerContractError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise BrokerContractError(
            "RUNTIME_LOCK_UNAVAILABLE", "runtime dependency lock is unavailable"
        ) from exc
    if type(value) is not dict or value != expected_runtime_lock(config):
        raise BrokerContractError(
            "RUNTIME_LOCK_MISMATCH",
            "runtime dependency lock differs from immutable configuration",
        )


def _assert_policy_binding(config: BrokerConfig, policy: Mapping[str, Any]) -> str:
    digest = canonical_digest(policy)
    if digest != config.collector_policy_digest:
        raise BrokerContractError("BUNDLED_POLICY_DIGEST_MISMATCH", "bundled policy digest differs")
    return canonical_json(policy)


def _assert_repair_invoker_policy_binding(
    config: BrokerConfig, policy: Mapping[str, Any]
) -> None:
    if canonical_digest(policy) != config.repair_invoker_policy_digest:
        raise BrokerContractError(
            "BUNDLED_INVOKER_POLICY_DIGEST_MISMATCH",
            "bundled repair invoker policy digest differs",
        )


def _strict_json_object(value: Any, code: str) -> dict[str, Any]:
    if isinstance(value, Mapping):
        return dict(value)
    if not isinstance(value, str):
        raise BrokerContractError(code, "provider policy is not a JSON object")

    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, item in pairs:
            if key in result:
                raise BrokerContractError(code, "provider policy has duplicate keys")
            result[key] = item
        return result

    try:
        parsed = json.loads(value, object_pairs_hook=reject_duplicates)
    except BrokerContractError:
        raise
    except json.JSONDecodeError as exc:
        raise BrokerContractError(code, "provider policy is malformed") from exc
    if type(parsed) is not dict:
        raise BrokerContractError(code, "provider policy is not a JSON object")
    return parsed


class AwsLocalControlPlaneAdapter:
    """Re-read and prove the exact local Lambda, DynamoDB, and KMS controls."""

    def __init__(
        self,
        *,
        lambda_client: Any,
        dynamodb: Any,
        kms: Any,
    ) -> None:
        self._lambda = lambda_client
        self._dynamodb = dynamodb
        self._kms = kms

    @staticmethod
    def _mapping(value: Any, code: str) -> Mapping[str, Any]:
        if not isinstance(value, Mapping):
            raise BrokerContractError(code, "provider control-plane response is malformed")
        return value

    @staticmethod
    def _expected_environment(
        config: BrokerConfig, *, function_kind: str
    ) -> dict[str, str]:
        expected = {
            "SOURCE_COMMIT": config.source_commit,
            "REPAIR_ID": config.repair_id,
            "PRINCIPAL_ID": config.principal_id,
            "IDENTITY_STORE_ID": config.identity_store_id,
            "IDENTITY_CENTER_INSTANCE_ARN": config.instance_arn,
            "COLLECTOR_PERMISSION_SET_ARN": config.collector_permission_set_arn,
            "REPAIR_INVOKER_PERMISSION_SET_ARN": (
                config.repair_invoker_permission_set_arn
            ),
            "COLLECTOR_POLICY_DIGEST": config.collector_policy_digest,
            "REPAIR_INVOKER_POLICY_DIGEST": config.repair_invoker_policy_digest,
            "ORIGINAL_GUG220_LEDGER_DIGEST": (
                config.original_gug220_ledger_digest
            ),
            "EXPECTED_PERMISSION_SET_TAGS_JSON": (
                config.expected_permission_set_tags_json
            ),
            "REPAIR_LEDGER_TABLE_NAME": config.ledger_table_name,
            "REPAIR_LEDGER_KMS_KEY_ARN": config.repair_ledger_kms_key_arn,
            "REPAIR_NOT_BEFORE": utc_timestamp(config.not_before),
            "REPAIR_NOT_AFTER": utc_timestamp(config.not_after),
            "COLLECTOR_SAML_PROVIDER_ARN": config.collector_saml_provider_arn,
            "IDENTITY_CENTER_KMS_MODE": config.identity_center_kms_mode,
            "IDENTITY_CENTER_KMS_KEY_ARN": (
                config.identity_center_kms_key_arn or ""
            ),
            "EXPECTED_BOTO3_VERSION": config.expected_boto3_version,
            "EXPECTED_BOTOCORE_VERSION": config.expected_botocore_version,
            "EXPECTED_ARTIFACT_CODE_SHA256": (
                config.expected_artifact_code_sha256
            ),
            "EXPECTED_CODE_SIGNING_CONFIG_ARN": (
                config.expected_code_signing_config_arn
            ),
            "EXPECTED_SIGNING_PROFILE_VERSION_ARN": (
                config.expected_signing_profile_version_arn
            ),
        }
        if function_kind == "reconcile":
            expected["REPAIR_FUNCTION_VERSION"] = config.repair_function_version
        if function_kind in {"repair", "reconcile"}:
            expected["PLAN_FUNCTION_VERSION"] = config.plan_function_version
        return expected

    def _alias(self, function_name: str, alias_name: str) -> Mapping[str, Any]:
        response = self._mapping(
            self._lambda.get_alias(FunctionName=function_name, Name=alias_name),
            "LAMBDA_ALIAS_READ_MALFORMED",
        )
        expected_arn = (
            f"arn:aws:lambda:{REGION}:{AUTHORITY_ACCOUNT_ID}:"
            f"function:{function_name}:{alias_name}"
        )
        version = response.get("FunctionVersion")
        routing = response.get("RoutingConfig")
        if (
            response.get("AliasArn") != expected_arn
            or response.get("Name") != alias_name
            or not isinstance(version, str)
            or _FUNCTION_VERSION_RE.fullmatch(version) is None
            or response.get("Description") not in (None, "")
            or routing not in (None, {}, {"AdditionalVersionWeights": {}})
        ):
            raise BrokerContractError(
                "LAMBDA_ALIAS_CONTROLS_CHANGED",
                "private Lambda alias binding or routing differs",
            )
        return {
            "alias_arn": expected_arn,
            "name": alias_name,
            "function_version": version,
            "routing": {},
        }

    def _function(
        self,
        *,
        config: BrokerConfig,
        function_name: str,
        qualifier: str | None,
        version: str,
        function_kind: str,
    ) -> Mapping[str, Any]:
        kwargs: dict[str, str] = {"FunctionName": function_name}
        if qualifier is not None:
            kwargs["Qualifier"] = qualifier
        response = self._mapping(
            self._lambda.get_function_configuration(**kwargs),
            "LAMBDA_CONFIGURATION_READ_MALFORMED",
        )
        base_arn = (
            f"arn:aws:lambda:{REGION}:{AUTHORITY_ACCOUNT_ID}:"
            f"function:{function_name}"
        )
        expected_arn = base_arn if version == "$LATEST" else f"{base_arn}:{version}"
        expected_role = {
            "plan": PLAN_EXECUTION_ROLE_ARN,
            "repair": REPAIR_EXECUTION_ROLE_ARN,
            "reconcile": READ_EXECUTION_ROLE_ARN,
        }[function_kind]
        expected_handler = {
            "plan": PLAN_FUNCTION_HANDLER,
            "repair": REPAIR_FUNCTION_HANDLER,
            "reconcile": READ_FUNCTION_HANDLER,
        }[function_kind]
        expected_description = (
            {
                "plan": PLAN_FUNCTION_DESCRIPTION,
                "repair": REPAIR_FUNCTION_DESCRIPTION,
                "reconcile": READ_FUNCTION_DESCRIPTION,
            }
            if version == "$LATEST"
            else {
                "plan": PLAN_FUNCTION_VERSION_DESCRIPTION,
                "repair": REPAIR_FUNCTION_VERSION_DESCRIPTION,
                "reconcile": READ_FUNCTION_VERSION_DESCRIPTION,
            }
        )[function_kind]
        expected_timeout = FUNCTION_TIMEOUT_SECONDS[function_kind]
        environment = self._mapping(
            response.get("Environment"), "LAMBDA_ENVIRONMENT_CHANGED"
        )
        variables = environment.get("Variables")
        if (
            environment.get("Error") not in (None, {})
            or type(variables) is not dict
            or variables
            != self._expected_environment(config, function_kind=function_kind)
        ):
            raise BrokerContractError(
                "LAMBDA_ENVIRONMENT_CHANGED",
                "published Lambda environment differs from immutable configuration",
            )
        vpc = response.get("VpcConfig")
        if vpc not in (None, {}):
            vpc = self._mapping(vpc, "LAMBDA_CONFIGURATION_CHANGED")
            if (
                vpc.get("SubnetIds") not in (None, [])
                or vpc.get("SecurityGroupIds") not in (None, [])
                or vpc.get("VpcId") not in (None, "")
                or vpc.get("Ipv6AllowedForDualStack") not in (None, False)
            ):
                raise BrokerContractError(
                    "LAMBDA_CONFIGURATION_CHANGED",
                    "Lambda VPC binding differs from the reviewed topology",
                )
        logging = response.get("LoggingConfig")
        if logging not in (None, {}):
            logging = self._mapping(logging, "LAMBDA_CONFIGURATION_CHANGED")
            expected_log_group = f"/aws/lambda/{function_name}"
            if (
                logging.get("LogFormat") not in (None, "Text")
                or logging.get("LogGroup") not in (None, expected_log_group)
                or logging.get("ApplicationLogLevel") not in (None, "")
                or logging.get("SystemLogLevel") not in (None, "", "INFO")
            ):
                raise BrokerContractError(
                    "LAMBDA_CONFIGURATION_CHANGED",
                    "Lambda logging controls differ from the reviewed topology",
                )
        snap_start = response.get("SnapStart")
        if snap_start not in (None, {}):
            snap_start = self._mapping(
                snap_start, "LAMBDA_CONFIGURATION_CHANGED"
            )
            if snap_start != {"ApplyOn": "None", "OptimizationStatus": "Off"}:
                raise BrokerContractError(
                    "LAMBDA_CONFIGURATION_CHANGED",
                    "Lambda SnapStart controls differ from the reviewed topology",
                )
        exact = {
            "FunctionName": function_name,
            "FunctionArn": expected_arn,
            "Runtime": "python3.12",
            "Role": expected_role,
            "Handler": expected_handler,
            "Description": expected_description,
            "Timeout": expected_timeout,
            "MemorySize": FUNCTION_MEMORY_SIZE_MB,
            "CodeSha256": config.expected_artifact_code_sha256,
            "Version": version,
            "State": "Active",
            "LastUpdateStatus": "Successful",
            "PackageType": "Zip",
            "Architectures": ["x86_64"],
        }
        if any(response.get(key) != value for key, value in exact.items()):
            raise BrokerContractError(
                "LAMBDA_CONFIGURATION_CHANGED",
                "published Lambda code or runtime configuration differs",
            )
        if (
            response.get("DeadLetterConfig") not in (None, {})
            or response.get("KMSKeyArn") not in (None, "")
            or response.get("Layers") not in (None, [])
            or response.get("FileSystemConfigs") not in (None, [])
            or response.get("MasterArn") not in (None, "")
            or response.get("ImageConfigResponse") not in (None, {})
            or response.get("TracingConfig") != {"Mode": "PassThrough"}
            or response.get("EphemeralStorage") != {"Size": 512}
        ):
            raise BrokerContractError(
                "LAMBDA_CONFIGURATION_CHANGED",
                "Lambda side-channel or storage configuration differs",
            )
        signing_profile_version_arn = response.get("SigningProfileVersionArn")
        if (
            not isinstance(signing_profile_version_arn, str)
            or signing_profile_version_arn
            != config.expected_signing_profile_version_arn
        ):
            raise BrokerContractError(
                "LAMBDA_SIGNER_BINDING_CHANGED",
                "published Lambda signer binding is absent or malformed",
            )
        return {
            "function_name": function_name,
            "qualifier": qualifier or "$LATEST",
            "function_arn": expected_arn,
            "version": version,
            "runtime": response["Runtime"],
            "role": response["Role"],
            "handler": response["Handler"],
            "description": response["Description"],
            "timeout": response["Timeout"],
            "memory_size": response["MemorySize"],
            "code_sha256": response["CodeSha256"],
            "signing_profile_version_arn": signing_profile_version_arn,
            "state": response["State"],
            "last_update_status": response["LastUpdateStatus"],
            "package_type": response["PackageType"],
            "architectures": response["Architectures"],
            "environment": variables,
            "vpc": {},
            "dead_letter": {},
            "tracing": response["TracingConfig"],
            "ephemeral_storage": response["EphemeralStorage"],
            "snap_start": snap_start or {},
            "logging": logging or {},
        }

    @staticmethod
    def _page_marker(
        response: Mapping[str, Any],
        *,
        seen: set[str],
        code: str,
    ) -> str | None:
        marker = response.get("NextMarker")
        if marker is None:
            return None
        if not isinstance(marker, str) or not marker or marker in seen:
            raise BrokerContractError(code, "Lambda inventory pagination is malformed")
        seen.add(marker)
        return marker

    def _function_inventory(
        self,
        expected_versions: Mapping[str, set[str]],
    ) -> tuple[Mapping[str, str], ...]:
        """Prove that the two PEP roles are not reusable by another function.

        ``lambda:SourceFunctionArn`` deliberately uses an unqualified ARN, so
        every version of the same function shares that condition value.  The
        account-wide inventory is therefore part of the authorization proof,
        not operational discovery.
        """

        expected_roles = {
            REPAIR_FUNCTION_NAME: REPAIR_EXECUTION_ROLE_ARN,
            PLAN_FUNCTION_NAME: PLAN_EXECUTION_ROLE_ARN,
            READ_FUNCTION_NAME: READ_EXECUTION_ROLE_ARN,
        }
        protected_roles = set(expected_roles.values())
        observed: dict[tuple[str, str], Mapping[str, str]] = {}
        marker: str | None = None
        seen_markers: set[str] = set()
        for _ in range(100):
            kwargs: dict[str, Any] = {
                "FunctionVersion": "ALL",
                "MaxItems": 50,
            }
            if marker is not None:
                kwargs["Marker"] = marker
            response = self._mapping(
                self._lambda.list_functions(**kwargs),
                "LAMBDA_FUNCTION_INVENTORY_MALFORMED",
            )
            functions = response.get("Functions")
            if not isinstance(functions, list):
                raise BrokerContractError(
                    "LAMBDA_FUNCTION_INVENTORY_MALFORMED",
                    "Lambda function inventory is malformed",
                )
            for raw in functions:
                item = self._mapping(
                    raw, "LAMBDA_FUNCTION_INVENTORY_MALFORMED"
                )
                name = item.get("FunctionName")
                version = item.get("Version")
                role = item.get("Role")
                function_arn = item.get("FunctionArn")
                if (
                    not isinstance(name, str)
                    or not name
                    or not isinstance(version, str)
                    or (
                        version != "$LATEST"
                        and _FUNCTION_VERSION_RE.fullmatch(version) is None
                    )
                    or not isinstance(role, str)
                    or not role
                    or not isinstance(function_arn, str)
                ):
                    raise BrokerContractError(
                        "LAMBDA_FUNCTION_INVENTORY_MALFORMED",
                        "Lambda function inventory is malformed",
                    )
                base_arn = (
                    f"arn:aws:lambda:{REGION}:{AUTHORITY_ACCOUNT_ID}:"
                    f"function:{name}"
                )
                expected_arn = (
                    base_arn if version == "$LATEST" else f"{base_arn}:{version}"
                )
                if function_arn != expected_arn:
                    raise BrokerContractError(
                        "LAMBDA_FUNCTION_INVENTORY_MALFORMED",
                        "Lambda function inventory ARN is malformed",
                    )
                key = (name, version)
                if key in observed:
                    raise BrokerContractError(
                        "LAMBDA_FUNCTION_INVENTORY_MALFORMED",
                        "Lambda function inventory contains duplicate entries",
                    )
                if role in protected_roles and name not in expected_roles:
                    raise BrokerContractError(
                        "LAMBDA_EXECUTION_ROLE_REUSED",
                        "a protected Lambda execution role is used by another function",
                    )
                if name in expected_roles:
                    if (
                        role != expected_roles[name]
                        or version not in expected_versions[name]
                    ):
                        raise BrokerContractError(
                            "LAMBDA_ALTERNATE_PEP_PRESENT",
                            "a reviewed Lambda has an unexpected version or execution role",
                        )
                    observed[key] = {
                        "function_name": name,
                        "function_arn": function_arn,
                        "version": version,
                        "role": role,
                    }
            marker = self._page_marker(
                response,
                seen=seen_markers,
                code="LAMBDA_FUNCTION_INVENTORY_MALFORMED",
            )
            if marker is None:
                expected = {
                    (name, version)
                    for name, versions in expected_versions.items()
                    for version in versions
                }
                if set(observed) != expected:
                    raise BrokerContractError(
                        "LAMBDA_ALTERNATE_PEP_PRESENT",
                        "reviewed Lambda versions are missing or unexpected",
                    )
                return tuple(observed[key] for key in sorted(observed))
        raise BrokerContractError(
            "LAMBDA_FUNCTION_INVENTORY_EXCEEDED",
            "Lambda function inventory exceeded the bounded page limit",
        )

    def _version_inventory(
        self,
        *,
        function_name: str,
        expected_role: str,
        expected_versions: set[str],
    ) -> tuple[Mapping[str, str], ...]:
        observed: dict[str, Mapping[str, str]] = {}
        marker: str | None = None
        seen_markers: set[str] = set()
        for _ in range(100):
            kwargs: dict[str, Any] = {
                "FunctionName": function_name,
                "MaxItems": 50,
            }
            if marker is not None:
                kwargs["Marker"] = marker
            response = self._mapping(
                self._lambda.list_versions_by_function(**kwargs),
                "LAMBDA_VERSION_INVENTORY_MALFORMED",
            )
            versions = response.get("Versions")
            if not isinstance(versions, list):
                raise BrokerContractError(
                    "LAMBDA_VERSION_INVENTORY_MALFORMED",
                    "Lambda version inventory is malformed",
                )
            for raw in versions:
                item = self._mapping(raw, "LAMBDA_VERSION_INVENTORY_MALFORMED")
                name = item.get("FunctionName")
                version = item.get("Version")
                role = item.get("Role")
                function_arn = item.get("FunctionArn")
                if (
                    name != function_name
                    or not isinstance(version, str)
                    or (
                        version != "$LATEST"
                        and _FUNCTION_VERSION_RE.fullmatch(version) is None
                    )
                    or role != expected_role
                    or not isinstance(function_arn, str)
                    or version in observed
                ):
                    raise BrokerContractError(
                        "LAMBDA_VERSION_INVENTORY_MALFORMED",
                        "Lambda version inventory is malformed",
                    )
                base_arn = (
                    f"arn:aws:lambda:{REGION}:{AUTHORITY_ACCOUNT_ID}:"
                    f"function:{function_name}"
                )
                expected_arn = (
                    base_arn if version == "$LATEST" else f"{base_arn}:{version}"
                )
                if function_arn != expected_arn:
                    raise BrokerContractError(
                        "LAMBDA_VERSION_INVENTORY_MALFORMED",
                        "Lambda version inventory ARN is malformed",
                    )
                observed[version] = {
                    "function_name": function_name,
                    "function_arn": function_arn,
                    "version": version,
                    "role": expected_role,
                }
            marker = self._page_marker(
                response,
                seen=seen_markers,
                code="LAMBDA_VERSION_INVENTORY_MALFORMED",
            )
            if marker is None:
                if set(observed) != expected_versions:
                    raise BrokerContractError(
                        "LAMBDA_ALTERNATE_PEP_PRESENT",
                        "Lambda version set differs from the reviewed set",
                    )
                return tuple(observed[key] for key in sorted(observed))
        raise BrokerContractError(
            "LAMBDA_VERSION_INVENTORY_EXCEEDED",
            "Lambda version inventory exceeded the bounded page limit",
        )

    def _alias_inventory(
        self,
        *,
        function_name: str,
        expected_aliases: Mapping[str, str],
    ) -> tuple[Mapping[str, str], ...]:
        observed: dict[str, Mapping[str, str]] = {}
        marker: str | None = None
        seen_markers: set[str] = set()
        for _ in range(100):
            kwargs: dict[str, Any] = {
                "FunctionName": function_name,
                "MaxItems": 50,
            }
            if marker is not None:
                kwargs["Marker"] = marker
            response = self._mapping(
                self._lambda.list_aliases(**kwargs),
                "LAMBDA_ALIAS_INVENTORY_MALFORMED",
            )
            aliases = response.get("Aliases")
            if not isinstance(aliases, list):
                raise BrokerContractError(
                    "LAMBDA_ALIAS_INVENTORY_MALFORMED",
                    "Lambda alias inventory is malformed",
                )
            for raw in aliases:
                item = self._mapping(raw, "LAMBDA_ALIAS_INVENTORY_MALFORMED")
                name = item.get("Name")
                version = item.get("FunctionVersion")
                alias_arn = item.get("AliasArn")
                routing = item.get("RoutingConfig")
                expected_arn = (
                    f"arn:aws:lambda:{REGION}:{AUTHORITY_ACCOUNT_ID}:"
                    f"function:{function_name}:{name}"
                )
                if (
                    not isinstance(name, str)
                    or name in observed
                    or version != expected_aliases.get(name)
                    or alias_arn != expected_arn
                    or item.get("Description") not in (None, "")
                    or routing not in (
                        None,
                        {},
                        {"AdditionalVersionWeights": {}},
                    )
                ):
                    raise BrokerContractError(
                        "LAMBDA_ALTERNATE_PEP_PRESENT",
                        "Lambda alias set or binding differs from the reviewed set",
                    )
                observed[name] = {
                    "alias_arn": expected_arn,
                    "name": name,
                    "function_version": str(version),
                }
            marker = self._page_marker(
                response,
                seen=seen_markers,
                code="LAMBDA_ALIAS_INVENTORY_MALFORMED",
            )
            if marker is None:
                if set(observed) != set(expected_aliases):
                    raise BrokerContractError(
                        "LAMBDA_ALTERNATE_PEP_PRESENT",
                        "Lambda alias set differs from the reviewed set",
                    )
                return tuple(observed[key] for key in sorted(observed))
        raise BrokerContractError(
            "LAMBDA_ALIAS_INVENTORY_EXCEEDED",
            "Lambda alias inventory exceeded the bounded page limit",
        )

    def _code_signing(self, function_name: str, expected_arn: str) -> Mapping[str, str]:
        response = self._mapping(
            self._lambda.get_function_code_signing_config(
                FunctionName=function_name
            ),
            "LAMBDA_CODE_SIGNING_READ_MALFORMED",
        )
        if (
            response.get("FunctionName") != function_name
            or response.get("CodeSigningConfigArn") != expected_arn
        ):
            raise BrokerContractError(
                "LAMBDA_CODE_SIGNING_CHANGED",
                "Lambda code-signing binding differs",
            )
        return {
            "function_name": function_name,
            "code_signing_config_arn": expected_arn,
        }

    def _code_signing_configuration(
        self, expected_arn: str, expected_signer_arn: str
    ) -> Mapping[str, Any]:
        response = self._mapping(
            self._lambda.get_code_signing_config(
                CodeSigningConfigArn=expected_arn
            ),
            "LAMBDA_CODE_SIGNING_READ_MALFORMED",
        )
        config = self._mapping(
            response.get("CodeSigningConfig"),
            "LAMBDA_CODE_SIGNING_READ_MALFORMED",
        )
        config_id = expected_arn.rsplit(":", 1)[-1]
        publishers = self._mapping(
            config.get("AllowedPublishers"), "LAMBDA_CODE_SIGNING_CHANGED"
        )
        policies = self._mapping(
            config.get("CodeSigningPolicies"), "LAMBDA_CODE_SIGNING_CHANGED"
        )
        if (
            config.get("CodeSigningConfigId") != config_id
            or config.get("CodeSigningConfigArn") != expected_arn
            or config.get("Description") != "GUG-221 enforce-only reviewed signer"
            or publishers.get("SigningProfileVersionArns") != [expected_signer_arn]
            or policies != {"UntrustedArtifactOnDeployment": "Enforce"}
        ):
            raise BrokerContractError(
                "LAMBDA_CODE_SIGNING_CHANGED",
                "Lambda signer allowlist or enforcement policy differs",
            )
        return {
            "code_signing_config_id": config_id,
            "code_signing_config_arn": expected_arn,
            "description": "GUG-221 enforce-only reviewed signer",
            "signing_profile_version_arns": [expected_signer_arn],
            "untrusted_artifact_on_deployment": "Enforce",
        }

    def _concurrency(self, function_name: str) -> Mapping[str, Any]:
        response = self._mapping(
            self._lambda.get_function_concurrency(FunctionName=function_name),
            "LAMBDA_CONCURRENCY_READ_MALFORMED",
        )
        reserved = response.get("ReservedConcurrentExecutions")
        if type(reserved) is not int or reserved != 1:
            raise BrokerContractError(
                "LAMBDA_CONCURRENCY_CHANGED",
                "Lambda reserved concurrency differs",
            )
        return {"function_name": function_name, "reserved_concurrency": 1}

    def _event_invoke(self, function_name: str, alias_name: str) -> Mapping[str, Any]:
        response = self._mapping(
            self._lambda.get_function_event_invoke_config(
                FunctionName=function_name,
                Qualifier=alias_name,
            ),
            "LAMBDA_ASYNC_CONFIGURATION_READ_MALFORMED",
        )
        expected_arn = (
            f"arn:aws:lambda:{REGION}:{AUTHORITY_ACCOUNT_ID}:"
            f"function:{function_name}:{alias_name}"
        )
        retries = response.get("MaximumRetryAttempts")
        maximum_age = response.get("MaximumEventAgeInSeconds")
        if (
            response.get("FunctionArn") != expected_arn
            or type(retries) is not int
            or retries != 0
            or type(maximum_age) is not int
            or maximum_age != 60
        ):
            raise BrokerContractError(
                "LAMBDA_ASYNC_CONFIGURATION_CHANGED",
                "Lambda async retry or destination controls differ",
            )
        destinations = response.get("DestinationConfig")
        if destinations not in (
            None,
            {},
            {"OnSuccess": {}, "OnFailure": {}},
        ):
            raise BrokerContractError(
                "LAMBDA_ASYNC_CONFIGURATION_CHANGED",
                "Lambda async destination controls differ",
            )
        return {
            "function_arn": expected_arn,
            "maximum_retry_attempts": 0,
            "maximum_event_age_seconds": 60,
            "destination_config": {},
        }

    def _require_absent_lambda_surface(
        self,
        *,
        operation: str,
        function_name: str,
        qualifier: str | None,
    ) -> Mapping[str, Any]:
        method = getattr(self._lambda, operation)
        kwargs: dict[str, str] = {"FunctionName": function_name}
        if qualifier is not None:
            kwargs["Qualifier"] = qualifier
        try:
            method(**kwargs)
        except Exception as exc:
            if _provider_code(exc) != "ResourceNotFoundException":
                raise BrokerContractError(
                    "LAMBDA_INVOCATION_SURFACE_READ_FAILED",
                    "Lambda invocation surface absence could not be proven",
                ) from exc
        else:
            raise BrokerContractError(
                "LAMBDA_INVOCATION_SURFACE_PRESENT",
                "a Lambda resource policy or function URL is present",
            )
        return {
            "operation": operation,
            "function_name": function_name,
            "qualifier": qualifier,
            "absent": True,
        }

    def _require_absent_event_invoke(
        self,
        *,
        function_name: str,
        qualifier: str | None,
    ) -> Mapping[str, Any]:
        kwargs: dict[str, str] = {"FunctionName": function_name}
        if qualifier is not None:
            kwargs["Qualifier"] = qualifier
        try:
            self._lambda.get_function_event_invoke_config(**kwargs)
        except Exception as exc:
            if _provider_code(exc) != "ResourceNotFoundException":
                raise BrokerContractError(
                    "LAMBDA_ASYNC_CONFIGURATION_READ_FAILED",
                    "Lambda async configuration absence could not be proven",
                ) from exc
        else:
            raise BrokerContractError(
                "LAMBDA_ASYNC_CONFIGURATION_CHANGED",
                "an unreviewed Lambda async configuration is present",
            )
        return {
            "function_name": function_name,
            "qualifier": qualifier,
            "absent": True,
        }

    def _event_source_mappings(
        self, function_name: str, qualifier: str | None
    ) -> Mapping[str, Any]:
        marker: str | None = None
        seen: set[str] = set()
        target = (
            function_name
            if qualifier is None
            else f"{function_name}:{qualifier}"
        )
        for _ in range(100):
            kwargs: dict[str, Any] = {
                "FunctionName": target,
                "MaxItems": 100,
            }
            if marker is not None:
                kwargs["Marker"] = marker
            response = self._mapping(
                self._lambda.list_event_source_mappings(**kwargs),
                "LAMBDA_EVENT_SOURCE_INVENTORY_MALFORMED",
            )
            mappings = response.get("EventSourceMappings")
            if not isinstance(mappings, list) or mappings:
                raise BrokerContractError(
                    "LAMBDA_EVENT_SOURCE_PRESENT",
                    "a Lambda event source mapping is present or ambiguous",
                )
            next_marker = response.get("NextMarker")
            if next_marker is None:
                return {
                    "function_name": function_name,
                    "qualifier": qualifier,
                    "mappings": [],
                }
            if (
                not isinstance(next_marker, str)
                or not next_marker
                or next_marker in seen
            ):
                raise BrokerContractError(
                    "LAMBDA_EVENT_SOURCE_PAGINATION_INVALID",
                    "Lambda event source pagination is malformed",
                )
            seen.add(next_marker)
            marker = next_marker
        raise BrokerContractError(
            "LAMBDA_EVENT_SOURCE_PAGINATION_EXCEEDED",
            "Lambda event source pagination exceeded the bounded inventory",
        )

    def _lambda_snapshot(self, config: BrokerConfig) -> tuple[str, str, str, str]:
        repair_alias = self._alias(REPAIR_FUNCTION_NAME, "repair-v1")
        plan_alias = self._alias(PLAN_FUNCTION_NAME, "plan-v1")
        reconcile_alias = self._alias(READ_FUNCTION_NAME, "reconcile-v1")
        repair_version = str(repair_alias["function_version"])
        plan_version = str(plan_alias["function_version"])
        reconcile_version = str(reconcile_alias["function_version"])
        if repair_version != config.repair_function_version:
            raise BrokerContractError(
                "LAMBDA_ALIAS_CONTROLS_CHANGED",
                "repair alias does not target the immutable repair version",
            )
        if config.mode == "plan" and plan_version != config.function_version:
            raise BrokerContractError(
                "LAMBDA_ALIAS_CONTROLS_CHANGED",
                "the executing Plan version differs from the private alias",
            )
        if config.mode == "reconcile" and reconcile_version != config.function_version:
            raise BrokerContractError(
                "LAMBDA_ALIAS_CONTROLS_CHANGED",
                "the executing Reconcile version differs from the private alias",
            )
        expected_versions = {
            REPAIR_FUNCTION_NAME: {"$LATEST", repair_version},
            PLAN_FUNCTION_NAME: {"$LATEST", plan_version},
            READ_FUNCTION_NAME: {"$LATEST", reconcile_version},
        }
        function_inventory = self._function_inventory(expected_versions)
        version_inventory = (
            self._version_inventory(
                function_name=REPAIR_FUNCTION_NAME,
                expected_role=REPAIR_EXECUTION_ROLE_ARN,
                expected_versions=expected_versions[REPAIR_FUNCTION_NAME],
            ),
            self._version_inventory(
                function_name=PLAN_FUNCTION_NAME,
                expected_role=PLAN_EXECUTION_ROLE_ARN,
                expected_versions=expected_versions[PLAN_FUNCTION_NAME],
            ),
            self._version_inventory(
                function_name=READ_FUNCTION_NAME,
                expected_role=READ_EXECUTION_ROLE_ARN,
                expected_versions=expected_versions[READ_FUNCTION_NAME],
            ),
        )
        alias_inventory = (
            self._alias_inventory(
                function_name=REPAIR_FUNCTION_NAME,
                expected_aliases={"repair-v1": repair_version},
            ),
            self._alias_inventory(
                function_name=PLAN_FUNCTION_NAME,
                expected_aliases={"plan-v1": plan_version},
            ),
            self._alias_inventory(
                function_name=READ_FUNCTION_NAME,
                expected_aliases={"reconcile-v1": reconcile_version},
            ),
        )
        functions = (
            self._function(
                config=config,
                function_name=REPAIR_FUNCTION_NAME,
                qualifier=None,
                version="$LATEST",
                function_kind="repair",
            ),
            self._function(
                config=config,
                function_name=REPAIR_FUNCTION_NAME,
                qualifier="repair-v1",
                version=repair_version,
                function_kind="repair",
            ),
            self._function(
                config=config,
                function_name=PLAN_FUNCTION_NAME,
                qualifier=None,
                version="$LATEST",
                function_kind="plan",
            ),
            self._function(
                config=config,
                function_name=PLAN_FUNCTION_NAME,
                qualifier="plan-v1",
                version=plan_version,
                function_kind="plan",
            ),
            self._function(
                config=config,
                function_name=READ_FUNCTION_NAME,
                qualifier=None,
                version="$LATEST",
                function_kind="reconcile",
            ),
            self._function(
                config=config,
                function_name=READ_FUNCTION_NAME,
                qualifier="reconcile-v1",
                version=reconcile_version,
                function_kind="reconcile",
            ),
        )
        code_signing = (
            self._code_signing(
                REPAIR_FUNCTION_NAME, config.expected_code_signing_config_arn
            ),
            self._code_signing(
                PLAN_FUNCTION_NAME, config.expected_code_signing_config_arn
            ),
            self._code_signing(
                READ_FUNCTION_NAME, config.expected_code_signing_config_arn
            ),
        )
        signer_arns = {
            str(item["signing_profile_version_arn"]) for item in functions
        }
        if len(signer_arns) != 1:
            raise BrokerContractError(
                "LAMBDA_SIGNER_BINDING_CHANGED",
                "repair, plan, and reconcile versions were not signed by one profile",
            )
        code_signing_configuration = self._code_signing_configuration(
            config.expected_code_signing_config_arn,
            config.expected_signing_profile_version_arn,
        )
        concurrency = (
            self._concurrency(REPAIR_FUNCTION_NAME),
            self._concurrency(PLAN_FUNCTION_NAME),
            self._concurrency(READ_FUNCTION_NAME),
        )
        event_invoke = (
            self._event_invoke(REPAIR_FUNCTION_NAME, "repair-v1"),
            self._event_invoke(PLAN_FUNCTION_NAME, "plan-v1"),
            self._event_invoke(READ_FUNCTION_NAME, "reconcile-v1"),
        )
        absent_event_invoke = tuple(
            self._require_absent_event_invoke(
                function_name=function_name,
                qualifier=qualifier,
            )
            for function_name, qualifier in (
                (REPAIR_FUNCTION_NAME, None),
                (REPAIR_FUNCTION_NAME, repair_version),
                (PLAN_FUNCTION_NAME, None),
                (PLAN_FUNCTION_NAME, plan_version),
                (READ_FUNCTION_NAME, None),
                (READ_FUNCTION_NAME, reconcile_version),
            )
        )
        invocation_surfaces = tuple(
            self._require_absent_lambda_surface(
                operation=operation,
                function_name=function_name,
                qualifier=qualifier,
            )
            for operation in ("get_policy", "get_function_url_config")
            for function_name, qualifier in (
                (REPAIR_FUNCTION_NAME, None),
                (REPAIR_FUNCTION_NAME, "repair-v1"),
                (PLAN_FUNCTION_NAME, None),
                (PLAN_FUNCTION_NAME, "plan-v1"),
                (READ_FUNCTION_NAME, None),
                (READ_FUNCTION_NAME, "reconcile-v1"),
            )
        ) + tuple(
            self._require_absent_lambda_surface(
                operation="get_policy",
                function_name=function_name,
                qualifier=version,
            )
            for function_name, version in (
                (REPAIR_FUNCTION_NAME, repair_version),
                (PLAN_FUNCTION_NAME, plan_version),
                (READ_FUNCTION_NAME, reconcile_version),
            )
        ) + tuple(
            self._require_absent_lambda_surface(
                operation="get_policy",
                function_name=function_name,
                qualifier="$LATEST",
            )
            for function_name in (
                REPAIR_FUNCTION_NAME,
                PLAN_FUNCTION_NAME,
                READ_FUNCTION_NAME,
            )
        )
        event_sources = tuple(
            self._event_source_mappings(function_name, qualifier)
            for function_name, qualifier in (
                (REPAIR_FUNCTION_NAME, None),
                (REPAIR_FUNCTION_NAME, "$LATEST"),
                (REPAIR_FUNCTION_NAME, repair_version),
                (REPAIR_FUNCTION_NAME, "repair-v1"),
                (PLAN_FUNCTION_NAME, None),
                (PLAN_FUNCTION_NAME, "$LATEST"),
                (PLAN_FUNCTION_NAME, plan_version),
                (PLAN_FUNCTION_NAME, "plan-v1"),
                (READ_FUNCTION_NAME, None),
                (READ_FUNCTION_NAME, "$LATEST"),
                (READ_FUNCTION_NAME, reconcile_version),
                (READ_FUNCTION_NAME, "reconcile-v1"),
            )
        )
        digest = canonical_digest(
            {
                "aliases": [repair_alias, plan_alias, reconcile_alias],
                "function_inventory": list(function_inventory),
                "version_inventory": [list(items) for items in version_inventory],
                "alias_inventory": [list(items) for items in alias_inventory],
                "functions": list(functions),
                "code_signing": list(code_signing),
                "code_signing_configuration": code_signing_configuration,
                "concurrency": list(concurrency),
                "event_invoke": list(event_invoke),
                "absent_event_invoke": list(absent_event_invoke),
                "invocation_surfaces": list(invocation_surfaces),
                "event_sources": list(event_sources),
            }
        )
        return repair_version, plan_version, reconcile_version, digest

    def _ledger_snapshot(self, config: BrokerConfig) -> tuple[str, str]:
        table_arn = (
            f"arn:aws:dynamodb:{REGION}:{AUTHORITY_ACCOUNT_ID}:"
            f"table/{config.ledger_table_name}"
        )
        response = self._mapping(
            self._dynamodb.describe_table(TableName=table_arn),
            "LEDGER_TABLE_READ_MALFORMED",
        )
        table = self._mapping(
            response.get("Table"), "LEDGER_TABLE_READ_MALFORMED"
        )
        billing = self._mapping(
            table.get("BillingModeSummary"), "LEDGER_TABLE_CONTROLS_CHANGED"
        )
        sse = self._mapping(
            table.get("SSEDescription"), "LEDGER_TABLE_CONTROLS_CHANGED"
        )
        table_class = self._mapping(
            table.get("TableClassSummary"), "LEDGER_TABLE_CONTROLS_CHANGED"
        )
        if (
            table.get("TableName") != config.ledger_table_name
            or table.get("TableArn") != table_arn
            or table.get("TableStatus") != "ACTIVE"
            or billing.get("BillingMode") != "PAY_PER_REQUEST"
            or table.get("KeySchema")
            != [{"AttributeName": "repair_id", "KeyType": "HASH"}]
            or table.get("AttributeDefinitions")
            != [{"AttributeName": "repair_id", "AttributeType": "S"}]
            or table.get("DeletionProtectionEnabled") is not True
            or table_class.get("TableClass") != "STANDARD"
            or sse.get("Status") != "ENABLED"
            or sse.get("SSEType") != "KMS"
            or sse.get("KMSMasterKeyArn") != config.repair_ledger_kms_key_arn
            or sse.get("InaccessibleEncryptionDateTime") is not None
            or table.get("LocalSecondaryIndexes") not in (None, [])
            or table.get("GlobalSecondaryIndexes") not in (None, [])
            or table.get("Replicas") not in (None, [])
            or table.get("GlobalTableWitnesses") not in (None, [])
            or table.get("LatestStreamArn") not in (None, "")
            or table.get("LatestStreamLabel") not in (None, "")
        ):
            raise BrokerContractError(
                "LEDGER_TABLE_CONTROLS_CHANGED",
                "repair ledger table controls differ",
            )
        stream = table.get("StreamSpecification")
        if stream not in (None, {}) and (
            not isinstance(stream, Mapping) or stream.get("StreamEnabled") is not False
        ):
            raise BrokerContractError(
                "LEDGER_TABLE_CONTROLS_CHANGED",
                "repair ledger stream controls differ",
            )
        backups = self._mapping(
            self._dynamodb.describe_continuous_backups(
                TableName=table_arn
            ).get("ContinuousBackupsDescription"),
            "LEDGER_RECOVERY_CONTROLS_CHANGED",
        )
        pitr = self._mapping(
            backups.get("PointInTimeRecoveryDescription"),
            "LEDGER_RECOVERY_CONTROLS_CHANGED",
        )
        recovery_period = pitr.get("RecoveryPeriodInDays")
        if (
            backups.get("ContinuousBackupsStatus") != "ENABLED"
            or pitr.get("PointInTimeRecoveryStatus") != "ENABLED"
            or type(recovery_period) is not int
            or recovery_period != 35
        ):
            raise BrokerContractError(
                "LEDGER_RECOVERY_CONTROLS_CHANGED",
                "repair ledger recovery controls differ",
            )
        ttl = self._mapping(
            self._dynamodb.describe_time_to_live(TableName=table_arn).get(
                "TimeToLiveDescription"
            ),
            "LEDGER_TTL_CONTROLS_CHANGED",
        )
        if (
            ttl.get("TimeToLiveStatus") != "DISABLED"
            or ttl.get("AttributeName") not in (None, "")
        ):
            raise BrokerContractError(
                "LEDGER_TTL_CONTROLS_CHANGED",
                "repair ledger TTL must remain disabled",
            )
        resource_policy_response = self._mapping(
            self._dynamodb.get_resource_policy(ResourceArn=table_arn),
            "LEDGER_RESOURCE_POLICY_CHANGED",
        )
        policy = _strict_json_object(
            resource_policy_response.get("Policy"),
            "LEDGER_RESOURCE_POLICY_CHANGED",
        )
        expected_statements = {
            "DenyPlanCreationOutsidePlanExecution": {
                "Sid": "DenyPlanCreationOutsidePlanExecution",
                "Effect": "Deny",
                "Principal": {"AWS": "*"},
                "Action": list(PLAN_LEDGER_WRITE_ACTIONS),
                "Resource": table_arn,
                "Condition": {
                    "ArnNotEquals": {
                        "aws:PrincipalArn": PLAN_EXECUTION_ROLE_ARN,
                    }
                },
            },
            "DenyPlanConsumptionOutsideRepairExecution": {
                "Sid": "DenyPlanConsumptionOutsideRepairExecution",
                "Effect": "Deny",
                "Principal": {"AWS": "*"},
                "Action": list(REPAIR_LEDGER_WRITE_ACTIONS),
                "Resource": table_arn,
                "Condition": {
                    "ArnNotEquals": {
                        "aws:PrincipalArn": REPAIR_EXECUTION_ROLE_ARN,
                    }
                },
            },
            "DenyEveryUnsupportedLedgerMutation": {
                "Sid": "DenyEveryUnsupportedLedgerMutation",
                "Effect": "Deny",
                "Principal": {"AWS": "*"},
                "Action": list(UNSUPPORTED_LEDGER_WRITE_ACTIONS),
                "Resource": table_arn,
            },
        }
        if (
            policy.get("Version") != "2012-10-17"
            or set(policy) != {"Version", "Statement"}
            or not isinstance(policy.get("Statement"), list)
            or len(policy["Statement"]) != len(expected_statements)
            or not all(
                isinstance(statement, Mapping)
                for statement in policy["Statement"]
            )
        ):
            raise BrokerContractError(
                "LEDGER_RESOURCE_POLICY_CHANGED",
                "repair ledger resource policy envelope differs",
            )
        normalized_statements: dict[str, Mapping[str, Any]] = {}
        for item in policy["Statement"]:
            statement = dict(item)
            sid = statement.get("Sid")
            actions = statement.get("Action")
            action_values = [actions] if isinstance(actions, str) else actions
            if (
                not isinstance(sid, str)
                or sid in normalized_statements
                or sid not in expected_statements
                or not isinstance(action_values, list)
                or not all(isinstance(action, str) for action in action_values)
            ):
                raise BrokerContractError(
                    "LEDGER_RESOURCE_POLICY_CHANGED",
                    "repair ledger resource policy statements differ",
                )
            expected_actions = expected_statements[sid]["Action"]
            if (
                len(action_values) != len(expected_actions)
                or set(action_values) != set(expected_actions)
            ):
                raise BrokerContractError(
                    "LEDGER_RESOURCE_POLICY_CHANGED",
                    "repair ledger resource policy actions differ",
                )
            statement["Action"] = list(expected_actions)
            normalized_statements[sid] = statement
        if normalized_statements != expected_statements:
            raise BrokerContractError(
                "LEDGER_RESOURCE_POLICY_CHANGED",
                "repair ledger resource policy differs",
            )
        normalized = {
            "table_name": config.ledger_table_name,
            "table_arn": table_arn,
            "status": "ACTIVE",
            "billing_mode": "PAY_PER_REQUEST",
            "key_schema": table["KeySchema"],
            "attribute_definitions": table["AttributeDefinitions"],
            "deletion_protection": True,
            "table_class": "STANDARD",
            "sse": {
                "status": "ENABLED",
                "type": "KMS",
                "key_arn": config.repair_ledger_kms_key_arn,
            },
            "indexes": [],
            "replicas": [],
            "stream_enabled": False,
            "continuous_backups": "ENABLED",
            "point_in_time_recovery": "ENABLED",
            "recovery_period_days": 35,
            "time_to_live": "DISABLED",
            "resource_policy": {
                "Version": "2012-10-17",
                "Statement": list(expected_statements.values()),
            },
        }
        return table_arn, canonical_digest(normalized)

    def _kms_snapshot(self, config: BrokerConfig) -> str:
        key_arn = config.repair_ledger_kms_key_arn
        key_id = key_arn.rsplit("/", 1)[-1]
        if _KMS_KEY_ID_RE.fullmatch(key_id) is None:
            raise BrokerContractError(
                "LEDGER_KMS_CONTROLS_CHANGED", "repair ledger KMS key id is malformed"
            )
        response = self._mapping(
            self._kms.describe_key(KeyId=key_arn),
            "LEDGER_KMS_READ_MALFORMED",
        )
        metadata = self._mapping(
            response.get("KeyMetadata"), "LEDGER_KMS_READ_MALFORMED"
        )
        if (
            metadata.get("AWSAccountId") != AUTHORITY_ACCOUNT_ID
            or metadata.get("KeyId") != key_id
            or metadata.get("Arn") != key_arn
            or metadata.get("Enabled") is not True
            or metadata.get("Description")
            != "GUG-221 retained repair-ledger encryption key"
            or metadata.get("KeyUsage") != "ENCRYPT_DECRYPT"
            or metadata.get("KeyState") != "Enabled"
            or metadata.get("Origin") != "AWS_KMS"
            or metadata.get("KeyManager") != "CUSTOMER"
            or metadata.get("CustomerMasterKeySpec") != "SYMMETRIC_DEFAULT"
            or metadata.get("KeySpec") != "SYMMETRIC_DEFAULT"
            or metadata.get("EncryptionAlgorithms") != ["SYMMETRIC_DEFAULT"]
            or metadata.get("SigningAlgorithms") not in (None, [])
            or metadata.get("MacAlgorithms") not in (None, [])
            or metadata.get("KeyAgreementAlgorithms") not in (None, [])
            or metadata.get("MultiRegion") is not False
            or metadata.get("MultiRegionConfiguration") is not None
            or metadata.get("DeletionDate") is not None
            or metadata.get("PendingDeletionWindowInDays") is not None
            or metadata.get("CustomKeyStoreId") is not None
            or metadata.get("CloudHsmClusterId") is not None
            or metadata.get("ExpirationModel")
            not in (None, "KEY_MATERIAL_DOES_NOT_EXPIRE")
        ):
            raise BrokerContractError(
                "LEDGER_KMS_CONTROLS_CHANGED",
                "repair ledger KMS key controls differ",
            )
        rotation = self._mapping(
            self._kms.get_key_rotation_status(KeyId=key_arn),
            "LEDGER_KMS_ROTATION_READ_MALFORMED",
        )
        rotation_period = rotation.get("RotationPeriodInDays")
        if (
            rotation.get("KeyId") != key_id
            or rotation.get("KeyRotationEnabled") is not True
            or type(rotation_period) is not int
            or rotation_period != 365
            or rotation.get("OnDemandRotationStartDate") is not None
        ):
            raise BrokerContractError(
                "LEDGER_KMS_ROTATION_CHANGED",
                "repair ledger KMS rotation controls differ",
            )
        policy_response = self._mapping(
            self._kms.get_key_policy(KeyId=key_arn, PolicyName="default"),
            "LEDGER_KMS_POLICY_READ_MALFORMED",
        )
        if policy_response.get("PolicyName") not in (None, "default"):
            raise BrokerContractError(
                "LEDGER_KMS_POLICY_CHANGED",
                "repair ledger KMS policy binding differs",
            )
        key_policy = _strict_json_object(
            policy_response.get("Policy"), "LEDGER_KMS_POLICY_CHANGED"
        )
        expected_key_policy = _expected_repair_ledger_key_policy()
        if key_policy != expected_key_policy:
            raise BrokerContractError(
                "LEDGER_KMS_POLICY_CHANGED",
                "repair ledger KMS policy differs from the reviewed policy",
            )

        aliases: list[Mapping[str, Any]] = []
        marker: str | None = None
        seen_alias_markers: set[str] = set()
        for _ in range(100):
            alias_kwargs: dict[str, Any] = {"KeyId": key_arn, "Limit": 100}
            if marker is not None:
                alias_kwargs["Marker"] = marker
            alias_response = self._mapping(
                self._kms.list_aliases(**alias_kwargs),
                "LEDGER_KMS_ALIAS_INVENTORY_MALFORMED",
            )
            page = alias_response.get("Aliases")
            truncated = alias_response.get("Truncated")
            next_marker = alias_response.get("NextMarker")
            if not isinstance(page, list) or type(truncated) is not bool:
                raise BrokerContractError(
                    "LEDGER_KMS_ALIAS_INVENTORY_MALFORMED",
                    "repair ledger KMS alias inventory is malformed",
                )
            if any(not isinstance(item, Mapping) for item in page):
                raise BrokerContractError(
                    "LEDGER_KMS_ALIAS_INVENTORY_MALFORMED",
                    "repair ledger KMS alias inventory is malformed",
                )
            aliases.extend(dict(item) for item in page)
            if not truncated:
                if next_marker is not None:
                    raise BrokerContractError(
                        "LEDGER_KMS_ALIAS_INVENTORY_MALFORMED",
                        "terminal KMS alias page carries a marker",
                    )
                break
            if (
                not isinstance(next_marker, str)
                or not next_marker
                or next_marker in seen_alias_markers
            ):
                raise BrokerContractError(
                    "LEDGER_KMS_ALIAS_INVENTORY_MALFORMED",
                    "repair ledger KMS alias pagination is malformed",
                )
            seen_alias_markers.add(next_marker)
            marker = next_marker
        else:
            raise BrokerContractError(
                "LEDGER_KMS_ALIAS_INVENTORY_MALFORMED",
                "repair ledger KMS alias inventory exceeded its page limit",
            )
        expected_alias_arn = (
            f"arn:aws:kms:{REGION}:{AUTHORITY_ACCOUNT_ID}:"
            f"{REPAIR_LEDGER_KEY_ALIAS}"
        )
        if len(aliases) != 1:
            raise BrokerContractError(
                "LEDGER_KMS_ALIAS_CHANGED",
                "repair ledger KMS alias set differs",
            )
        alias = aliases[0]
        if (
            alias.get("AliasName") != REPAIR_LEDGER_KEY_ALIAS
            or alias.get("AliasArn") != expected_alias_arn
            or alias.get("TargetKeyId") != key_id
            or not set(alias).issubset(
                {
                    "AliasName",
                    "AliasArn",
                    "TargetKeyId",
                    "CreationDate",
                    "LastUpdatedDate",
                }
            )
        ):
            raise BrokerContractError(
                "LEDGER_KMS_ALIAS_CHANGED",
                "repair ledger KMS alias binding differs",
            )
        for timestamp_name in ("CreationDate", "LastUpdatedDate"):
            if timestamp_name in alias and not isinstance(
                alias[timestamp_name], datetime
            ):
                raise BrokerContractError(
                    "LEDGER_KMS_ALIAS_INVENTORY_MALFORMED",
                    "repair ledger KMS alias timestamp is malformed",
                )

        observed_tags: dict[str, str] = {}
        marker = None
        seen_tag_markers: set[str] = set()
        for _ in range(100):
            tag_kwargs: dict[str, Any] = {"KeyId": key_arn, "Limit": 50}
            if marker is not None:
                tag_kwargs["Marker"] = marker
            tag_response = self._mapping(
                self._kms.list_resource_tags(**tag_kwargs),
                "LEDGER_KMS_TAG_INVENTORY_MALFORMED",
            )
            tags = tag_response.get("Tags")
            truncated = tag_response.get("Truncated")
            next_marker = tag_response.get("NextMarker")
            if not isinstance(tags, list) or type(truncated) is not bool:
                raise BrokerContractError(
                    "LEDGER_KMS_TAG_INVENTORY_MALFORMED",
                    "repair ledger KMS tag inventory is malformed",
                )
            for item in tags:
                if (
                    not isinstance(item, Mapping)
                    or set(item) != {"TagKey", "TagValue"}
                    or not isinstance(item.get("TagKey"), str)
                    or not item.get("TagKey")
                    or not isinstance(item.get("TagValue"), str)
                    or item["TagKey"] in observed_tags
                ):
                    raise BrokerContractError(
                        "LEDGER_KMS_TAG_INVENTORY_MALFORMED",
                        "repair ledger KMS tags are malformed or duplicated",
                    )
                observed_tags[item["TagKey"]] = item["TagValue"]
            if not truncated:
                if next_marker is not None:
                    raise BrokerContractError(
                        "LEDGER_KMS_TAG_INVENTORY_MALFORMED",
                        "terminal KMS tag page carries a marker",
                    )
                break
            if (
                not isinstance(next_marker, str)
                or not next_marker
                or next_marker in seen_tag_markers
            ):
                raise BrokerContractError(
                    "LEDGER_KMS_TAG_INVENTORY_MALFORMED",
                    "repair ledger KMS tag pagination is malformed",
                )
            seen_tag_markers.add(next_marker)
            marker = next_marker
        else:
            raise BrokerContractError(
                "LEDGER_KMS_TAG_INVENTORY_MALFORMED",
                "repair ledger KMS tag inventory exceeded its page limit",
            )
        if observed_tags != REPAIR_LEDGER_KEY_TAGS:
            raise BrokerContractError(
                "LEDGER_KMS_TAGS_CHANGED",
                "repair ledger KMS tags differ",
            )
        return canonical_digest(
            {
                "account_id": AUTHORITY_ACCOUNT_ID,
                "key_id": key_id,
                "key_arn": key_arn,
                "enabled": True,
                "description": "GUG-221 retained repair-ledger encryption key",
                "key_usage": "ENCRYPT_DECRYPT",
                "key_state": "Enabled",
                "origin": "AWS_KMS",
                "key_manager": "CUSTOMER",
                "key_spec": "SYMMETRIC_DEFAULT",
                "encryption_algorithms": ["SYMMETRIC_DEFAULT"],
                "multi_region": False,
                "rotation_enabled": True,
                "rotation_period_days": 365,
                "key_policy": expected_key_policy,
                "alias": {
                    "alias_name": REPAIR_LEDGER_KEY_ALIAS,
                    "alias_arn": expected_alias_arn,
                    "target_key_id": key_id,
                },
                "tags": dict(sorted(REPAIR_LEDGER_KEY_TAGS.items())),
            }
        )

    def snapshot(self, config: BrokerConfig) -> LocalControlPlaneSnapshot:
        repair_version, plan_version, reconcile_version, lambda_digest = (
            self._lambda_snapshot(config)
        )
        table_arn, ledger_digest = self._ledger_snapshot(config)
        kms_digest = self._kms_snapshot(config)
        observed = LocalControlPlaneSnapshot(
            repair_function_version=repair_version,
            plan_function_version=plan_version,
            reconcile_function_version=reconcile_version,
            artifact_code_sha256=config.expected_artifact_code_sha256,
            code_signing_config_arn=config.expected_code_signing_config_arn,
            signing_profile_version_arn=(
                config.expected_signing_profile_version_arn
            ),
            ledger_table_arn=table_arn,
            ledger_kms_key_arn=config.repair_ledger_kms_key_arn,
            lambda_controls_digest=lambda_digest,
            ledger_controls_digest=ledger_digest,
            kms_controls_digest=kms_digest,
        )
        validate_local_control_plane_snapshot(config, observed)
        return observed


class DynamoLedger:
    """Provider-backed one-shot CAS ledger with no SDK retries."""

    def __init__(self, client: Any, table_name: str) -> None:
        self._client = client
        self._table_name = table_name

    @staticmethod
    def _encode(item: Mapping[str, Any]) -> dict[str, dict[str, str]]:
        encoded: dict[str, dict[str, str]] = {}
        for key, value in item.items():
            if isinstance(value, bool):
                encoded[key] = {"BOOL": value}  # type: ignore[assignment]
            elif isinstance(value, int):
                encoded[key] = {"N": str(value)}
            elif value is None:
                encoded[key] = {"NULL": True}  # type: ignore[assignment]
            else:
                encoded[key] = {"S": str(value)}
        return encoded

    @staticmethod
    def _decode(item: Mapping[str, Mapping[str, Any]]) -> dict[str, Any]:
        decoded: dict[str, Any] = {}
        for key, value in item.items():
            if "S" in value:
                decoded[key] = value["S"]
            elif "N" in value:
                decoded[key] = int(value["N"])
            elif "BOOL" in value:
                decoded[key] = bool(value["BOOL"])
            elif "NULL" in value:
                decoded[key] = None
            else:
                raise BrokerContractError("LEDGER_MALFORMED", "ledger contains an unsupported value")
        return decoded

    def claim(self, claim: Mapping[str, Any]) -> None:
        try:
            self._client.put_item(
                TableName=self._table_name,
                Item=self._encode(claim),
                ConditionExpression="attribute_not_exists(repair_id)",
                ReturnConsumedCapacity="NONE",
            )
        except Exception as exc:
            if _provider_code(exc) == "ConditionalCheckFailedException":
                raise BrokerContractError("REPLAY_BLOCKED", "repair id is already consumed") from exc
            raise ProviderResponseAmbiguous("durable claim response is ambiguous") from exc

    def read(self, repair_id: str) -> Mapping[str, Any] | None:
        response = self._client.get_item(
            TableName=self._table_name,
            Key={"repair_id": {"S": repair_id}},
            ConsistentRead=True,
            ProjectionExpression=(
                "schema_version,record_type,repair_id,intent_digest,ledger_digest,"
                "source_commit,original_gug220_ledger_digest,authority_account_id,"
                "management_account_id,#region,#status,stage,effects_attempted,"
                "effects_completed,state_digest,planned_state_digest,"
                "plan_function_version,repair_function_version,repair_not_before,"
                "repair_not_after,provider_immutable,claim_condition,"
                "mutation_retry_attempted,production_authorized,planned_at,claimed_at,"
                "updated_at"
            ),
            ExpressionAttributeNames={"#status": "status", "#region": "region"},
        )
        item = response.get("Item")
        if item is None:
            return None
        if not isinstance(item, Mapping):
            raise BrokerContractError("LEDGER_MALFORMED", "ledger readback is malformed")
        return self._decode(item)

    def transition(
        self,
        *,
        repair_id: str,
        intent_digest: str,
        ledger_digest: str,
        expected_ledger: Mapping[str, Any],
        expected_status: str,
        new_status: str,
        stage: str,
        effects_attempted: int,
        effects_completed: int,
        state_digest: str,
        updated_at: datetime,
        claimed_at: datetime | None = None,
    ) -> None:
        expected_updated_at = expected_ledger.get("updated_at")
        expected_state_digest = expected_ledger.get("state_digest")
        expected_claimed_at = expected_ledger.get("claimed_at")
        if not isinstance(expected_state_digest, str):
            raise BrokerContractError(
                "LEDGER_PROGRESS_INVALID", "ledger transition metadata is incomplete"
            )
        condition = (
            "#schema = :schema AND #record = :record AND #intent = :intent "
            "AND #ledger = :ledger AND #source = :source AND #original = :original "
            "AND #authority = :authority AND #management = :management "
            "AND #region = :region AND #status = :expected AND #stage = :expected_stage "
            "AND #attempted = :expected_attempted AND #completed = :expected_completed "
            "AND #plan_version = :plan_version AND #repair_version = :repair_version "
            "AND #repair_not_before = :repair_not_before "
            "AND #repair_not_after = :repair_not_after "
            "AND #planned_state = :planned_state AND #planned = :planned "
            "AND #state = :expected_state AND #immutable = :immutable "
            "AND #claim_condition = :claim_condition AND #retry = :retry "
            "AND #production = :production"
        )
        if expected_updated_at is None:
            condition += " AND attribute_not_exists(#updated)"
        else:
            condition += " AND #updated = :expected_updated"
        if expected_claimed_at is None:
            condition += " AND attribute_not_exists(#claimed)"
        else:
            condition += " AND #claimed = :expected_claimed"
        expression_values: dict[str, Mapping[str, Any]] = {
            ":schema": {"N": str(expected_ledger["schema_version"])},
            ":record": {"S": str(expected_ledger["record_type"])},
            ":intent": {"S": intent_digest},
            ":ledger": {"S": ledger_digest},
            ":source": {"S": str(expected_ledger["source_commit"])},
            ":original": {"S": str(expected_ledger["original_gug220_ledger_digest"])},
            ":authority": {"S": str(expected_ledger["authority_account_id"])},
            ":management": {"S": str(expected_ledger["management_account_id"])},
            ":region": {"S": str(expected_ledger["region"])},
            ":expected": {"S": expected_status},
            ":expected_stage": {"S": str(expected_ledger["stage"])},
            ":expected_attempted": {"N": str(expected_ledger["effects_attempted"])},
            ":expected_completed": {"N": str(expected_ledger["effects_completed"])},
            ":plan_version": {"S": str(expected_ledger["plan_function_version"])},
            ":repair_version": {"S": str(expected_ledger["repair_function_version"])},
            ":repair_not_before": {"S": str(expected_ledger["repair_not_before"])},
            ":repair_not_after": {"S": str(expected_ledger["repair_not_after"])},
            ":planned_state": {"S": str(expected_ledger["planned_state_digest"])},
            ":planned": {"S": str(expected_ledger["planned_at"])},
            ":expected_state": {"S": expected_state_digest},
            ":immutable": {"BOOL": True},
            ":claim_condition": {"S": "attribute_not_exists(repair_id)"},
            ":retry": {"BOOL": False},
            ":production": {"BOOL": False},
            ":new": {"S": new_status},
            ":stage": {"S": stage},
            ":attempted": {"N": str(effects_attempted)},
            ":completed": {"N": str(effects_completed)},
            ":state": {"S": state_digest},
            ":updated": {"S": utc_timestamp(updated_at)},
        }
        if expected_updated_at is not None:
            expression_values[":expected_updated"] = {"S": str(expected_updated_at)}
        if expected_claimed_at is not None:
            expression_values[":expected_claimed"] = {"S": str(expected_claimed_at)}
        update_expression = (
            "SET #status = :new, stage = :stage, effects_attempted = :attempted, "
            "effects_completed = :completed, state_digest = :state, updated_at = :updated"
        )
        if claimed_at is not None:
            if expected_claimed_at is not None:
                raise BrokerContractError(
                    "LEDGER_PROGRESS_INVALID", "claimed_at may only be established once"
                )
            expression_values[":claimed"] = {"S": utc_timestamp(claimed_at)}
            update_expression += ", claimed_at = :claimed"
        try:
            self._client.update_item(
                TableName=self._table_name,
                Key={"repair_id": {"S": repair_id}},
                ConditionExpression=condition,
                UpdateExpression=update_expression,
                ExpressionAttributeNames={
                    "#schema": "schema_version",
                    "#record": "record_type",
                    "#intent": "intent_digest",
                    "#ledger": "ledger_digest",
                    "#source": "source_commit",
                    "#original": "original_gug220_ledger_digest",
                    "#authority": "authority_account_id",
                    "#management": "management_account_id",
                    "#region": "region",
                    "#status": "status",
                    "#stage": "stage",
                    "#attempted": "effects_attempted",
                    "#completed": "effects_completed",
                    "#plan_version": "plan_function_version",
                    "#repair_version": "repair_function_version",
                    "#repair_not_before": "repair_not_before",
                    "#repair_not_after": "repair_not_after",
                    "#planned_state": "planned_state_digest",
                    "#planned": "planned_at",
                    "#claimed": "claimed_at",
                    "#updated": "updated_at",
                    "#state": "state_digest",
                    "#immutable": "provider_immutable",
                    "#claim_condition": "claim_condition",
                    "#retry": "mutation_retry_attempted",
                    "#production": "production_authorized",
                },
                ExpressionAttributeValues=expression_values,
                ReturnValues="NONE",
            )
        except Exception as exc:
            if _provider_code(exc) == "ConditionalCheckFailedException":
                raise BrokerContractError("LEDGER_CAS_MISMATCH", "durable ledger changed") from exc
            raise ProviderResponseAmbiguous("durable ledger transition is ambiguous") from exc


def _append_page(
    values: list[Any], response: Any, method_name: str, result_key: str
) -> None:
    if not isinstance(response, Mapping) or result_key not in response:
        raise BrokerContractError(
            "PROVIDER_RESPONSE_MALFORMED", f"{method_name} response is malformed"
        )
    result = response[result_key]
    if not isinstance(result, list):
        raise BrokerContractError(
            "PROVIDER_RESPONSE_MALFORMED", f"{method_name} response is malformed"
        )
    values.extend(result)
    if len(values) > 10_000:
        raise BrokerContractError(
            "PROVIDER_RESPONSE_OVERSIZED", "provider inventory is oversized"
        )


def _paginate_next_token(
    client: Any, method_name: str, result_key: str, **kwargs: Any
) -> list[Any]:
    values: list[Any] = []
    token: str | None = None
    seen_tokens: set[str] = set()
    for _ in range(100):
        call_kwargs = dict(kwargs)
        if token is not None:
            call_kwargs["NextToken"] = token
        response = getattr(client, method_name)(**call_kwargs)
        _append_page(values, response, method_name, result_key)
        token = response.get("NextToken")
        if token is None:
            return values
        if not isinstance(token, str) or not token:
            raise BrokerContractError("PROVIDER_RESPONSE_MALFORMED", "pagination token is malformed")
        if token in seen_tokens:
            raise BrokerContractError("PAGINATION_CYCLE", "provider pagination repeated a token")
        seen_tokens.add(token)
    raise BrokerContractError("PAGINATION_LIMIT", "provider inventory exceeded the page limit")


def _paginate_iam_marker(
    client: Any, method_name: str, result_key: str, **kwargs: Any
) -> list[Any]:
    values: list[Any] = []
    marker: str | None = None
    seen_markers: set[str] = set()
    for _ in range(100):
        call_kwargs = dict(kwargs)
        if marker is not None:
            call_kwargs["Marker"] = marker
        response = getattr(client, method_name)(**call_kwargs)
        _append_page(values, response, method_name, result_key)
        is_truncated = response.get("IsTruncated")
        if type(is_truncated) is not bool:
            raise BrokerContractError(
                "PROVIDER_RESPONSE_MALFORMED", "IAM pagination state is malformed"
            )
        next_marker = response.get("Marker")
        if not is_truncated:
            if next_marker is not None:
                raise BrokerContractError(
                    "PROVIDER_RESPONSE_MALFORMED", "IAM terminal page has a marker"
                )
            return values
        if not isinstance(next_marker, str) or not next_marker:
            raise BrokerContractError(
                "PROVIDER_RESPONSE_MALFORMED", "IAM pagination marker is malformed"
            )
        if next_marker in seen_markers:
            raise BrokerContractError(
                "PAGINATION_CYCLE", "provider pagination repeated a marker"
            )
        seen_markers.add(next_marker)
        marker = next_marker
    raise BrokerContractError("PAGINATION_LIMIT", "provider inventory exceeded the page limit")


class AwsIdentityCenterAdapter:
    """Narrow management-account SSO adapter plus authority-account IAM readback."""

    def __init__(
        self,
        *,
        config: BrokerConfig,
        sso_admin: Any,
        identitystore: Any,
        authority_iam: Any,
    ) -> None:
        self._config = config
        self._sso = sso_admin
        self._identitystore = identitystore
        self._iam = authority_iam

    def _instance_binding(self, config: BrokerConfig) -> tuple[str, str | None]:
        response = self._sso.describe_instance(InstanceArn=config.instance_arn)
        if response.get("InstanceArn") != config.instance_arn:
            raise BrokerContractError("INSTANCE_READBACK_MISMATCH", "instance ARN differs")
        if response.get("IdentityStoreId") != config.identity_store_id:
            raise BrokerContractError("IDENTITY_STORE_READBACK_MISMATCH", "identity store differs")
        if response.get("OwnerAccountId") != MANAGEMENT_ACCOUNT_ID:
            raise BrokerContractError("INSTANCE_OWNER_MISMATCH", "instance owner differs")
        if response.get("Status") != "ACTIVE":
            raise BrokerContractError("INSTANCE_STATUS_MISMATCH", "instance is not active")
        details = response.get("EncryptionConfigurationDetails")
        if not isinstance(details, Mapping) or not details:
            raise BrokerContractError("KMS_READBACK_MALFORMED", "encryption configuration is malformed")
        key_type = details.get("KeyType")
        key_arn = details.get("KmsKeyArn")
        encryption_status = details.get("EncryptionStatus")
        if not isinstance(key_type, str) or (key_arn is not None and not isinstance(key_arn, str)):
            raise BrokerContractError("KMS_READBACK_MALFORMED", "encryption configuration is malformed")
        if encryption_status != "ENABLED":
            raise BrokerContractError("KMS_NOT_ENABLED", "Identity Center encryption is not enabled")
        if key_type != config.identity_center_kms_mode or key_arn != config.identity_center_kms_key_arn:
            raise BrokerContractError("KMS_READBACK_MISMATCH", "Identity Center KMS binding differs")
        return key_type, key_arn

    def _permission_set_roles(
        self, config: BrokerConfig, role_prefix: str
    ) -> tuple[CollectorRole, ...]:
        exact_role_path = "/aws-reserved/sso.amazonaws.com/"
        roles = _paginate_iam_marker(
            self._iam,
            "list_roles",
            "Roles",
            PathPrefix="/aws-reserved/sso.amazonaws.com/",
        )
        if any(
            not isinstance(role, Mapping)
            or not isinstance(role.get("RoleName"), str)
            or not role.get("RoleName")
            or not isinstance(role.get("Path"), str)
            or not isinstance(role.get("Arn"), str)
            for role in roles
        ):
            raise BrokerContractError("ROLE_LIST_MALFORMED", "IAM role inventory is malformed")
        role_names = [role["RoleName"] for role in roles]
        if len(role_names) != len(set(role_names)):
            raise BrokerContractError("ROLE_LIST_DUPLICATE", "IAM role inventory has duplicates")
        candidates = [
            role
            for role in roles
            if role["RoleName"].startswith(role_prefix)
        ]
        result: list[CollectorRole] = []
        for candidate in candidates:
            role_name = candidate["RoleName"]
            expected_role_arn = (
                f"arn:aws:iam::{AUTHORITY_ACCOUNT_ID}:role"
                f"{exact_role_path}{role_name}"
            )
            if (
                candidate["Path"] != exact_role_path
                or candidate["Arn"] != expected_role_arn
            ):
                raise BrokerContractError(
                    "ROLE_BINDING_MISMATCH", "permission-set role path or ARN differs"
                )
            role_response = self._iam.get_role(RoleName=role_name)
            role = role_response.get("Role")
            if (
                not isinstance(role, Mapping)
                or role.get("RoleName") != role_name
                or role.get("Path") != exact_role_path
                or role.get("Arn") != expected_role_arn
            ):
                raise BrokerContractError("ROLE_READBACK_MALFORMED", "collector role readback is malformed")
            provider_arn, audience = _parse_exact_saml_trust(
                role.get("AssumeRolePolicyDocument"), config.collector_saml_provider_arn
            )
            attached = _paginate_iam_marker(
                self._iam,
                "list_attached_role_policies",
                "AttachedPolicies",
                RoleName=role_name,
            )
            if any(
                not isinstance(item, Mapping)
                or not isinstance(item.get("PolicyArn"), str)
                or not isinstance(item.get("PolicyName"), str)
                or not item.get("PolicyName")
                for item in attached
            ):
                raise BrokerContractError("ROLE_POLICY_LIST_MALFORMED", "attached policy inventory is malformed")
            attached_arns = tuple(
                sorted(item["PolicyArn"] for item in attached)
            )
            if len(attached_arns) != len(set(attached_arns)):
                raise BrokerContractError("ROLE_POLICY_LIST_DUPLICATE", "attached policies are duplicated")
            inline_raw = _paginate_iam_marker(
                self._iam,
                "list_role_policies",
                "PolicyNames",
                RoleName=role_name,
            )
            if any(not isinstance(name, str) or not name for name in inline_raw):
                raise BrokerContractError("ROLE_POLICY_LIST_MALFORMED", "inline policy inventory is malformed")
            inline_names = tuple(
                sorted(inline_raw)
            )
            if len(inline_names) != len(set(inline_names)):
                raise BrokerContractError("ROLE_POLICY_LIST_DUPLICATE", "inline policies are duplicated")
            inline_digest = canonical_digest({})
            if COLLECTOR_INLINE_POLICY_NAME in inline_names:
                policy_response = self._iam.get_role_policy(
                    RoleName=role_name,
                    PolicyName=COLLECTOR_INLINE_POLICY_NAME,
                )
                if (
                    policy_response.get("RoleName") != role_name
                    or policy_response.get("PolicyName")
                    != COLLECTOR_INLINE_POLICY_NAME
                ):
                    raise BrokerContractError(
                        "ROLE_POLICY_READBACK_MALFORMED",
                        "inline role policy binding differs",
                    )
                inline_digest = canonical_digest(
                    _normalize_policy(policy_response.get("PolicyDocument"))
                )
            extra_inline = tuple(
                name for name in inline_names if name != COLLECTOR_INLINE_POLICY_NAME
            )
            boundary_raw = role.get("PermissionsBoundary")
            if boundary_raw is None:
                boundary_arn = None
            elif (
                isinstance(boundary_raw, Mapping)
                and boundary_raw.get("PermissionsBoundaryType") == "Policy"
                and isinstance(boundary_raw.get("PermissionsBoundaryArn"), str)
                and boundary_raw.get("PermissionsBoundaryArn")
            ):
                boundary_arn = boundary_raw["PermissionsBoundaryArn"]
            else:
                raise BrokerContractError(
                    "ROLE_BOUNDARY_MALFORMED", "role permissions boundary is malformed"
                )
            result.append(
                CollectorRole(
                    role_name=role_name,
                    saml_provider_arn=provider_arn,
                    saml_audience=audience,
                    inline_policy_name=(
                        COLLECTOR_INLINE_POLICY_NAME
                        if COLLECTOR_INLINE_POLICY_NAME in inline_names
                        else "MISSING"
                    ),
                    inline_policy_digest=inline_digest,
                    attached_managed_policy_arns=attached_arns,
                    extra_inline_policy_names=extra_inline,
                    permissions_boundary_arn=boundary_arn,
                )
            )
        return tuple(sorted(result, key=lambda item: item.role_name))

    def _collector_roles(
        self, config: BrokerConfig, collector_policy: Mapping[str, Any]
    ) -> tuple[CollectorRole, ...]:
        del collector_policy
        return self._permission_set_roles(config, COLLECTOR_ROLE_PREFIX)

    def _repair_invoker_roles(
        self, config: BrokerConfig, repair_invoker_policy: Mapping[str, Any]
    ) -> tuple[CollectorRole, ...]:
        del repair_invoker_policy
        return self._permission_set_roles(config, REPAIR_INVOKER_ROLE_PREFIX)

    def _assert_no_pending_operations(
        self, config: BrokerConfig, permission_set_arn: str
    ) -> None:
        operations = (
            (
                "list_account_assignment_creation_status",
                "AccountAssignmentsCreationStatus",
                "describe_account_assignment_creation_status",
                "AccountAssignmentCreationRequestId",
                "AccountAssignmentCreationStatus",
                ("TargetId", "TargetType", "PrincipalType", "PrincipalId"),
            ),
            (
                "list_account_assignment_deletion_status",
                "AccountAssignmentsDeletionStatus",
                "describe_account_assignment_deletion_status",
                "AccountAssignmentDeletionRequestId",
                "AccountAssignmentDeletionStatus",
                ("TargetId", "TargetType", "PrincipalType", "PrincipalId"),
            ),
            (
                "list_permission_set_provisioning_status",
                "PermissionSetsProvisioningStatus",
                "describe_permission_set_provisioning_status",
                "ProvisionPermissionSetRequestId",
                "PermissionSetProvisioningStatus",
                ("AccountId",),
            ),
        )
        for (
            method_name,
            result_key,
            describe_method_name,
            request_parameter,
            describe_result_key,
            extra_fields,
        ) in operations:
            items = _paginate_next_token(
                self._sso,
                method_name,
                result_key,
                InstanceArn=config.instance_arn,
                Filter={"Status": "IN_PROGRESS"},
            )
            for item in items:
                if (
                    not isinstance(item, Mapping)
                    or not isinstance(item.get("RequestId"), str)
                    or not item.get("RequestId")
                    or item.get("Status") != "IN_PROGRESS"
                ):
                    raise BrokerContractError(
                        "OPERATION_LIST_MALFORMED",
                        "Identity Center operation inventory is malformed",
                    )
                detail_response = getattr(self._sso, describe_method_name)(
                    InstanceArn=config.instance_arn,
                    **{request_parameter: item["RequestId"]},
                )
                detail = (
                    detail_response.get(describe_result_key)
                    if isinstance(detail_response, Mapping)
                    else None
                )
                required_fields = (
                    "RequestId",
                    "Status",
                    "PermissionSetArn",
                    *extra_fields,
                )
                if (
                    not isinstance(detail, Mapping)
                    or any(
                        not isinstance(detail.get(field), str)
                        or not detail.get(field)
                        for field in required_fields
                    )
                    or detail.get("RequestId") != item["RequestId"]
                    or detail.get("Status") != "IN_PROGRESS"
                ):
                    raise BrokerContractError(
                        "OPERATION_READBACK_MALFORMED",
                        "Identity Center operation readback is malformed",
                    )
                if detail["PermissionSetArn"] == permission_set_arn:
                    raise BrokerContractError(
                        "PERMISSION_SET_OPERATION_IN_PROGRESS",
                        "permission set has a concurrent provider operation",
                    )

    def _permission_set_inventory(
        self, config: BrokerConfig, permission_set_arn: str
    ) -> dict[str, Any]:
        permission_set = self._sso.describe_permission_set(
            InstanceArn=config.instance_arn,
            PermissionSetArn=permission_set_arn,
        ).get("PermissionSet")
        if (
            not isinstance(permission_set, Mapping)
            or permission_set.get("PermissionSetArn") != permission_set_arn
        ):
            raise BrokerContractError("PERMISSION_SET_MALFORMED", "permission set readback is malformed")
        self._assert_no_pending_operations(config, permission_set_arn)
        tags_raw = _paginate_next_token(
            self._sso,
            "list_tags_for_resource",
            "Tags",
            InstanceArn=config.instance_arn,
            ResourceArn=permission_set_arn,
        )
        if any(
            not isinstance(item, Mapping)
            or set(item) != {"Key", "Value"}
            or not isinstance(item.get("Key"), str)
            or not item.get("Key")
            or not isinstance(item.get("Value"), str)
            for item in tags_raw
        ):
            raise BrokerContractError("TAG_LIST_MALFORMED", "permission set tags are malformed")
        tags = tuple(
            sorted((item["Key"], item["Value"]) for item in tags_raw)
        )
        if len(tags) != len({key for key, _ in tags}):
            raise BrokerContractError("TAG_LIST_DUPLICATE", "permission set tags are duplicated")
        inline = self._sso.get_inline_policy_for_permission_set(
            InstanceArn=config.instance_arn,
            PermissionSetArn=permission_set_arn,
        ).get("InlinePolicy")
        inline_digest = canonical_digest(_normalize_policy(inline)) if inline else None
        managed = _paginate_next_token(
            self._sso,
            "list_managed_policies_in_permission_set",
            "AttachedManagedPolicies",
            InstanceArn=config.instance_arn,
            PermissionSetArn=permission_set_arn,
        )
        if any(
            not isinstance(item, Mapping)
            or not isinstance(item.get("Arn"), str)
            or not item.get("Arn")
            or not isinstance(item.get("Name"), str)
            for item in managed
        ):
            raise BrokerContractError("MANAGED_POLICY_LIST_MALFORMED", "managed policies are malformed")
        managed_arns = tuple(
            sorted(item["Arn"] for item in managed)
        )
        if len(managed_arns) != len(set(managed_arns)):
            raise BrokerContractError("MANAGED_POLICY_LIST_DUPLICATE", "managed policies are duplicated")
        customer = _paginate_next_token(
            self._sso,
            "list_customer_managed_policy_references_in_permission_set",
            "CustomerManagedPolicyReferences",
            InstanceArn=config.instance_arn,
            PermissionSetArn=permission_set_arn,
        )
        if any(
            not isinstance(item, Mapping)
            or not isinstance(item.get("Name"), str)
            or not item.get("Name")
            or (
                "Path" in item
                and (
                    not isinstance(item.get("Path"), str)
                    or not item.get("Path")
                )
            )
            for item in customer
        ):
            raise BrokerContractError(
                "CUSTOMER_POLICY_LIST_MALFORMED",
                "customer-managed policy references are malformed",
            )
        customer_refs = tuple(
            sorted(canonical_json(item) for item in customer)
        )
        if len(customer_refs) != len(set(customer_refs)):
            raise BrokerContractError("CUSTOMER_POLICY_LIST_DUPLICATE", "customer policies are duplicated")
        try:
            boundary = self._sso.get_permissions_boundary_for_permission_set(
                InstanceArn=config.instance_arn,
                PermissionSetArn=permission_set_arn,
            ).get("PermissionsBoundary")
        except Exception as exc:
            if _provider_code(exc) in {
                "ResourceNotFoundException",
                "ResourceNotFound",
            }:
                boundary = None
            else:
                raise
        accounts_raw = _paginate_next_token(
            self._sso,
            "list_accounts_for_provisioned_permission_set",
            "AccountIds",
            InstanceArn=config.instance_arn,
            PermissionSetArn=permission_set_arn,
        )
        if any(
            not isinstance(account, str) or not re.fullmatch(r"[0-9]{12}", account)
            for account in accounts_raw
        ):
            raise BrokerContractError("ACCOUNT_LIST_MALFORMED", "provisioned accounts are malformed")
        accounts = tuple(sorted(accounts_raw))
        if len(accounts) != len(set(accounts)):
            raise BrokerContractError("ACCOUNT_LIST_DUPLICATE", "provisioned accounts are duplicated")
        assignments_raw: list[Any] = []
        for account_id in sorted(set(accounts) | {AUTHORITY_ACCOUNT_ID}):
            page = _paginate_next_token(
                self._sso,
                "list_account_assignments",
                "AccountAssignments",
                InstanceArn=config.instance_arn,
                AccountId=account_id,
                PermissionSetArn=permission_set_arn,
            )
            if any(
                not isinstance(item, Mapping)
                or not all(
                    isinstance(item.get(field), str) and item.get(field)
                    for field in (
                        "AccountId",
                        "PermissionSetArn",
                        "PrincipalType",
                        "PrincipalId",
                    )
                )
                or item.get("AccountId") != account_id
                or item.get("PermissionSetArn") != permission_set_arn
                for item in page
            ):
                raise BrokerContractError(
                    "ASSIGNMENT_LIST_MALFORMED", "account assignments are malformed"
                )
            assignments_raw.extend(page)
        assignments = tuple(
            sorted(
                (
                    Assignment(
                        item["PrincipalType"],
                        item["PrincipalId"],
                        item["AccountId"],
                    )
                    for item in assignments_raw
                ),
                key=lambda item: (
                    item.target_account_id,
                    item.principal_type,
                    item.principal_id,
                ),
            )
        )
        if len(assignments) != len(set(assignments)):
            raise BrokerContractError(
                "ASSIGNMENT_LIST_DUPLICATE", "account assignments are duplicated"
            )
        return {
            "permission_set": permission_set,
            "tags": tags,
            "inline_digest": inline_digest,
            "managed_arns": managed_arns,
            "customer_refs": customer_refs,
            "boundary": boundary,
            "assignments": assignments,
            "accounts": accounts,
        }

    def snapshot(
        self,
        config: BrokerConfig,
        collector_policy: Mapping[str, Any],
        repair_invoker_policy: Mapping[str, Any],
    ) -> BrokerLiveSnapshot:
        kms_mode, kms_key_arn = self._instance_binding(config)
        user = self._identitystore.describe_user(
            IdentityStoreId=config.identity_store_id,
            UserId=config.principal_id,
        )
        if user.get("UserId") != config.principal_id:
            raise BrokerContractError("PRINCIPAL_READBACK_MISMATCH", "collector user differs")
        collector = self._permission_set_inventory(
            config, config.collector_permission_set_arn
        )
        invoker = self._permission_set_inventory(
            config, config.repair_invoker_permission_set_arn
        )
        collector_permission_set = collector["permission_set"]
        invoker_permission_set = invoker["permission_set"]
        return BrokerLiveSnapshot(
            invoker=RepairInvokerSnapshot(
                permission_set_arn=config.repair_invoker_permission_set_arn,
                permission_set_name=str(invoker_permission_set.get("Name", "")),
                permission_set_description=str(
                    invoker_permission_set.get("Description", "")
                ),
                session_duration=str(invoker_permission_set.get("SessionDuration", "")),
                relay_state=(
                    None
                    if invoker_permission_set.get("RelayState") in (None, "")
                    else str(invoker_permission_set.get("RelayState"))
                ),
                permission_set_tags=invoker["tags"],
                inline_policy_digest=invoker["inline_digest"],
                managed_policy_arns=invoker["managed_arns"],
                customer_managed_policy_references=invoker["customer_refs"],
                permissions_boundary_present=bool(invoker["boundary"]),
                assignments=invoker["assignments"],
                provisioned_account_ids=invoker["accounts"],
                invoker_roles=self._repair_invoker_roles(
                    config, repair_invoker_policy
                ),
            ),
            collector=LiveSnapshot(
            instance_arn=config.instance_arn,
            identity_store_id=config.identity_store_id,
            kms_mode=kms_mode,
            kms_key_arn=kms_key_arn,
            permission_set_arn=config.collector_permission_set_arn,
            permission_set_name=str(collector_permission_set.get("Name", "")),
            permission_set_description=str(
                collector_permission_set.get("Description", "")
            ),
            session_duration=str(collector_permission_set.get("SessionDuration", "")),
            relay_state=(
                None
                if collector_permission_set.get("RelayState") in (None, "")
                else str(collector_permission_set.get("RelayState"))
            ),
            permission_set_tags=collector["tags"],
            inline_policy_digest=collector["inline_digest"],
            managed_policy_arns=collector["managed_arns"],
            customer_managed_policy_references=collector["customer_refs"],
            permissions_boundary_present=bool(collector["boundary"]),
            assignments=collector["assignments"],
            provisioned_account_ids=collector["accounts"],
            collector_roles=self._collector_roles(config, collector_policy),
            ),
        )

    def put_inline_policy(self, config: BrokerConfig, policy_json: str) -> None:
        self._sso.put_inline_policy_to_permission_set(
            InstanceArn=config.instance_arn,
            PermissionSetArn=config.collector_permission_set_arn,
            InlinePolicy=policy_json,
        )

    def create_account_assignment(self, config: BrokerConfig) -> OperationResult:
        response = self._sso.create_account_assignment(
            InstanceArn=config.instance_arn,
            TargetId=AUTHORITY_ACCOUNT_ID,
            TargetType="AWS_ACCOUNT",
            PermissionSetArn=config.collector_permission_set_arn,
            PrincipalType="USER",
            PrincipalId=config.principal_id,
        ).get("AccountAssignmentCreationStatus")
        return _parse_operation(response, "RequestId")

    def describe_account_assignment(self, request_id: str) -> str:
        response = self._sso.describe_account_assignment_creation_status(
            InstanceArn=self._config.instance_arn,
            AccountAssignmentCreationRequestId=request_id,
        ).get("AccountAssignmentCreationStatus")
        return _parse_operation(response, "RequestId").status

    def provision_permission_set(self, config: BrokerConfig) -> OperationResult:
        response = self._sso.provision_permission_set(
            InstanceArn=config.instance_arn,
            PermissionSetArn=config.collector_permission_set_arn,
            TargetId=AUTHORITY_ACCOUNT_ID,
            TargetType="AWS_ACCOUNT",
        ).get("PermissionSetProvisioningStatus")
        return _parse_operation(response, "RequestId")

    def describe_provisioning(self, request_id: str) -> str:
        response = self._sso.describe_permission_set_provisioning_status(
            InstanceArn=self._config.instance_arn,
            ProvisionPermissionSetRequestId=request_id,
        ).get("PermissionSetProvisioningStatus")
        return _parse_operation(response, "RequestId").status


def _parse_operation(value: Any, request_key: str) -> OperationResult:
    if not isinstance(value, Mapping):
        raise ProviderResponseAmbiguous("mutation status is absent")
    request_id = value.get(request_key)
    status = value.get("Status")
    if not isinstance(request_id, str) or not request_id or status not in {
        "IN_PROGRESS",
        "SUCCEEDED",
        "FAILED",
    }:
        raise ProviderResponseAmbiguous("mutation status is malformed")
    return OperationResult(request_id=request_id, status=status)


def _parse_exact_saml_trust(value: Any, expected_provider_arn: str) -> tuple[str, str]:
    policy = _normalize_policy(value)
    statements = policy.get("Statement")
    if isinstance(statements, Mapping):
        statements = [statements]
    if not isinstance(statements, list) or len(statements) != 1:
        raise BrokerContractError("SAML_TRUST_MISMATCH", "collector trust must have one statement")
    statement = statements[0]
    if not isinstance(statement, Mapping):
        raise BrokerContractError("SAML_TRUST_MISMATCH", "collector SAML statement is malformed")
    actions = statement.get("Action")
    if isinstance(actions, str):
        action_values = [actions]
    elif isinstance(actions, list) and all(isinstance(item, str) for item in actions):
        action_values = actions
    else:
        raise BrokerContractError("SAML_TRUST_MISMATCH", "collector SAML actions are malformed")
    expected_without_action = {
        "Effect": "Allow",
        "Principal": {"Federated": expected_provider_arn},
        "Condition": {"StringEquals": {"SAML:aud": "https://signin.aws.amazon.com/saml"}},
    }
    observed_without_action = dict(statement)
    observed_without_action.pop("Action", None)
    if (
        observed_without_action != expected_without_action
        or len(action_values) != 2
        or set(action_values) != {"sts:AssumeRoleWithSAML", "sts:TagSession"}
    ):
        raise BrokerContractError("SAML_TRUST_MISMATCH", "collector SAML trust differs")
    return expected_provider_arn, "https://signin.aws.amazon.com/saml"


def _ledger_matches(
    ledger: Mapping[str, Any] | None,
    *,
    config: BrokerConfig,
    intent_digest: str,
    ledger_digest: str,
) -> Mapping[str, Any]:
    if ledger is None:
        raise BrokerContractError("LEDGER_MISSING", "durable ledger claim is missing")
    exact = {
        "schema_version": SCHEMA_VERSION,
        "record_type": PRIVATE_LEDGER_TYPE,
        "repair_id": config.repair_id,
        "intent_digest": intent_digest,
        "ledger_digest": ledger_digest,
        "source_commit": config.source_commit,
        "original_gug220_ledger_digest": config.original_gug220_ledger_digest,
        "authority_account_id": config.authority_account_id,
        "management_account_id": config.management_account_id,
        "region": config.region,
        "plan_function_version": config.plan_function_version,
        "repair_function_version": config.repair_function_version,
        "repair_not_before": utc_timestamp(config.not_before),
        "repair_not_after": utc_timestamp(config.not_after),
        "provider_immutable": True,
        "claim_condition": "attribute_not_exists(repair_id)",
        "mutation_retry_attempted": False,
        "production_authorized": False,
    }
    for key, expected in exact.items():
        if ledger.get(key) != expected:
            raise BrokerContractError("LEDGER_BINDING_MISMATCH", "durable ledger binding differs")

    planned_state_digest = ledger.get("planned_state_digest")
    if (
        not isinstance(planned_state_digest, str)
        or not _SHA256_RE.fullmatch(planned_state_digest)
    ):
        raise BrokerContractError(
            "LEDGER_BINDING_MISMATCH", "planned provider state digest differs"
        )
    try:
        planned_at = parse_utc_timestamp(ledger.get("planned_at"), "planned_at")
    except BrokerContractError as exc:
        raise BrokerContractError(
            "LEDGER_BINDING_MISMATCH", "durable Plan timestamp differs"
        ) from exc
    if planned_at < config.not_before or planned_at > config.not_after:
        raise BrokerContractError(
            "LEDGER_BINDING_MISMATCH", "durable Plan timestamp is outside the repair window"
        )
    initial_binding = {
        "schema_version": SCHEMA_VERSION,
        "record_type": PRIVATE_LEDGER_TYPE,
        "repair_id": config.repair_id,
        "intent_digest": intent_digest,
        "source_commit": config.source_commit,
        "original_gug220_ledger_digest": config.original_gug220_ledger_digest,
        "authority_account_id": config.authority_account_id,
        "management_account_id": config.management_account_id,
        "region": config.region,
        "plan_function_version": config.plan_function_version,
        "repair_function_version": config.repair_function_version,
        "repair_not_before": utc_timestamp(config.not_before),
        "repair_not_after": utc_timestamp(config.not_after),
        "status": "PLAN_VERIFIED",
        "stage": "PLAN_STATE_VERIFIED",
        "effects_attempted": 0,
        "effects_completed": 0,
        "planned_state_digest": planned_state_digest,
        "state_digest": planned_state_digest,
        "provider_immutable": True,
        "claim_condition": "attribute_not_exists(repair_id)",
        "mutation_retry_attempted": False,
        "production_authorized": False,
        "planned_at": utc_timestamp(planned_at),
    }
    if canonical_digest(initial_binding) != ledger_digest:
        raise BrokerContractError(
            "LEDGER_BINDING_MISMATCH", "durable ledger digest differs"
        )

    status = ledger.get("status")
    claimed_at_raw = ledger.get("claimed_at")
    updated_at_raw = ledger.get("updated_at")
    state_digest = ledger.get("state_digest")
    if not isinstance(state_digest, str) or not _SHA256_RE.fullmatch(state_digest):
        raise BrokerContractError(
            "LEDGER_BINDING_MISMATCH", "durable ledger state digest differs"
        )
    if status == "PLAN_VERIFIED":
        if (
            claimed_at_raw is not None
            or updated_at_raw is not None
            or state_digest != planned_state_digest
        ):
            raise BrokerContractError(
                "LEDGER_BINDING_MISMATCH", "unconsumed Plan contains repair metadata"
            )
    else:
        try:
            claimed_at = parse_utc_timestamp(claimed_at_raw, "claimed_at")
            updated_at = parse_utc_timestamp(updated_at_raw, "updated_at")
        except BrokerContractError as exc:
            raise BrokerContractError(
                "LEDGER_BINDING_MISMATCH", "durable ledger update timestamp differs"
            ) from exc
        if (
            claimed_at < planned_at
            or claimed_at < config.not_before
            or claimed_at > config.not_after
            or updated_at < claimed_at
        ):
            raise BrokerContractError(
                "LEDGER_BINDING_MISMATCH", "durable ledger timestamps are out of order"
            )
    return ledger


def _validate_ledger_progress(ledger: Mapping[str, Any]) -> None:
    status = ledger.get("status")
    stage = ledger.get("stage")
    attempted = ledger.get("effects_attempted")
    completed = ledger.get("effects_completed")
    if type(attempted) is not int or type(completed) is not int:
        raise BrokerContractError("LEDGER_PROGRESS_INVALID", "ledger counters are malformed")
    exact: dict[str, tuple[str, int, int]] = {
        "PLAN_VERIFIED": ("PLAN_STATE_VERIFIED", 0, 0),
        "CLAIMED": ("BEFORE_FIRST_EFFECT", 0, 0),
        "ATTEMPTING_1": ("BEFORE_PUT_INLINE_POLICY", 0, 0),
        "COMPLETED_1": ("AFTER_PUT_INLINE_POLICY", 1, 1),
        "ATTEMPTING_2": ("BEFORE_CREATE_ACCOUNT_ASSIGNMENT", 1, 1),
        "COMPLETED_2": ("AFTER_CREATE_ACCOUNT_ASSIGNMENT", 2, 2),
        "ATTEMPTING_3": ("BEFORE_PROVISION_PERMISSION_SET", 2, 2),
        "COMPLETED_3": ("AFTER_PROVISION_PERMISSION_SET", 3, 3),
        "REPAIR_VERIFIED": ("FINAL_READBACK_VERIFIED", 3, 3),
    }
    if status in exact:
        if (stage, attempted, completed) != exact[status]:
            raise BrokerContractError("LEDGER_PROGRESS_INVALID", "ledger progress is impossible")
        return
    if status != "UNCERTAIN_RECONCILE_ONLY":
        raise BrokerContractError("LEDGER_PROGRESS_INVALID", "ledger status is unsupported")
    uncertain_stages = {
        "UNCERTAIN_PUT_INLINE_POLICY": (1, 0),
        "UNCERTAIN_PUT_INLINE_POLICY_LEDGER_COMMIT": (1, 1),
        "UNCERTAIN_CREATE_ACCOUNT_ASSIGNMENT": (2, 1),
        "UNCERTAIN_CREATE_ACCOUNT_ASSIGNMENT_LEDGER_COMMIT": (2, 2),
        "UNCERTAIN_PROVISION_PERMISSION_SET": (3, 2),
        "UNCERTAIN_PROVISION_PERMISSION_SET_LEDGER_COMMIT": (3, 3),
        "UNCERTAIN_FINAL_READBACK": (3, 3),
    }
    if stage not in uncertain_stages or (attempted, completed) != uncertain_stages[stage]:
        raise BrokerContractError("LEDGER_PROGRESS_INVALID", "uncertain ledger progress is impossible")


class RepairBroker:
    def __init__(
        self,
        *,
        config: BrokerConfig,
        identity: IdentityCenterPort,
        local_control_plane: LocalControlPlanePort,
        iam_effective: IamEffectiveVerifierPort,
        invocation_authority: InvocationAuthorityPort,
        ledger: LedgerPort,
        collector_policy: Mapping[str, Any],
        repair_invoker_policy: Mapping[str, Any],
        invoked_function_arn: str,
        caller_arn: str,
        now: Callable[[], datetime] | None = None,
        sleep: Callable[[float], None] = time.sleep,
        remaining_time_ms: Callable[[], int] | None = None,
        repo_root: Path | None = None,
    ) -> None:
        self._config = config
        self._identity = identity
        self._local_control_plane = local_control_plane
        self._iam_effective = iam_effective
        self._invocation_authority = invocation_authority
        self._last_invocation_authority: (
            VerifiedRepairInvocationAuthority | None
        ) = None
        self._ledger = ledger
        self._policy = dict(collector_policy)
        self._repair_invoker_policy = dict(repair_invoker_policy)
        self._policy_json = _assert_policy_binding(config, self._policy)
        _assert_repair_invoker_policy_binding(config, self._repair_invoker_policy)
        self._invoked_function_arn = invoked_function_arn
        self._caller_arn = caller_arn
        self._now = now or (lambda: datetime.now(timezone.utc))
        self._sleep = sleep
        self._remaining_time_ms = remaining_time_ms or (
            lambda: FUNCTION_TIMEOUT_SECONDS[config.mode] * 1_000
        )
        self._repo_root = repo_root

    def _validate_static(self) -> None:
        validate_invocation(self._config, self._invoked_function_arn, self._caller_arn)
        if canonical_digest(build_private_intent(self._config)) != self.intent_digest:
            raise BrokerContractError("SOURCE_BINDING_CHANGED", "immutable intent changed")

    def _snapshot(self) -> VerifiedBrokerLiveSnapshot:
        identity = self._identity.snapshot(
            self._config,
            self._policy,
            self._repair_invoker_policy,
        )
        validate_repair_invoker_snapshot(self._config, identity.invoker)
        try:
            invocation_authority = self._invocation_authority.snapshot(
                self._config, identity.invoker
            )
            if self._last_invocation_authority is not None:
                require_stable_authority(
                    self._last_invocation_authority, invocation_authority
                )
        except AuthorityInventoryError as exc:
            raise BrokerContractError(
                "INVOCATION_AUTHORITY_UNVERIFIED",
                "the complete Lambda invocation graph is not exactly reviewed",
            ) from exc
        self._last_invocation_authority = invocation_authority
        local = self._local_control_plane.snapshot(self._config)
        validate_local_control_plane_snapshot(self._config, local)
        iam = self._iam_effective.snapshot(self._config)
        validate_iam_effective_snapshot(
            self._config, iam, repo_root=self._repo_root
        )
        observed = VerifiedBrokerLiveSnapshot(
            identity=identity,
            local=local,
            iam=iam,
            invocation_authority=invocation_authority,
        )
        return observed

    @property
    def intent_digest(self) -> str:
        return canonical_digest(build_private_intent(self._config))

    def _receipt(
        self,
        *,
        status: str,
        ledger: Mapping[str, Any] | None,
        state_digest: str,
        next_action: str,
        mutation_attribution: str,
    ) -> dict[str, Any]:
        attempted = int(ledger.get("effects_attempted", 0)) if ledger else 0
        completed = int(ledger.get("effects_completed", 0)) if ledger else 0
        return build_public_receipt(
            config=self._config,
            status=status,
            intent_digest=self.intent_digest,
            ledger_digest=(str(ledger["ledger_digest"]) if ledger else None),
            state_digest=state_digest,
            effects_attempted=attempted,
            effects_completed=completed,
            mutation_attribution=mutation_attribution,
            required_next_action=next_action,
            generated_at=self._now(),
        )

    def run(self, event: Any) -> dict[str, Any]:
        validate_empty_event(event)
        self._validate_static()
        if self._config.mode == "plan":
            return self._run_plan()
        if self._config.mode == "reconcile":
            return self._run_reconcile()
        return self._run_repair()

    def _run_plan(self) -> dict[str, Any]:
        plan_time = self._now()
        validate_time(self._config, plan_time)
        snapshot = self._snapshot()
        validate_snapshot(self._config, snapshot.collector, "BEFORE_PUT_INLINE_POLICY")
        validate_time(self._config, self._now())
        claim = build_private_ledger_claim(
            self._config, plan_time, snapshot.digest()
        )
        ledger_digest = str(claim["ledger_digest"])
        try:
            self._ledger.claim(claim)
        except ProviderResponseAmbiguous:
            # A lost PutItem response is reconciled only by exact strongly
            # consistent readback.  No retry is ever issued.
            observed = _ledger_matches(
                self._ledger.read(self._config.repair_id),
                config=self._config,
                intent_digest=self.intent_digest,
                ledger_digest=ledger_digest,
            )
            _validate_ledger_progress(observed)
            if observed.get("status") != "PLAN_VERIFIED":
                raise BrokerContractError(
                    "LEDGER_STAGE_MISMATCH", "durable Plan state differs"
                )
        ledger = _ledger_matches(
            self._ledger.read(self._config.repair_id),
            config=self._config,
            intent_digest=self.intent_digest,
            ledger_digest=ledger_digest,
        )
        _validate_ledger_progress(ledger)
        if ledger.get("status") != "PLAN_VERIFIED":
            raise BrokerContractError(
                "LEDGER_STAGE_MISMATCH", "durable Plan state differs"
            )
        return self._receipt(
            status="PLAN_VERIFIED",
            ledger=ledger,
            state_digest=snapshot.digest(),
            next_action="INVOKE_REPAIR_ALIAS",
            mutation_attribution="PROVEN_BY_DURABLE_LEDGER",
        )

    def _run_reconcile(self) -> dict[str, Any]:
        ledger = self._ledger.read(self._config.repair_id)
        if ledger is None:
            return self._receipt(
                status="BLOCKED",
                ledger=None,
                state_digest=sanitized_blocked_state_digest("LEDGER_MISSING"),
                next_action="REVIEW_BLOCKER",
                mutation_attribution="UNPROVEN",
            )
        ledger_digest = str(ledger.get("ledger_digest", ""))
        try:
            ledger = _ledger_matches(
                ledger,
                config=self._config,
                intent_digest=self.intent_digest,
                ledger_digest=ledger_digest,
            )
            _validate_ledger_progress(ledger)
        except BrokerContractError as exc:
            return self._receipt(
                status="BLOCKED",
                ledger=None,
                state_digest=sanitized_blocked_state_digest(exc.code),
                next_action="REVIEW_BLOCKER",
                mutation_attribution="UNPROVEN",
            )
        snapshot = self._snapshot()
        final_exact = True
        try:
            validate_snapshot(self._config, snapshot.collector, "FINAL")
        except BrokerContractError:
            final_exact = False
        status = ledger.get("status")
        stage = ledger.get("stage")
        completed_proof = status == "REPAIR_VERIFIED" or (
            status == "UNCERTAIN_RECONCILE_ONLY"
            and stage in {
                "UNCERTAIN_CREATE_ACCOUNT_ASSIGNMENT",
                "UNCERTAIN_CREATE_ACCOUNT_ASSIGNMENT_LEDGER_COMMIT",
                "UNCERTAIN_PROVISION_PERMISSION_SET",
                "UNCERTAIN_PROVISION_PERMISSION_SET_LEDGER_COMMIT",
                "UNCERTAIN_FINAL_READBACK",
            }
            and (
                ledger.get("effects_attempted"),
                ledger.get("effects_completed"),
            )
            in {(2, 2), (3, 2), (3, 3)}
        )
        if final_exact and completed_proof:
            return self._receipt(
                status="RECONCILE_VERIFIED",
                ledger=ledger,
                state_digest=snapshot.digest(),
                next_action="NONE",
                mutation_attribution="PROVEN_BY_DURABLE_LEDGER",
            )
        if status == "UNCERTAIN_RECONCILE_ONLY":
            return self._receipt(
                status="UNCERTAIN_RECONCILE_ONLY",
                ledger=ledger,
                state_digest=snapshot.digest(),
                next_action="INVOKE_RECONCILE_ALIAS",
                mutation_attribution="PROVEN_BY_DURABLE_LEDGER",
            )
        return self._receipt(
            status="BLOCKED",
            ledger=None,
            state_digest=snapshot.digest(),
            next_action="REVIEW_BLOCKER",
            mutation_attribution="UNPROVEN",
        )

    def _transition(
        self,
        *,
        ledger_digest: str,
        expected_status: str,
        new_status: str,
        stage: str,
        attempted: int,
        completed: int,
        state_digest: str,
        claimed_at: datetime | None = None,
    ) -> Mapping[str, Any]:
        expected_ledger = _ledger_matches(
            self._ledger.read(self._config.repair_id),
            config=self._config,
            intent_digest=self.intent_digest,
            ledger_digest=ledger_digest,
        )
        _validate_ledger_progress(expected_ledger)
        if expected_ledger.get("status") != expected_status:
            raise BrokerContractError(
                "LEDGER_STAGE_MISMATCH", "durable ledger stage differs"
            )
        self._ledger.transition(
            repair_id=self._config.repair_id,
            intent_digest=self.intent_digest,
            ledger_digest=ledger_digest,
            expected_ledger=expected_ledger,
            expected_status=expected_status,
            new_status=new_status,
            stage=stage,
            effects_attempted=attempted,
            effects_completed=completed,
            state_digest=state_digest,
            updated_at=self._now(),
            claimed_at=claimed_at,
        )
        ledger = self._ledger.read(self._config.repair_id)
        ledger = _ledger_matches(
            ledger,
            config=self._config,
            intent_digest=self.intent_digest,
            ledger_digest=ledger_digest,
        )
        _validate_ledger_progress(ledger)
        if ledger.get("status") != new_status:
            raise BrokerContractError(
                "LEDGER_STAGE_MISMATCH", "durable ledger transition differs"
            )
        return ledger

    def _wait(self, operation: OperationResult, describe: Callable[[str], str]) -> None:
        status = operation.status
        if status == "FAILED":
            raise ProviderResponseAmbiguous("provider reported failed mutation without safe retry")
        for _ in range(60):
            if status == "SUCCEEDED":
                return
            if self._now() >= self._config.not_after:
                raise ProviderResponseAmbiguous(
                    "provider operation outlived the immutable execution window"
                )
            remaining = self._remaining_time_ms()
            if type(remaining) is not int or remaining <= LAMBDA_POLLING_RESERVE_MS:
                raise ProviderResponseAmbiguous(
                    "provider operation cannot be proven before Lambda timeout"
                )
            self._sleep(1.0)
            status = describe(operation.request_id)
            if status == "FAILED":
                raise ProviderResponseAmbiguous("provider reported failed mutation without safe retry")
        raise ProviderResponseAmbiguous("provider mutation did not reach a proven terminal state")

    def _assert_mutation_dispatch_budget(self) -> None:
        """Reserve enough runtime to persist uncertainty after one SDK timeout."""

        now = self._now()
        validate_time(self._config, now)
        if (
            self._config.not_after - now.astimezone(timezone.utc)
        ).total_seconds() <= MUTATION_WINDOW_MIN_REMAINING_SECONDS:
            raise BrokerContractError(
                "MUTATION_WINDOW_INSUFFICIENT",
                "the immutable window cannot safely contain one mutation attempt",
            )
        remaining = self._remaining_time_ms()
        if (
            type(remaining) is not int
            or remaining <= LAMBDA_MUTATION_DISPATCH_MIN_REMAINING_MS
        ):
            raise BrokerContractError(
                "LAMBDA_BUDGET_INSUFFICIENT",
                "the remaining Lambda budget cannot safely dispatch a mutation",
            )

    def _assert_repair_start_window(self, now: datetime) -> None:
        """Do not consume a durable Plan without the complete repair window."""

        validate_time(self._config, now)
        remaining = (
            self._config.not_after - now.astimezone(timezone.utc)
        ).total_seconds()
        if remaining < REPAIR_START_MIN_WINDOW_REMAINING_SECONDS:
            raise BrokerContractError(
                "REPAIR_WINDOW_INSUFFICIENT",
                "the immutable window cannot safely contain the repair",
            )

    def _assert_repair_claim_budget(self) -> None:
        """Do not consume Plan after the initial inventory exhausts runtime."""

        remaining = self._remaining_time_ms()
        if (
            type(remaining) is not int
            or remaining <= REPAIR_CLAIM_MIN_REMAINING_MS
        ):
            raise BrokerContractError(
                "LAMBDA_BUDGET_INSUFFICIENT",
                "the remaining Lambda budget cannot safely consume the durable Plan",
            )

    def _mark_uncertain(
        self,
        *,
        ledger_digest: str,
        expected_status: str,
        stage: str,
        attempted: int,
        completed: int,
        state_digest: str,
    ) -> Mapping[str, Any] | None:
        try:
            return self._transition(
                ledger_digest=ledger_digest,
                expected_status=expected_status,
                new_status="UNCERTAIN_RECONCILE_ONLY",
                stage=stage,
                attempted=attempted,
                completed=completed,
                state_digest=state_digest,
            )
        except Exception:
            # Never retry a mutation because uncertainty could not be persisted.
            return None

    def _run_repair(self) -> dict[str, Any]:
        now = self._now()
        self._assert_repair_start_window(now)
        initial = self._snapshot()
        validate_snapshot(self._config, initial.collector, "BEFORE_PUT_INLINE_POLICY")
        ledger = self._ledger.read(self._config.repair_id)
        if ledger is None:
            raise BrokerContractError(
                "PLAN_REQUIRED", "repair requires a durable verified Plan"
            )
        ledger_digest = str(ledger.get("ledger_digest", ""))
        ledger = _ledger_matches(
            ledger,
            config=self._config,
            intent_digest=self.intent_digest,
            ledger_digest=ledger_digest,
        )
        _validate_ledger_progress(ledger)
        if ledger.get("status") != "PLAN_VERIFIED":
            raise BrokerContractError(
                "REPLAY_BLOCKED", "durable Plan is absent or already consumed"
            )
        if ledger.get("planned_state_digest") != initial.digest():
            raise BrokerContractError(
                "PLAN_STATE_CHANGED", "provider state changed after the durable Plan"
            )
        claim_time = self._now()
        self._assert_repair_start_window(claim_time)
        self._assert_repair_claim_budget()
        try:
            ledger = self._transition(
                ledger_digest=ledger_digest,
                expected_status="PLAN_VERIFIED",
                new_status="CLAIMED",
                stage="BEFORE_FIRST_EFFECT",
                attempted=0,
                completed=0,
                state_digest=initial.digest(),
                claimed_at=claim_time,
            )
        except (ProviderResponseAmbiguous, BrokerContractError):
            try:
                observed = _ledger_matches(
                    self._ledger.read(self._config.repair_id),
                    config=self._config,
                    intent_digest=self.intent_digest,
                    ledger_digest=ledger_digest,
                )
            except Exception:
                observed = None
            if observed is not None and observed.get("status") == "CLAIMED":
                _validate_ledger_progress(observed)
                return self._receipt(
                    status="BLOCKED",
                    ledger=observed,
                    state_digest=initial.digest(),
                    next_action="REVIEW_BLOCKER",
                    mutation_attribution="UNPROVEN",
                )
            return self._receipt(
                status="UNCERTAIN_RECONCILE_ONLY",
                ledger=None,
                state_digest=initial.digest(),
                next_action="INVOKE_RECONCILE_ALIAS",
                mutation_attribution="UNPROVEN",
            )
        expected_status = "CLAIMED"
        completed = 0
        stage_specs = (
            (
                "BEFORE_PUT_INLINE_POLICY",
                lambda: self._identity.put_inline_policy(self._config, self._policy_json),
                None,
            ),
            (
                "BEFORE_CREATE_ACCOUNT_ASSIGNMENT",
                lambda: self._identity.create_account_assignment(self._config),
                self._identity.describe_account_assignment,
            ),
            (
                "BEFORE_PROVISION_PERMISSION_SET",
                lambda: self._identity.provision_permission_set(self._config),
                self._identity.describe_provisioning,
            ),
        )
        last_state = initial
        for index, (stage, effect, status_reader) in enumerate(stage_specs, start=1):
            # Deterministic preconditions are not mutation attempts.  They may
            # consume the one-shot claim, but they never overclaim SSO effects.
            try:
                validate_time(self._config, self._now())
                self._validate_static()
                ledger = _ledger_matches(
                    self._ledger.read(self._config.repair_id),
                    config=self._config,
                    intent_digest=self.intent_digest,
                    ledger_digest=ledger_digest,
                )
                _validate_ledger_progress(ledger)
                if ledger.get("status") != expected_status:
                    raise BrokerContractError("LEDGER_STAGE_MISMATCH", "durable ledger stage differs")
                self._assert_mutation_dispatch_budget()
            except Exception:
                return self._receipt(
                    status="BLOCKED",
                    ledger=ledger,
                    state_digest=last_state.digest(),
                    next_action="REVIEW_BLOCKER",
                    mutation_attribution=(
                        "PROVEN_BY_DURABLE_LEDGER" if completed else "UNPROVEN"
                    ),
                )

            # Reserve the dispatch boundary.  ATTEMPTING keeps the prior
            # counters until the SSO call is actually issued.
            try:
                ledger = self._transition(
                    ledger_digest=ledger_digest,
                    expected_status=expected_status,
                    new_status=f"ATTEMPTING_{index}",
                    stage=stage,
                    attempted=completed,
                    completed=completed,
                    state_digest=last_state.digest(),
                )
                expected_status = f"ATTEMPTING_{index}"
            except Exception:
                try:
                    observed = self._ledger.read(self._config.repair_id)
                except Exception:
                    observed = None
                return self._receipt(
                    status="BLOCKED",
                    ledger=observed or ledger,
                    state_digest=last_state.digest(),
                    next_action="REVIEW_BLOCKER",
                    mutation_attribution=(
                        "PROVEN_BY_DURABLE_LEDGER" if completed else "UNPROVEN"
                    ),
                )

            # Revalidate after the CAS and immediately before provider dispatch.
            try:
                validate_time(self._config, self._now())
                self._validate_static()
                ledger = _ledger_matches(
                    self._ledger.read(self._config.repair_id),
                    config=self._config,
                    intent_digest=self.intent_digest,
                    ledger_digest=ledger_digest,
                )
                _validate_ledger_progress(ledger)
                if ledger.get("status") != expected_status:
                    raise BrokerContractError("LEDGER_STAGE_MISMATCH", "durable ledger stage differs")
                last_state = self._snapshot()
                validate_snapshot(self._config, last_state.collector, stage)
                self._assert_mutation_dispatch_budget()
            except Exception:
                return self._receipt(
                    status="BLOCKED",
                    ledger=ledger,
                    state_digest=last_state.digest(),
                    next_action="REVIEW_BLOCKER",
                    mutation_attribution=(
                        "PROVEN_BY_DURABLE_LEDGER" if completed else "UNPROVEN"
                    ),
                )

            try:
                result = effect()
                if status_reader is not None:
                    if not isinstance(result, OperationResult):
                        raise ProviderResponseAmbiguous("mutation response lacks request identity")
                    self._wait(result, status_reader)
            except Exception:
                uncertain = self._mark_uncertain(
                    ledger_digest=ledger_digest,
                    expected_status=expected_status,
                    stage=f"UNCERTAIN_{EFFECTS[index - 1]}",
                    attempted=index,
                    completed=completed,
                    state_digest=last_state.digest(),
                )
                return self._receipt(
                    status="UNCERTAIN_RECONCILE_ONLY",
                    ledger=uncertain,
                    state_digest=last_state.digest(),
                    next_action="INVOKE_RECONCILE_ALIAS",
                    mutation_attribution=(
                        "PROVEN_BY_DURABLE_LEDGER"
                        if uncertain
                        and uncertain.get("status") == "UNCERTAIN_RECONCILE_ONLY"
                        else "UNPROVEN"
                    ),
                )

            completed = index
            try:
                ledger = self._transition(
                    ledger_digest=ledger_digest,
                    expected_status=expected_status,
                    new_status=f"COMPLETED_{index}",
                    stage=f"AFTER_{EFFECTS[index - 1]}",
                    attempted=index,
                    completed=completed,
                    state_digest=last_state.digest(),
                )
                expected_status = f"COMPLETED_{index}"
            except Exception:
                uncertain = self._mark_uncertain(
                    ledger_digest=ledger_digest,
                    expected_status=expected_status,
                    stage=f"UNCERTAIN_{EFFECTS[index - 1]}_LEDGER_COMMIT",
                    attempted=index,
                    completed=completed,
                    state_digest=last_state.digest(),
                )
                return self._receipt(
                    status="UNCERTAIN_RECONCILE_ONLY",
                    ledger=uncertain,
                    state_digest=last_state.digest(),
                    next_action="INVOKE_RECONCILE_ALIAS",
                    mutation_attribution=(
                        "PROVEN_BY_DURABLE_LEDGER"
                        if uncertain
                        and uncertain.get("status") == "UNCERTAIN_RECONCILE_ONLY"
                        else "UNPROVEN"
                    ),
                )

        try:
            validate_time(self._config, self._now())
            self._validate_static()
            ledger = _ledger_matches(
                self._ledger.read(self._config.repair_id),
                config=self._config,
                intent_digest=self.intent_digest,
                ledger_digest=ledger_digest,
            )
            _validate_ledger_progress(ledger)
            final = self._snapshot()
            validate_snapshot(self._config, final.collector, "FINAL")
            validate_time(self._config, self._now())
            ledger = self._transition(
                ledger_digest=ledger_digest,
                expected_status=expected_status,
                new_status="REPAIR_VERIFIED",
                stage="FINAL_READBACK_VERIFIED",
                attempted=3,
                completed=3,
                state_digest=final.digest(),
            )
        except Exception:
            uncertain = self._mark_uncertain(
                ledger_digest=ledger_digest,
                expected_status=expected_status,
                stage="UNCERTAIN_FINAL_READBACK",
                attempted=3,
                completed=3,
                state_digest=last_state.digest(),
            )
            return self._receipt(
                status="UNCERTAIN_RECONCILE_ONLY",
                ledger=uncertain,
                state_digest=last_state.digest(),
                next_action="INVOKE_RECONCILE_ALIAS",
                mutation_attribution=(
                    "PROVEN_BY_DURABLE_LEDGER"
                    if uncertain
                    and uncertain.get("status") == "UNCERTAIN_RECONCILE_ONLY"
                    else "UNPROVEN"
                ),
            )
        return self._receipt(
            status="REPAIR_VERIFIED",
            ledger=ledger,
            state_digest=final.digest(),
            next_action="NONE",
            mutation_attribution="PROVEN_BY_DURABLE_LEDGER",
        )


def validate_runtime_sdk_versions(
    config: BrokerConfig, *, boto3_module: Any, botocore_module: Any
) -> None:
    """Bind AWS-managed SDK modules to the reviewed artifact handoff."""

    actual_boto3 = getattr(boto3_module, "__version__", None)
    actual_botocore = getattr(botocore_module, "__version__", None)
    if (
        not isinstance(actual_boto3, str)
        or actual_boto3 != config.expected_boto3_version
    ):
        raise BrokerContractError(
            "BOTO3_VERSION_MISMATCH", "the runtime boto3 version is not reviewed"
        )
    if (
        not isinstance(actual_botocore, str)
        or actual_botocore != config.expected_botocore_version
    ):
        raise BrokerContractError(
            "BOTOCORE_VERSION_MISMATCH",
            "the runtime botocore version is not reviewed",
        )


def _require_inventory_provider_call_budget(
    remaining_time_ms: Callable[[], int],
) -> None:
    """Reserve enough Lambda runtime to fail closed after one read-only call."""

    remaining = remaining_time_ms()
    if (
        type(remaining) is not int
        or remaining <= INVENTORY_PROVIDER_CALL_RESERVE_MS
    ):
        raise AuthorityInventoryError("LAMBDA_BUDGET_INSUFFICIENT")


class _BudgetGuardedClient:
    """Apply the Lambda budget guard immediately before every provider call."""

    def __init__(
        self, client: Any, remaining_time_ms: Callable[[], int]
    ) -> None:
        self._client = client
        self._remaining_time_ms = remaining_time_ms

    def __getattr__(self, name: str) -> Any:
        value = getattr(self._client, name)
        if not callable(value):
            return value

        def guarded(*args: Any, **kwargs: Any) -> Any:
            _require_inventory_provider_call_budget(self._remaining_time_ms)
            return value(*args, **kwargs)

        return guarded


class BotoSessionFactory:
    """Construct clients with SDK retries disabled and exact account roles."""

    def __init__(self, boto3_module: Any, botocore_config: Any) -> None:
        self._boto3 = boto3_module
        self._config_type = botocore_config
        self.client_config = self._config_type(
            region_name=REGION,
            retries={"mode": "standard", "total_max_attempts": 1},
            connect_timeout=SDK_CONNECT_TIMEOUT_SECONDS,
            read_timeout=SDK_READ_TIMEOUT_SECONDS,
        )

    def local_client(self, service: str) -> Any:
        return self._boto3.client(service, region_name=REGION, config=self.client_config)

    def assumed_clients(
        self, role_arn: str, repair_id: str
    ) -> tuple[Any, Any, Any]:
        sts = self.local_client("sts")
        response = sts.assume_role(
            RoleArn=role_arn,
            RoleSessionName=f"gug221-{sha_short(repair_id)}",
            SourceIdentity=f"gug221-{sha_short(repair_id)}",
            DurationSeconds=900,
        )
        credentials = response.get("Credentials")
        assumed = response.get("AssumedRoleUser")
        session_name = f"gug221-{sha_short(repair_id)}"
        expected_assumed_arn = (
            f"arn:aws:sts::{MANAGEMENT_ACCOUNT_ID}:assumed-role/"
            f"{role_arn.rsplit('/', 1)[-1]}/{session_name}"
        )
        if not isinstance(assumed, Mapping) or assumed.get("Arn") != expected_assumed_arn:
            raise BrokerContractError("ASSUME_ROLE_IDENTITY_MISMATCH", "assumed service role differs")
        if not isinstance(credentials, Mapping):
            raise BrokerContractError("ASSUME_ROLE_MALFORMED", "assume-role credentials are absent")
        kwargs = {
            "region_name": REGION,
            "config": self.client_config,
            "aws_access_key_id": credentials.get("AccessKeyId"),
            "aws_secret_access_key": credentials.get("SecretAccessKey"),
            "aws_session_token": credentials.get("SessionToken"),
        }
        if not all(isinstance(kwargs[key], str) and kwargs[key] for key in (
            "aws_access_key_id",
            "aws_secret_access_key",
            "aws_session_token",
        )):
            raise BrokerContractError("ASSUME_ROLE_MALFORMED", "assume-role credentials are malformed")
        return (
            self._boto3.client("sso-admin", **kwargs),
            self._boto3.client("identitystore", **kwargs),
            self._boto3.client("iam", **kwargs),
        )

    def authority_inventory_adapter(
        self,
        *,
        role_arn: str,
        repair_id: str,
        clock: Callable[[], datetime],
        remaining_time_ms: Callable[[], int] | None = None,
    ) -> tuple[AwsReadOnlyInventoryAdapter, str]:
        """Assume only the exact read-only invocation-inspector role."""

        if role_arn != INVOCATION_INSPECTOR_ROLE_ARN:
            raise BrokerContractError(
                "INSPECTOR_ROLE_MISMATCH", "invocation inspector role differs"
            )
        budget = remaining_time_ms or (
            lambda: FUNCTION_TIMEOUT_SECONDS["repair"] * 1_000
        )
        _require_inventory_provider_call_budget(budget)
        sts = self.local_client("sts")
        session_name = f"gug221-authority-{sha_short(repair_id)}"
        try:
            response = sts.assume_role(
                RoleArn=role_arn,
                RoleSessionName=session_name,
                SourceIdentity=session_name,
                DurationSeconds=900,
            )
        except Exception as exc:
            raise BrokerContractError(
                "INSPECTOR_ASSUME_ROLE_FAILED",
                "invocation inspector role could not be assumed",
            ) from exc
        credentials = response.get("Credentials") if isinstance(response, Mapping) else None
        assumed = response.get("AssumedRoleUser") if isinstance(response, Mapping) else None
        canonical_principal_arn = (
            f"arn:aws:sts::{AUTHORITY_ACCOUNT_ID}:assumed-role/"
            f"{INVOCATION_INSPECTOR_ROLE_NAME}"
        )
        expected_session_arn = f"{canonical_principal_arn}/{session_name}"
        if (
            not isinstance(assumed, Mapping)
            or assumed.get("Arn") != expected_session_arn
        ):
            raise BrokerContractError(
                "INSPECTOR_IDENTITY_MISMATCH",
                "assumed invocation inspector identity differs",
            )
        if not isinstance(credentials, Mapping):
            raise BrokerContractError(
                "INSPECTOR_CREDENTIALS_MALFORMED",
                "invocation inspector credentials are absent",
            )
        credential_kwargs = {
            "config": self.client_config,
            "aws_access_key_id": credentials.get("AccessKeyId"),
            "aws_secret_access_key": credentials.get("SecretAccessKey"),
            "aws_session_token": credentials.get("SessionToken"),
        }
        if not all(
            isinstance(credential_kwargs[key], str) and credential_kwargs[key]
            for key in (
                "aws_access_key_id",
                "aws_secret_access_key",
                "aws_session_token",
            )
        ):
            raise BrokerContractError(
                "INSPECTOR_CREDENTIALS_MALFORMED",
                "invocation inspector credentials are malformed",
            )

        def client(service: str, region: str) -> Any:
            return _BudgetGuardedClient(
                self._boto3.client(
                    service,
                    region_name=region,
                    **credential_kwargs,
                ),
                budget,
            )

        adapter = AwsReadOnlyInventoryAdapter(
            sts=client("sts", REGION),
            ec2=client("ec2", REGION),
            lambda_client=client("lambda", REGION),
            iam=client("iam", REGION),
            lambda_client_factory=lambda target_region: client(
                "lambda", target_region
            ),
            clock=clock,
        )
        return adapter, digest_text(canonical_principal_arn)


class AwsInvocationAuthorityVerifier:
    """Collect and verify the complete account-wide invocation graph."""

    def __init__(
        self,
        *,
        adapter: AwsReadOnlyInventoryAdapter,
        collector_principal_digest: str,
        clock: Callable[[], datetime],
    ) -> None:
        self._adapter = adapter
        self._collector_principal_digest = collector_principal_digest
        self._clock = clock
        self._capture_index = 0

    def snapshot(
        self, config: BrokerConfig, invoker: RepairInvokerSnapshot
    ) -> VerifiedRepairInvocationAuthority:
        if len(invoker.invoker_roles) != 1:
            raise AuthorityInventoryError("INVOKER_ROLE_COUNT_INVALID")
        role_name = invoker.invoker_roles[0].role_name
        role_arn = (
            f"arn:aws:iam::{AUTHORITY_ACCOUNT_ID}:role/"
            f"aws-reserved/sso.amazonaws.com/{role_name}"
        )
        binding = RepairInvocationAuthorityBinding(
            authority_account_id=AUTHORITY_ACCOUNT_ID,
            region=REGION,
            invoker_role_arn=role_arn,
            invoker_policy_digest=config.repair_invoker_policy_digest,
            collector_principal_digest=self._collector_principal_digest,
            saml_provider_arn=config.collector_saml_provider_arn,
        )
        self._capture_index += 1
        snapshots = collect_provider_invocation_snapshots(
            adapter=self._adapter,
            binding=binding,
            scan_id=(
                f"gug221:{sha_short(config.repair_id)}:"
                f"{self._capture_index:03d}"
            ),
        )
        return verify_provider_invocation_authority(
            binding=binding,
            snapshots=snapshots,
            decision_at=utc_timestamp(self._clock()),
        )


def sha_short(value: str) -> str:
    return canonical_digest({"value": value})[:16]


def _resolve_provider_derived_versions(
    config: BrokerConfig, lambda_client: Any
) -> BrokerConfig:
    """Resolve the Plan-to-Repair binding without a CloudFormation cycle.

    The dedicated Plan function cannot carry a Ref to the Repair version while
    Repair carries a Ref to Plan.  Plan therefore derives the immutable numeric
    Repair version from the exact private ``repair-v1`` alias.  The full local
    control-plane snapshot immediately re-reads and binds the same alias.
    """

    if config.repair_function_version != PROVIDER_DERIVED_FUNCTION_VERSION:
        return config
    if config.mode != "plan":
        raise BrokerContractError(
            "UNPUBLISHED_FUNCTION", "provider-derived version is not allowed in this mode"
        )
    try:
        response = lambda_client.get_alias(
            FunctionName=REPAIR_FUNCTION_NAME,
            Name="repair-v1",
        )
    except Exception as exc:
        raise BrokerContractError(
            "LAMBDA_ALIAS_READ_FAILED", "repair alias could not be read"
        ) from exc
    if not isinstance(response, Mapping):
        raise BrokerContractError(
            "LAMBDA_ALIAS_READ_MALFORMED", "repair alias response is malformed"
        )
    version = response.get("FunctionVersion")
    expected_arn = (
        f"arn:aws:lambda:{REGION}:{AUTHORITY_ACCOUNT_ID}:"
        f"function:{REPAIR_FUNCTION_NAME}:repair-v1"
    )
    if (
        response.get("AliasArn") != expected_arn
        or response.get("Name") != "repair-v1"
        or not isinstance(version, str)
        or _FUNCTION_VERSION_RE.fullmatch(version) is None
        or response.get("Description") not in (None, "")
        or response.get("RoutingConfig")
        not in (None, {}, {"AdditionalVersionWeights": {}})
    ):
        raise BrokerContractError(
            "LAMBDA_ALIAS_CONTROLS_CHANGED", "repair alias binding differs"
        )
    return replace(config, repair_function_version=version)


def build_runtime(
    *,
    env: Mapping[str, str],
    invoked_function_arn: str,
    boto3_module: Any,
    botocore_module: Any,
    botocore_config: Any,
    mode: str | None = None,
    qualifier: str | None = None,
    repo_root: Path | None = None,
    now: Callable[[], datetime] | None = None,
    sleep: Callable[[float], None] = time.sleep,
    remaining_time_ms: Callable[[], int] | None = None,
) -> RepairBroker:
    runtime_clock = now or (lambda: datetime.now(timezone.utc))
    config = BrokerConfig.from_env(
        env,
        mode_override=mode,
        qualifier_override=qualifier,
    )
    runtime_budget = remaining_time_ms or (
        lambda: FUNCTION_TIMEOUT_SECONDS[config.mode] * 1_000
    )
    validate_runtime_lock(config, repo_root=repo_root)
    validate_runtime_sdk_versions(
        config,
        boto3_module=boto3_module,
        botocore_module=botocore_module,
    )
    factory = BotoSessionFactory(boto3_module, botocore_config)
    lambda_client = factory.local_client("lambda")
    config = _resolve_provider_derived_versions(config, lambda_client)
    collector_policy = load_bundled_collector_policy(repo_root)
    repair_invoker_policy = load_bundled_repair_invoker_policy(repo_root)
    _assert_policy_binding(config, collector_policy)
    _assert_repair_invoker_policy_binding(config, repair_invoker_policy)
    sts = factory.local_client("sts")
    identity = sts.get_caller_identity()
    if identity.get("Account") != AUTHORITY_ACCOUNT_ID or not isinstance(identity.get("Arn"), str):
        raise BrokerContractError("LOCAL_IDENTITY_MISMATCH", "local Lambda identity differs")
    sso_admin, identitystore, management_iam = factory.assumed_clients(
        config.service_role_arn, config.repair_id
    )
    authority_iam = factory.local_client("iam")
    adapter = AwsIdentityCenterAdapter(
        config=config,
        sso_admin=sso_admin,
        identitystore=identitystore,
        authority_iam=authority_iam,
    )
    dynamodb = factory.local_client("dynamodb")
    local_control_plane = AwsLocalControlPlaneAdapter(
        lambda_client=lambda_client,
        dynamodb=dynamodb,
        kms=factory.local_client("kms"),
    )
    iam_effective = AwsIamEffectiveVerifier(
        authority_iam=authority_iam,
        management_iam=management_iam,
        repo_root=repo_root,
    )
    inventory_adapter, collector_principal_digest = (
        factory.authority_inventory_adapter(
            role_arn=INVOCATION_INSPECTOR_ROLE_ARN,
            repair_id=config.repair_id,
            clock=runtime_clock,
            remaining_time_ms=runtime_budget,
        )
    )
    invocation_authority = AwsInvocationAuthorityVerifier(
        adapter=inventory_adapter,
        collector_principal_digest=collector_principal_digest,
        clock=runtime_clock,
    )
    ledger = DynamoLedger(dynamodb, config.ledger_table_name)
    return RepairBroker(
        config=config,
        identity=adapter,
        local_control_plane=local_control_plane,
        iam_effective=iam_effective,
        invocation_authority=invocation_authority,
        ledger=ledger,
        collector_policy=collector_policy,
        repair_invoker_policy=repair_invoker_policy,
        invoked_function_arn=invoked_function_arn,
        caller_arn=identity["Arn"],
        now=runtime_clock,
        sleep=sleep,
        remaining_time_ms=runtime_budget,
        repo_root=repo_root,
    )


def _validate_synchronous_transport(context: Any) -> None:
    """Prove RequestResponse transport without treating the marker as authority.

    AWS Lambda exposes ``ClientContext`` to the function only for synchronous
    invocations.  Accounts, principals, policies, mode, and effects still come
    exclusively from the published version, alias, and immutable configuration.
    """

    client_context = getattr(context, "client_context", None)
    custom = getattr(client_context, "custom", None)
    if type(custom) is not dict or custom != SYNC_CLIENT_CONTEXT_CUSTOM:
        raise BrokerContractError(
            "SYNCHRONOUS_TRANSPORT_UNPROVEN",
            "the exact synchronous transport marker is absent",
        )


def _mode_handler_impl(
    expected_mode: str, expected_qualifier: str, event: Any, context: Any
) -> dict[str, Any]:
    """Private Lambda implementation. Never log event or provider payloads."""

    validate_empty_event(event)
    _validate_synchronous_transport(context)
    invoked_arn = getattr(context, "invoked_function_arn", None)
    if not isinstance(invoked_arn, str):
        raise BrokerContractError("FUNCTION_CONTEXT_MISSING", "Lambda invocation ARN is absent")
    remaining_time_ms = getattr(context, "get_remaining_time_in_millis", None)
    if not callable(remaining_time_ms):
        raise BrokerContractError(
            "FUNCTION_CONTEXT_MISSING", "Lambda remaining-time context is absent"
        )
    try:
        import boto3  # type: ignore
        import botocore  # type: ignore
        from botocore.config import Config  # type: ignore
    except ImportError as exc:  # pragma: no cover - deployment packaging failure.
        raise BrokerContractError("AWS_SDK_MISSING", "AWS SDK is unavailable") from exc
    runtime = build_runtime(
        env=os.environ,
        invoked_function_arn=invoked_arn,
        boto3_module=boto3,
        botocore_module=botocore,
        botocore_config=Config,
        mode=expected_mode,
        qualifier=expected_qualifier,
        remaining_time_ms=remaining_time_ms,
    )
    return runtime.run(event)


def _capture_mode_handler(
    expected_mode: str, expected_qualifier: str, event: Any, context: Any
) -> tuple[dict[str, Any] | None, str | None]:
    """Collapse private exceptions before they cross the Lambda boundary."""

    try:
        return (
            _mode_handler_impl(expected_mode, expected_qualifier, event, context),
            None,
        )
    except BrokerContractError as exc:
        code = exc.code if _PUBLIC_ERROR_CODE_RE.fullmatch(exc.code) else "CONTRACT_FAILURE"
        return None, code
    except Exception:
        return None, "PROVIDER_FAILURE"


def _mode_handler(
    expected_mode: str, expected_qualifier: str, event: Any, context: Any
) -> dict[str, Any]:
    result, error_code = _capture_mode_handler(
        expected_mode, expected_qualifier, event, context
    )
    if error_code is not None:
        # This raise occurs outside the private exception handler so provider
        # exception context, request IDs, ARNs, and payloads cannot be chained.
        raise PublicBrokerFailure(error_code)
    if result is None:  # Defensive typing guard; capture always returns one side.
        raise PublicBrokerFailure("PROVIDER_FAILURE")
    return result


def plan_handler(event: Any, context: Any) -> dict[str, Any]:
    return _mode_handler("plan", "plan-v1", event, context)


def repair_handler(event: Any, context: Any) -> dict[str, Any]:
    return _mode_handler("repair", "repair-v1", event, context)


def reconcile_handler(event: Any, context: Any) -> dict[str, Any]:
    return _mode_handler("reconcile", "reconcile-v1", event, context)
