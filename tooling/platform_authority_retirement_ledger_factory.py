"""One-shot factory for the protected GUG-215 retirement ledger.

This dedicated GUG-365 Lambda is neither the GUG-215 retirement broker nor a
human executor.  It creates one exact DynamoDB table with the canonical
resource policy embedded atomically in ``CreateTable`` and then enables the
exact 35-day PITR contract.  The target account, Region, table, role, tags,
schema and policy are compiled into reviewed source; the event must be exactly
``{}`` and deployment must configure an empty environment.

SDK retries are disabled.  ``CreateTable`` and ``UpdateContinuousBackups`` are
each called at most once.  Any effect-boundary ambiguity is terminal for this
runtime and returns ``UNCERTAIN_RECONCILE_ONLY``; a subsequent investigation
must revoke this factory and use a separate read-only principal.  Responses
contain only digests and status codes, never raw identifiers, policy JSON,
revision IDs, provider responses or exception text.  This module does not log.
"""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json
import re
from time import sleep
from typing import Any, Callable, Mapping


RECEIPT_ARTIFACT_TYPE = (
    "scanalyze.platform_authority.retirement_ledger_factory_receipt.v1"
)
SCHEMA_VERSION = 1
PARTITION = "aws"
AUTHORITY_ACCOUNT_ID = "042360977644"
REGION = "us-east-1"
LEDGER_TABLE_NAME = "scanalyze-platform-authority-change-set-retirements"
RETIREMENT_BROKER_ROLE_NAME = "ScanalyzeGug215BrokerExecution"
FACTORY_ROLE_NAME = "ScanalyzeGug365LedgerFactory"
FACTORY_FUNCTION_NAME = "scanalyze-platform-authority-gug365-ledger-factory"
KMS_KEY_ALIAS = "alias/aws/dynamodb"

ABSENCE_CONFIRMATION_DELAY_SECONDS = 1.0
ACTIVE_READBACK_MAX_ATTEMPTS = 30
ACTIVE_READBACK_DELAY_SECONDS = 1.0
POLICY_READBACK_MAX_ATTEMPTS = 6
POLICY_READBACK_DELAY_SECONDS = 1.0
PITR_READBACK_MAX_ATTEMPTS = 12
PITR_READBACK_DELAY_SECONDS = 1.0

WRITE_ACTIONS = (
    "dynamodb:BatchWriteItem",
    "dynamodb:DeleteItem",
    "dynamodb:PartiQLDelete",
    "dynamodb:PartiQLInsert",
    "dynamodb:PartiQLUpdate",
    "dynamodb:PutItem",
    "dynamodb:TransactWriteItems",
    "dynamodb:UpdateItem",
)
EXPECTED_LEDGER_TAGS = {
    "managed_by": "reviewed-direct-dynamodb",
    "service": "scanalyze-platform-authority",
    "data_class": "control-metadata",
    "work_package": "GUG-215",
    "environment": "non-production",
    "production": "false",
    "account_id": AUTHORITY_ACCOUNT_ID,
    "region": REGION,
}

_FUNCTION_VERSION = re.compile(r"^[1-9][0-9]{0,7}$")
_REVISION_ID = re.compile(r"^[^\s]{1,255}$")
_ASSUMED_ROLE_ARN = re.compile(
    r"^arn:aws:sts::"
    + AUTHORITY_ACCOUNT_ID
    + r":assumed-role/"
    + re.escape(FACTORY_ROLE_NAME)
    + r"/[A-Za-z0-9+=,.@_-]{2,64}$"
)
_KMS_KEY_ARN = re.compile(
    r"^arn:aws:kms:"
    + re.escape(REGION)
    + r":"
    + AUTHORITY_ACCOUNT_ID
    + r":key/[0-9a-f-]{36}$",
    re.IGNORECASE,
)
_KMS_KEY_ID = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    re.IGNORECASE,
)


class LedgerFactoryError(ValueError):
    """Stable fail-closed error carrying only a sanitized reason code."""

    def __init__(self, code: str) -> None:
        if re.fullmatch(r"[A-Z][A-Z0-9_]{2,95}", code) is None:
            code = "LEDGER_FACTORY_DENIED"
        self.code = code
        super().__init__(code)


def _fail(code: str) -> None:
    raise LedgerFactoryError(code)


def canonical_json(value: Any) -> str:
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        )
    except (TypeError, ValueError) as exc:
        raise LedgerFactoryError("CANONICAL_JSON_INVALID") from exc


def canonical_digest(value: Any) -> str:
    return "sha256:" + sha256(canonical_json(value).encode("utf-8")).hexdigest()


def _secret_digest(label: str, value: str) -> str:
    return canonical_digest({label: value})


def _table_arn() -> str:
    return (
        f"arn:{PARTITION}:dynamodb:{REGION}:{AUTHORITY_ACCOUNT_ID}:"
        f"table/{LEDGER_TABLE_NAME}"
    )


def _retirement_broker_role_arn() -> str:
    return (
        f"arn:{PARTITION}:iam::{AUTHORITY_ACCOUNT_ID}:"
        f"role/{RETIREMENT_BROKER_ROLE_NAME}"
    )


def _factory_function_arn(*, version: str) -> str:
    return (
        f"arn:{PARTITION}:lambda:{REGION}:{AUTHORITY_ACCOUNT_ID}:"
        f"function:{FACTORY_FUNCTION_NAME}:{version}"
    )


def canonical_resource_policy() -> dict[str, Any]:
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "DenyWritesOutsideRetirementBroker",
                "Effect": "Deny",
                "Principal": {"AWS": "*"},
                "Action": list(WRITE_ACTIONS),
                "Resource": _table_arn(),
                "Condition": {
                    "ArnNotEquals": {
                        "aws:PrincipalArn": _retirement_broker_role_arn(),
                    }
                },
            }
        ],
    }


def create_table_request() -> dict[str, Any]:
    """Return the only CreateTable request this runtime can issue."""

    return {
        "TableName": LEDGER_TABLE_NAME,
        "AttributeDefinitions": [
            {"AttributeName": "retirement_id", "AttributeType": "S"}
        ],
        "KeySchema": [
            {"AttributeName": "retirement_id", "KeyType": "HASH"}
        ],
        "BillingMode": "PAY_PER_REQUEST",
        "SSESpecification": {
            "Enabled": True,
            "SSEType": "KMS",
            "KMSMasterKeyId": KMS_KEY_ALIAS,
        },
        "DeletionProtectionEnabled": True,
        "TableClass": "STANDARD",
        # DynamoDB models ResourcePolicy as a JSON string, not a document map.
        "ResourcePolicy": canonical_json(canonical_resource_policy()),
        "Tags": [
            {"Key": key, "Value": value}
            for key, value in EXPECTED_LEDGER_TAGS.items()
        ],
    }


def update_pitr_request() -> dict[str, Any]:
    return {
        "TableName": LEDGER_TABLE_NAME,
        "PointInTimeRecoverySpecification": {
            "PointInTimeRecoveryEnabled": True,
            "RecoveryPeriodInDays": 35,
        },
    }


def _contract_projection() -> dict[str, Any]:
    return {
        "account_sha256": _secret_digest(
            "authority_account_id", AUTHORITY_ACCOUNT_ID
        ),
        "region_sha256": _secret_digest("region", REGION),
        "table_sha256": _secret_digest("table_arn", _table_arn()),
        "factory_role_sha256": _secret_digest(
            "factory_role_name", FACTORY_ROLE_NAME
        ),
        "factory_function_sha256": _secret_digest(
            "factory_function_name", FACTORY_FUNCTION_NAME
        ),
        "create_table_request_sha256": canonical_digest(create_table_request()),
        "update_pitr_request_sha256": canonical_digest(update_pitr_request()),
        "resource_policy_sha256": canonical_digest(canonical_resource_policy()),
        "kms_key_alias_sha256": _secret_digest(
            "kms_key_alias", KMS_KEY_ALIAS
        ),
    }


CONTRACT_SHA256 = canonical_digest(_contract_projection())


def _validate_event(event: object) -> None:
    if type(event) is not dict or event != {}:
        _fail("EMPTY_EVENT_REQUIRED")


def _runtime_version(context: object) -> str:
    version = getattr(context, "function_version", None)
    invoked = getattr(context, "invoked_function_arn", None)
    if (
        not isinstance(version, str)
        or _FUNCTION_VERSION.fullmatch(version) is None
        or invoked != _factory_function_arn(version=version)
    ):
        _fail("DEDICATED_FUNCTION_VERSION_REQUIRED")
    return version


def _provider_error_code(exc: BaseException) -> str | None:
    response = getattr(exc, "response", None)
    if not isinstance(response, Mapping):
        return None
    error = response.get("Error")
    if not isinstance(error, Mapping):
        return None
    code = error.get("Code")
    return code if isinstance(code, str) else None


def _strict_json_object(value: object) -> dict[str, Any]:
    if not isinstance(value, str) or not value or len(value.encode("utf-8")) > 20_480:
        _fail("RESOURCE_POLICY_READBACK_INVALID")

    def no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, item in pairs:
            if key in result:
                _fail("RESOURCE_POLICY_READBACK_INVALID")
            result[key] = item
        return result

    try:
        parsed = json.loads(value, object_pairs_hook=no_duplicates)
    except (json.JSONDecodeError, UnicodeError) as exc:
        raise LedgerFactoryError("RESOURCE_POLICY_READBACK_INVALID") from exc
    if not isinstance(parsed, dict):
        _fail("RESOURCE_POLICY_READBACK_INVALID")
    return parsed


@dataclass(frozen=True, slots=True)
class BotoClients:
    sts: Any
    dynamodb: Any
    kms: Any

    @classmethod
    def create(cls) -> "BotoClients":
        try:
            import boto3  # type: ignore[import-not-found]
            from botocore.config import Config  # type: ignore[import-not-found]
        except ImportError:
            raise LedgerFactoryError("AWS_SDK_UNAVAILABLE") from None
        # max_attempts=0 means one HTTP attempt per application write call.
        no_retry = Config(
            region_name=REGION,
            connect_timeout=3,
            read_timeout=10,
            retries={"max_attempts": 0, "mode": "standard"},
        )
        return cls(
            sts=boto3.client("sts", region_name=REGION, config=no_retry),
            dynamodb=boto3.client(
                "dynamodb", region_name=REGION, config=no_retry
            ),
            kms=boto3.client("kms", region_name=REGION, config=no_retry),
        )


def _validate_caller_identity(sts: Any) -> None:
    try:
        response = sts.get_caller_identity()
    except Exception:
        raise LedgerFactoryError("CALLER_IDENTITY_UNAVAILABLE") from None
    if (
        not isinstance(response, Mapping)
        or response.get("Account") != AUTHORITY_ACCOUNT_ID
        or not isinstance(response.get("Arn"), str)
        or _ASSUMED_ROLE_ARN.fullmatch(response["Arn"]) is None
    ):
        _fail("CALLER_IDENTITY_BINDING_MISMATCH")


def _kms_key_projection(metadata: Mapping[str, Any]) -> dict[str, Any]:
    """Return the stable, non-secret AWS-managed key contract projection."""

    return {
        "account_sha256": _secret_digest(
            "kms_aws_account_id", str(metadata["AWSAccountId"])
        ),
        "arn_sha256": _secret_digest("kms_key_arn", str(metadata["Arn"])),
        "enabled": metadata["Enabled"],
        "key_usage": metadata["KeyUsage"],
        "key_state": metadata["KeyState"],
        "origin": metadata["Origin"],
        "key_manager": metadata["KeyManager"],
        "key_spec": metadata["KeySpec"],
        "multi_region": metadata["MultiRegion"],
        "encryption_algorithms": list(metadata["EncryptionAlgorithms"]),
    }


def _describe_exact_kms_key(kms: Any) -> tuple[str, str, str]:
    try:
        response = kms.describe_key(KeyId=KMS_KEY_ALIAS)
    except Exception:
        raise LedgerFactoryError("KMS_KEY_READ_UNAVAILABLE") from None
    metadata = (
        response.get("KeyMetadata")
        if isinstance(response, Mapping)
        else None
    )
    if not isinstance(metadata, Mapping):
        _fail("KMS_KEY_METADATA_INVALID")
    arn = metadata.get("Arn")
    key_id = metadata.get("KeyId")
    forbidden = {
        "CustomKeyStoreId",
        "CloudHsmClusterId",
        "DeletionDate",
        "ValidTo",
        "ExpirationModel",
        "MultiRegionConfiguration",
        "PendingDeletionWindowInDays",
        "SigningAlgorithms",
        "KeyAgreementAlgorithms",
        "MacAlgorithms",
        "XksKeyConfiguration",
    }
    if (
        metadata.get("AWSAccountId") != AUTHORITY_ACCOUNT_ID
        or not isinstance(arn, str)
        or _KMS_KEY_ARN.fullmatch(arn) is None
        or not isinstance(key_id, str)
        or _KMS_KEY_ID.fullmatch(key_id) is None
        or not arn.endswith("key/" + key_id)
        or metadata.get("Enabled") is not True
        or metadata.get("KeyUsage") != "ENCRYPT_DECRYPT"
        or metadata.get("KeyState") != "Enabled"
        or metadata.get("Origin") != "AWS_KMS"
        or metadata.get("KeyManager") != "AWS"
        or metadata.get("KeySpec") != "SYMMETRIC_DEFAULT"
        or metadata.get("CustomerMasterKeySpec")
        not in (None, "SYMMETRIC_DEFAULT")
        or metadata.get("MultiRegion") is not False
        or metadata.get("EncryptionAlgorithms") != ["SYMMETRIC_DEFAULT"]
        or forbidden.intersection(metadata)
    ):
        _fail("KMS_KEY_CONTROLS_CHANGED")
    return (
        arn,
        _secret_digest("kms_key_arn", arn),
        canonical_digest(_kms_key_projection(metadata)),
    )


def _describe_table(dynamodb: Any) -> Mapping[str, Any] | None:
    try:
        response = dynamodb.describe_table(TableName=LEDGER_TABLE_NAME)
    except Exception as exc:
        if _provider_error_code(exc) == "ResourceNotFoundException":
            return None
        raise LedgerFactoryError("LEDGER_TABLE_READ_UNAVAILABLE") from None
    table = response.get("Table") if isinstance(response, Mapping) else None
    if not isinstance(table, Mapping):
        _fail("LEDGER_TABLE_READBACK_INVALID")
    return table


def _validate_table_structure(
    table: Mapping[str, Any],
    *,
    active: bool,
    expected_kms_key_arn: str | None = None,
) -> None:
    billing = table.get("BillingModeSummary")
    sse = table.get("SSEDescription")
    table_class = table.get("TableClassSummary")
    if (
        table.get("TableName") != LEDGER_TABLE_NAME
        or table.get("TableArn") != _table_arn()
        or (active and table.get("TableStatus") != "ACTIVE")
        or (not active and table.get("TableStatus") not in {"CREATING", "ACTIVE"})
        or table.get("KeySchema")
        != [{"AttributeName": "retirement_id", "KeyType": "HASH"}]
        or table.get("AttributeDefinitions")
        != [{"AttributeName": "retirement_id", "AttributeType": "S"}]
        or table.get("DeletionProtectionEnabled") is not True
        or not isinstance(billing, Mapping)
        or billing.get("BillingMode") != "PAY_PER_REQUEST"
        or not isinstance(sse, Mapping)
        or (
            sse.get("Status") != "ENABLED"
            if active
            else sse.get("Status") not in {"ENABLING", "ENABLED"}
        )
        or sse.get("SSEType") != "KMS"
        or (
            active
            and (
                not isinstance(sse.get("KMSMasterKeyArn"), str)
                or _KMS_KEY_ARN.fullmatch(sse["KMSMasterKeyArn"]) is None
                or (
                    expected_kms_key_arn is not None
                    and sse["KMSMasterKeyArn"] != expected_kms_key_arn
                )
            )
        )
        or (
            not active
            and sse.get("KMSMasterKeyArn") is not None
            and (
                not isinstance(sse.get("KMSMasterKeyArn"), str)
                or _KMS_KEY_ARN.fullmatch(sse["KMSMasterKeyArn"]) is None
                or (
                    expected_kms_key_arn is not None
                    and sse["KMSMasterKeyArn"] != expected_kms_key_arn
                )
            )
        )
        or not isinstance(table_class, Mapping)
        or table_class.get("TableClass") != "STANDARD"
        or table.get("LatestStreamArn") not in (None, "")
        or table.get("LatestStreamLabel") not in (None, "")
        or table.get("LocalSecondaryIndexes") not in (None, [])
        or table.get("GlobalSecondaryIndexes") not in (None, [])
        or table.get("Replicas") not in (None, [])
        or table.get("GlobalTableWitnesses") not in (None, [])
    ):
        _fail("LEDGER_TABLE_CONTROLS_CHANGED")


def _validate_create_response(table: Mapping[str, Any]) -> None:
    """Validate only stable identity fields; full controls come from readback."""

    table_arn = table.get("TableArn")
    if (
        table.get("TableName") != LEDGER_TABLE_NAME
        or table.get("TableStatus") not in {"CREATING", "ACTIVE"}
        or table_arn not in (None, _table_arn())
    ):
        _fail("CREATE_TABLE_RESPONSE_INVALID")


def _wait_until_active(
    dynamodb: Any,
    *,
    sleeper: Callable[[float], None],
    expected_kms_key_arn: str | None = None,
) -> tuple[Mapping[str, Any] | None, int]:
    for attempt in range(1, ACTIVE_READBACK_MAX_ATTEMPTS + 1):
        try:
            table = _describe_table(dynamodb)
            if table is not None:
                _validate_table_structure(
                    table,
                    active=False,
                    expected_kms_key_arn=expected_kms_key_arn,
                )
                if table.get("TableStatus") == "ACTIVE":
                    _validate_table_structure(
                        table,
                        active=True,
                        expected_kms_key_arn=expected_kms_key_arn,
                    )
                    return table, attempt
        except LedgerFactoryError as exc:
            if exc.code != "LEDGER_TABLE_READ_UNAVAILABLE":
                return None, attempt
        if attempt < ACTIVE_READBACK_MAX_ATTEMPTS:
            sleeper(ACTIVE_READBACK_DELAY_SECONDS)
    return None, ACTIVE_READBACK_MAX_ATTEMPTS


def _resource_policy_snapshot(dynamodb: Any) -> tuple[str, str | None]:
    try:
        response = dynamodb.get_resource_policy(ResourceArn=_table_arn())
    except Exception as exc:
        if _provider_error_code(exc) in {
            "PolicyNotFoundException",
            "ResourceNotFoundException",
        }:
            return "ABSENT", None
        raise LedgerFactoryError("RESOURCE_POLICY_READ_UNAVAILABLE") from None
    if not isinstance(response, Mapping):
        _fail("RESOURCE_POLICY_READBACK_INVALID")
    observed = _strict_json_object(response.get("Policy"))
    revision_id = response.get("RevisionId")
    if not isinstance(revision_id, str) or _REVISION_ID.fullmatch(revision_id) is None:
        _fail("RESOURCE_POLICY_REVISION_INVALID")
    return (
        "EXACT" if observed == canonical_resource_policy() else "DRIFTED",
        revision_id,
    )


def _poll_exact_policy(
    dynamodb: Any, *, sleeper: Callable[[float], None]
) -> tuple[str | None, int]:
    for attempt in range(1, POLICY_READBACK_MAX_ATTEMPTS + 1):
        try:
            state, revision_id = _resource_policy_snapshot(dynamodb)
        except LedgerFactoryError:
            state, revision_id = "UNAVAILABLE", None
        if state == "EXACT":
            return revision_id, attempt
        if state == "DRIFTED":
            return None, attempt
        if attempt < POLICY_READBACK_MAX_ATTEMPTS:
            sleeper(POLICY_READBACK_DELAY_SECONDS)
    return None, POLICY_READBACK_MAX_ATTEMPTS


def _validate_tags(dynamodb: Any) -> None:
    try:
        response = dynamodb.list_tags_of_resource(ResourceArn=_table_arn())
    except Exception:
        raise LedgerFactoryError("LEDGER_TAGS_READ_UNAVAILABLE") from None
    tags = response.get("Tags") if isinstance(response, Mapping) else None
    if (
        not isinstance(tags, list)
        or response.get("NextToken") not in (None, "")
        or any(
            not isinstance(item, Mapping)
            or not isinstance(item.get("Key"), str)
            or not isinstance(item.get("Value"), str)
            for item in tags
        )
    ):
        _fail("LEDGER_TAGS_CHANGED")
    normalized = {item["Key"]: item["Value"] for item in tags}
    if len(normalized) != len(tags) or normalized != EXPECTED_LEDGER_TAGS:
        _fail("LEDGER_TAGS_CHANGED")


def _validate_empty(dynamodb: Any) -> None:
    try:
        response = dynamodb.scan(
            TableName=LEDGER_TABLE_NAME,
            ConsistentRead=True,
            Select="COUNT",
            Limit=1,
        )
    except Exception:
        raise LedgerFactoryError("LEDGER_EMPTY_READ_UNAVAILABLE") from None
    if (
        not isinstance(response, Mapping)
        or response.get("Count") != 0
        or response.get("ScannedCount") != 0
        or response.get("LastEvaluatedKey") is not None
        or response.get("Items") not in (None, [])
    ):
        _fail("LEDGER_NOT_EMPTY")


def _validate_ttl_disabled(dynamodb: Any) -> None:
    try:
        response = dynamodb.describe_time_to_live(TableName=LEDGER_TABLE_NAME)
    except Exception:
        raise LedgerFactoryError("LEDGER_TTL_READ_UNAVAILABLE") from None
    description = (
        response.get("TimeToLiveDescription")
        if isinstance(response, Mapping)
        else None
    )
    if (
        not isinstance(description, Mapping)
        or description.get("TimeToLiveStatus") != "DISABLED"
        or "AttributeName" in description
        or set(description) != {"TimeToLiveStatus"}
    ):
        _fail("LEDGER_TTL_CONTROLS_CHANGED")


def _pitr_exact(dynamodb: Any) -> bool:
    try:
        response = dynamodb.describe_continuous_backups(
            TableName=LEDGER_TABLE_NAME
        )
    except Exception:
        raise LedgerFactoryError("LEDGER_RECOVERY_READ_UNAVAILABLE") from None
    backups = (
        response.get("ContinuousBackupsDescription")
        if isinstance(response, Mapping)
        else None
    )
    pitr = (
        backups.get("PointInTimeRecoveryDescription")
        if isinstance(backups, Mapping)
        else None
    )
    return bool(
        isinstance(backups, Mapping)
        and backups.get("ContinuousBackupsStatus") == "ENABLED"
        and isinstance(pitr, Mapping)
        and pitr.get("PointInTimeRecoveryStatus") == "ENABLED"
        and pitr.get("RecoveryPeriodInDays") == 35
    )


def _poll_exact_pitr(
    dynamodb: Any, *, sleeper: Callable[[float], None]
) -> tuple[bool, int]:
    for attempt in range(1, PITR_READBACK_MAX_ATTEMPTS + 1):
        try:
            if _pitr_exact(dynamodb):
                return True, attempt
        except LedgerFactoryError:
            pass
        if attempt < PITR_READBACK_MAX_ATTEMPTS:
            sleeper(PITR_READBACK_DELAY_SECONDS)
    return False, PITR_READBACK_MAX_ATTEMPTS


def _certify_exact(
    dynamodb: Any,
    kms: Any,
    *,
    sleeper: Callable[[float], None],
    expected_revision_id: str | None = None,
) -> tuple[str, int, int, str, str]:
    (
        kms_key_arn,
        kms_key_arn_sha256,
        kms_key_metadata_sha256,
    ) = _describe_exact_kms_key(kms)
    table, active_attempts = _wait_until_active(
        dynamodb,
        sleeper=sleeper,
        expected_kms_key_arn=kms_key_arn,
    )
    if table is None:
        _fail("LEDGER_ACTIVE_READBACK_NOT_PROVEN")
    revision_id, policy_attempts = _poll_exact_policy(dynamodb, sleeper=sleeper)
    if revision_id is None:
        _fail("LEDGER_RESOURCE_POLICY_NOT_PROVEN")
    if expected_revision_id is not None and revision_id != expected_revision_id:
        _fail("LEDGER_RESOURCE_POLICY_REVISION_CHANGED")
    if not _pitr_exact(dynamodb):
        _fail("LEDGER_RECOVERY_CONTROLS_CHANGED")
    _validate_tags(dynamodb)
    _validate_empty(dynamodb)
    _validate_ttl_disabled(dynamodb)
    return (
        revision_id,
        active_attempts,
        policy_attempts,
        kms_key_arn_sha256,
        kms_key_metadata_sha256,
    )


def _existing_table_receipt(
    dynamodb: Any,
    kms: Any,
    *,
    sleeper: Callable[[float], None],
    version: str,
) -> dict[str, Any]:
    """Read-only classification for a table present before this invocation."""

    try:
        (
            revision,
            active_attempts,
            policy_attempts,
            kms_key_arn_sha256,
            kms_key_metadata_sha256,
        ) = _certify_exact(
            dynamodb, kms, sleeper=sleeper
        )
    except LedgerFactoryError as exc:
        return _receipt(
            status="EXISTING_DRIFT_DENIED",
            reason_code=exc.code,
            version=version,
            create_table_call_count=0,
            update_pitr_call_count=0,
            next_required_action="HUMAN_REVIEW_REQUIRED",
        )
    return _receipt(
        status="ALREADY_EXACT",
        reason_code="LEDGER_ALREADY_EXACT",
        version=version,
        create_table_call_count=0,
        update_pitr_call_count=0,
        next_required_action="REVOKE_FACTORY_AUTHORITY",
        revision_id=revision,
        kms_key_arn_sha256=kms_key_arn_sha256,
        kms_key_metadata_sha256=kms_key_metadata_sha256,
        active_readback_attempt_count=active_attempts,
        policy_readback_attempt_count=policy_attempts,
    )


def _receipt(
    *,
    status: str,
    reason_code: str,
    version: str,
    create_table_call_count: int,
    update_pitr_call_count: int,
    next_required_action: str,
    kms_key_arn_sha256: str | None = None,
    kms_key_metadata_sha256: str | None = None,
    revision_id: str | None = None,
    active_readback_attempt_count: int = 0,
    policy_readback_attempt_count: int = 0,
    pitr_readback_attempt_count: int = 0,
) -> dict[str, Any]:
    receipt: dict[str, Any] = {
        "artifact_type": RECEIPT_ARTIFACT_TYPE,
        "schema_version": SCHEMA_VERSION,
        "status": status,
        "reason_code": reason_code,
        "attempt": 1,
        "create_table_call_count": create_table_call_count,
        "update_pitr_call_count": update_pitr_call_count,
        "retry_permitted": False,
        "next_required_action": next_required_action,
        "request_sha256": canonical_digest({}),
        "contract_sha256": CONTRACT_SHA256,
        "qualified_function_sha256": _secret_digest(
            "qualified_function_arn", _factory_function_arn(version=version)
        ),
        "resource_policy_sha256": canonical_digest(canonical_resource_policy()),
        "kms_key_arn_sha256": kms_key_arn_sha256,
        "kms_key_metadata_sha256": kms_key_metadata_sha256,
        "revision_id_sha256": (
            _secret_digest("revision_id", revision_id)
            if revision_id is not None
            else None
        ),
        "active_readback_attempt_count": active_readback_attempt_count,
        "policy_readback_attempt_count": policy_readback_attempt_count,
        "pitr_readback_attempt_count": pitr_readback_attempt_count,
    }
    receipt["receipt_sha256"] = canonical_digest(receipt)
    return receipt


def _deny_receipt(code: str) -> dict[str, Any]:
    receipt: dict[str, Any] = {
        "artifact_type": RECEIPT_ARTIFACT_TYPE,
        "schema_version": SCHEMA_VERSION,
        "status": "DENY",
        "reason_code": code,
        "create_table_call_count": 0,
        "update_pitr_call_count": 0,
        "retry_permitted": False,
        "next_required_action": "STOP",
        "contract_sha256": CONTRACT_SHA256,
    }
    receipt["receipt_sha256"] = canonical_digest(receipt)
    return receipt


def execute(
    *,
    event: object,
    context: object,
    clients: BotoClients,
    sleeper: Callable[[float], None] = sleep,
) -> dict[str, Any]:
    """Create and certify one exact protected empty ledger."""

    _validate_event(event)
    version = _runtime_version(context)

    # This is intentionally the first provider API call of every invocation.
    _validate_caller_identity(clients.sts)
    first = _describe_table(clients.dynamodb)
    if first is not None:
        return _existing_table_receipt(
            clients.dynamodb, clients.kms, sleeper=sleeper, version=version
        )
    sleeper(ABSENCE_CONFIRMATION_DELAY_SECONDS)
    if _describe_table(clients.dynamodb) is not None:
        # A concurrent creator won the race. Never call CreateTable; classify
        # its result read-only and refuse any repair.
        return _existing_table_receipt(
            clients.dynamodb, clients.kms, sleeper=sleeper, version=version
        )

    # Resolve and validate the AWS-managed DynamoDB key immediately before the
    # one allowed CreateTable attempt. Its ARN is account-specific and cannot
    # be safely hard-coded, while the predefined alias is stable.
    try:
        (
            kms_key_arn,
            kms_key_arn_sha256,
            kms_key_metadata_sha256,
        ) = _describe_exact_kms_key(clients.kms)
    except LedgerFactoryError as exc:
        return _receipt(
            status="DENY",
            reason_code=exc.code,
            version=version,
            create_table_call_count=0,
            update_pitr_call_count=0,
            next_required_action="STOP",
        )

    try:
        create_response = clients.dynamodb.create_table(**create_table_request())
    except Exception:
        # The effect may have crossed the boundary. Bounded readback only; no
        # UpdateContinuousBackups and never another CreateTable call.
        _, active_attempts = _wait_until_active(
            clients.dynamodb,
            sleeper=sleeper,
            expected_kms_key_arn=kms_key_arn,
        )
        return _receipt(
            status="UNCERTAIN_RECONCILE_ONLY",
            reason_code="CREATE_TABLE_OUTCOME_NOT_PROVEN",
            version=version,
            create_table_call_count=1,
            update_pitr_call_count=0,
            next_required_action="REVOKE_THEN_READ_ONLY_RECONCILE",
            kms_key_arn_sha256=kms_key_arn_sha256,
            kms_key_metadata_sha256=kms_key_metadata_sha256,
            active_readback_attempt_count=active_attempts,
        )
    created = (
        create_response.get("TableDescription")
        if isinstance(create_response, Mapping)
        else None
    )
    try:
        if not isinstance(created, Mapping):
            _fail("CREATE_TABLE_RESPONSE_INVALID")
        _validate_create_response(created)
    except LedgerFactoryError:
        _, active_attempts = _wait_until_active(
            clients.dynamodb,
            sleeper=sleeper,
            expected_kms_key_arn=kms_key_arn,
        )
        return _receipt(
            status="UNCERTAIN_RECONCILE_ONLY",
            reason_code="CREATE_TABLE_RESPONSE_NOT_PROVEN",
            version=version,
            create_table_call_count=1,
            update_pitr_call_count=0,
            next_required_action="REVOKE_THEN_READ_ONLY_RECONCILE",
            kms_key_arn_sha256=kms_key_arn_sha256,
            kms_key_metadata_sha256=kms_key_metadata_sha256,
            active_readback_attempt_count=active_attempts,
        )

    table, active_attempts = _wait_until_active(
        clients.dynamodb,
        sleeper=sleeper,
        expected_kms_key_arn=kms_key_arn,
    )
    if table is None:
        return _receipt(
            status="UNCERTAIN_RECONCILE_ONLY",
            reason_code="CREATE_TABLE_ACTIVE_NOT_PROVEN",
            version=version,
            create_table_call_count=1,
            update_pitr_call_count=0,
            next_required_action="REVOKE_THEN_READ_ONLY_RECONCILE",
            kms_key_arn_sha256=kms_key_arn_sha256,
            kms_key_metadata_sha256=kms_key_metadata_sha256,
            active_readback_attempt_count=active_attempts,
        )
    revision, policy_attempts = _poll_exact_policy(
        clients.dynamodb, sleeper=sleeper
    )
    try:
        if revision is None:
            _fail("CREATE_TABLE_POLICY_NOT_PROVEN")
        _validate_tags(clients.dynamodb)
        _validate_empty(clients.dynamodb)
        _validate_ttl_disabled(clients.dynamodb)
    except LedgerFactoryError:
        return _receipt(
            status="UNCERTAIN_RECONCILE_ONLY",
            reason_code="CREATE_TABLE_CONTROLS_NOT_PROVEN",
            version=version,
            create_table_call_count=1,
            update_pitr_call_count=0,
            next_required_action="REVOKE_THEN_READ_ONLY_RECONCILE",
            kms_key_arn_sha256=kms_key_arn_sha256,
            kms_key_metadata_sha256=kms_key_metadata_sha256,
            revision_id=revision,
            active_readback_attempt_count=active_attempts,
            policy_readback_attempt_count=policy_attempts,
        )

    update_failed = False
    try:
        clients.dynamodb.update_continuous_backups(**update_pitr_request())
    except Exception:
        update_failed = True
    pitr_exact, pitr_attempts = _poll_exact_pitr(
        clients.dynamodb, sleeper=sleeper
    )
    if not pitr_exact:
        return _receipt(
            status="UNCERTAIN_RECONCILE_ONLY",
            reason_code="PITR_UPDATE_OUTCOME_NOT_PROVEN",
            version=version,
            create_table_call_count=1,
            update_pitr_call_count=1,
            next_required_action="REVOKE_THEN_READ_ONLY_RECONCILE",
            kms_key_arn_sha256=kms_key_arn_sha256,
            kms_key_metadata_sha256=kms_key_metadata_sha256,
            revision_id=revision,
            active_readback_attempt_count=active_attempts,
            policy_readback_attempt_count=policy_attempts,
            pitr_readback_attempt_count=pitr_attempts,
        )
    try:
        (
            final_revision,
            final_active_attempts,
            final_policy_attempts,
            final_kms_key_arn_sha256,
            final_kms_key_metadata_sha256,
        ) = _certify_exact(
            clients.dynamodb,
            clients.kms,
            sleeper=sleeper,
            expected_revision_id=revision,
        )
        if (
            final_kms_key_arn_sha256 != kms_key_arn_sha256
            or final_kms_key_metadata_sha256 != kms_key_metadata_sha256
        ):
            _fail("KMS_KEY_READBACK_CHANGED")
    except LedgerFactoryError:
        return _receipt(
            status="UNCERTAIN_RECONCILE_ONLY",
            reason_code="FINAL_CERTIFICATION_NOT_PROVEN",
            version=version,
            create_table_call_count=1,
            update_pitr_call_count=1,
            next_required_action="REVOKE_THEN_READ_ONLY_RECONCILE",
            kms_key_arn_sha256=kms_key_arn_sha256,
            kms_key_metadata_sha256=kms_key_metadata_sha256,
            revision_id=revision,
            active_readback_attempt_count=active_attempts,
            policy_readback_attempt_count=policy_attempts,
            pitr_readback_attempt_count=pitr_attempts,
        )
    return _receipt(
        status="CREATED_RECONCILED" if update_failed else "CREATED",
        reason_code="LEDGER_EXACT_FULL_READBACK",
        version=version,
        create_table_call_count=1,
        update_pitr_call_count=1,
        next_required_action="REVOKE_FACTORY_AUTHORITY",
        kms_key_arn_sha256=final_kms_key_arn_sha256,
        kms_key_metadata_sha256=final_kms_key_metadata_sha256,
        revision_id=final_revision,
        active_readback_attempt_count=(active_attempts + final_active_attempts),
        policy_readback_attempt_count=(policy_attempts + final_policy_attempts),
        pitr_readback_attempt_count=pitr_attempts,
    )


def handler(event: object, context: object) -> dict[str, Any]:
    """Lambda entrypoint returning only a sanitized digest-bound receipt."""

    try:
        return execute(event=event, context=context, clients=BotoClients.create())
    except LedgerFactoryError as exc:
        return _deny_receipt(exc.code)
    except Exception:
        return _deny_receipt("LEDGER_FACTORY_INTERNAL_ERROR")
