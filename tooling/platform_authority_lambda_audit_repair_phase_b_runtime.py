"""AWS adapters for the dedicated GUG-221 Phase B proof-only PEP.

All SDK clients have automatic retries disabled.  In particular, an ambiguous
``ExecuteChangeSet`` response is terminal and reconcile-only.  The
CloudFormation client is created from the Lambda service role; STS proof
credentials never enter this module's execution client.
"""

from __future__ import annotations

import base64
import binascii
import json
import os
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Mapping, Protocol

from tooling.platform_authority_lambda_audit_repair_phase_b_pep import (
    AUTHORITY_ACCOUNT_ID,
    BROKER_TOPOLOGY_SIGNATURE_ALGORITHM,
    BROKER_ROLE_NAME,
    CHANGE_SET_NAME,
    FUNCTION_ALIAS,
    MANAGEMENT_ACCOUNT_ID,
    REQUEST_KEYS,
    REGION,
    STACK_NAME,
    OneShotExecutionLedger,
    PhaseBExecutionBroker,
    PhaseBExecutionClient,
    PhaseBIdentityBinding,
    PhaseBIdentityProofVerifier,
    PhaseBLedgerStore,
    PhaseBPep,
    PhaseBPepError,
    PhaseBClosurePendingReceipt,
    parse_timestamp,
    validate_broker_topology_evidence,
)


MAX_BROKER_TOPOLOGY_EVIDENCE_JSON_BYTES = 4096
SYNC_CLIENT_CONTEXT_KEYS = frozenset(
    {"transport", "execution_id", "broker_topology_sha256"}
)


class BrokerTopologyEvidenceAuthenticator(Protocol):
    """Verify evidence provenance outside its self-canonical JSON envelope."""

    def verify(
        self,
        *,
        evidence: Mapping[str, Any],
        receipt_digest: str,
    ) -> None: ...


class KmsBrokerTopologyEvidenceAuthenticator:
    """Authenticate the exact canonical topology digest with one KMS key."""

    def __init__(
        self,
        *,
        client: Any,
        key_arn: str,
        signing_algorithm: str,
    ) -> None:
        self._client = client
        self._key_arn = key_arn
        self._signing_algorithm = signing_algorithm

    def verify(
        self,
        *,
        evidence: Mapping[str, Any],
        receipt_digest: str,
    ) -> None:
        if (
            evidence.get("signing_key_arn") != self._key_arn
            or evidence.get("signature_algorithm")
            != self._signing_algorithm
            or self._signing_algorithm
            != BROKER_TOPOLOGY_SIGNATURE_ALGORITHM
        ):
            raise PhaseBPepError("BROKER_TOPOLOGY_SIGNATURE_BINDING_MISMATCH")
        signature = evidence.get("signature")
        try:
            decoded_signature = base64.b64decode(
                str(signature),
                validate=True,
            )
            message_digest = bytes.fromhex(receipt_digest.removeprefix("sha256:"))
        except (binascii.Error, ValueError):
            raise PhaseBPepError("BROKER_TOPOLOGY_SIGNATURE_INVALID") from None
        if len(message_digest) != 32:
            raise PhaseBPepError("BROKER_TOPOLOGY_SIGNATURE_INVALID")
        try:
            response = self._client.verify(
                KeyId=self._key_arn,
                Message=message_digest,
                MessageType="DIGEST",
                Signature=decoded_signature,
                SigningAlgorithm=self._signing_algorithm,
            )
        except Exception:
            raise PhaseBPepError("BROKER_TOPOLOGY_AUTHENTICATION_FAILED") from None
        metadata = (
            response.get("ResponseMetadata")
            if isinstance(response, Mapping)
            else None
        )
        if (
            not isinstance(response, Mapping)
            or response.get("SignatureValid") is not True
            or response.get("KeyId") != self._key_arn
            or response.get("SigningAlgorithm") != self._signing_algorithm
            or not isinstance(metadata, Mapping)
            or metadata.get("HTTPStatusCode") != 200
        ):
            raise PhaseBPepError("BROKER_TOPOLOGY_AUTHENTICATION_FAILED")


def _required(env: Mapping[str, str], name: str) -> str:
    value = env.get(name)
    if not isinstance(value, str) or not value or value != value.strip():
        raise PhaseBPepError("CONFIGURATION_INCOMPLETE")
    return value


def _validated_topology_evidence_from_invocation(
    *,
    event: object,
    binding: PhaseBIdentityBinding,
    now: datetime,
) -> tuple[Mapping[str, Any], str]:
    """Validate the exact bounded payload before creating any AWS client."""

    if type(event) is not dict or set(event) != REQUEST_KEYS:
        raise PhaseBPepError("REQUEST_AUTHORITY_FORBIDDEN")
    value = event.get("broker_topology_evidence")
    if type(value) is not dict:
        raise PhaseBPepError("BROKER_TOPOLOGY_EVIDENCE_INVALID")
    try:
        encoded = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeError):
        raise PhaseBPepError("BROKER_TOPOLOGY_EVIDENCE_INVALID") from None
    if len(encoded) > MAX_BROKER_TOPOLOGY_EVIDENCE_JSON_BYTES:
        raise PhaseBPepError("BROKER_TOPOLOGY_EVIDENCE_INVALID")
    receipt_digest = validate_broker_topology_evidence(value, now=now)
    if value.get("broker_topology_sha256") != binding.broker_topology_sha256:
        raise PhaseBPepError("BROKER_TOPOLOGY_EVIDENCE_BINDING_MISMATCH")
    for field_name in (
        "invoker_policy_sha256",
        "broker_policy_sha256",
        "proof_policy_sha256",
        "application_actor_policy_sha256",
    ):
        if value.get(field_name) != getattr(binding, field_name):
            raise PhaseBPepError("BROKER_TOPOLOGY_POLICY_DIGEST_MISMATCH")
    if (
        value.get("signing_key_arn")
        != binding.broker_topology_signing_key_arn
        or value.get("signature_algorithm")
        != binding.broker_topology_signature_algorithm
    ):
        raise PhaseBPepError("BROKER_TOPOLOGY_SIGNATURE_BINDING_MISMATCH")
    return value, receipt_digest


def _authenticate_topology_evidence(
    *,
    evidence: Mapping[str, Any],
    receipt_digest: str,
    authenticator: BrokerTopologyEvidenceAuthenticator | None,
) -> None:
    if authenticator is None:
        # The live readback collector and KMS/immutable-object verifier are a
        # separate deployment boundary. Never treat self-canonical JSON as
        # authenticated provider evidence.
        raise PhaseBPepError("BROKER_TOPOLOGY_AUTHENTICATOR_UNAVAILABLE")
    try:
        authenticator.verify(
            evidence=evidence,
            receipt_digest=receipt_digest,
        )
    except PhaseBPepError:
        raise
    except Exception:
        raise PhaseBPepError("BROKER_TOPOLOGY_AUTHENTICATION_FAILED") from None


def _topology_evidence_from_invocation(
    *,
    event: object,
    binding: PhaseBIdentityBinding,
    now: datetime,
    authenticator: BrokerTopologyEvidenceAuthenticator | None,
) -> tuple[Mapping[str, Any], str]:
    """Validate then authenticate one provider-derived invocation field."""

    evidence, receipt_digest = _validated_topology_evidence_from_invocation(
        event=event,
        binding=binding,
        now=now,
    )
    _authenticate_topology_evidence(
        evidence=evidence,
        receipt_digest=receipt_digest,
        authenticator=authenticator,
    )
    return evidence, receipt_digest


def _validate_synchronous_client_context(
    context: object,
    *,
    binding: PhaseBIdentityBinding,
) -> None:
    """Require the marker that Lambda exposes only to RequestResponse calls."""

    client_context = getattr(context, "client_context", None)
    custom = getattr(client_context, "custom", None)
    if (
        type(custom) is not dict
        or set(custom) != SYNC_CLIENT_CONTEXT_KEYS
        or custom.get("transport") != "REQUEST_RESPONSE"
        or custom.get("execution_id") != binding.execution_id
        or custom.get("broker_topology_sha256")
        != binding.broker_topology_sha256
        or any(not isinstance(value, str) for value in custom.values())
    ):
        raise PhaseBPepError("SYNCHRONOUS_TRANSPORT_UNPROVEN")


def binding_from_environment(
    env: Mapping[str, str] | None = None,
) -> PhaseBIdentityBinding:
    source = os.environ if env is None else env
    authority_account_id = _required(source, "AUTHORITY_ACCOUNT_ID")
    management_account_id = _required(source, "MANAGEMENT_ACCOUNT_ID")
    region = _required(source, "AUTHORITY_REGION")
    if (
        authority_account_id != AUTHORITY_ACCOUNT_ID
        or management_account_id != MANAGEMENT_ACCOUNT_ID
        or region != REGION
    ):
        raise PhaseBPepError("FIXED_TOPOLOGY_MISMATCH")
    return PhaseBIdentityBinding(
        authority_account_id=authority_account_id,
        management_account_id=management_account_id,
        region=region,
        identity_center_application_arn=_required(
            source, "IDENTITY_CENTER_APPLICATION_ARN"
        ),
        identity_center_instance_arn=_required(
            source, "IDENTITY_CENTER_INSTANCE_ARN"
        ),
        identity_store_arn=_required(source, "IDENTITY_STORE_ARN"),
        redirect_uri=_required(source, "IDENTITY_CENTER_REDIRECT_URI"),
        operator_user_id=_required(source, "OPERATOR_IDENTITY_STORE_USER_ID"),
        invoker_role_arn=_required(source, "INVOKER_ROLE_ARN"),
        broker_execution_role_arn=_required(
            source, "BROKER_EXECUTION_ROLE_ARN"
        ),
        proof_role_arn=_required(source, "PROOF_ROLE_ARN"),
        ledger_table_arn=_required(source, "EXECUTION_LEDGER_TABLE_ARN"),
        stack_arn=_required(source, "EXACT_STACK_ARN"),
        change_set_arn=_required(source, "EXACT_CHANGE_SET_ARN"),
        client_request_token=_required(source, "EXACT_CLIENT_REQUEST_TOKEN"),
        phase_b_intent_digest=_required(source, "PHASE_B_INTENT_DIGEST"),
        change_set_receipt_digest=_required(
            source, "CHANGE_SET_RECEIPT_DIGEST"
        ),
        template_digest=_required(source, "TEMPLATE_DIGEST"),
        parameters_digest=_required(source, "PARAMETERS_DIGEST"),
        resource_inventory_digest=_required(
            source, "RESOURCE_INVENTORY_DIGEST"
        ),
        ledger_controls_digest=_required(source, "LEDGER_CONTROLS_DIGEST"),
        oauth_state_digest=_required(source, "OAUTH_STATE_DIGEST"),
        invoker_policy_sha256=_required(source, "INVOKER_POLICY_SHA256"),
        broker_policy_sha256=_required(source, "BROKER_POLICY_SHA256"),
        proof_policy_sha256=_required(source, "PROOF_POLICY_SHA256"),
        application_actor_policy_sha256=_required(
            source, "APPLICATION_ACTOR_POLICY_SHA256"
        ),
        broker_artifact_bucket=_required(source, "BROKER_ARTIFACT_BUCKET"),
        broker_artifact_key=_required(source, "BROKER_ARTIFACT_KEY"),
        broker_artifact_version=_required(source, "BROKER_ARTIFACT_VERSION"),
        broker_artifact_code_sha256=_required(
            source, "BROKER_ARTIFACT_CODE_SHA256"
        ),
        broker_code_signing_config_arn=_required(
            source, "BROKER_CODE_SIGNING_CONFIG_ARN"
        ),
        broker_topology_provider_evidence_digest=None,
        broker_topology_signing_key_arn=_required(
            source, "BROKER_TOPOLOGY_SIGNING_KEY_ARN"
        ),
        broker_topology_signature_algorithm=_required(
            source, "BROKER_TOPOLOGY_SIGNATURE_ALGORITHM"
        ),
        expected_broker_topology_sha256=_required(
            source, "EXPECTED_BROKER_TOPOLOGY_SHA256"
        ),
        configured_execution_id=_required(source, "CONFIGURED_EXECUTION_ID"),
        execution_not_before=parse_timestamp(
            _required(source, "EXECUTION_NOT_BEFORE"),
            code="EXECUTION_WINDOW_INVALID",
        ),
        execution_not_after=parse_timestamp(
            _required(source, "EXECUTION_NOT_AFTER"),
            code="EXECUTION_WINDOW_INVALID",
        ),
    )


def _attribute_item(value: Mapping[str, Any]) -> dict[str, dict[str, Any]]:
    """Marshal the bounded ledger record without accepting arbitrary types."""

    result: dict[str, dict[str, str]] = {}
    for key, item in value.items():
        if item is None:
            result[key] = {"NULL": True}
        elif isinstance(item, bool):
            result[key] = {"BOOL": item}
        elif isinstance(item, int) and not isinstance(item, bool):
            result[key] = {"N": str(item)}
        elif isinstance(item, str):
            result[key] = {"S": item}
        else:  # pragma: no cover - pure contracts prevent this.
            raise PhaseBPepError("LEDGER_ITEM_TYPE_INVALID")
    return result


class DynamoDbPhaseBLedgerStore(PhaseBLedgerStore):
    """Exact-key conditional store; the first attempt closes the window."""

    def __init__(self, *, client: Any, table_name: str) -> None:
        self._client = client
        self._table_name = table_name

    def assert_open(self, *, binding: PhaseBIdentityBinding) -> None:
        try:
            response = self._client.get_item(
                TableName=self._table_name,
                Key={"execution_id": {"S": binding.execution_id}},
                ConsistentRead=True,
                ProjectionExpression=(
                    "execution_id,#status,attempts,execution_gate_consumed"
                ),
                ExpressionAttributeNames={"#status": "status"},
            )
        except Exception:
            raise PhaseBPepError("REVOCATION_STATE_UNCERTAIN") from None
        if not isinstance(response, Mapping):
            raise PhaseBPepError("REVOCATION_STATE_UNCERTAIN")
        item = response.get("Item")
        if item is not None:
            # Missing/malformed fields and every recorded state are closed.
            raise PhaseBPepError("EXECUTION_WINDOW_CLOSED")

    def claim_once(self, *, ledger: OneShotExecutionLedger) -> None:
        item = ledger.to_dict()
        try:
            self._client.put_item(
                TableName=self._table_name,
                Item=_attribute_item(item),
                ConditionExpression="attribute_not_exists(execution_id)",
                ReturnConsumedCapacity="NONE",
            )
        except Exception:
            # Conditional failure and transport ambiguity have the same
            # one-shot disposition: do not execute and do not retry.
            raise PhaseBPepError("LEDGER_CLAIM_UNCERTAIN") from None

    def close_once(
        self,
        *,
        claimed_ledger_digest: str,
        terminal_ledger: OneShotExecutionLedger,
        closure_pending: PhaseBClosurePendingReceipt,
    ) -> None:
        try:
            self._client.update_item(
                TableName=self._table_name,
                Key={"execution_id": {"S": terminal_ledger.execution_id}},
                ConditionExpression=(
                    "#status = :attempted AND attempts = :one "
                    "AND ledger_digest = :claimed "
                    "AND binding_digest = :binding"
                ),
                UpdateExpression=(
                    "SET #status = :terminal, terminal_at = :terminal_at, "
                    "ledger_digest = :ledger, "
                    "closure_pending_receipt_digest = :closure, "
                    "closure_status = :closure_status, "
                    "execution_gate_consumed = :consumed, "
                    "retry_permitted = :retry"
                ),
                ExpressionAttributeNames={"#status": "status"},
                ExpressionAttributeValues={
                    ":attempted": {"S": "ATTEMPTED"},
                    ":one": {"N": "1"},
                    ":claimed": {"S": claimed_ledger_digest},
                    ":binding": {"S": terminal_ledger.binding_digest},
                    ":terminal": {"S": terminal_ledger.status},
                    ":terminal_at": {"S": str(terminal_ledger.terminal_at)},
                    ":ledger": {"S": terminal_ledger.ledger_digest},
                    ":closure": {"S": closure_pending.receipt_digest},
                    ":closure_status": {"S": "PROVIDER_REVOCATION_PENDING"},
                    ":consumed": {"BOOL": True},
                    ":retry": {"BOOL": False},
                },
                ReturnValues="NONE",
            )
        except Exception:
            raise PhaseBPepError("LEDGER_CLOSE_UNCERTAIN") from None


class AwsPhaseBExecutionClient(PhaseBExecutionClient):
    """Read exact target, then issue one exact service-principal request."""

    def __init__(self, *, cloudformation_client: Any) -> None:
        self._cloudformation = cloudformation_client

    def assert_exact_target(
        self, *, binding: PhaseBIdentityBinding
    ) -> None:
        try:
            response = self._cloudformation.describe_change_set(
                ChangeSetName=binding.change_set_arn,
                StackName=binding.stack_arn,
                IncludePropertyValues=True,
            )
        except Exception:
            raise PhaseBPepError("CHANGE_SET_PREFLIGHT_UNCERTAIN") from None
        if (
            not isinstance(response, Mapping)
            or response.get("ChangeSetId") != binding.change_set_arn
            or response.get("ChangeSetName") != CHANGE_SET_NAME
            or response.get("StackId") != binding.stack_arn
            or response.get("StackName") != STACK_NAME
            or response.get("ChangeSetType") != "CREATE"
            or response.get("Status") != "CREATE_COMPLETE"
            or response.get("ExecutionStatus") != "AVAILABLE"
            or response.get("Capabilities") != ["CAPABILITY_NAMED_IAM"]
            or "RoleARN" in response
            or response.get("OnStackFailure") != "ROLLBACK"
            or response.get("ImportExistingResources", False) is not False
            or response.get("IncludeNestedStacks", False) is not False
            or response.get("ParentChangeSetId") not in (None, "")
            or response.get("RootChangeSetId") not in (None, "")
        ):
            raise PhaseBPepError("CHANGE_SET_PREFLIGHT_INVALID")

    def execute_exact(self, *, binding: PhaseBIdentityBinding) -> None:
        try:
            response = self._cloudformation.execute_change_set(
                **binding.execution_request
            )
        except Exception:
            raise PhaseBPepError("EXECUTE_CHANGE_SET_UNCERTAIN") from None
        if not isinstance(response, Mapping):
            raise PhaseBPepError("EXECUTE_CHANGE_SET_UNCERTAIN")
        metadata = response.get("ResponseMetadata")
        if isinstance(metadata, Mapping) and metadata.get("HTTPStatusCode") != 200:
            raise PhaseBPepError("EXECUTE_CHANGE_SET_UNCERTAIN")


@dataclass(frozen=True, slots=True)
class BotoClients:
    sso_oidc: Any
    sts: Any
    cloudformation: Any
    dynamodb: Any

    @classmethod
    def create(cls, *, region: str) -> "BotoClients":
        try:
            import boto3
            from botocore.config import Config
        except ImportError:
            raise PhaseBPepError("AWS_SDK_UNAVAILABLE") from None
        # max_attempts=0 is deliberate for every one-shot boundary.  The
        # application owns reconciliation and never delegates retries to SDKs.
        config = Config(
            connect_timeout=3,
            read_timeout=10,
            retries={"max_attempts": 0, "mode": "standard"},
        )
        return cls(
            sso_oidc=boto3.client("sso-oidc", region_name=region, config=config),
            sts=boto3.client("sts", region_name=region, config=config),
            cloudformation=boto3.client(
                "cloudformation", region_name=region, config=config
            ),
            dynamodb=boto3.client(
                "dynamodb", region_name=region, config=config
            ),
        )


def create_kms_verifier_client(*, region: str) -> Any:
    """Create only the verifier client; it carries no mutation authority."""

    try:
        import boto3
        from botocore.config import Config
    except ImportError:
        raise PhaseBPepError("AWS_SDK_UNAVAILABLE") from None
    return boto3.client(
        "kms",
        region_name=region,
        config=Config(
            connect_timeout=3,
            read_timeout=10,
            retries={"max_attempts": 0, "mode": "standard"},
        ),
    )


def _qualifier(context: object) -> str:
    invoked = getattr(context, "invoked_function_arn", None)
    if (
        not isinstance(invoked, str)
        or invoked.rsplit(":", 1)[-1] != FUNCTION_ALIAS
    ):
        raise PhaseBPepError("FUNCTION_ALIAS_NOT_AUTHORIZED")
    return FUNCTION_ALIAS


def _response(status_code: int, value: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "statusCode": status_code,
        "headers": {
            "cache-control": "no-store",
            "content-type": "application/json",
            "pragma": "no-cache",
            "x-content-type-options": "nosniff",
        },
        "isBase64Encoded": False,
        "body": json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ),
    }


def handler(event: object, context: object) -> dict[str, Any]:
    """Verify proof and dispatch at most one exact ExecuteChangeSet request."""

    try:
        _qualifier(context)
        binding = binding_from_environment()
        if binding.broker_execution_role_arn.rsplit("/", 1)[-1] != BROKER_ROLE_NAME:
            raise PhaseBPepError("BROKER_ROLE_BINDING_INVALID")
        clock = lambda: datetime.now(tz=UTC)
        _validate_synchronous_client_context(context, binding=binding)
        evidence, evidence_digest = (
            _validated_topology_evidence_from_invocation(
                event=event,
                binding=binding,
                now=clock(),
            )
        )
        # Request shape, freshness, static binding and all additional fields
        # are rejected before any AWS client or one-shot CAS exists.
        kms_client = create_kms_verifier_client(region=binding.region)
        _authenticate_topology_evidence(
            evidence=evidence,
            receipt_digest=evidence_digest,
            authenticator=KmsBrokerTopologyEvidenceAuthenticator(
                client=kms_client,
                key_arn=binding.broker_topology_signing_key_arn,
                signing_algorithm=(
                    binding.broker_topology_signature_algorithm
                ),
            ),
        )
        # No mutable/provider-effect client, CAS write or protected effect
        # exists above this point. KMS Verify is the only provider call.
        clients = BotoClients.create(region=binding.region)
        broker = PhaseBExecutionBroker(
            ledger_store=DynamoDbPhaseBLedgerStore(
                client=clients.dynamodb,
                table_name=binding.ledger_table_arn.rsplit("/", 1)[-1],
            ),
            execution_client=AwsPhaseBExecutionClient(
                cloudformation_client=clients.cloudformation
            ),
            clock=clock,
        )
        result = PhaseBPep(
            proof_verifier=PhaseBIdentityProofVerifier(
                oidc_client=clients.sso_oidc,
                sts_client=clients.sts,
                clock=clock,
            ),
            broker=broker,
        ).execute(
            event=event,
            binding=binding,
            broker_topology_provider_evidence_digest=evidence_digest,
            now=clock(),
        )
        status = result["broker_effect"]["status"]
        return _response(
            202 if status == "UNCERTAIN_RECONCILE_ONLY" else 200,
            result,
        )
    except PhaseBPepError as exc:
        return _response(403, {"status": "DENY", "reason_code": exc.code})
    except Exception:
        return _response(
            500,
            {
                "status": "DENY",
                "reason_code": "PHASE_B_PEP_INTERNAL_ERROR",
            },
        )
