"""AWS-enforced one-shot PEP for one retained CloudFormation Change Set.

The broker is the only runtime principal allowed to mutate the GUG-215 ledger
or call ``DeleteChangeSet``. Human permission sets can only obtain
ordinary sessions for exact synchronous Function URLs. GUG-217 proves the
human identity inside this version-pinned broker before the proof digest is
persisted. Request payloads never establish target, identity, or action.

The module intentionally emits only sanitized status codes. It does not log
AWS responses, identifiers, Identity Store values, or control-plane payloads.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Callable, Mapping, Protocol


CANONICAL_STACK_NAME = "scanalyze-platform-authority-state-backend"
CANONICAL_STATE_KEY = "platform-authority/terraform.tfstate"
RETIREMENT_LEDGER_TABLE = "scanalyze-platform-authority-change-set-retirements"
BROKER_FUNCTION_NAME = "scanalyze-platform-authority-gug215-retirement"
BROKER_POLICY_NAME = "Gug215ExactRetirement"
CLASSIFIER_INVOKER_POLICY_NAME = "Gug215ClassifierInvokeOnly"
APPROVER_INVOKER_POLICY_NAME = "Gug215ApproverInvokeOnly"
PROOF_POLICY_NAME = "Gug217ZeroAuthorityProof"
ALIAS_CLASSIFY = "classify"
ALIAS_RETIRE = "retire"
ALIAS_RECONCILE = "reconcile"
ALLOWED_ALIASES = frozenset({ALIAS_CLASSIFY, ALIAS_RETIRE, ALIAS_RECONCILE})
ACCOUNT_ID = re.compile(r"^(?!000000000000$)[0-9]{12}$")
REGION = re.compile(r"^[a-z]{2}(?:-[a-z]+)+-[0-9]+$")
DIGEST = re.compile(r"^sha256:[a-f0-9]{64}$")
BASE64_SHA256 = re.compile(r"^[A-Za-z0-9+/]{43}=$")
CHANGE_SET_NAME = re.compile(r"^scanalyze-platform-authority-bootstrap-[0-9]{14}$")
IDENTITY_STORE_USER_ID = re.compile(
    r"^(?:[0-9a-f]{10}-)?[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$",
    re.IGNORECASE,
)
UUID = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-"
    r"[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)
EXPECTED_TAGS = {
    "managed_by": "cloudformation",
    "service": "scanalyze-platform-authority",
    "work_package": "GUG-206",
}
EXPECTED_LEDGER_TAGS = {
    "managed_by": "cloudformation",
    "service": "scanalyze-platform-authority",
    "data_class": "control-metadata",
    "work_package": "GUG-215",
    "environment": "non-production",
    "production": "false",
}
EXPECTED_RESOURCE_CHANGES = (
    ("StateBucket", "AWS::S3::Bucket", "Add", "False"),
    ("StateBucketPolicy", "AWS::S3::BucketPolicy", "Add", "False"),
    ("StateKmsAlias", "AWS::KMS::Alias", "Add", "False"),
    ("StateKmsKey", "AWS::KMS::Key", "Add", "False"),
)
PUBLIC_ACCESS_BLOCK_KEYS = frozenset(
    {
        "BlockPublicAcls",
        "BlockPublicPolicy",
        "IgnorePublicAcls",
        "RestrictPublicBuckets",
    }
)
LEDGER_STATES = frozenset(
    {"CLASSIFIED", "APPROVED", "ATTEMPTED", "RETIRED_RECONCILED"}
)
LEDGER_KEYS = frozenset(
    {
        "schema_version",
        "record_type",
        "environment",
        "production",
        "authority_account_id_digest",
        "region",
        "stack_name",
        "retirement_id",
        "stack_id_digest",
        "change_set_id_digest",
        "change_set_name_digest",
        "template_sha256",
        "resource_inventory_sha256",
        "identity_binding_digest",
        "identity_store_arn_digest",
        "identity_center_instance_arn_digest",
        "identity_center_application_arn_digest",
        "classifier_identity_store_user_id_digest",
        "approver_identity_store_user_id_digest",
        "classifier_assignment_sha256",
        "approver_assignment_sha256",
        "classifier_invoker_policy_sha256",
        "approver_invoker_policy_sha256",
        "classifier_proof_policy_sha256",
        "approver_proof_policy_sha256",
        "identity_center_application_actor_policy_sha256",
        "broker_code_sha256",
        "broker_policy_sha256",
        "identity_separation",
        "human_authentication_evidence",
        "aws_effect_principal",
        "native_on_behalf_of",
        "classifier_identity_proof_sha256",
        "approver_identity_proof_sha256",
        "reconciliation_identity_proof_sha256",
        "state",
        "version",
        "attempt_count",
        "approval_digest",
        "attempt_digest",
        "verification_digest",
        "classified_at",
        "approved_at",
        "attempted_at",
        "verified_at",
        "effect_attribution",
        "next_required_control",
        "updated_at",
        "ledger_digest",
    }
)
WRITE_ACTIONS = frozenset(
    {
        "dynamodb:BatchWriteItem",
        "dynamodb:DeleteItem",
        "dynamodb:PartiQLDelete",
        "dynamodb:PartiQLInsert",
        "dynamodb:PartiQLUpdate",
        "dynamodb:PutItem",
        "dynamodb:TransactWriteItems",
        "dynamodb:UpdateItem",
    }
)


class BrokerError(ValueError):
    """A fail-closed broker decision with a non-sensitive reason code."""

    def __init__(self, code: str) -> None:
        if not re.fullmatch(r"[A-Z][A-Z0-9_]{2,63}", code):
            code = "BROKER_DENIED"
        self.code = code
        super().__init__(code)


def canonical_digest(value: Mapping[str, Any]) -> str:
    payload = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )
    return "sha256:" + hashlib.sha256(payload.encode("utf-8")).hexdigest()


def secret_digest(label: str, value: str) -> str:
    return canonical_digest({label: value})


def _require_digest(value: str, code: str) -> str:
    if DIGEST.fullmatch(value) is None:
        raise BrokerError(code)
    return value


def _partition(region: str) -> str:
    if region.startswith("cn-"):
        return "aws-cn"
    if region.startswith("us-gov-"):
        return "aws-us-gov"
    return "aws"


def _timestamp(now: datetime) -> str:
    if now.tzinfo is None:
        raise BrokerError("CLOCK_INVALID")
    return now.astimezone(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _parse_timestamp(value: object) -> datetime:
    if not isinstance(value, str):
        raise BrokerError("LEDGER_MALFORMED")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise BrokerError("LEDGER_MALFORMED") from exc
    if parsed.tzinfo is None:
        raise BrokerError("LEDGER_MALFORMED")
    return parsed.astimezone(UTC)


@dataclass(frozen=True, slots=True)
class BrokerConfig:
    authority_account_id: str
    region: str
    change_set_name: str
    expected_template_sha256: str
    expected_evidence_sha256: str
    expected_code_sha256: str
    expected_broker_policy_sha256: str
    identity_store_arn: str
    identity_center_instance_arn: str
    identity_center_application_arn: str
    classifier_identity_store_user_id: str
    approver_identity_store_user_id: str
    classifier_assignment_sha256: str
    approver_assignment_sha256: str
    classifier_invoker_policy_sha256: str
    approver_invoker_policy_sha256: str
    classifier_proof_policy_sha256: str
    approver_proof_policy_sha256: str
    identity_center_application_actor_policy_sha256: str
    classifier_invoker_role_name: str
    approver_invoker_role_name: str
    classifier_proof_role_name: str
    approver_proof_role_name: str
    classifier_permission_set_role_arn: str
    approver_permission_set_role_arn: str
    broker_execution_role_name: str
    code_signing_config_arn: str
    retirement_id: str
    stack_name: str = CANONICAL_STACK_NAME
    ledger_table_name: str = RETIREMENT_LEDGER_TABLE
    function_name: str = BROKER_FUNCTION_NAME

    def __post_init__(self) -> None:
        if ACCOUNT_ID.fullmatch(self.authority_account_id) is None:
            raise BrokerError("ACCOUNT_BINDING_INVALID")
        if REGION.fullmatch(self.region) is None:
            raise BrokerError("REGION_BINDING_INVALID")
        if self.stack_name != CANONICAL_STACK_NAME:
            raise BrokerError("STACK_BINDING_INVALID")
        if self.ledger_table_name != RETIREMENT_LEDGER_TABLE:
            raise BrokerError("LEDGER_BINDING_INVALID")
        if self.function_name != BROKER_FUNCTION_NAME:
            raise BrokerError("FUNCTION_BINDING_INVALID")
        if CHANGE_SET_NAME.fullmatch(self.change_set_name) is None:
            raise BrokerError("CHANGE_SET_BINDING_INVALID")
        if re.fullmatch(r"gug215#sha256:[a-f0-9]{64}", self.retirement_id) is None:
            raise BrokerError("RETIREMENT_ID_INVALID")
        for value, code in (
            (self.expected_template_sha256, "TEMPLATE_DIGEST_INVALID"),
            (self.expected_evidence_sha256, "EVIDENCE_DIGEST_INVALID"),
            (self.expected_broker_policy_sha256, "BROKER_POLICY_DIGEST_INVALID"),
            (self.classifier_assignment_sha256, "CLASSIFIER_ASSIGNMENT_DIGEST_INVALID"),
            (self.approver_assignment_sha256, "APPROVER_ASSIGNMENT_DIGEST_INVALID"),
            (
                self.classifier_invoker_policy_sha256,
                "CLASSIFIER_POLICY_DIGEST_INVALID",
            ),
            (self.approver_invoker_policy_sha256, "APPROVER_POLICY_DIGEST_INVALID"),
            (self.classifier_proof_policy_sha256, "CLASSIFIER_PROOF_POLICY_DIGEST_INVALID"),
            (self.approver_proof_policy_sha256, "APPROVER_PROOF_POLICY_DIGEST_INVALID"),
            (
                self.identity_center_application_actor_policy_sha256,
                "APPLICATION_ACTOR_POLICY_DIGEST_INVALID",
            ),
        ):
            _require_digest(value, code)
        if BASE64_SHA256.fullmatch(self.expected_code_sha256) is None:
            raise BrokerError("CODE_DIGEST_INVALID")
        if (
            IDENTITY_STORE_USER_ID.fullmatch(self.classifier_identity_store_user_id)
            is None
            or IDENTITY_STORE_USER_ID.fullmatch(self.approver_identity_store_user_id)
            is None
        ):
            raise BrokerError("IDENTITY_STORE_USER_INVALID")
        if (
            self.classifier_identity_store_user_id.lower()
            == self.approver_identity_store_user_id.lower()
        ):
            raise BrokerError("INDEPENDENT_OPERATOR_REQUIRED")
        partition = _partition(self.region)
        if not re.fullmatch(
            rf"arn:{partition}:identitystore::[0-9]{{12}}:identitystore/d-[a-z0-9]{{10,}}",
            self.identity_store_arn,
        ):
            raise BrokerError("IDENTITY_STORE_BINDING_INVALID")
        if not re.fullmatch(
            rf"arn:{partition}:sso:::instance/ssoins-[A-Za-z0-9]{{16}}",
            self.identity_center_instance_arn,
        ):
            raise BrokerError("IDENTITY_CENTER_INSTANCE_INVALID")
        if not re.fullmatch(
            rf"arn:{partition}:sso::[0-9]{{12}}:application/"
            r"ssoins-[A-Za-z0-9]{16}/apl-[A-Za-z0-9]{16}",
            self.identity_center_application_arn,
        ):
            raise BrokerError("IDENTITY_CENTER_APPLICATION_INVALID")
        for name in (
            self.classifier_invoker_role_name,
            self.approver_invoker_role_name,
            self.classifier_proof_role_name,
            self.approver_proof_role_name,
            self.broker_execution_role_name,
        ):
            if not re.fullmatch(r"[A-Za-z0-9+=,.@_-]{1,64}", name):
                raise BrokerError("ROLE_BINDING_INVALID")
        if (
            self.classifier_invoker_role_name != "ScanalyzeGug215ClassifierInvoker"
            or self.approver_invoker_role_name != "ScanalyzeGug215ApproverInvoker"
            or self.classifier_proof_role_name != "ScanalyzeGug217ClassifierProof"
            or self.approver_proof_role_name != "ScanalyzeGug217ApproverProof"
            or self.broker_execution_role_name != "ScanalyzeGug215BrokerExecution"
        ):
            raise BrokerError("ROLE_BINDING_INVALID")
        permission_set_role_patterns = (
            (
                self.classifier_permission_set_role_arn,
                "ScanalyzeAuthorityRetireClass",
            ),
            (
                self.approver_permission_set_role_arn,
                "ScanalyzeAuthorityRetireApprove",
            ),
        )
        for role_arn, permission_set_name in permission_set_role_patterns:
            if re.fullmatch(
                rf"arn:{partition}:iam::{self.authority_account_id}:role/"
                r"aws-reserved/sso\.amazonaws\.com/(?:[a-z0-9-]+/)?"
                rf"AWSReservedSSO_{permission_set_name}_[0-9A-Fa-f]{{16}}",
                role_arn,
            ) is None:
                raise BrokerError("PERMISSION_SET_ROLE_BINDING_INVALID")
        if not self.code_signing_config_arn.startswith(
            f"arn:{partition}:lambda:{self.region}:{self.authority_account_id}:code-signing-config:"
        ):
            raise BrokerError("CODE_SIGNING_BINDING_INVALID")

    @classmethod
    def from_environment(cls, env: Mapping[str, str] | None = None) -> "BrokerConfig":
        source = os.environ if env is None else env

        def required(name: str) -> str:
            value = source.get(name)
            if not isinstance(value, str) or not value:
                raise BrokerError("CONFIGURATION_INCOMPLETE")
            return value

        return cls(
            authority_account_id=required("AUTHORITY_ACCOUNT_ID"),
            region=required("AUTHORITY_REGION"),
            change_set_name=required("CHANGE_SET_NAME"),
            expected_template_sha256=required("EXPECTED_TEMPLATE_SHA256"),
            expected_evidence_sha256=required("EXPECTED_EVIDENCE_SHA256"),
            expected_code_sha256=required("EXPECTED_CODE_SHA256"),
            expected_broker_policy_sha256=required("EXPECTED_BROKER_POLICY_SHA256"),
            identity_store_arn=required("IDENTITY_STORE_ARN"),
            identity_center_instance_arn=required("IDENTITY_CENTER_INSTANCE_ARN"),
            identity_center_application_arn=required("IDENTITY_CENTER_APPLICATION_ARN"),
            classifier_identity_store_user_id=required("CLASSIFIER_IDENTITY_STORE_USER_ID"),
            approver_identity_store_user_id=required("APPROVER_IDENTITY_STORE_USER_ID"),
            classifier_assignment_sha256=required("CLASSIFIER_ASSIGNMENT_SHA256"),
            approver_assignment_sha256=required("APPROVER_ASSIGNMENT_SHA256"),
            classifier_invoker_policy_sha256=required("CLASSIFIER_INVOKER_POLICY_SHA256"),
            approver_invoker_policy_sha256=required("APPROVER_INVOKER_POLICY_SHA256"),
            classifier_proof_policy_sha256=required("CLASSIFIER_PROOF_POLICY_SHA256"),
            approver_proof_policy_sha256=required("APPROVER_PROOF_POLICY_SHA256"),
            identity_center_application_actor_policy_sha256=required(
                "IDENTITY_CENTER_APPLICATION_ACTOR_POLICY_SHA256"
            ),
            classifier_invoker_role_name=required("CLASSIFIER_INVOKER_ROLE_NAME"),
            approver_invoker_role_name=required("APPROVER_INVOKER_ROLE_NAME"),
            classifier_proof_role_name=required("CLASSIFIER_PROOF_ROLE_NAME"),
            approver_proof_role_name=required("APPROVER_PROOF_ROLE_NAME"),
            classifier_permission_set_role_arn=required(
                "CLASSIFIER_PERMISSION_SET_ROLE_ARN"
            ),
            approver_permission_set_role_arn=required(
                "APPROVER_PERMISSION_SET_ROLE_ARN"
            ),
            broker_execution_role_name=required("BROKER_EXECUTION_ROLE_NAME"),
            code_signing_config_arn=required("CODE_SIGNING_CONFIG_ARN"),
            retirement_id=required("RETIREMENT_ID"),
        )

    @property
    def partition(self) -> str:
        return _partition(self.region)

    @property
    def stack_arn(self) -> str:
        return (
            f"arn:{self.partition}:cloudformation:{self.region}:"
            f"{self.authority_account_id}:stack/{self.stack_name}/*"
        )

    @property
    def table_arn(self) -> str:
        return (
            f"arn:{self.partition}:dynamodb:{self.region}:"
            f"{self.authority_account_id}:table/{self.ledger_table_name}"
        )

    @property
    def function_arn(self) -> str:
        return (
            f"arn:{self.partition}:lambda:{self.region}:"
            f"{self.authority_account_id}:function:{self.function_name}"
        )

    @property
    def execution_role_arn(self) -> str:
        return (
            f"arn:{self.partition}:iam::{self.authority_account_id}:"
            f"role/{self.broker_execution_role_name}"
        )

    @property
    def classifier_invoker_role_arn(self) -> str:
        return (
            f"arn:{self.partition}:iam::{self.authority_account_id}:"
            f"role/{self.classifier_invoker_role_name}"
        )

    @property
    def approver_invoker_role_arn(self) -> str:
        return (
            f"arn:{self.partition}:iam::{self.authority_account_id}:"
            f"role/{self.approver_invoker_role_name}"
        )

    @property
    def classifier_proof_role_arn(self) -> str:
        return (
            f"arn:{self.partition}:iam::{self.authority_account_id}:"
            f"role/{self.classifier_proof_role_name}"
        )

    @property
    def approver_proof_role_arn(self) -> str:
        return (
            f"arn:{self.partition}:iam::{self.authority_account_id}:"
            f"role/{self.approver_proof_role_name}"
        )

    @property
    def identity_binding(self) -> dict[str, str]:
        return {
            "identity_store_arn_digest": secret_digest(
                "identity_store_arn", self.identity_store_arn
            ),
            "identity_center_instance_arn_digest": secret_digest(
                "identity_center_instance_arn", self.identity_center_instance_arn
            ),
            "identity_center_application_arn_digest": secret_digest(
                "identity_center_application_arn", self.identity_center_application_arn
            ),
            "classifier_identity_store_user_id_digest": secret_digest(
                "identity_store_user_id", self.classifier_identity_store_user_id.lower()
            ),
            "approver_identity_store_user_id_digest": secret_digest(
                "identity_store_user_id", self.approver_identity_store_user_id.lower()
            ),
            "classifier_assignment_sha256": self.classifier_assignment_sha256,
            "approver_assignment_sha256": self.approver_assignment_sha256,
            "classifier_invoker_policy_sha256": self.classifier_invoker_policy_sha256,
            "approver_invoker_policy_sha256": self.approver_invoker_policy_sha256,
            "classifier_proof_policy_sha256": self.classifier_proof_policy_sha256,
            "approver_proof_policy_sha256": self.approver_proof_policy_sha256,
            "identity_center_application_actor_policy_sha256": (
                self.identity_center_application_actor_policy_sha256
            ),
        }

    @property
    def identity_binding_digest(self) -> str:
        return canonical_digest(self.identity_binding)


class AwsClients(Protocol):
    cloudformation: Any
    dynamodb: Any
    iam: Any
    kms: Any
    lambda_client: Any
    s3control: Any
    sso_oidc: Any
    sts: Any


@dataclass(slots=True)
class BotoClients:
    cloudformation: Any
    dynamodb: Any
    iam: Any
    kms: Any
    lambda_client: Any
    s3control: Any
    sso_oidc: Any
    sts: Any

    @classmethod
    def create(cls, region: str) -> "BotoClients":
        try:
            import boto3  # type: ignore[import-not-found]
            from botocore.config import Config  # type: ignore[import-not-found]
        except ImportError as exc:
            raise BrokerError("RUNTIME_DEPENDENCY_MISSING") from exc
        no_retry = Config(region_name=region, retries={"max_attempts": 0, "mode": "standard"})
        return cls(
            cloudformation=boto3.client("cloudformation", config=no_retry),
            dynamodb=boto3.client("dynamodb", config=no_retry),
            iam=boto3.client("iam", config=no_retry),
            kms=boto3.client("kms", config=no_retry),
            lambda_client=boto3.client("lambda", config=no_retry),
            s3control=boto3.client("s3control", config=no_retry),
            sso_oidc=boto3.client("sso-oidc", config=no_retry),
            sts=boto3.client("sts", config=no_retry),
        )


def _strict_json_object(value: str, code: str) -> dict[str, Any]:
    try:
        parsed = json.loads(value)
    except (TypeError, json.JSONDecodeError) as exc:
        raise BrokerError(code) from exc
    if not isinstance(parsed, dict):
        raise BrokerError(code)
    return parsed


def _actions(statement: Mapping[str, Any]) -> set[str]:
    value = statement.get("Action")
    if isinstance(value, str):
        return {value}
    if isinstance(value, list) and all(isinstance(item, str) for item in value):
        return set(value)
    raise BrokerError("POLICY_READBACK_INVALID")


def _policy_document_digest(value: object) -> str:
    if isinstance(value, str):
        document = _strict_json_object(value, "POLICY_READBACK_INVALID")
    elif isinstance(value, Mapping):
        document = dict(value)
    else:
        raise BrokerError("POLICY_READBACK_INVALID")
    return canonical_digest(document)


class RetirementBroker:
    """Purely bounded side-effect coordinator around injected AWS clients."""

    def __init__(
        self,
        *,
        config: BrokerConfig,
        clients: AwsClients,
        now: Callable[[], datetime] | None = None,
    ) -> None:
        self.config = config
        self.clients = clients
        self.now: Callable[[], datetime] = now or (lambda: datetime.now(tz=UTC))

    def handle(
        self,
        *,
        alias: str,
        event: object,
        identity_proof_sha256: str,
    ) -> dict[str, Any]:
        if alias not in ALLOWED_ALIASES:
            raise BrokerError("ALIAS_NOT_AUTHORIZED")
        if event != {}:
            raise BrokerError("REQUEST_AUTHORITY_FORBIDDEN")
        _require_digest(identity_proof_sha256, "IDENTITY_PROOF_DIGEST_INVALID")
        self.preflight(alias=alias)
        if alias == ALIAS_CLASSIFY:
            return self._classify(identity_proof_sha256)
        if alias == ALIAS_RETIRE:
            return self._retire(identity_proof_sha256)
        return self._reconcile(identity_proof_sha256)

    def preflight(self, *, alias: str) -> None:
        """Read back every mutable PEP boundary without issuing a proof."""

        if alias not in ALLOWED_ALIASES:
            raise BrokerError("ALIAS_NOT_AUTHORIZED")
        self._verify_runtime_boundary(alias)
        self._verify_table_controls()

    def _verify_invoker_role(
        self,
        *,
        role_name: str,
        role_arn: str,
        permission_set_role_arn: str,
        policy_name: str,
        expected_policy_sha256: str,
    ) -> None:
        role = self.clients.iam.get_role(RoleName=role_name).get("Role")
        if not isinstance(role, Mapping) or role.get("Arn") != role_arn:
            raise BrokerError("INVOKER_ROLE_READBACK_INVALID")
        expected_trust = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "AssumeFromExactPermissionSet",
                    "Effect": "Allow",
                    "Principal": {
                        "AWS": (
                            f"arn:{self.config.partition}:iam::"
                            f"{self.config.authority_account_id}:root"
                        )
                    },
                    "Action": "sts:AssumeRole",
                    "Condition": {
                        "ArnEquals": {"aws:PrincipalArn": permission_set_role_arn}
                    },
                },
            ],
        }
        if (
            role.get("AssumeRolePolicyDocument") != expected_trust
            or role.get("PermissionsBoundary") is not None
        ):
            raise BrokerError("INVOKER_ROLE_BOUNDARY_CHANGED")
        inline = self.clients.iam.list_role_policies(RoleName=role_name).get(
            "PolicyNames"
        )
        attached = self.clients.iam.list_attached_role_policies(
            RoleName=role_name
        ).get("AttachedPolicies")
        if inline != [policy_name] or attached not in ([], None):
            raise BrokerError("INVOKER_ROLE_POLICY_INVENTORY_CHANGED")
        policy = self.clients.iam.get_role_policy(
            RoleName=role_name,
            PolicyName=policy_name,
        )
        if _policy_document_digest(policy.get("PolicyDocument")) != expected_policy_sha256:
            raise BrokerError("INVOKER_ROLE_POLICY_CHANGED")

    def _verify_proof_role(
        self,
        *,
        role_name: str,
        role_arn: str,
        identity_store_user_id: str,
        expected_policy_sha256: str,
        trust_sid: str,
    ) -> None:
        role = self.clients.iam.get_role(RoleName=role_name).get("Role")
        if not isinstance(role, Mapping) or role.get("Arn") != role_arn:
            raise BrokerError("PROOF_ROLE_READBACK_INVALID")
        principal = (
            f"arn:{self.config.partition}:iam::"
            f"{self.config.authority_account_id}:root"
        )
        expected_trust = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "AssumeFromExactBroker",
                    "Effect": "Allow",
                    "Principal": {"AWS": principal},
                    "Action": "sts:AssumeRole",
                    "Condition": {
                        "ArnEquals": {
                            "aws:PrincipalArn": self.config.execution_role_arn
                        }
                    },
                },
                {
                    "Sid": trust_sid,
                    "Effect": "Allow",
                    "Principal": {"AWS": principal},
                    "Action": "sts:SetContext",
                    "Condition": {
                        "ForAllValues:ArnEquals": {
                            "sts:RequestContextProviders": [
                                "arn:aws:iam::aws:contextProvider/IdentityCenter"
                            ]
                        },
                        "StringEquals": {
                            "sts:RequestContext/identitystore:UserId": identity_store_user_id
                        },
                        "ArnEquals": {
                            "aws:PrincipalArn": self.config.execution_role_arn,
                            "sts:RequestContext/identitystore:IdentityStoreArn": self.config.identity_store_arn,
                            "sts:RequestContext/identitycenter:InstanceArn": self.config.identity_center_instance_arn,
                            "sts:RequestContext/identitycenter:ApplicationArn": self.config.identity_center_application_arn,
                        },
                        "Null": {
                            "sts:RequestContextProviders": "false",
                            "sts:RequestContext/identitystore:UserId": "false",
                            "sts:RequestContext/identitystore:IdentityStoreArn": "false",
                            "sts:RequestContext/identitycenter:InstanceArn": "false",
                            "sts:RequestContext/identitycenter:ApplicationArn": "false",
                        },
                    },
                },
            ],
        }
        if (
            role.get("AssumeRolePolicyDocument") != expected_trust
            or role.get("PermissionsBoundary") is not None
            or role.get("MaxSessionDuration") != 3600
        ):
            raise BrokerError("PROOF_ROLE_BOUNDARY_CHANGED")
        inline = self.clients.iam.list_role_policies(RoleName=role_name).get(
            "PolicyNames"
        )
        attached = self.clients.iam.list_attached_role_policies(
            RoleName=role_name
        ).get("AttachedPolicies")
        if inline != [PROOF_POLICY_NAME] or attached not in ([], None):
            raise BrokerError("PROOF_ROLE_POLICY_INVENTORY_CHANGED")
        policy = self.clients.iam.get_role_policy(
            RoleName=role_name,
            PolicyName=PROOF_POLICY_NAME,
        )
        document = policy.get("PolicyDocument")
        if (
            _policy_document_digest(document) != expected_policy_sha256
            or (
                _strict_json_object(document, "PROOF_POLICY_INVALID")
                if isinstance(document, str)
                else document
            )
            != {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Sid": "DenyEveryProofSessionAction",
                        "Effect": "Deny",
                        "Action": "*",
                        "Resource": "*",
                    }
                ],
            }
        ):
            raise BrokerError("PROOF_ROLE_POLICY_CHANGED")

    def _verify_function_url(self, *, alias: str, invoker_role_arn: str) -> None:
        config = self.clients.lambda_client.get_function_url_config(
            FunctionName=self.config.function_name,
            Qualifier=alias,
        )
        function_arn = f"{self.config.function_arn}:{alias}"
        url = config.get("FunctionUrl")
        if (
            config.get("AuthType") != "AWS_IAM"
            or config.get("InvokeMode") != "BUFFERED"
            or config.get("FunctionArn") != function_arn
            or config.get("Cors") not in (None, {})
            or not isinstance(url, str)
            or not url.startswith("https://")
            or not url.endswith(f".lambda-url.{self.config.region}.on.aws/")
        ):
            raise BrokerError("FUNCTION_URL_BOUNDARY_CHANGED")
        response = self.clients.lambda_client.get_policy(
            FunctionName=self.config.function_name,
            Qualifier=alias,
        )
        document = _strict_json_object(
            response.get("Policy"), "FUNCTION_URL_POLICY_INVALID"
        )
        statements = document.get("Statement")
        if document.get("Version") != "2012-10-17" or not isinstance(
            statements, list
        ):
            raise BrokerError("FUNCTION_URL_POLICY_INVALID")
        normalized = {
            (
                statement.get("Effect"),
                json.dumps(statement.get("Principal"), sort_keys=True),
                statement.get("Action"),
                statement.get("Resource"),
                json.dumps(statement.get("Condition"), sort_keys=True),
            )
            for statement in statements
            if isinstance(statement, Mapping)
        }
        expected = {
            (
                "Allow",
                json.dumps({"AWS": invoker_role_arn}, sort_keys=True),
                "lambda:InvokeFunctionUrl",
                function_arn,
                json.dumps(
                    {
                        "StringEquals": {
                            "lambda:FunctionUrlAuthType": "AWS_IAM"
                        }
                    },
                    sort_keys=True,
                ),
            ),
            (
                "Allow",
                json.dumps({"AWS": invoker_role_arn}, sort_keys=True),
                "lambda:InvokeFunction",
                function_arn,
                json.dumps(
                    {"Bool": {"lambda:InvokedViaFunctionUrl": "true"}},
                    sort_keys=True,
                ),
            ),
        }
        if normalized != expected:
            raise BrokerError("FUNCTION_URL_POLICY_CHANGED")

    def _verify_runtime_boundary(self, alias: str) -> None:
        role = self.clients.iam.get_role(RoleName=self.config.broker_execution_role_name)
        value = role.get("Role")
        if not isinstance(value, Mapping):
            raise BrokerError("BROKER_ROLE_READBACK_INVALID")
        trust = value.get("AssumeRolePolicyDocument")
        expected_trust = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "lambda.amazonaws.com"},
                    "Action": "sts:AssumeRole",
                }
            ],
        }
        if trust != expected_trust or value.get("PermissionsBoundary") is not None:
            raise BrokerError("BROKER_ROLE_BOUNDARY_CHANGED")
        inline = self.clients.iam.list_role_policies(
            RoleName=self.config.broker_execution_role_name
        ).get("PolicyNames")
        attached = self.clients.iam.list_attached_role_policies(
            RoleName=self.config.broker_execution_role_name
        ).get("AttachedPolicies")
        if inline != [BROKER_POLICY_NAME] or attached not in ([], None):
            raise BrokerError("BROKER_ROLE_POLICY_INVENTORY_CHANGED")
        policy = self.clients.iam.get_role_policy(
            RoleName=self.config.broker_execution_role_name,
            PolicyName=BROKER_POLICY_NAME,
        )
        if (
            _policy_document_digest(policy.get("PolicyDocument"))
            != self.config.expected_broker_policy_sha256
        ):
            raise BrokerError("BROKER_ROLE_POLICY_CHANGED")
        self._verify_invoker_role(
            role_name=self.config.classifier_invoker_role_name,
            role_arn=self.config.classifier_invoker_role_arn,
            permission_set_role_arn=self.config.classifier_permission_set_role_arn,
            policy_name=CLASSIFIER_INVOKER_POLICY_NAME,
            expected_policy_sha256=self.config.classifier_invoker_policy_sha256,
        )
        self._verify_invoker_role(
            role_name=self.config.approver_invoker_role_name,
            role_arn=self.config.approver_invoker_role_arn,
            permission_set_role_arn=self.config.approver_permission_set_role_arn,
            policy_name=APPROVER_INVOKER_POLICY_NAME,
            expected_policy_sha256=self.config.approver_invoker_policy_sha256,
        )
        self._verify_proof_role(
            role_name=self.config.classifier_proof_role_name,
            role_arn=self.config.classifier_proof_role_arn,
            identity_store_user_id=self.config.classifier_identity_store_user_id,
            expected_policy_sha256=self.config.classifier_proof_policy_sha256,
            trust_sid="SetExactClassifierIdentityContext",
        )
        self._verify_proof_role(
            role_name=self.config.approver_proof_role_name,
            role_arn=self.config.approver_proof_role_arn,
            identity_store_user_id=self.config.approver_identity_store_user_id,
            expected_policy_sha256=self.config.approver_proof_policy_sha256,
            trust_sid="SetExactApproverIdentityContext",
        )
        function = self.clients.lambda_client.get_function_configuration(
            FunctionName=f"{self.config.function_name}:{alias}"
        )
        if (
            function.get("Version") in (None, "$LATEST")
            or function.get("FunctionArn")
            != f"{self.config.function_arn}:{function.get('Version')}"
            or function.get("CodeSha256") != self.config.expected_code_sha256
            or function.get("Role") != self.config.execution_role_arn
        ):
            raise BrokerError("BROKER_CODE_BOUNDARY_CHANGED")
        concurrency = self.clients.lambda_client.get_function_concurrency(
            FunctionName=self.config.function_name
        )
        if concurrency.get("ReservedConcurrentExecutions") != 1:
            raise BrokerError("BROKER_CONCURRENCY_CHANGED")
        alias_record = self.clients.lambda_client.get_alias(
            FunctionName=self.config.function_name,
            Name=alias,
        )
        if (
            alias_record.get("FunctionVersion") != function.get("Version")
            or alias_record.get("RoutingConfig")
            not in (None, {}, {"AdditionalVersionWeights": {}})
        ):
            raise BrokerError("BROKER_ALIAS_CHANGED")
        signing = self.clients.lambda_client.get_function_code_signing_config(
            FunctionName=self.config.function_name
        )
        if signing.get("CodeSigningConfigArn") != self.config.code_signing_config_arn:
            raise BrokerError("BROKER_CODE_SIGNING_CHANGED")
        for qualifier in (None, str(function["Version"])):
            try:
                self.clients.lambda_client.get_policy(
                    FunctionName=self.config.function_name,
                    **({"Qualifier": qualifier} if qualifier is not None else {}),
                )
            except Exception as exc:  # No policy is ResourceNotFound for each scope.
                response = getattr(exc, "response", None)
                code = (
                    response.get("Error", {}).get("Code")
                    if isinstance(response, Mapping)
                    else None
                )
                if code != "ResourceNotFoundException":
                    raise BrokerError("BROKER_RESOURCE_POLICY_READ_FAILED") from exc
            else:
                raise BrokerError("BROKER_RESOURCE_POLICY_CHANGED")
        invoker_role_arn = (
            self.config.classifier_invoker_role_arn
            if alias == ALIAS_CLASSIFY
            else self.config.approver_invoker_role_arn
        )
        self._verify_function_url(alias=alias, invoker_role_arn=invoker_role_arn)

    def _verify_table_controls(self) -> None:
        response = self.clients.dynamodb.describe_table(
            TableName=self.config.ledger_table_name
        )
        table = response.get("Table")
        if not isinstance(table, Mapping):
            raise BrokerError("LEDGER_TABLE_INVALID")
        sse = table.get("SSEDescription")
        key_arn = sse.get("KMSMasterKeyArn") if isinstance(sse, Mapping) else None
        key_arn_pattern = re.compile(
            rf"^arn:{self.config.partition}:kms:{self.config.region}:"
            rf"{self.config.authority_account_id}:key/[0-9a-f-]{{36}}$",
            re.IGNORECASE,
        )
        if (
            table.get("TableStatus") != "ACTIVE"
            or table.get("TableArn") != self.config.table_arn
            or table.get("KeySchema")
            != [{"AttributeName": "retirement_id", "KeyType": "HASH"}]
            or table.get("DeletionProtectionEnabled") is not True
            or not isinstance(sse, Mapping)
            or sse.get("Status") != "ENABLED"
            or sse.get("SSEType") != "KMS"
            or not isinstance(key_arn, str)
            or key_arn_pattern.fullmatch(key_arn) is None
            or table.get("BillingModeSummary", {}).get("BillingMode") != "PAY_PER_REQUEST"
            or table.get("LatestStreamArn") not in (None, "")
            or table.get("Replicas") not in (None, [])
        ):
            raise BrokerError("LEDGER_TABLE_CONTROLS_CHANGED")
        key_metadata = self.clients.kms.describe_key(KeyId=key_arn).get("KeyMetadata")
        if (
            not isinstance(key_metadata, Mapping)
            or key_metadata.get("Arn") != key_arn
            or key_metadata.get("AWSAccountId") != self.config.authority_account_id
            or key_metadata.get("Enabled") is not True
            or key_metadata.get("KeyManager") != "AWS"
            or key_metadata.get("KeyState") != "Enabled"
            or key_metadata.get("KeyUsage") != "ENCRYPT_DECRYPT"
            or key_metadata.get("Origin") != "AWS_KMS"
            or key_metadata.get("MultiRegion") is not False
        ):
            raise BrokerError("LEDGER_KMS_CONTROLS_CHANGED")
        backups = self.clients.dynamodb.describe_continuous_backups(
            TableName=self.config.ledger_table_name
        ).get("ContinuousBackupsDescription")
        pitr = (
            backups.get("PointInTimeRecoveryDescription")
            if isinstance(backups, Mapping)
            else None
        )
        if (
            not isinstance(backups, Mapping)
            or backups.get("ContinuousBackupsStatus") != "ENABLED"
            or not isinstance(pitr, Mapping)
            or pitr.get("PointInTimeRecoveryStatus") != "ENABLED"
            or pitr.get("RecoveryPeriodInDays") != 35
        ):
            raise BrokerError("LEDGER_RECOVERY_CONTROLS_CHANGED")
        tags = self.clients.dynamodb.list_tags_of_resource(
            ResourceArn=self.config.table_arn
        ).get("Tags")
        if not isinstance(tags, list):
            raise BrokerError("LEDGER_TAGS_CHANGED")
        normalized_tags = {
            item.get("Key"): item.get("Value")
            for item in tags
            if isinstance(item, Mapping)
        }
        expected_tags = {
            **EXPECTED_LEDGER_TAGS,
            "account_id": self.config.authority_account_id,
            "region": self.config.region,
        }
        if normalized_tags != expected_tags:
            raise BrokerError("LEDGER_TAGS_CHANGED")
        policy = self.clients.dynamodb.get_resource_policy(
            ResourceArn=self.config.table_arn
        ).get("Policy")
        document = _strict_json_object(policy, "LEDGER_RESOURCE_POLICY_CHANGED")
        statements = document.get("Statement")
        if not isinstance(statements, list) or len(statements) != 1:
            raise BrokerError("LEDGER_RESOURCE_POLICY_CHANGED")
        statement = statements[0]
        if (
            not isinstance(statement, Mapping)
            or statement.get("Effect") != "Deny"
            or statement.get("Principal") != {"AWS": "*"}
            or _actions(statement) != set(WRITE_ACTIONS)
            or statement.get("Resource") != self.config.table_arn
            or statement.get("Condition")
            != {
                "ArnNotEquals": {
                    "aws:PrincipalArn": self.config.execution_role_arn
                }
            }
        ):
            raise BrokerError("LEDGER_RESOURCE_POLICY_CHANGED")

    def _stack(self) -> Mapping[str, Any]:
        response = self.clients.cloudformation.describe_stacks(
            StackName=self.config.stack_name
        )
        stacks = response.get("Stacks")
        if not isinstance(stacks, list) or len(stacks) != 1:
            raise BrokerError("STACK_SHELL_AMBIGUOUS")
        stack = stacks[0]
        if not isinstance(stack, Mapping):
            raise BrokerError("STACK_SHELL_AMBIGUOUS")
        stack_id = stack.get("StackId")
        if (
            stack.get("StackName") != self.config.stack_name
            or stack.get("StackStatus") != "REVIEW_IN_PROGRESS"
            or not isinstance(stack_id, str)
            or not stack_id.startswith(self.config.stack_arn.removesuffix("*"))
            or stack.get("RoleARN") not in (None, "")
            or stack.get("NotificationARNs", []) != []
            or stack.get("ParentId") not in (None, "")
            or stack.get("RootId") not in (None, "")
        ):
            raise BrokerError("STACK_SHELL_CHANGED")
        resources = self.clients.cloudformation.list_stack_resources(
            StackName=stack_id
        ).get("StackResourceSummaries")
        if resources != []:
            raise BrokerError("STACK_RESOURCE_INVENTORY_CHANGED")
        return stack

    def _change_set_inventory(self, stack_id: str) -> list[Mapping[str, Any]]:
        items: list[Mapping[str, Any]] = []
        token: str | None = None
        seen: set[str] = set()
        for _ in range(100):
            kwargs: dict[str, Any] = {"StackName": stack_id}
            if token is not None:
                kwargs["NextToken"] = token
            response = self.clients.cloudformation.list_change_sets(**kwargs)
            summaries = response.get("Summaries")
            if not isinstance(summaries, list) or any(
                not isinstance(item, Mapping) for item in summaries
            ):
                raise BrokerError("CHANGE_SET_INVENTORY_AMBIGUOUS")
            items.extend(summaries)
            next_token = response.get("NextToken")
            if next_token is None:
                return items
            if (
                not isinstance(next_token, str)
                or not next_token
                or next_token in seen
            ):
                raise BrokerError("CHANGE_SET_PAGINATION_INVALID")
            seen.add(next_token)
            token = next_token
        raise BrokerError("CHANGE_SET_PAGINATION_EXCEEDED")

    def _target_evidence(self) -> dict[str, Any]:
        stack = self._stack()
        stack_id = stack.get("StackId")
        if not isinstance(stack_id, str):
            raise BrokerError("STACK_SHELL_CHANGED")
        inventory = self._change_set_inventory(stack_id)
        if len(inventory) != 1:
            raise BrokerError("CHANGE_SET_INVENTORY_NOT_EXACT")
        summary = inventory[0]
        if (
            summary.get("ChangeSetName") != self.config.change_set_name
            or summary.get("Status") != "CREATE_COMPLETE"
            or summary.get("ExecutionStatus") != "AVAILABLE"
        ):
            raise BrokerError("CHANGE_SET_SUMMARY_CHANGED")
        summary_change_set_id = summary.get("ChangeSetId")
        if not isinstance(summary_change_set_id, str):
            raise BrokerError("CHANGE_SET_IDENTITY_CHANGED")
        response = self.clients.cloudformation.describe_change_set(
            ChangeSetName=summary_change_set_id,
            StackName=stack_id,
        )
        change_set_id = response.get("ChangeSetId")
        response_stack_id = response.get("StackId")
        if (
            response.get("ChangeSetName") != self.config.change_set_name
            or response.get("StackName") != self.config.stack_name
            or response.get("Status") != "CREATE_COMPLETE"
            or response.get("ExecutionStatus") != "AVAILABLE"
            or response.get("ChangeSetType") != "CREATE"
            or response.get("Capabilities", []) != []
            or response.get("RoleARN") not in (None, "")
            or response.get("NotificationARNs", []) != []
            or response.get("IncludeNestedStacks") not in (None, False)
            or response.get("ParentChangeSetId") not in (None, "")
            or response.get("RootChangeSetId") not in (None, "")
            or not isinstance(change_set_id, str)
            or not isinstance(response_stack_id, str)
            or response_stack_id != stack_id
            or summary_change_set_id != change_set_id
        ):
            raise BrokerError("CHANGE_SET_IDENTITY_CHANGED")
        suffix = change_set_id.rsplit("/", 1)[-1]
        if UUID.fullmatch(suffix) is None:
            raise BrokerError("CHANGE_SET_IDENTITY_CHANGED")
        changes = response.get("Changes")
        if not isinstance(changes, list):
            raise BrokerError("CHANGE_SET_RESOURCES_CHANGED")
        normalized: list[tuple[str, str, str, str]] = []
        for change in changes:
            if not isinstance(change, Mapping) or change.get("Type") != "Resource":
                raise BrokerError("CHANGE_SET_RESOURCES_CHANGED")
            resource = change.get("ResourceChange")
            if not isinstance(resource, Mapping):
                raise BrokerError("CHANGE_SET_RESOURCES_CHANGED")
            values = (
                resource.get("LogicalResourceId"),
                resource.get("ResourceType"),
                resource.get("Action"),
                resource.get("Replacement"),
            )
            if not all(isinstance(value, str) for value in values):
                raise BrokerError("CHANGE_SET_RESOURCES_CHANGED")
            normalized.append(values)  # type: ignore[arg-type]
        if tuple(sorted(normalized)) != EXPECTED_RESOURCE_CHANGES:
            raise BrokerError("CHANGE_SET_RESOURCES_CHANGED")
        tags = response.get("Tags")
        parameters = response.get("Parameters")
        if not isinstance(tags, list) or not isinstance(parameters, list):
            raise BrokerError("CHANGE_SET_METADATA_CHANGED")
        normalized_tags = {
            item.get("Key"): item.get("Value")
            for item in tags
            if isinstance(item, Mapping)
        }
        normalized_parameters = {
            item.get("ParameterKey"): item.get("ParameterValue")
            for item in parameters
            if isinstance(item, Mapping)
        }
        if normalized_tags != EXPECTED_TAGS or normalized_parameters != {
            "AuthorityAccountId": self.config.authority_account_id,
            "NoncurrentVersionRetentionDays": "365",
            "StateKey": CANONICAL_STATE_KEY,
        }:
            raise BrokerError("CHANGE_SET_METADATA_CHANGED")
        template = self.clients.cloudformation.get_template(
            ChangeSetName=change_set_id,
            StackName=stack_id,
            TemplateStage="Original",
        ).get("TemplateBody")
        if not isinstance(template, str):
            raise BrokerError("CHANGE_SET_TEMPLATE_AMBIGUOUS")
        template_digest = "sha256:" + hashlib.sha256(template.encode("utf-8")).hexdigest()
        evidence = {
            "_change_set_id": change_set_id,
            "_stack_id": response_stack_id,
            "stack_id_digest": secret_digest("stack_id", response_stack_id),
            "change_set_id_digest": secret_digest("change_set_id", change_set_id),
            "change_set_name_digest": secret_digest(
                "change_set_name", self.config.change_set_name
            ),
            "template_sha256": template_digest,
            "resource_inventory_sha256": canonical_digest(
                {
                    "resource_changes": [list(item) for item in EXPECTED_RESOURCE_CHANGES],
                    "tags": EXPECTED_TAGS,
                    "parameters": normalized_parameters,
                    "capabilities": [],
                }
            ),
            "retirement_id": "gug215#sha256:"
            + hashlib.sha256(change_set_id.encode("utf-8")).hexdigest(),
        }
        if (
            evidence["template_sha256"] != self.config.expected_template_sha256
            or evidence["resource_inventory_sha256"]
            != self.config.expected_evidence_sha256
        ):
            raise BrokerError("REVIEWED_BASELINE_CHANGED")
        return evidence

    @staticmethod
    def _require_evidence_matches_ledger(
        record: Mapping[str, Any], evidence: Mapping[str, Any]
    ) -> None:
        for field in (
            "retirement_id",
            "stack_id_digest",
            "change_set_id_digest",
            "change_set_name_digest",
            "template_sha256",
            "resource_inventory_sha256",
        ):
            if record.get(field) != evidence.get(field):
                raise BrokerError("LIVE_TARGET_CHANGED")

    @staticmethod
    def _require_reconciliation_stack(
        record: Mapping[str, Any], stack: Mapping[str, Any]
    ) -> str:
        stack_id = stack.get("StackId")
        if (
            not isinstance(stack_id, str)
            or secret_digest("stack_id", stack_id) != record.get("stack_id_digest")
        ):
            raise BrokerError("RECONCILIATION_SHELL_CHANGED")
        return stack_id

    def _account_pab(self) -> dict[str, bool] | None:
        try:
            response = self.clients.s3control.get_public_access_block(
                AccountId=self.config.authority_account_id
            )
        except Exception as exc:  # SDK-specific missing response remains non-authoritative.
            response = getattr(exc, "response", None)
            code = (
                response.get("Error", {}).get("Code")
                if isinstance(response, Mapping)
                else None
            )
            if code == "NoSuchPublicAccessBlockConfiguration":
                return None
            raise BrokerError("PAB_READ_FAILED") from exc
        value = response.get("PublicAccessBlockConfiguration")
        if (
            not isinstance(value, Mapping)
            or set(value) != set(PUBLIC_ACCESS_BLOCK_KEYS)
            or any(not isinstance(value[key], bool) for key in PUBLIC_ACCESS_BLOCK_KEYS)
        ):
            raise BrokerError("PAB_READBACK_INVALID")
        return {key: bool(value[key]) for key in sorted(PUBLIC_ACCESS_BLOCK_KEYS)}

    def _base_ledger(
        self,
        evidence: Mapping[str, Any],
        identity_proof_sha256: str,
    ) -> dict[str, Any]:
        timestamp = _timestamp(self.now())
        record: dict[str, Any] = {
            "schema_version": "2",
            "record_type": "platform_authority_change_set_retirement_pep_ledger",
            "environment": "non-production",
            "production": False,
            "authority_account_id_digest": secret_digest(
                "authority_account_id", self.config.authority_account_id
            ),
            "region": self.config.region,
            "stack_name": self.config.stack_name,
            "retirement_id": evidence["retirement_id"],
            "stack_id_digest": evidence["stack_id_digest"],
            "change_set_id_digest": evidence["change_set_id_digest"],
            "change_set_name_digest": evidence["change_set_name_digest"],
            "template_sha256": evidence["template_sha256"],
            "resource_inventory_sha256": evidence["resource_inventory_sha256"],
            "identity_binding_digest": self.config.identity_binding_digest,
            **self.config.identity_binding,
            "broker_code_sha256": self.config.expected_code_sha256,
            "broker_policy_sha256": self.config.expected_broker_policy_sha256,
            "identity_separation": "VERIFIED_DISTINCT_IDENTITYSTORE_USERS",
            "human_authentication_evidence": "STS_EVALUATED_IDENTITY_CONTEXT",
            "aws_effect_principal": "BROKER_EXECUTION_ROLE",
            "native_on_behalf_of": False,
            "classifier_identity_proof_sha256": identity_proof_sha256,
            "approver_identity_proof_sha256": None,
            "reconciliation_identity_proof_sha256": None,
            "state": "CLASSIFIED",
            "version": 1,
            "attempt_count": 0,
            "approval_digest": None,
            "attempt_digest": None,
            "verification_digest": None,
            "classified_at": timestamp,
            "approved_at": None,
            "attempted_at": None,
            "verified_at": None,
            "effect_attribution": None,
            "next_required_control": "INDEPENDENT_APPROVAL_REQUIRED",
            "updated_at": timestamp,
        }
        record["ledger_digest"] = canonical_digest(record)
        return record

    def _validate_ledger(self, value: Mapping[str, Any]) -> dict[str, Any]:
        record = dict(value)
        if set(record) != set(LEDGER_KEYS):
            raise BrokerError("LEDGER_MALFORMED")
        digest = record.pop("ledger_digest", None)
        if not isinstance(digest, str) or canonical_digest(record) != digest:
            raise BrokerError("LEDGER_DIGEST_INVALID")
        record["ledger_digest"] = digest
        state = record.get("state")
        if state not in LEDGER_STATES:
            raise BrokerError("LEDGER_STATE_INVALID")
        expected_version = {
            "CLASSIFIED": 1,
            "APPROVED": 2,
            "ATTEMPTED": 3,
            "RETIRED_RECONCILED": 4,
        }[state]
        if record.get("version") != expected_version or record.get("attempt_count") != (
            0 if state in {"CLASSIFIED", "APPROVED"} else 1
        ):
            raise BrokerError("LEDGER_STATE_INVALID")
        expected_bindings = {
            "schema_version": "2",
            "record_type": "platform_authority_change_set_retirement_pep_ledger",
            "environment": "non-production",
            "production": False,
            "authority_account_id_digest": secret_digest(
                "authority_account_id", self.config.authority_account_id
            ),
            "region": self.config.region,
            "stack_name": self.config.stack_name,
            "retirement_id": self.config.retirement_id,
            "change_set_name_digest": secret_digest(
                "change_set_name", self.config.change_set_name
            ),
            "template_sha256": self.config.expected_template_sha256,
            "resource_inventory_sha256": self.config.expected_evidence_sha256,
            "identity_binding_digest": self.config.identity_binding_digest,
            **self.config.identity_binding,
            "broker_code_sha256": self.config.expected_code_sha256,
            "broker_policy_sha256": self.config.expected_broker_policy_sha256,
            "identity_separation": "VERIFIED_DISTINCT_IDENTITYSTORE_USERS",
            "human_authentication_evidence": "STS_EVALUATED_IDENTITY_CONTEXT",
            "aws_effect_principal": "BROKER_EXECUTION_ROLE",
            "native_on_behalf_of": False,
        }
        if any(record.get(key) != expected for key, expected in expected_bindings.items()):
            raise BrokerError("LEDGER_BINDING_CHANGED")
        for field in ("stack_id_digest", "change_set_id_digest"):
            value_digest = record.get(field)
            if not isinstance(value_digest, str) or DIGEST.fullmatch(value_digest) is None:
                raise BrokerError("LEDGER_BINDING_CHANGED")
        if (
            record.get("classifier_identity_store_user_id_digest")
            == record.get("approver_identity_store_user_id_digest")
        ):
            raise BrokerError("LEDGER_BINDING_CHANGED")
        proof_presence: dict[str, tuple[bool, bool, bool]] = {
            "CLASSIFIED": (True, False, False),
            "APPROVED": (True, True, False),
            "ATTEMPTED": (True, True, False),
            "RETIRED_RECONCILED": (True, True, True),
        }
        for field, present in zip(
            (
                "classifier_identity_proof_sha256",
                "approver_identity_proof_sha256",
                "reconciliation_identity_proof_sha256",
            ),
            proof_presence[state],
            strict=True,
        ):
            value = record.get(field)
            if present:
                if not isinstance(value, str) or DIGEST.fullmatch(value) is None:
                    raise BrokerError("IDENTITY_PROOF_LEDGER_INVALID")
            elif value is not None:
                raise BrokerError("IDENTITY_PROOF_LEDGER_INVALID")
        expected_fields: dict[str, tuple[bool, ...]] = {
            "CLASSIFIED": (False, False, False),
            "APPROVED": (True, False, False),
            "ATTEMPTED": (True, True, False),
            "RETIRED_RECONCILED": (True, True, True),
        }
        approval_present, attempt_present, verification_present = expected_fields[state]
        for field, present in (
            ("approval_digest", approval_present),
            ("attempt_digest", attempt_present),
            ("verification_digest", verification_present),
        ):
            field_value = record.get(field)
            if present:
                if not isinstance(field_value, str) or DIGEST.fullmatch(field_value) is None:
                    raise BrokerError("LEDGER_STATE_INVALID")
            elif field_value is not None:
                raise BrokerError("LEDGER_STATE_INVALID")
        timestamps = [_parse_timestamp(record.get("classified_at"))]
        for field, present in (
            ("approved_at", approval_present),
            ("attempted_at", attempt_present),
            ("verified_at", verification_present),
        ):
            field_value = record.get(field)
            if present:
                timestamps.append(_parse_timestamp(field_value))
            elif field_value is not None:
                raise BrokerError("LEDGER_STATE_INVALID")
        updated_at = _parse_timestamp(record.get("updated_at"))
        if timestamps != sorted(timestamps) or updated_at < timestamps[-1]:
            raise BrokerError("LEDGER_STATE_INVALID")
        expected_next_controls: dict[str, set[str]] = {
            "CLASSIFIED": {"INDEPENDENT_APPROVAL_REQUIRED"},
            "APPROVED": {"ONE_SHOT_ATTEMPT_REQUIRED"},
            "ATTEMPTED": {"READ_ONLY_RECONCILIATION_REQUIRED"},
            "RETIRED_RECONCILED": {
                "RETIREMENT_ROLE_REVOCATION_REQUIRED",
                "PAB_AND_REVOCATION_REQUIRED",
            },
        }
        if record.get("next_required_control") not in expected_next_controls[state]:
            raise BrokerError("LEDGER_STATE_INVALID")
        expected_attribution = (
            "BROKER_SERVICE_PRINCIPAL_AFTER_STS_PROOF"
            if verification_present
            else None
        )
        if record.get("effect_attribution") != expected_attribution:
            raise BrokerError("LEDGER_STATE_INVALID")
        return record

    def _get_ledger(self, retirement_id: str) -> dict[str, Any] | None:
        response = self.clients.dynamodb.get_item(
            TableName=self.config.ledger_table_name,
            Key={"retirement_id": {"S": retirement_id}},
            ConsistentRead=True,
            ProjectionExpression="document",
        )
        item = response.get("Item")
        raw = item.get("document", {}).get("S") if isinstance(item, Mapping) else None
        if raw is None:
            return None
        return self._validate_ledger(_strict_json_object(raw, "LEDGER_MALFORMED"))

    def _create_ledger(self, ledger: Mapping[str, Any]) -> None:
        try:
            self.clients.dynamodb.put_item(
                TableName=self.config.ledger_table_name,
                Item={
                    "retirement_id": {"S": str(ledger["retirement_id"])},
                    "state": {"S": str(ledger["state"])},
                    "version": {"N": str(ledger["version"])},
                    "attempt_count": {"N": str(ledger["attempt_count"])},
                    "ledger_digest": {"S": str(ledger["ledger_digest"])},
                    "document": {
                        "S": json.dumps(ledger, sort_keys=True, separators=(",", ":"))
                    },
                },
                ConditionExpression="attribute_not_exists(retirement_id)",
                ReturnConsumedCapacity="NONE",
            )
        except Exception as exc:
            try:
                observed = self._get_ledger(str(ledger["retirement_id"]))
            except Exception as read_exc:
                raise BrokerError("LEDGER_CREATE_UNCERTAIN") from read_exc
            if observed != dict(ledger):
                raise BrokerError("LEDGER_CREATE_UNCERTAIN") from exc

    def _transition(
        self,
        before: Mapping[str, Any],
        *,
        state: str,
        **updates: Any,
    ) -> dict[str, Any]:
        current = self._validate_ledger(before)
        expected_next = {
            "CLASSIFIED": "APPROVED",
            "APPROVED": "ATTEMPTED",
            "ATTEMPTED": "RETIRED_RECONCILED",
        }.get(str(current["state"]))
        if state != expected_next:
            raise BrokerError("LEDGER_TRANSITION_FORBIDDEN")
        candidate = {
            key: value for key, value in current.items() if key != "ledger_digest"
        }
        candidate.update(updates)
        candidate["state"] = state
        candidate["version"] = int(current["version"]) + 1
        candidate["attempt_count"] = 1 if state in {
            "ATTEMPTED",
            "RETIRED_RECONCILED",
        } else 0
        candidate["updated_at"] = _timestamp(self.now())
        candidate["ledger_digest"] = canonical_digest(candidate)
        validated = self._validate_ledger(candidate)
        try:
            self.clients.dynamodb.update_item(
                TableName=self.config.ledger_table_name,
                Key={"retirement_id": {"S": str(current["retirement_id"])}},
                UpdateExpression=(
                    "SET #state = :state, #version = :version, "
                    "#attempt_count = :attempt_count, #ledger_digest = :ledger_digest, "
                    "#document = :document"
                ),
                ConditionExpression=(
                    "#state = :expected_state AND #version = :expected_version AND "
                    "#attempt_count = :expected_attempt_count AND "
                    "#ledger_digest = :expected_ledger_digest"
                ),
                ExpressionAttributeNames={
                    "#state": "state",
                    "#version": "version",
                    "#attempt_count": "attempt_count",
                    "#ledger_digest": "ledger_digest",
                    "#document": "document",
                },
                ExpressionAttributeValues={
                    ":state": {"S": state},
                    ":version": {"N": str(validated["version"])},
                    ":attempt_count": {"N": str(validated["attempt_count"])},
                    ":ledger_digest": {"S": str(validated["ledger_digest"])},
                    ":document": {
                        "S": json.dumps(
                            validated, sort_keys=True, separators=(",", ":")
                        )
                    },
                    ":expected_state": {"S": str(current["state"])},
                    ":expected_version": {"N": str(current["version"])},
                    ":expected_attempt_count": {
                        "N": str(current["attempt_count"])
                    },
                    ":expected_ledger_digest": {
                        "S": str(current["ledger_digest"])
                    },
                },
                ReturnValues="NONE",
            )
        except Exception as exc:
            try:
                observed = self._get_ledger(str(validated["retirement_id"]))
            except Exception as read_exc:
                raise BrokerError("LEDGER_TRANSITION_UNCERTAIN") from read_exc
            if observed != validated:
                raise BrokerError("LEDGER_TRANSITION_UNCERTAIN") from exc
        return validated

    def _classify(self, identity_proof_sha256: str) -> dict[str, Any]:
        existing = self._get_ledger(self.config.retirement_id)
        if existing is not None:
            if existing["state"] != "CLASSIFIED":
                raise BrokerError("CLASSIFICATION_ALREADY_ADVANCED")
            evidence = self._target_evidence()
            self._require_evidence_matches_ledger(existing, evidence)
            return {
                "status": "CLASSIFIED_ALREADY_RECORDED",
                "ledger_digest": existing["ledger_digest"],
                "next_required_control": existing["next_required_control"],
            }
        evidence = self._target_evidence()
        if evidence.get("retirement_id") != self.config.retirement_id:
            raise BrokerError("RETIREMENT_ID_CHANGED")
        ledger = self._base_ledger(evidence, identity_proof_sha256)
        self._create_ledger(ledger)
        return {
            "status": "CLASSIFIED",
            "ledger_digest": ledger["ledger_digest"],
            "next_required_control": ledger["next_required_control"],
        }

    def _retire(self, identity_proof_sha256: str) -> dict[str, Any]:
        # Read the durable claim before inspecting the live target. Once an
        # attempt exists, a missing Change Set is the expected ambiguous
        # outcome and must never cause a second DeleteChangeSet invocation.
        current = self._get_ledger(self.config.retirement_id)
        if current is None:
            raise BrokerError("CLASSIFICATION_LEDGER_MISSING")
        if current["state"] == "ATTEMPTED":
            return {
                "status": "RECONCILIATION_REQUIRED",
                "ledger_digest": current["ledger_digest"],
                "next_required_control": "READ_ONLY_RECONCILIATION_REQUIRED",
            }
        if current["state"] not in {"CLASSIFIED", "APPROVED"}:
            raise BrokerError("RETIREMENT_STATE_NOT_AUTHORIZED")
        evidence = self._target_evidence()
        self._require_evidence_matches_ledger(current, evidence)
        approved = current
        if current["state"] == "CLASSIFIED":
            approved_at = _timestamp(self.now())
            approval_digest = canonical_digest(
                {
                    "retirement_id": current["retirement_id"],
                    "classification_ledger_digest": current["ledger_digest"],
                    "approver_identity_store_user_id_digest": current[
                        "approver_identity_store_user_id_digest"
                    ],
                    "identity_binding_digest": current["identity_binding_digest"],
                    "approver_identity_proof_sha256": identity_proof_sha256,
                    "decision": "RETIRE_EXACT_UNEXECUTED_CHANGE_SET",
                    "allowed_action": "scanalyze:RetireExactChangeSet",
                    "approved_at": approved_at,
                }
            )
            approved = self._transition(
                current,
                state="APPROVED",
                approval_digest=approval_digest,
                approver_identity_proof_sha256=identity_proof_sha256,
                approved_at=approved_at,
                next_required_control="ONE_SHOT_ATTEMPT_REQUIRED",
            )
        attempted_at = _timestamp(self.now())
        attempt_digest = canonical_digest(
            {
                "retirement_id": approved["retirement_id"],
                "approval_digest": approved["approval_digest"],
                "attempt_count": 1,
                "attempted_at": attempted_at,
            }
        )
        attempted = self._transition(
            approved,
            state="ATTEMPTED",
            attempt_digest=attempt_digest,
            attempted_at=attempted_at,
            next_required_control="READ_ONLY_RECONCILIATION_REQUIRED",
        )
        # Re-read the exact target after the durable one-shot claim. The SDK
        # client is configured with zero retries and this call occurs once.
        final_evidence = self._target_evidence()
        self._require_evidence_matches_ledger(attempted, final_evidence)
        exact_change_set_id = final_evidence.get("_change_set_id")
        exact_stack_id = final_evidence.get("_stack_id")
        if not isinstance(exact_change_set_id, str) or not isinstance(
            exact_stack_id, str
        ):
            raise BrokerError("CHANGE_SET_IDENTITY_CHANGED")
        try:
            self.clients.cloudformation.delete_change_set(
                ChangeSetName=exact_change_set_id,
                StackName=exact_stack_id,
            )
        except Exception:
            return {
                "status": "RECONCILIATION_REQUIRED",
                "ledger_digest": attempted["ledger_digest"],
                "next_required_control": "READ_ONLY_RECONCILIATION_REQUIRED",
            }
        return {
            "status": "RETIREMENT_ATTEMPTED",
            "ledger_digest": attempted["ledger_digest"],
            "next_required_control": "READ_ONLY_RECONCILIATION_REQUIRED",
        }

    def _reconcile(self, identity_proof_sha256: str) -> dict[str, Any]:
        # The durable deployment-bound key is authoritative. Live names or
        # IDs can never select a different ledger record.
        current = self._get_ledger(self.config.retirement_id)
        if current is None or current.get("state") != "ATTEMPTED":
            raise BrokerError("RECONCILIATION_STATE_NOT_AUTHORIZED")
        stack = self._stack()
        stack_id = self._require_reconciliation_stack(current, stack)
        inventory = self._change_set_inventory(stack_id)
        target = [
            item
            for item in inventory
            if item.get("ChangeSetName") == self.config.change_set_name
        ]
        if len(target) > 1 or len(inventory) != len(target):
            raise BrokerError("RECONCILIATION_INVENTORY_AMBIGUOUS")
        if target:
            change_set_id = target[0].get("ChangeSetId")
            if (
                not isinstance(change_set_id, str)
                or secret_digest("change_set_id", change_set_id)
                != current.get("change_set_id_digest")
            ):
                raise BrokerError("RECONCILIATION_INVENTORY_AMBIGUOUS")
            return {
                "status": "RECONCILIATION_REQUIRED",
                "ledger_digest": current["ledger_digest"],
                "next_required_control": "READ_ONLY_RECONCILIATION_REQUIRED",
            }
        pab = self._account_pab()
        verified_at = _timestamp(self.now())
        verification_digest = canonical_digest(
            {
                "retirement_id": current["retirement_id"],
                "attempt_digest": current["attempt_digest"],
                "stack_status": "REVIEW_IN_PROGRESS",
                "stack_resource_count": 0,
                "active_change_set_count": 0,
                "target_absent": True,
                "account_public_access_block": pab,
                "reconciliation_identity_proof_sha256": identity_proof_sha256,
                "verified_at": verified_at,
            }
        )
        # Repeat the exact shell and inventory proof immediately before the
        # terminal CAS. A recreated stack or reappearing Change Set leaves the
        # durable state ATTEMPTED and requires a fresh read-only investigation.
        final_stack = self._stack()
        final_stack_id = self._require_reconciliation_stack(current, final_stack)
        if self._change_set_inventory(final_stack_id) != []:
            raise BrokerError("RECONCILIATION_INVENTORY_AMBIGUOUS")
        next_control = (
            "RETIREMENT_ROLE_REVOCATION_REQUIRED"
            if pab is not None and all(pab.values())
            else "PAB_AND_REVOCATION_REQUIRED"
        )
        reconciled = self._transition(
            current,
            state="RETIRED_RECONCILED",
            verification_digest=verification_digest,
            reconciliation_identity_proof_sha256=identity_proof_sha256,
            verified_at=verified_at,
            effect_attribution="BROKER_SERVICE_PRINCIPAL_AFTER_STS_PROOF",
            next_required_control=next_control,
        )
        return {
            "status": "RETIRED_RECONCILED",
            "ledger_digest": reconciled["ledger_digest"],
            "next_required_control": next_control,
        }


def _alias_from_context(context: object) -> str:
    arn = getattr(context, "invoked_function_arn", None)
    if not isinstance(arn, str):
        raise BrokerError("INVOCATION_CONTEXT_MISSING")
    alias = arn.rsplit(":", 1)[-1]
    if alias not in ALLOWED_ALIASES:
        raise BrokerError("ALIAS_NOT_AUTHORIZED")
    return alias


def handler(event: object, context: object) -> dict[str, Any]:
    """Retained fail-closed shim; the template uses the GUG-217 URL handler."""
    del event, context
    return {"status": "DENY", "reason_code": "DIRECT_ENTRYPOINT_DISABLED"}
