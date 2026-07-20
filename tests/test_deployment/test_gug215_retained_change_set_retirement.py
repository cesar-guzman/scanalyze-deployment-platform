"""GUG-215 AWS-enforced retained Change Set retirement PEP tests."""
from __future__ import annotations

import copy
import importlib.util
import inspect
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import ModuleType, SimpleNamespace
from typing import Any, Mapping

import pytest
import yaml

from tooling.platform_authority_change_set_retirement_broker import (
    ALIAS_CLASSIFY,
    ALIAS_RECONCILE,
    ALIAS_RETIRE,
    APPROVER_INVOKER_POLICY_NAME,
    BROKER_FUNCTION_NAME,
    BROKER_POLICY_NAME,
    CLASSIFIER_INVOKER_POLICY_NAME,
    EXPECTED_LEDGER_TAGS,
    EXPECTED_RESOURCE_CHANGES,
    EXPECTED_TAGS,
    BrokerConfig,
    BrokerError,
    RetirementBroker,
    canonical_digest,
)
from tooling.platform_authority_bootstrap import (
    BootstrapAuthorizationError,
    BootstrapBinding,
    render_bootstrap_iam_policy,
)


REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / "scripts/deployment/platform-authority-change-set-retirement.py"
BROKER_MODULE = REPO_ROOT / "tooling/platform_authority_change_set_retirement_broker.py"
PLAN_POLICY = REPO_ROOT / "policies/iam/platform-authority-bootstrap-plan-role.json"
CLASSIFIER_POLICY = (
    REPO_ROOT
    / "policies/iam/platform-authority-change-set-retirement-classifier-role.json"
)
APPROVER_POLICY = (
    REPO_ROOT / "policies/iam/platform-authority-change-set-retirement-role.json"
)
PEP_TEMPLATE = (
    REPO_ROOT / "bootstrap/cfn-platform-authority-change-set-retirement-ledger.yaml"
)
ACCOUNT = "111122223333"
MANAGEMENT_ACCOUNT = "999900001111"
REGION = "us-east-1"
STACK_NAME = "scanalyze-platform-authority-state-backend"
STACK_ID = (
    f"arn:aws:cloudformation:{REGION}:{ACCOUNT}:stack/{STACK_NAME}/"
    "00000000-0000-4000-8000-000000000001"
)
CHANGE_SET_NAME = "scanalyze-platform-authority-bootstrap-20300101000000"
CHANGE_SET_ID = (
    f"arn:aws:cloudformation:{REGION}:{ACCOUNT}:changeSet/{CHANGE_SET_NAME}/"
    "00000000-0000-4000-8000-000000000002"
)
REPLACEMENT_STACK_ID = STACK_ID.rsplit("/", 1)[0] + "/00000000-0000-4000-8000-000000000003"
REPLACEMENT_CHANGE_SET_ID = (
    CHANGE_SET_ID.rsplit("/", 1)[0] + "/00000000-0000-4000-8000-000000000004"
)
RETIREMENT_ID = "gug215#sha256:" + __import__("hashlib").sha256(
    CHANGE_SET_ID.encode("utf-8")
).hexdigest()
CLASSIFIER_USER_ID = "00000000-0000-4000-8000-000000000011"
APPROVER_USER_ID = "00000000-0000-4000-8000-000000000022"
IDENTITY_STORE_ARN = (
    f"arn:aws:identitystore::{MANAGEMENT_ACCOUNT}:identitystore/d-1234567890"
)
INSTANCE_ARN = "arn:aws:sso:::instance/ssoins-1234567890abcdef"
APPLICATION_ARN = (
    f"arn:aws:sso::{MANAGEMENT_ACCOUNT}:application/"
    "ssoins-1234567890abcdef/apl-1234567890abcdef"
)
CLASSIFIER_ROLE = "ScanalyzeGug215ClassifierInvoker"
APPROVER_ROLE = "ScanalyzeGug215ApproverInvoker"
EXECUTION_ROLE = "ScanalyzeGug215BrokerExecution"
CLASSIFIER_PERMISSION_SET_ROLE_ARN = (
    f"arn:aws:iam::{ACCOUNT}:role/aws-reserved/sso.amazonaws.com/"
    "AWSReservedSSO_ScanalyzeAuthorityRetireClass_0123456789abcdef"
)
APPROVER_PERMISSION_SET_ROLE_ARN = (
    f"arn:aws:iam::{ACCOUNT}:role/aws-reserved/sso.amazonaws.com/"
    "AWSReservedSSO_ScanalyzeAuthorityRetireApprove_fedcba9876543210"
)
CODE_SHA256 = "A" * 43 + "="
LEDGER_KMS_KEY_ARN = (
    f"arn:aws:kms:{REGION}:{ACCOUNT}:key/00000000-0000-4000-8000-000000000099"
)
NOW = datetime(2030, 1, 1, tzinfo=UTC)
TEMPLATE_BODY = "synthetic-reviewed-template"
TEMPLATE_SHA256 = "sha256:" + __import__("hashlib").sha256(
    TEMPLATE_BODY.encode("utf-8")
).hexdigest()
PARAMETERS = {
    "AuthorityAccountId": ACCOUNT,
    "NoncurrentVersionRetentionDays": "365",
    "StateKey": "platform-authority/terraform.tfstate",
}
EVIDENCE_SHA256 = canonical_digest(
    {
        "resource_changes": [list(item) for item in EXPECTED_RESOURCE_CHANGES],
        "tags": EXPECTED_TAGS,
        "parameters": PARAMETERS,
        "capabilities": [],
    }
)
BROKER_POLICY = {
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Action": "synthetic:Exact", "Resource": "*"}],
}
BROKER_POLICY_SHA256 = canonical_digest(BROKER_POLICY)
CLASSIFIER_INVOKER_POLICY = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": "lambda:InvokeFunction",
            "Resource": "arn:aws:lambda:us-east-1:111122223333:function:synthetic:classify",
        }
    ],
}
APPROVER_INVOKER_POLICY = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": "lambda:InvokeFunction",
            "Resource": [
                "arn:aws:lambda:us-east-1:111122223333:function:synthetic:retire",
                "arn:aws:lambda:us-east-1:111122223333:function:synthetic:reconcile",
            ],
        }
    ],
}
ALL_TRUE_PAB = {
    "BlockPublicAcls": True,
    "BlockPublicPolicy": True,
    "IgnorePublicAcls": True,
    "RestrictPublicBuckets": True,
}


def _digest(seed: str) -> str:
    return "sha256:" + __import__("hashlib").sha256(seed.encode("utf-8")).hexdigest()


def _config(**overrides: str) -> BrokerConfig:
    values = {
        "authority_account_id": ACCOUNT,
        "region": REGION,
        "change_set_name": CHANGE_SET_NAME,
        "expected_template_sha256": TEMPLATE_SHA256,
        "expected_evidence_sha256": EVIDENCE_SHA256,
        "expected_code_sha256": CODE_SHA256,
        "expected_broker_policy_sha256": BROKER_POLICY_SHA256,
        "identity_store_arn": IDENTITY_STORE_ARN,
        "identity_center_instance_arn": INSTANCE_ARN,
        "identity_center_application_arn": APPLICATION_ARN,
        "classifier_identity_store_user_id": CLASSIFIER_USER_ID,
        "approver_identity_store_user_id": APPROVER_USER_ID,
        "classifier_assignment_sha256": _digest("classifier-assignment"),
        "approver_assignment_sha256": _digest("approver-assignment"),
        "classifier_invoker_policy_sha256": canonical_digest(
            CLASSIFIER_INVOKER_POLICY
        ),
        "approver_invoker_policy_sha256": canonical_digest(APPROVER_INVOKER_POLICY),
        "classifier_invoker_role_name": CLASSIFIER_ROLE,
        "approver_invoker_role_name": APPROVER_ROLE,
        "classifier_permission_set_role_arn": CLASSIFIER_PERMISSION_SET_ROLE_ARN,
        "approver_permission_set_role_arn": APPROVER_PERMISSION_SET_ROLE_ARN,
        "broker_execution_role_name": EXECUTION_ROLE,
        "code_signing_config_arn": (
            f"arn:aws:lambda:{REGION}:{ACCOUNT}:code-signing-config:csc-1234567890abcdef"
        ),
        "retirement_id": RETIREMENT_ID,
    }
    values.update(overrides)
    return BrokerConfig(**values)


def _load_script() -> ModuleType:
    spec = importlib.util.spec_from_file_location("gug215_retirement_cli", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class FakeIam:
    def __init__(self, log: list[str], config: BrokerConfig) -> None:
        self.log = log
        self.config = config
        self.policy_document: Mapping[str, Any] = BROKER_POLICY
        self.trust: Mapping[str, Any] = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "lambda.amazonaws.com"},
                    "Action": "sts:AssumeRole",
                }
            ],
        }
        self.inline_names = [BROKER_POLICY_NAME]
        self.attached: list[dict[str, str]] = []
        self.boundary: object = None
        self.classifier_trust_override: Mapping[str, Any] | None = None
        self.approver_trust_override: Mapping[str, Any] | None = None
        self.classifier_policy_document: Mapping[str, Any] = CLASSIFIER_INVOKER_POLICY
        self.approver_policy_document: Mapping[str, Any] = APPROVER_INVOKER_POLICY
        self.classifier_inline_names = [CLASSIFIER_INVOKER_POLICY_NAME]
        self.approver_inline_names = [APPROVER_INVOKER_POLICY_NAME]

    def _invoker_trust(self, *, classifier: bool) -> dict[str, Any]:
        principal = (
            CLASSIFIER_PERMISSION_SET_ROLE_ARN
            if classifier
            else APPROVER_PERMISSION_SET_ROLE_ARN
        )
        user_id = CLASSIFIER_USER_ID if classifier else APPROVER_USER_ID
        return {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "AssumeFromExactPermissionSet",
                    "Effect": "Allow",
                    "Principal": {"AWS": f"arn:aws:iam::{ACCOUNT}:root"},
                    "Action": "sts:AssumeRole",
                    "Condition": {"ArnEquals": {"aws:PrincipalArn": principal}},
                },
                {
                    "Sid": "SetVerifiedIdentityCenterContext",
                    "Effect": "Allow",
                    "Principal": {"AWS": f"arn:aws:iam::{ACCOUNT}:root"},
                    "Action": "sts:SetContext",
                    "Condition": {
                        "ForAllValues:ArnEquals": {
                            "sts:RequestContextProviders": [
                                "arn:aws:iam::aws:contextProvider/IdentityCenter"
                            ]
                        },
                        "StringEquals": {
                            "sts:RequestContext/identitystore:UserId": user_id
                        },
                        "ArnEquals": {
                            "aws:PrincipalArn": principal,
                            "sts:RequestContext/identitystore:IdentityStoreArn": IDENTITY_STORE_ARN,
                            "sts:RequestContext/identitycenter:InstanceArn": INSTANCE_ARN,
                            "sts:RequestContext/identitycenter:ApplicationArn": APPLICATION_ARN,
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

    def get_role(self, *, RoleName: str) -> dict[str, Any]:
        self.log.append("iam:get-role")
        if RoleName == CLASSIFIER_ROLE:
            trust = self.classifier_trust_override or self._invoker_trust(
                classifier=True
            )
            arn = self.config.classifier_invoker_role_arn
        elif RoleName == APPROVER_ROLE:
            trust = self.approver_trust_override or self._invoker_trust(
                classifier=False
            )
            arn = self.config.approver_invoker_role_arn
        else:
            assert RoleName == EXECUTION_ROLE
            trust = self.trust
            arn = self.config.execution_role_arn
        return {
            "Role": {
                "Arn": arn,
                "AssumeRolePolicyDocument": trust,
                "PermissionsBoundary": self.boundary,
            }
        }

    def list_role_policies(self, *, RoleName: str) -> dict[str, Any]:
        self.log.append("iam:list-role-policies")
        if RoleName == CLASSIFIER_ROLE:
            return {"PolicyNames": self.classifier_inline_names}
        if RoleName == APPROVER_ROLE:
            return {"PolicyNames": self.approver_inline_names}
        assert RoleName == EXECUTION_ROLE
        return {"PolicyNames": self.inline_names}

    def list_attached_role_policies(self, *, RoleName: str) -> dict[str, Any]:
        self.log.append("iam:list-attached-role-policies")
        assert RoleName in {EXECUTION_ROLE, CLASSIFIER_ROLE, APPROVER_ROLE}
        return {"AttachedPolicies": self.attached}

    def get_role_policy(self, *, RoleName: str, PolicyName: str) -> dict[str, Any]:
        self.log.append("iam:get-role-policy")
        if RoleName == CLASSIFIER_ROLE:
            assert PolicyName == CLASSIFIER_INVOKER_POLICY_NAME
            return {"PolicyDocument": self.classifier_policy_document}
        if RoleName == APPROVER_ROLE:
            assert PolicyName == APPROVER_INVOKER_POLICY_NAME
            return {"PolicyDocument": self.approver_policy_document}
        assert RoleName == EXECUTION_ROLE and PolicyName == BROKER_POLICY_NAME
        return {"PolicyDocument": self.policy_document}


class FakeLambda:
    def __init__(self, log: list[str], config: BrokerConfig) -> None:
        self.log = log
        self.config = config
        self.code_sha256 = CODE_SHA256
        self.role_arn = config.execution_role_arn
        self.version = "7"
        self.alias_version = "7"
        self.routing_config: dict[str, Any] | None = None
        self.concurrency = 1
        self.signing_arn = config.code_signing_config_arn
        self.resource_policy_qualifiers: set[str | None] = set()

    def get_function_configuration(self, *, FunctionName: str) -> dict[str, Any]:
        self.log.append("lambda:get-function-configuration")
        assert FunctionName.startswith(BROKER_FUNCTION_NAME + ":")
        return {
            "FunctionArn": f"{self.config.function_arn}:{self.version}",
            "Version": self.version,
            "CodeSha256": self.code_sha256,
            "Role": self.role_arn,
        }

    def get_function_concurrency(self, *, FunctionName: str) -> dict[str, Any]:
        self.log.append("lambda:get-function-concurrency")
        assert FunctionName == BROKER_FUNCTION_NAME
        return {"ReservedConcurrentExecutions": self.concurrency}

    def get_alias(self, *, FunctionName: str, Name: str) -> dict[str, Any]:
        self.log.append("lambda:get-alias")
        assert FunctionName == BROKER_FUNCTION_NAME
        assert Name in {ALIAS_CLASSIFY, ALIAS_RETIRE, ALIAS_RECONCILE}
        response: dict[str, Any] = {"FunctionVersion": self.alias_version}
        if self.routing_config is not None:
            response["RoutingConfig"] = self.routing_config
        return response

    def get_function_code_signing_config(self, *, FunctionName: str) -> dict[str, Any]:
        self.log.append("lambda:get-code-signing")
        assert FunctionName == BROKER_FUNCTION_NAME
        return {"CodeSigningConfigArn": self.signing_arn}

    def get_policy(
        self, *, FunctionName: str, Qualifier: str | None = None
    ) -> dict[str, Any]:
        self.log.append("lambda:get-policy")
        assert FunctionName == BROKER_FUNCTION_NAME
        assert Qualifier in {
            None,
            ALIAS_CLASSIFY,
            ALIAS_RETIRE,
            ALIAS_RECONCILE,
            self.version,
        }
        if Qualifier in self.resource_policy_qualifiers:
            return {
                "Policy": json.dumps(
                    {
                        "Version": "2012-10-17",
                        "Statement": [{"Effect": "Allow", "Principal": "*"}],
                    }
                )
            }
        error = RuntimeError("synthetic resource policy not found")
        error.response = {  # type: ignore[attr-defined]
            "Error": {"Code": "ResourceNotFoundException"}
        }
        raise error


class FakeDynamoDb:
    def __init__(self, log: list[str], config: BrokerConfig) -> None:
        self.log = log
        self.config = config
        self.ledger: dict[str, Any] | None = None
        self.write_count = 0
        self.resource_policy: dict[str, Any] = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "DenyWritesOutsideRetirementBroker",
                    "Effect": "Deny",
                    "Principal": {"AWS": "*"},
                    "Action": [
                        "dynamodb:BatchWriteItem",
                        "dynamodb:DeleteItem",
                        "dynamodb:PartiQLDelete",
                        "dynamodb:PartiQLInsert",
                        "dynamodb:PartiQLUpdate",
                        "dynamodb:PutItem",
                        "dynamodb:TransactWriteItems",
                        "dynamodb:UpdateItem",
                    ],
                    "Resource": config.table_arn,
                    "Condition": {
                        "ArnNotEquals": {
                            "aws:PrincipalArn": config.execution_role_arn
                        }
                    },
                }
            ],
        }
        self.table_overrides: dict[str, Any] = {}
        self.pitr_enabled = True
        self.raise_after_put_commit = False
        self.raise_after_update_states: set[str] = set()

    def describe_table(self, *, TableName: str) -> dict[str, Any]:
        self.log.append("ddb:describe-table")
        table = {
            "TableStatus": "ACTIVE",
            "TableArn": self.config.table_arn,
            "KeySchema": [{"AttributeName": "retirement_id", "KeyType": "HASH"}],
            "DeletionProtectionEnabled": True,
            "SSEDescription": {
                "Status": "ENABLED",
                "SSEType": "KMS",
                "KMSMasterKeyArn": LEDGER_KMS_KEY_ARN,
            },
            "BillingModeSummary": {"BillingMode": "PAY_PER_REQUEST"},
            "Replicas": [],
        }
        table.update(self.table_overrides)
        return {"Table": table}

    def describe_continuous_backups(self, *, TableName: str) -> dict[str, Any]:
        self.log.append("ddb:describe-continuous-backups")
        return {
            "ContinuousBackupsDescription": {
                "ContinuousBackupsStatus": "ENABLED" if self.pitr_enabled else "DISABLED",
                "PointInTimeRecoveryDescription": {
                    "PointInTimeRecoveryStatus": "ENABLED" if self.pitr_enabled else "DISABLED",
                    "RecoveryPeriodInDays": 35,
                },
            }
        }

    def list_tags_of_resource(self, *, ResourceArn: str) -> dict[str, Any]:
        self.log.append("ddb:list-tags")
        tags = {
            **EXPECTED_LEDGER_TAGS,
            "account_id": ACCOUNT,
            "region": REGION,
        }
        return {"Tags": [{"Key": key, "Value": value} for key, value in tags.items()]}

    def get_resource_policy(self, *, ResourceArn: str) -> dict[str, Any]:
        self.log.append("ddb:get-resource-policy")
        return {"Policy": json.dumps(self.resource_policy)}

    def get_item(self, **kwargs: Any) -> dict[str, Any]:
        self.log.append("ddb:get-item")
        assert kwargs["ConsistentRead"] is True
        if self.ledger is None:
            return {}
        return {
            "Item": {
                "document": {
                    "S": json.dumps(self.ledger, sort_keys=True, separators=(",", ":"))
                }
            }
        }

    def put_item(self, **kwargs: Any) -> dict[str, Any]:
        self.log.append("ddb:put-item")
        assert kwargs["ConditionExpression"] == "attribute_not_exists(retirement_id)"
        assert self.ledger is None
        self.ledger = json.loads(kwargs["Item"]["document"]["S"])
        self.write_count += 1
        if self.raise_after_put_commit:
            raise RuntimeError("synthetic response loss after put commit")
        return {}

    def update_item(self, **kwargs: Any) -> dict[str, Any]:
        self.log.append("ddb:update-item")
        assert self.ledger is not None
        assert "#ledger_digest = :expected_ledger_digest" in kwargs["ConditionExpression"]
        values = kwargs["ExpressionAttributeValues"]
        assert values[":expected_state"]["S"] == self.ledger["state"]
        assert int(values[":expected_version"]["N"]) == self.ledger["version"]
        assert values[":expected_ledger_digest"]["S"] == self.ledger["ledger_digest"]
        self.ledger = json.loads(values[":document"]["S"])
        self.write_count += 1
        if self.ledger["state"] in self.raise_after_update_states:
            self.raise_after_update_states.remove(self.ledger["state"])
            raise RuntimeError("synthetic response loss after update commit")
        return {}


class FakeCloudFormation:
    def __init__(self, log: list[str]) -> None:
        self.log = log
        self.stack_id = STACK_ID
        self.change_set_id = CHANGE_SET_ID
        self.target_present = True
        self.foreign_target = False
        self.delete_calls = 0
        self.delete_error = False
        self.describe_stack_calls = 0
        self.list_change_set_calls = 0
        self.replace_stack_on_describe_call: int | None = None
        self.replace_change_set_on_list_call: int | None = None
        self.capabilities: list[str] = []
        self.resource_changes = list(EXPECTED_RESOURCE_CHANGES)
        self.template_body = TEMPLATE_BODY

    def describe_stacks(self, **kwargs: Any) -> dict[str, Any]:
        self.log.append("cfn:describe-stacks")
        assert kwargs == {"StackName": STACK_NAME}
        self.describe_stack_calls += 1
        if self.describe_stack_calls == self.replace_stack_on_describe_call:
            self.stack_id = REPLACEMENT_STACK_ID
        return {
            "Stacks": [
                {
                    "StackName": STACK_NAME,
                    "StackId": self.stack_id,
                    "StackStatus": "REVIEW_IN_PROGRESS",
                    "NotificationARNs": [],
                }
            ]
        }

    def list_stack_resources(self, **kwargs: Any) -> dict[str, Any]:
        self.log.append("cfn:list-stack-resources")
        assert kwargs == {"StackName": self.stack_id}
        return {"StackResourceSummaries": []}

    def list_change_sets(self, **kwargs: Any) -> dict[str, Any]:
        self.log.append("cfn:list-change-sets")
        assert kwargs == {"StackName": self.stack_id}
        self.list_change_set_calls += 1
        if self.list_change_set_calls == self.replace_change_set_on_list_call:
            self.change_set_id = REPLACEMENT_CHANGE_SET_ID
        summaries: list[dict[str, Any]] = []
        if self.target_present:
            summaries.append(
                {
                    "ChangeSetName": CHANGE_SET_NAME,
                    "ChangeSetId": self.change_set_id,
                    "Status": "CREATE_COMPLETE",
                    "ExecutionStatus": "AVAILABLE",
                }
            )
        if self.foreign_target:
            summaries.append(
                {
                    "ChangeSetName": "foreign",
                    "ChangeSetId": self.change_set_id.replace(
                        CHANGE_SET_NAME, "foreign"
                    ),
                    "Status": "CREATE_COMPLETE",
                    "ExecutionStatus": "AVAILABLE",
                }
            )
        return {"Summaries": summaries}

    def describe_change_set(self, **kwargs: Any) -> dict[str, Any]:
        self.log.append("cfn:describe-change-set")
        assert kwargs == {
            "ChangeSetName": self.change_set_id,
            "StackName": self.stack_id,
        }
        changes = []
        for logical_id, resource_type, action, replacement in self.resource_changes:
            changes.append(
                {
                    "Type": "Resource",
                    "ResourceChange": {
                        "LogicalResourceId": logical_id,
                        "ResourceType": resource_type,
                        "Action": action,
                        "Replacement": replacement,
                    },
                }
            )
        return {
            "ChangeSetName": CHANGE_SET_NAME,
            "ChangeSetId": self.change_set_id,
            "StackName": STACK_NAME,
            "StackId": self.stack_id,
            "Status": "CREATE_COMPLETE",
            "ExecutionStatus": "AVAILABLE",
            "ChangeSetType": "CREATE",
            "Capabilities": self.capabilities,
            "NotificationARNs": [],
            "IncludeNestedStacks": False,
            "Tags": [{"Key": key, "Value": value} for key, value in EXPECTED_TAGS.items()],
            "Parameters": [
                {"ParameterKey": key, "ParameterValue": value}
                for key, value in PARAMETERS.items()
            ],
            "Changes": changes,
        }

    def get_template(self, **kwargs: Any) -> dict[str, Any]:
        self.log.append("cfn:get-template")
        assert kwargs == {
            "ChangeSetName": self.change_set_id,
            "StackName": self.stack_id,
            "TemplateStage": "Original",
        }
        return {"TemplateBody": self.template_body}

    def delete_change_set(self, **kwargs: Any) -> dict[str, Any]:
        self.log.append("cfn:delete-change-set")
        assert kwargs == {
            "ChangeSetName": self.change_set_id,
            "StackName": self.stack_id,
        }
        self.delete_calls += 1
        if self.delete_error:
            raise RuntimeError("synthetic ambiguous result")
        self.target_present = False
        return {}


class FakeS3Control:
    def __init__(self, log: list[str]) -> None:
        self.log = log
        self.pab = dict(ALL_TRUE_PAB)

    def get_public_access_block(self, **kwargs: Any) -> dict[str, Any]:
        self.log.append("s3control:get-public-access-block")
        return {"PublicAccessBlockConfiguration": self.pab}


class FakeKms:
    def __init__(self, log: list[str]) -> None:
        self.log = log
        self.overrides: dict[str, Any] = {}

    def describe_key(self, *, KeyId: str) -> dict[str, Any]:
        self.log.append("kms:describe-key")
        assert KeyId == LEDGER_KMS_KEY_ARN
        metadata = {
            "Arn": LEDGER_KMS_KEY_ARN,
            "AWSAccountId": ACCOUNT,
            "Enabled": True,
            "KeyManager": "AWS",
            "KeyState": "Enabled",
            "KeyUsage": "ENCRYPT_DECRYPT",
            "Origin": "AWS_KMS",
            "MultiRegion": False,
        }
        metadata.update(self.overrides)
        return {"KeyMetadata": metadata}


class FakeClients:
    def __init__(self, config: BrokerConfig | None = None) -> None:
        self.config = config or _config()
        self.log: list[str] = []
        self.iam = FakeIam(self.log, self.config)
        self.lambda_client = FakeLambda(self.log, self.config)
        self.dynamodb = FakeDynamoDb(self.log, self.config)
        self.kms = FakeKms(self.log)
        self.cloudformation = FakeCloudFormation(self.log)
        self.s3control = FakeS3Control(self.log)


def _broker(
    clients: FakeClients | None = None,
    *,
    config: BrokerConfig | None = None,
) -> tuple[RetirementBroker, FakeClients]:
    resolved_config = config or _config()
    resolved_clients = clients or FakeClients(resolved_config)
    ticks = iter(NOW + timedelta(seconds=index) for index in range(100))
    return (
        RetirementBroker(
            config=resolved_config,
            clients=resolved_clients,
            now=lambda: next(ticks),
        ),
        resolved_clients,
    )


def test_config_requires_two_distinct_immutable_identity_store_users() -> None:
    with pytest.raises(BrokerError, match="INDEPENDENT_OPERATOR_REQUIRED"):
        _config(approver_identity_store_user_id=CLASSIFIER_USER_ID)
    config = _config()
    assert config.identity_binding[
        "classifier_identity_store_user_id_digest"
    ] != config.identity_binding["approver_identity_store_user_id_digest"]
    assert config.identity_binding_digest.startswith("sha256:")
    assert CLASSIFIER_USER_ID not in json.dumps(config.identity_binding)
    assert APPROVER_USER_ID not in json.dumps(config.identity_binding)


def test_identity_store_user_id_contract_accepts_new_uuid_versions() -> None:
    config = _config(
        classifier_identity_store_user_id="00000000-0000-7000-8000-000000000011"
    )
    assert config.classifier_identity_store_user_id.endswith("0011")


@pytest.mark.parametrize(
    ("field", "value", "code"),
    (
        ("authority_account_id", "000000000000", "ACCOUNT_BINDING_INVALID"),
        ("region", "us-east-1;rm", "REGION_BINDING_INVALID"),
        ("change_set_name", "request-selected", "CHANGE_SET_BINDING_INVALID"),
        ("retirement_id", "gug215#request", "RETIREMENT_ID_INVALID"),
        ("expected_code_sha256", "sha256:" + "a" * 64, "CODE_DIGEST_INVALID"),
        (
            "classifier_permission_set_role_arn",
            f"arn:aws:iam::{ACCOUNT}:role/Foreign",
            "PERMISSION_SET_ROLE_BINDING_INVALID",
        ),
    ),
)
def test_config_rejects_malformed_or_request_selected_bindings(
    field: str, value: str, code: str
) -> None:
    with pytest.raises(BrokerError, match=code):
        _config(**{field: value})


def test_broker_rejects_payload_identity_locator_or_action() -> None:
    broker, clients = _broker()
    for payload in (
        {"operation": "retire"},
        {"change_set_name": CHANGE_SET_NAME},
        {"identity_store_user_id": CLASSIFIER_USER_ID},
        {"retirement_id": RETIREMENT_ID},
    ):
        with pytest.raises(BrokerError, match="REQUEST_AUTHORITY_FORBIDDEN"):
            broker.handle(alias=ALIAS_CLASSIFY, event=payload)
    assert clients.cloudformation.delete_calls == 0
    assert clients.dynamodb.write_count == 0


def test_classification_requires_configured_retirement_id_to_match_live_target() -> None:
    config = _config(retirement_id="gug215#sha256:" + "f" * 64)
    broker, clients = _broker(config=config)
    with pytest.raises(BrokerError, match="RETIREMENT_ID_CHANGED"):
        broker.handle(alias=ALIAS_CLASSIFY, event={})
    assert clients.dynamodb.write_count == 0


def test_human_permission_sets_have_no_delete_or_ledger_write_allow() -> None:
    for path, expected_role in (
        (CLASSIFIER_POLICY, CLASSIFIER_ROLE),
        (APPROVER_POLICY, APPROVER_ROLE),
    ):
        policy = json.loads(path.read_text(encoding="utf-8"))
        allows: set[str] = set()
        denies: set[str] = set()
        for statement in policy["Statement"]:
            actions = statement["Action"]
            actions = [actions] if isinstance(actions, str) else actions
            (allows if statement["Effect"] == "Allow" else denies).update(actions)
        assert allows == {
            "sso-oauth:CreateTokenWithIAM",
            "sts:AssumeRole",
            "sts:SetContext",
        }
        assert "cloudformation:DeleteChangeSet" in denies
        assert "dynamodb:PutItem" in denies
        assert "dynamodb:UpdateItem" in denies
        assume_statement = next(
            statement
            for statement in policy["Statement"]
            if statement["Sid"].startswith("AssumeExactIdentityEnhanced")
        )
        assert expected_role in assume_statement["Resource"]


def test_normal_plan_cannot_delete_or_write_retirement_ledger() -> None:
    policy = json.loads(PLAN_POLICY.read_text(encoding="utf-8"))
    allowed: set[str] = set()
    denied: set[str] = set()
    for statement in policy["Statement"]:
        actions = statement["Action"]
        actions = [actions] if isinstance(actions, str) else actions
        (allowed if statement["Effect"] == "Allow" else denied).update(actions)
    assert "cloudformation:DeleteChangeSet" not in allowed
    assert "dynamodb:PutItem" not in allowed
    assert "dynamodb:UpdateItem" not in allowed
    assert {"cloudformation:DeleteChangeSet", "dynamodb:PutItem", "dynamodb:UpdateItem"} <= denied


def test_bootstrap_policy_validator_rejects_reintroduced_direct_delete() -> None:
    binding = BootstrapBinding(
        authority_account_id=ACCOUNT,
        region=REGION,
        stack_name=STACK_NAME,
        state_bucket_name=f"scanalyze-platform-authority-{ACCOUNT}-{REGION}-state",
        state_key="platform-authority/terraform.tfstate",
        destination_account_ids=("444455556666",),
    )
    template = json.loads(PLAN_POLICY.read_text(encoding="utf-8"))
    render_bootstrap_iam_policy(
        policy_template=template,
        binding=binding,
        change_set_name=CHANGE_SET_NAME,
    )
    tampered = copy.deepcopy(template)
    tampered["Statement"].append(
        {
            "Sid": "BypassBroker",
            "Effect": "Allow",
            "Action": "cloudformation:DeleteChangeSet",
            "Resource": "*",
        }
    )
    with pytest.raises(BootstrapAuthorizationError):
        render_bootstrap_iam_policy(
            policy_template=tampered,
            binding=binding,
            change_set_name=CHANGE_SET_NAME,
        )


def test_pep_template_has_one_non_human_delete_writer_and_identity_context() -> None:
    source = PEP_TEMPLATE.read_text(encoding="utf-8")
    assert yaml.compose(source) is not None
    assert source.count("Type: AWS::DynamoDB::Table") == 1
    assert source.count("Type: AWS::Lambda::Function") == 1
    assert source.count("Type: AWS::Lambda::Version") == 1
    assert source.count("Type: AWS::Lambda::Alias") == 3
    assert "CodeSha256: !Ref BrokerArtifactCodeSha256" in source
    assert "ReservedConcurrentExecutions: 1" in source
    assert "lambda:GetPolicy" in source
    assert "DenyWritesOutsideRetirementBroker" in source
    assert "dynamodb:LeadingKeys: 'false'" in source
    assert "aws:PrincipalArn: !Sub arn:${AWS::Partition}:iam::${AuthorityAccountId}:role/ScanalyzeGug215BrokerExecution" in source
    assert "sts:RequestContext/identitystore:UserId" in source
    assert "identitystore:IdentityStoreArn" in source
    assert "identitycenter:ApplicationArn" in source
    assert "sts:RequestContextProviders" in source
    assert "arn:aws:iam::aws:contextProvider/IdentityCenter" in source
    assert "IfExists" not in source
    assert "dynamodb:PartiQLBatchWrite" not in source
    assert "dynamodb:ExecuteStatement" not in source
    assert "dynamodb:ExecuteTransaction" not in source
    assert "!GetAtt ChangeSetRetirementLedger.Arn" not in source
    assert "IndependentOperatorsRequired" in source
    execution_section = source[
        source.index("RetirementBrokerExecutionRole:") : source.index(
            "RetirementBrokerFunction:"
        )
    ]
    assert execution_section.count("cloudformation:DeleteChangeSet") == 1
    classifier_section = source[
        source.index("ClassifierInvokerRole:") : source.index("ApproverInvokerRole:")
    ]
    approver_section = source[source.index("ApproverInvokerRole:") :]
    assert "Effect: Allow\n                Action: cloudformation:DeleteChangeSet" not in classifier_section
    assert "Effect: Allow\n                Action: cloudformation:DeleteChangeSet" not in approver_section


def test_classification_is_service_owned_create_only_and_sanitized() -> None:
    broker, clients = _broker()
    response = broker.handle(alias=ALIAS_CLASSIFY, event={})
    assert response["status"] == "CLASSIFIED"
    assert response["next_required_control"] == "INDEPENDENT_APPROVAL_REQUIRED"
    assert clients.dynamodb.write_count == 1
    assert clients.dynamodb.ledger is not None
    ledger = clients.dynamodb.ledger
    assert "_change_set_id" not in ledger
    assert "_stack_id" not in ledger
    assert CHANGE_SET_ID not in json.dumps(ledger)
    assert STACK_ID not in json.dumps(ledger)
    assert ledger["state"] == "CLASSIFIED"
    assert ledger["version"] == 1
    assert ledger["attempt_count"] == 0
    assert ledger["identity_separation"] == "VERIFIED_DISTINCT_IDENTITYSTORE_USERS"
    serialized = json.dumps(response)
    assert ACCOUNT not in serialized
    assert CHANGE_SET_NAME not in serialized
    assert CLASSIFIER_USER_ID not in serialized
    assert APPROVER_USER_ID not in serialized


def test_create_and_transition_response_loss_are_reconciled_by_exact_readback() -> None:
    clients = FakeClients(_config())
    clients.dynamodb.raise_after_put_commit = True
    clients.dynamodb.raise_after_update_states = {"APPROVED", "ATTEMPTED"}
    broker, _ = _broker(clients)
    classified = broker.handle(alias=ALIAS_CLASSIFY, event={})
    retired = broker.handle(alias=ALIAS_RETIRE, event={})
    assert classified["status"] == "CLASSIFIED"
    assert retired["status"] == "RETIREMENT_ATTEMPTED"
    assert clients.dynamodb.ledger is not None
    assert clients.dynamodb.ledger["state"] == "ATTEMPTED"
    assert clients.cloudformation.delete_calls == 1


@pytest.mark.parametrize(
    ("field", "value", "code"),
    (
        ("legacy_session_alias", "spoofed", "LEDGER_MALFORMED"),
        ("version", 2, "LEDGER_STATE_INVALID"),
        (
            "classifier_identity_store_user_id_digest",
            _digest("foreign-user"),
            "LEDGER_BINDING_CHANGED",
        ),
    ),
)
def test_ledger_rejects_legacy_identity_fields_and_binding_drift(
    field: str, value: object, code: str
) -> None:
    broker, clients = _broker()
    broker.handle(alias=ALIAS_CLASSIFY, event={})
    assert clients.dynamodb.ledger is not None
    tampered = copy.deepcopy(clients.dynamodb.ledger)
    tampered[field] = value
    tampered.pop("ledger_digest")
    tampered["ledger_digest"] = canonical_digest(tampered)
    with pytest.raises(BrokerError, match=code):
        broker._validate_ledger(tampered)


def test_approved_ledger_is_resumable_without_reapproving() -> None:
    broker, clients = _broker()
    broker.handle(alias=ALIAS_CLASSIFY, event={})
    assert clients.dynamodb.ledger is not None
    current = copy.deepcopy(clients.dynamodb.ledger)
    approved_at = "2030-01-01T00:00:01Z"
    approval_digest = canonical_digest(
        {
            "retirement_id": current["retirement_id"],
            "classification_ledger_digest": current["ledger_digest"],
            "approver_identity_store_user_id_digest": current[
                "approver_identity_store_user_id_digest"
            ],
            "identity_binding_digest": current["identity_binding_digest"],
            "decision": "RETIRE_EXACT_UNEXECUTED_CHANGE_SET",
            "allowed_action": "scanalyze:RetireExactChangeSet",
            "approved_at": approved_at,
        }
    )
    broker._transition(
        current,
        state="APPROVED",
        approval_digest=approval_digest,
        approved_at=approved_at,
        next_required_control="ONE_SHOT_ATTEMPT_REQUIRED",
    )
    response = broker.handle(alias=ALIAS_RETIRE, event={})
    assert response["status"] == "RETIREMENT_ATTEMPTED"
    assert clients.cloudformation.delete_calls == 1


def test_retirement_claims_approval_and_attempt_before_one_exact_delete() -> None:
    broker, clients = _broker()
    broker.handle(alias=ALIAS_CLASSIFY, event={})
    clients.log.clear()
    response = broker.handle(alias=ALIAS_RETIRE, event={})
    assert response["status"] == "RETIREMENT_ATTEMPTED"
    assert clients.cloudformation.delete_calls == 1
    assert clients.dynamodb.ledger is not None
    assert clients.dynamodb.ledger["state"] == "ATTEMPTED"
    assert clients.dynamodb.ledger["attempt_count"] == 1
    assert clients.dynamodb.ledger["version"] == 3
    transition_positions = [
        index for index, call in enumerate(clients.log) if call == "ddb:update-item"
    ]
    delete_position = clients.log.index("cfn:delete-change-set")
    assert len(transition_positions) == 2
    assert transition_positions[0] < transition_positions[1] < delete_position
    assert clients.log[:delete_position].count("cfn:describe-change-set") == 2


def test_change_set_replacement_after_attempt_fails_closed_without_delete() -> None:
    broker, clients = _broker()
    broker.handle(alias=ALIAS_CLASSIFY, event={})
    # Classification is list call one, the pre-claim read is call two, and
    # the post-claim read is call three.
    clients.cloudformation.replace_change_set_on_list_call = 3
    with pytest.raises(BrokerError, match="LIVE_TARGET_CHANGED"):
        broker.handle(alias=ALIAS_RETIRE, event={})
    assert clients.cloudformation.delete_calls == 0
    assert clients.dynamodb.ledger is not None
    assert clients.dynamodb.ledger["state"] == "ATTEMPTED"
    assert clients.dynamodb.ledger["attempt_count"] == 1


def test_replay_after_attempt_never_reissues_delete() -> None:
    broker, clients = _broker()
    broker.handle(alias=ALIAS_CLASSIFY, event={})
    broker.handle(alias=ALIAS_RETIRE, event={})
    assert clients.cloudformation.delete_calls == 1
    response = broker.handle(alias=ALIAS_RETIRE, event={})
    assert response["status"] == "RECONCILIATION_REQUIRED"
    assert clients.cloudformation.delete_calls == 1


def test_ambiguous_delete_leaves_durable_attempt_and_requires_reconcile() -> None:
    broker, clients = _broker()
    broker.handle(alias=ALIAS_CLASSIFY, event={})
    clients.cloudformation.delete_error = True
    response = broker.handle(alias=ALIAS_RETIRE, event={})
    assert response["status"] == "RECONCILIATION_REQUIRED"
    assert clients.dynamodb.ledger is not None
    assert clients.dynamodb.ledger["state"] == "ATTEMPTED"
    assert clients.cloudformation.delete_calls == 1
    second = broker.handle(alias=ALIAS_RETIRE, event={})
    assert second["status"] == "RECONCILIATION_REQUIRED"
    assert clients.cloudformation.delete_calls == 1


def test_reconciliation_is_read_only_on_target_and_never_deletes_again() -> None:
    broker, clients = _broker()
    broker.handle(alias=ALIAS_CLASSIFY, event={})
    broker.handle(alias=ALIAS_RETIRE, event={})
    delete_calls = clients.cloudformation.delete_calls
    response = broker.handle(alias=ALIAS_RECONCILE, event={})
    assert response["status"] == "RETIRED_RECONCILED"
    assert response["next_required_control"] == "RETIREMENT_ROLE_REVOCATION_REQUIRED"
    assert clients.cloudformation.delete_calls == delete_calls
    assert clients.dynamodb.ledger is not None
    assert clients.dynamodb.ledger["state"] == "RETIRED_RECONCILED"
    assert clients.dynamodb.ledger["effect_attribution"] == "UNPROVEN"


def test_reconciliation_with_target_still_present_does_not_mutate_or_delete() -> None:
    broker, clients = _broker()
    broker.handle(alias=ALIAS_CLASSIFY, event={})
    clients.cloudformation.delete_error = True
    broker.handle(alias=ALIAS_RETIRE, event={})
    before_writes = clients.dynamodb.write_count
    before_deletes = clients.cloudformation.delete_calls
    response = broker.handle(alias=ALIAS_RECONCILE, event={})
    assert response["status"] == "RECONCILIATION_REQUIRED"
    assert clients.dynamodb.write_count == before_writes
    assert clients.cloudformation.delete_calls == before_deletes


def test_reconciliation_rejects_foreign_change_sets() -> None:
    broker, clients = _broker()
    broker.handle(alias=ALIAS_CLASSIFY, event={})
    clients.cloudformation.delete_error = True
    broker.handle(alias=ALIAS_RETIRE, event={})
    clients.cloudformation.foreign_target = True
    with pytest.raises(BrokerError, match="RECONCILIATION_INVENTORY_AMBIGUOUS"):
        broker.handle(alias=ALIAS_RECONCILE, event={})
    assert clients.cloudformation.delete_calls == 1


def test_reconciliation_rejects_recreated_stack_shell() -> None:
    broker, clients = _broker()
    broker.handle(alias=ALIAS_CLASSIFY, event={})
    broker.handle(alias=ALIAS_RETIRE, event={})
    clients.cloudformation.stack_id = REPLACEMENT_STACK_ID
    with pytest.raises(BrokerError, match="RECONCILIATION_SHELL_CHANGED"):
        broker.handle(alias=ALIAS_RECONCILE, event={})
    assert clients.dynamodb.ledger is not None
    assert clients.dynamodb.ledger["state"] == "ATTEMPTED"
    assert clients.cloudformation.delete_calls == 1


def test_reconciliation_revalidates_stack_continuity_before_terminal_cas() -> None:
    broker, clients = _broker()
    broker.handle(alias=ALIAS_CLASSIFY, event={})
    broker.handle(alias=ALIAS_RETIRE, event={})
    # classify + two retire reads consume three stack reads; reconciliation
    # reads the original shell on call four and sees replacement on call five.
    clients.cloudformation.replace_stack_on_describe_call = 5
    with pytest.raises(BrokerError, match="RECONCILIATION_SHELL_CHANGED"):
        broker.handle(alias=ALIAS_RECONCILE, event={})
    assert clients.dynamodb.ledger is not None
    assert clients.dynamodb.ledger["state"] == "ATTEMPTED"
    assert clients.cloudformation.delete_calls == 1


@pytest.mark.parametrize(
    ("mutation", "code"),
    (
        ("policy", "BROKER_ROLE_POLICY_CHANGED"),
        ("trust", "BROKER_ROLE_BOUNDARY_CHANGED"),
        ("attached", "BROKER_ROLE_POLICY_INVENTORY_CHANGED"),
        ("code", "BROKER_CODE_BOUNDARY_CHANGED"),
        ("concurrency", "BROKER_CONCURRENCY_CHANGED"),
        ("alias", "BROKER_ALIAS_CHANGED"),
        ("routing", "BROKER_ALIAS_CHANGED"),
        ("signing", "BROKER_CODE_SIGNING_CHANGED"),
        ("base_resource_policy", "BROKER_RESOURCE_POLICY_CHANGED"),
        ("alias_resource_policy", "BROKER_RESOURCE_POLICY_CHANGED"),
        ("version_resource_policy", "BROKER_RESOURCE_POLICY_CHANGED"),
    ),
)
def test_effective_broker_role_code_alias_and_signing_are_read_back(
    mutation: str, code: str
) -> None:
    config = _config()
    clients = FakeClients(config)
    if mutation == "policy":
        clients.iam.policy_document = {"Version": "2012-10-17", "Statement": []}
    elif mutation == "trust":
        clients.iam.trust = {"Version": "2012-10-17", "Statement": []}
    elif mutation == "attached":
        clients.iam.attached = [{"PolicyName": "Broad", "PolicyArn": "arn:synthetic"}]
    elif mutation == "code":
        clients.lambda_client.code_sha256 = "B" * 43 + "="
    elif mutation == "concurrency":
        clients.lambda_client.concurrency = 2
    elif mutation == "alias":
        clients.lambda_client.alias_version = "8"
    elif mutation == "routing":
        clients.lambda_client.routing_config = {
            "AdditionalVersionWeights": {"8": 0.1}
        }
    elif mutation == "signing":
        clients.lambda_client.signing_arn += "-foreign"
    elif mutation == "base_resource_policy":
        clients.lambda_client.resource_policy_qualifiers = {None}
    elif mutation == "alias_resource_policy":
        clients.lambda_client.resource_policy_qualifiers = {ALIAS_CLASSIFY}
    else:
        clients.lambda_client.resource_policy_qualifiers = {"7"}
    broker, _ = _broker(clients, config=config)
    with pytest.raises(BrokerError, match=code):
        broker.handle(alias=ALIAS_CLASSIFY, event={})
    assert clients.cloudformation.delete_calls == 0
    assert clients.dynamodb.write_count == 0


@pytest.mark.parametrize(
    ("mutation", "code"),
    (
        ("trust", "INVOKER_ROLE_BOUNDARY_CHANGED"),
        ("policy", "INVOKER_ROLE_POLICY_CHANGED"),
        ("inventory", "INVOKER_ROLE_POLICY_INVENTORY_CHANGED"),
    ),
)
def test_effective_invoker_trust_and_policy_are_read_back(
    mutation: str, code: str
) -> None:
    clients = FakeClients(_config())
    if mutation == "trust":
        clients.iam.classifier_trust_override = {
            "Version": "2012-10-17",
            "Statement": [],
        }
    elif mutation == "policy":
        clients.iam.classifier_policy_document = {
            "Version": "2012-10-17",
            "Statement": [],
        }
    else:
        clients.iam.classifier_inline_names.append("Foreign")
    broker, _ = _broker(clients)
    with pytest.raises(BrokerError, match=code):
        broker.handle(alias=ALIAS_CLASSIFY, event={})
    assert clients.dynamodb.write_count == 0
    assert clients.cloudformation.delete_calls == 0


@pytest.mark.parametrize(
    "mutation",
    ("billing", "kms", "kms-manager", "stream", "replica", "pitr", "policy"),
)
def test_ledger_controls_fail_closed_before_any_effect(mutation: str) -> None:
    config = _config()
    clients = FakeClients(config)
    if mutation == "billing":
        clients.dynamodb.table_overrides["BillingModeSummary"] = {"BillingMode": "PROVISIONED"}
    elif mutation == "kms":
        clients.dynamodb.table_overrides["SSEDescription"] = {
            "Status": "ENABLED",
            "SSEType": "KMS",
            "KMSMasterKeyArn": f"arn:aws:kms:{REGION}:{ACCOUNT}:key/foreign",
        }
    elif mutation == "kms-manager":
        clients.kms.overrides["KeyManager"] = "CUSTOMER"
    elif mutation == "stream":
        clients.dynamodb.table_overrides["LatestStreamArn"] = "arn:synthetic"
    elif mutation == "replica":
        clients.dynamodb.table_overrides["Replicas"] = [{"RegionName": "us-west-2"}]
    elif mutation == "pitr":
        clients.dynamodb.pitr_enabled = False
    else:
        clients.dynamodb.resource_policy["Statement"][0]["Principal"] = {"AWS": ACCOUNT}
    broker, _ = _broker(clients, config=config)
    with pytest.raises(BrokerError, match="LEDGER_"):
        broker.handle(alias=ALIAS_CLASSIFY, event={})
    assert clients.cloudformation.delete_calls == 0
    assert clients.dynamodb.write_count == 0


@pytest.mark.parametrize("mutation", ("capability", "resource", "template"))
def test_live_target_drift_blocks_before_ledger_or_delete(mutation: str) -> None:
    clients = FakeClients(_config())
    if mutation == "capability":
        clients.cloudformation.capabilities = ["CAPABILITY_IAM"]
    elif mutation == "resource":
        clients.cloudformation.resource_changes = list(EXPECTED_RESOURCE_CHANGES[:-1])
    else:
        clients.cloudformation.template_body = "changed"
    broker, _ = _broker(clients)
    with pytest.raises(BrokerError):
        broker.handle(alias=ALIAS_CLASSIFY, event={})
    assert clients.dynamodb.write_count == 0
    assert clients.cloudformation.delete_calls == 0


def test_direct_cli_mutation_adapters_are_hard_disabled() -> None:
    module = _load_script()
    client = module.AwsCli(region=REGION)
    assert not hasattr(client, "delete_change_set_once")
    assert not hasattr(client, "mutate_once")
    assert not hasattr(client, "run")
    source = inspect.getsource(module._parser)
    assert "retire-retained" not in source
    assert "approve-retirement" not in source
    assert {"broker-classify", "broker-retire", "broker-reconcile"} <= {
        choice
        for action in module._parser()._subparsers._group_actions
        if action.dest == "command"
        for choice in action.choices
    }
    reconcile = module._parser().parse_args(
        [
            "broker-reconcile",
            "--authority-account-id",
            ACCOUNT,
            "--region",
            REGION,
        ]
    )
    with pytest.raises(Exception, match="--allow-broker-reconciliation"):
        reconcile.handler(reconcile)


def test_broker_source_has_no_logging_and_sdk_has_zero_retries() -> None:
    source = BROKER_MODULE.read_text(encoding="utf-8")
    assert "print(" not in source
    assert "logging." not in source
    assert '"max_attempts": 0' in source
    assert "delete_change_set(" in source
    assert source.count("delete_change_set(") == 1


def test_handler_converts_all_failures_to_sanitized_denials(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = __import__(
        "tooling.platform_authority_change_set_retirement_broker",
        fromlist=["handler"],
    )
    monkeypatch.setattr(
        module.BrokerConfig,
        "from_environment",
        classmethod(lambda cls: (_ for _ in ()).throw(BrokerError("SAFE_DENY"))),
    )
    response = module.handler({}, SimpleNamespace(invoked_function_arn="invalid"))
    assert response == {"status": "DENY", "reason_code": "SAFE_DENY"}


def test_policy_names_and_role_names_fit_identity_center_contracts() -> None:
    assert BROKER_POLICY_NAME == "Gug215ExactRetirement"
    assert CLASSIFIER_INVOKER_POLICY_NAME == "Gug215ClassifierInvokeOnly"
    assert APPROVER_INVOKER_POLICY_NAME == "Gug215ApproverInvokeOnly"
    for name in (
        "ScanalyzeAuthorityRetireClass",
        "ScanalyzeAuthorityRetireApprove",
    ):
        assert len(name) <= 32
