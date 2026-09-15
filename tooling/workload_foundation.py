"""Closed, offline workload-IAM bootstrap documents and receipt verification.

These builders do not authorize AWS activity or attest that resources exist.
The baseline owner installs the reviewed template; terminal roles cannot edit
its trusts or boundaries. Consumers verify actual IAM readback separately.
"""
from __future__ import annotations

from copy import deepcopy
import hashlib
import json
import re


SERVICES = (
    "ingest-api", "ocr-worker", "classifier-worker", "bank-worker",
    "personal-worker", "gov-worker", "postprocess-worker",
)
STAGES = (
    "ingest", "ocr", "classify", "bank-extract", "personal-extract",
    "gov-extract", "validate", "persist", "notify",
)
TUPLE_FIELDS = frozenset({
    "customer_id", "deployment_id", "account_id", "region", "environment", "aws_partition",
})
RECEIPT_FIELDS = TUPLE_FIELDS | {
    "schema_version", "ecs_task_execution_role_arn", "workload_role_arns",
    "workload_boundary_arn", "identity_runtime_boundary_arn", "policy_digests",
    "template_sha256", "contract_digest",
}


def canonical_bytes(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def digest(value: object) -> str:
    return "sha256:" + hashlib.sha256(canonical_bytes(value)).hexdigest()


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def _validate_tuple(identity: dict) -> dict:
    _require(isinstance(identity, dict) and set(identity) == TUPLE_FIELDS, "foundation target fields are invalid")
    patterns = {
        "customer_id": r"cust_[0-9A-HJKMNP-TV-Z]{26}",
        "deployment_id": r"dep_[0-9A-HJKMNP-TV-Z]{26}",
        "account_id": r"(?!000000000000$)[0-9]{12}",
        "region": r"[a-z]{2}(?:-[a-z]+)+-[0-9]+",
    }
    for key, pattern in patterns.items():
        _require(isinstance(identity[key], str) and re.fullmatch(pattern, identity[key]) is not None, "foundation target identity is invalid")
    _require(isinstance(identity["environment"], str) and identity["environment"] in {"sandbox", "dev", "staging", "production"}, "foundation environment is invalid")
    partition = "aws-cn" if identity["region"].startswith("cn-") else "aws-us-gov" if identity["region"].startswith("us-gov-") else "aws"
    _require(identity["aws_partition"] == partition, "foundation partition and region disagree")
    return deepcopy(identity)


def _coordinates(identity: dict) -> dict:
    stem = f"arn:{identity['aws_partition']}:iam::{identity['account_id']}:"
    deployment = identity["deployment_id"]
    return {
        "ecs_task_execution_role_arn": f"{stem}role/{deployment}-ecs-task-execution",
        "workload_role_arns": {f"scanalyze-{service}": f"{stem}role/{deployment}-workload-{service}" for service in SERVICES},
        "workload_boundary_arn": f"{stem}policy/{deployment}-workload-boundary",
        "identity_runtime_boundary_arn": f"{stem}policy/{deployment}-identity-runtime-boundary",
    }


def verify_workload_foundation_receipt(receipt: dict, expected_digest: str, expected_target_tuple: dict) -> dict:
    identity = _validate_tuple(expected_target_tuple)
    _require(isinstance(receipt, dict) and set(receipt) == RECEIPT_FIELDS, "foundation receipt fields are invalid")
    _require(receipt["schema_version"] == "1", "foundation receipt version is unsupported")
    _require(all(receipt[field] == value for field, value in identity.items()), "foundation receipt target mismatch")
    for field, value in _coordinates(identity).items():
        if receipt[field] != value: raise ValueError(f"mismatch for {field}: expected {value}, got {receipt.get(field)}")
    hashes = receipt["policy_digests"]
    _require(isinstance(hashes, dict) and set(hashes) == {"workload", "identity_runtime"}, "foundation policy digests are invalid")
    for value in [*hashes.values(), receipt["template_sha256"], receipt["contract_digest"], expected_digest]:
        _require(isinstance(value, str) and re.fullmatch(r"sha256:[a-f0-9]{64}", value) is not None, "foundation digest format is invalid")
    actual = digest({key: value for key, value in receipt.items() if key != "contract_digest"})
    _require(actual == receipt["contract_digest"] == expected_digest, "foundation receipt external digest mismatch")
    return deepcopy(receipt)


def build_workload_foundation_policy_documents(identity: dict, bedrock_model_arns: list[str], *, sqs_visibility_enabled: bool = True) -> dict:
    identity = _validate_tuple(identity)
    partition, account, region, deployment = (identity[key] for key in ("aws_partition", "account_id", "region", "deployment_id"))
    _require(type(sqs_visibility_enabled) is bool, "foundation visibility selection is invalid")
    _require(isinstance(bedrock_model_arns, list) and len(bedrock_model_arns) <= 4 and all(isinstance(value, str) for value in bedrock_model_arns), "foundation model selection is invalid")
    pattern = rf"arn:{re.escape(partition)}:bedrock:{re.escape(region)}::foundation-model/[A-Za-z0-9][A-Za-z0-9.:-]*"
    _require(len(set(bedrock_model_arns)) == len(bedrock_model_arns) and all(re.fullmatch(pattern, arn) for arn in bedrock_model_arns), "foundation model must be an exact regional foundation model")
    workload = {"Version": "2012-10-17", "Statement": [
        {"Sid": "AllowComputeActions", "Effect": "Allow", "Action": [
            "s3:GetObject", "s3:PutObject", "s3:ListBucket", "sqs:SendMessage",
            "sqs:ReceiveMessage", "sqs:DeleteMessage", "sqs:GetQueueAttributes",
            "dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:UpdateItem", "dynamodb:Query", "dynamodb:Scan",
            "logs:CreateLogStream", "logs:PutLogEvents", "kms:Decrypt", "kms:GenerateDataKey",
            "ssm:GetParameter", "ssm:GetParameters", "ssm:GetParametersByPath", "textract:*",
            "ecr:GetAuthorizationToken", "ecr:BatchGetImage", "ecr:GetDownloadUrlForLayer",
        ], "Resource": "*"},
        {"Sid": "DenyControlPlaneEscalation", "Effect": "Deny", "Action": [
            "iam:CreateRole", "iam:DeleteRole", "iam:AttachRolePolicy", "iam:DetachRolePolicy",
            "iam:PutRolePolicy", "iam:DeleteRolePolicy", "iam:CreatePolicy", "iam:DeletePolicy",
            "iam:UpdateAssumeRolePolicy", "iam:PutRolePermissionsBoundary", "iam:DeleteRolePermissionsBoundary",
            "organizations:*", "account:*",
        ], "Resource": "*"},
    ]}
    if sqs_visibility_enabled:
        workload["Statement"].append({"Sid": "ExtendDeploymentStageVisibility", "Effect": "Allow", "Action": ["sqs:ChangeMessageVisibility"], "Resource": [f"arn:{partition}:sqs:{region}:{account}:{deployment}-{stage}-stage-queue" for stage in STAGES]})
    if bedrock_model_arns:
        workload["Statement"].append({"Sid": "InvokeSelectedRegionalModels", "Effect": "Allow", "Action": ["bedrock:InvokeModel"], "Resource": sorted(bedrock_model_arns)})
    identity_policy = {"Version": "2012-10-17", "Statement": [
        {"Sid": "IdentityTablesOnly", "Effect": "Allow", "Action": ["dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:UpdateItem"], "Resource": f"arn:{partition}:dynamodb:{region}:{account}:table/{deployment}-identity-*"},
        {"Sid": "IdentityControlQueueOnly", "Effect": "Allow", "Action": ["sqs:ChangeMessageVisibility", "sqs:DeleteMessage", "sqs:GetQueueAttributes", "sqs:ReceiveMessage"], "Resource": f"arn:{partition}:sqs:{region}:{account}:{deployment}-identity-*"},
        {"Sid": "IdentityOperationalLogsOnly", "Effect": "Allow", "Action": ["logs:CreateLogStream", "logs:PutLogEvents"], "Resource": f"arn:{partition}:logs:{region}:{account}:log-group:/aws/lambda/{deployment}-identity-*:*"},
        {"Sid": "TaggedDeploymentUserPoolOnly", "Effect": "Allow", "Action": ["cognito-idp:AdminGetUser", "cognito-idp:CreateUserPoolClient", "cognito-idp:DeleteUserPoolClient", "cognito-idp:DescribeUserPoolClient", "cognito-idp:ListUserPoolClients"], "Resource": f"arn:{partition}:cognito-idp:{region}:{account}:userpool/*", "Condition": {"StringEquals": {"aws:ResourceTag/deployment_id": deployment}}},
        {"Sid": "IdentityM2MSecretsOnly", "Effect": "Allow", "Action": ["secretsmanager:CreateSecret", "secretsmanager:DescribeSecret", "secretsmanager:PutSecretValue", "secretsmanager:TagResource"], "Resource": f"arn:{partition}:secretsmanager:{region}:{account}:secret:{deployment}-identity-m2m-*"},
        {"Sid": "TaggedIdentityEncryptionOnly", "Effect": "Allow", "Action": ["kms:Decrypt", "kms:Encrypt", "kms:GenerateDataKey"], "Resource": f"arn:{partition}:kms:{region}:{account}:key/*", "Condition": {"StringEquals": {"aws:ResourceTag/deployment_id": deployment, "aws:ResourceTag/layer": "identity-control-plane"}}},
        {"Sid": "DenyControlPlaneEscalation", "Effect": "Deny", "Action": ["account:*", "iam:*", "organizations:*", "sts:AssumeRole"], "Resource": "*"},
    ]}
    return {"workload": workload, "identity_runtime": identity_policy}


def build_workload_foundation(identity: dict, bedrock_model_arns: list[str], *, sqs_visibility_enabled: bool = True) -> tuple[dict, dict]:
    """Build a fixed CFN template and candidate receipt, without publishing either."""
    identity = _validate_tuple(identity)
    coordinates = _coordinates(identity)
    policies = build_workload_foundation_policy_documents(identity, bedrock_model_arns, sqs_visibility_enabled=sqs_visibility_enabled)
    policy_digests = {key: digest(value) for key, value in policies.items()}
    resources = {}
    for logical, key, name in (
        ("WorkloadBoundary", "workload", "workload-boundary"),
        ("IdentityRuntimeBoundary", "identity_runtime", "identity-runtime-boundary"),
    ):
        resources[logical] = {"Type": "AWS::IAM::ManagedPolicy", "DeletionPolicy": "Retain", "UpdateReplacePolicy": "Retain", "Properties": {"ManagedPolicyName": f"{identity['deployment_id']}-{name}", "PolicyDocument": policies[key]}}
    trust = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"Service": "ecs-tasks.amazonaws.com"}, "Action": "sts:AssumeRole", "Condition": {"StringEquals": {"aws:SourceAccount": identity["account_id"]}}}]}
    for index, service in enumerate(("ecs-task-execution", *SERVICES)):
        name = f"{identity['deployment_id']}-" + (service if index == 0 else f"workload-{service}")
        tags = {"customer_id": identity["customer_id"], "deployment_id": identity["deployment_id"], "layer": "global", "managed_by": "external-account-baseline", "purpose": "ecs-task-execution" if index == 0 else "workload-task-role"}
        if index:
            tags["service"] = service
        properties = {"RoleName": name, "AssumeRolePolicyDocument": deepcopy(trust), "PermissionsBoundary": {"Ref": "WorkloadBoundary"}, "Tags": [{"Key": key, "Value": value} for key, value in sorted(tags.items())]}
        if index == 0:
            properties["ManagedPolicyArns"] = [f"arn:{identity['aws_partition']}:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"]
        resources["ExecutionRole" if index == 0 else "WorkloadRole" + str(index)] = {"Type": "AWS::IAM::Role", "DeletionPolicy": "Retain", "UpdateReplacePolicy": "Retain", "Properties": properties}
    template = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Description": "Fixed deployment workload foundation owned by the external account baseline; no workload execution.",
        "Metadata": {"Scanalyze": {"Contract": "workload-foundation/v1", **identity, "PolicyDigests": policy_digests}},
        "Resources": resources,
        "Outputs": {
            "WorkloadBoundaryArn": {"Value": {"Ref": "WorkloadBoundary"}},
            "IdentityRuntimeBoundaryArn": {"Value": {"Ref": "IdentityRuntimeBoundary"}},
            "EcsTaskExecutionRoleArn": {"Value": {"Fn::GetAtt": ["ExecutionRole", "Arn"]}},
            **{"WorkloadRole" + str(index) + "Arn": {"Value": {"Fn::GetAtt": ["WorkloadRole" + str(index), "Arn"]}} for index, _ in enumerate(SERVICES, start=1)},
        },
    }
    receipt = {"schema_version": "1", **identity, **coordinates, "policy_digests": policy_digests, "template_sha256": "sha256:" + hashlib.sha256(canonical_bytes(template)).hexdigest()}
    receipt["contract_digest"] = digest(receipt)
    return template, receipt
