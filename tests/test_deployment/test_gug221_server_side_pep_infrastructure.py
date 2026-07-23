"""Infrastructure contracts for the GUG-221 server-side repair PEP."""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Iterable

from tooling import platform_authority_lambda_audit_repair_broker_runtime as runtime


REPO_ROOT = Path(__file__).resolve().parents[2]
AUTHORITY_TEMPLATE = (
    REPO_ROOT / "bootstrap/cfn-platform-authority-lambda-audit-repair-pep.yaml"
)
MANAGEMENT_TEMPLATE = (
    REPO_ROOT
    / "bootstrap/cfn-platform-authority-lambda-audit-repair-delegation.yaml"
)
POLICIES = REPO_ROOT / "policies/iam"
PACKAGE_MODULE = (
    REPO_ROOT / "tooling/platform_authority_lambda_audit_repair_package.py"
)

AUTHORITY_ACCOUNT = "042360977644"
MANAGEMENT_ACCOUNT = "839393571433"
REGION = "us-east-1"
MUTATIONS = {
    "sso:CreateAccountAssignment",
    "sso:ProvisionPermissionSet",
    "sso:PutInlinePolicyToPermissionSet",
}
DYNAMODB_WRITES = {
    "dynamodb:BatchWriteItem",
    "dynamodb:DeleteItem",
    "dynamodb:PartiQLDelete",
    "dynamodb:PartiQLInsert",
    "dynamodb:PartiQLUpdate",
    "dynamodb:PutItem",
    "dynamodb:TransactWriteItems",
    "dynamodb:UpdateItem",
}
SSO_READS = {
    "sso:DescribeAccountAssignmentCreationStatus",
    "sso:DescribeAccountAssignmentDeletionStatus",
    "sso:DescribeInstance",
    "sso:DescribePermissionSet",
    "sso:DescribePermissionSetProvisioningStatus",
    "sso:GetInlinePolicyForPermissionSet",
    "sso:GetPermissionsBoundaryForPermissionSet",
    "sso:ListAccountAssignmentCreationStatus",
    "sso:ListAccountAssignmentDeletionStatus",
    "sso:ListAccountAssignments",
    "sso:ListAccountsForProvisionedPermissionSet",
    "sso:ListCustomerManagedPolicyReferencesInPermissionSet",
    "sso:ListManagedPoliciesInPermissionSet",
    "sso:ListPermissionSetProvisioningStatus",
    "sso:ListTagsForResource",
}
UNUSED_READS = {
    "identitystore:GetUserId",
    "sso:ListPermissionSets",
}
PENDING_OPERATION_READS = {
    "sso:DescribeAccountAssignmentCreationStatus",
    "sso:DescribeAccountAssignmentDeletionStatus",
    "sso:DescribePermissionSetProvisioningStatus",
    "sso:ListAccountAssignmentCreationStatus",
    "sso:ListAccountAssignmentDeletionStatus",
    "sso:ListPermissionSetProvisioningStatus",
}
BROKER_ENVIRONMENT = {
    "COLLECTOR_PERMISSION_SET_ARN",
    "COLLECTOR_POLICY_DIGEST",
    "COLLECTOR_SAML_PROVIDER_ARN",
    "EXPECTED_PERMISSION_SET_TAGS_JSON",
    "EXPECTED_BOTO3_VERSION",
    "EXPECTED_BOTOCORE_VERSION",
    "EXPECTED_ARTIFACT_CODE_SHA256",
    "EXPECTED_CODE_SIGNING_CONFIG_ARN",
    "EXPECTED_SIGNING_PROFILE_VERSION_ARN",
    "IDENTITY_CENTER_INSTANCE_ARN",
    "IDENTITY_CENTER_KMS_KEY_ARN",
    "IDENTITY_CENTER_KMS_MODE",
    "IDENTITY_STORE_ID",
    "ORIGINAL_GUG220_LEDGER_DIGEST",
    "PRINCIPAL_ID",
    "REPAIR_INVOKER_POLICY_DIGEST",
    "REPAIR_ID",
    "REPAIR_INVOKER_PERMISSION_SET_ARN",
    "REPAIR_LEDGER_KMS_KEY_ARN",
    "REPAIR_LEDGER_TABLE_NAME",
    "REPAIR_NOT_AFTER",
    "REPAIR_NOT_BEFORE",
    "SOURCE_COMMIT",
}


def _source(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _resource(source: str, name: str) -> str:
    start = source.index(f"  {name}:\n")
    match = re.search(r"(?m)^  [A-Za-z][A-Za-z0-9]+:\n", source[start + 3 :])
    if match is None:
        return source[start:]
    return source[start : start + 3 + match.start()]


def _load_policy(name: str) -> dict[str, Any]:
    return json.loads((POLICIES / name).read_text(encoding="utf-8"))


def _actions(statement: dict[str, Any]) -> set[str]:
    value = statement.get("Action", [])
    if isinstance(value, str):
        return {value}
    return set(value)


def _allow_statements(policy: dict[str, Any]) -> Iterable[dict[str, Any]]:
    return (
        statement
        for statement in policy["Statement"]
        if statement.get("Effect") == "Allow"
    )


def _listed_actions(source: str) -> set[str]:
    return set(re.findall(r"(?m)^\s+- ((?:sso|identitystore|iam|sts|lambda|dynamodb):[^\s]+)$", source))


def _environment_keys(resource: str) -> set[str]:
    match = re.search(
        r"(?m)^      Environment:\n        Variables:\n"
        r"(?P<body>(?:^          [A-Z][A-Z0-9_]+:.*\n)+)",
        resource,
    )
    assert match is not None
    return {
        line.strip().split(":", 1)[0]
        for line in match.group("body").splitlines()
    }


def test_authority_template_is_private_version_pinned_and_async_bounded() -> None:
    source = _source(AUTHORITY_TEMPLATE)
    assert source.count("Type: AWS::Lambda::Function\n") == 3
    assert source.count("Type: AWS::Lambda::Version\n") == 3
    assert source.count("Type: AWS::Lambda::Alias\n") == 3
    assert "Name: plan-v1" in source
    assert "Name: repair-v1" in source
    assert "Name: reconcile-v1" in source
    assert source.count("ReservedConcurrentExecutions: 1") == 3
    assert source.count("CodeSigningConfigArn: !Ref RepairCodeSigningConfig") == 3
    assert source.count("CodeSha256: !Ref") == 3
    assert "AWS::Lambda::Url" not in source
    assert "AWS::Lambda::Permission" not in source
    assert source.count("Type: AWS::Lambda::EventInvokeConfig\n") == 3
    assert source.count("MaximumRetryAttempts: 0") == 3
    assert source.count("MaximumEventAgeInSeconds: 60") == 3
    assert "DestinationConfig:" not in source
    for resource_name, function_ref, qualifier in (
        ("RepairEventInvokeConfig", "RepairFunction", "repair-v1"),
        ("PlanEventInvokeConfig", "PlanFunction", "plan-v1"),
        ("ReconcileEventInvokeConfig", "ReconcileFunction", "reconcile-v1"),
    ):
        config = _resource(source, resource_name)
        assert f"FunctionName: !Ref {function_ref}" in config
        assert f"Qualifier: {qualifier}" in config
        assert "MaximumRetryAttempts: 0" in config
        assert "MaximumEventAgeInSeconds: 60" in config
        assert "DestinationConfig:" not in config
    handlers = {
        "tooling.platform_authority_lambda_audit_repair_broker_runtime.plan_handler",
        "tooling.platform_authority_lambda_audit_repair_broker_runtime.repair_handler",
        "tooling.platform_authority_lambda_audit_repair_broker_runtime.reconcile_handler",
    }
    for handler in handlers:
        assert source.count(f"Handler: {handler}") == 1
    assert "platform_authority_lambda_audit_repair_broker_runtime.read_handler" not in source
    expected_runtime = {
        "PlanFunction": 300,
        "RepairFunction": 600,
        "ReconcileFunction": 300,
    }
    for resource_name, timeout in expected_runtime.items():
        function = _resource(source, resource_name)
        assert f"Timeout: {timeout}" in function
        assert "MemorySize: 1024" in function
    assert "Timeout: 90" not in source
    assert "MemorySize: 256" not in source


def test_authority_template_lambda_descriptions_match_runtime_contract() -> None:
    source = _source(AUTHORITY_TEMPLATE)
    expected = {
        "PlanFunction": runtime.PLAN_FUNCTION_DESCRIPTION,
        "PlanFunctionVersion": runtime.PLAN_FUNCTION_VERSION_DESCRIPTION,
        "RepairFunction": runtime.REPAIR_FUNCTION_DESCRIPTION,
        "RepairFunctionVersion": runtime.REPAIR_FUNCTION_VERSION_DESCRIPTION,
        "ReconcileFunction": runtime.READ_FUNCTION_DESCRIPTION,
        "ReconcileFunctionVersion": runtime.READ_FUNCTION_VERSION_DESCRIPTION,
    }

    for resource_name, description in expected.items():
        assert f"Description: {description}" in _resource(source, resource_name)


def test_all_functions_use_one_reviewed_package_and_guard_managed_sdk_versions() -> None:
    source = _source(AUTHORITY_TEMPLATE)
    signed_job_key_pattern = (
        "AllowedPattern: '^scanalyze/platform-authority/gug-221/signed/"
        "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-"
        "[0-9a-f]{12}\\.zip$'"
    )
    assert source.count(signed_job_key_pattern) == 2
    assert "^scanalyze/platform-authority/gug-221/[A-Za-z0-9._/-]+" not in source
    rule = _resource(source, "BothFunctionsMustUseTheSameReviewedArtifact")
    for pair in (
        "RepairArtifactBucket, !Ref ReconcileArtifactBucket",
        "RepairArtifactKey, !Ref ReconcileArtifactKey",
        "RepairArtifactVersion, !Ref ReconcileArtifactVersion",
        "RepairArtifactCodeSha256, !Ref ReconcileArtifactCodeSha256",
    ):
        assert pair in rule
    plan = _resource(source, "PlanFunction")
    assert "S3Bucket: !Ref ReconcileArtifactBucket" in plan
    assert "S3Key: !Ref ReconcileArtifactKey" in plan
    assert "S3ObjectVersion: !Ref ReconcileArtifactVersion" in plan
    plan_version = _resource(source, "PlanFunctionVersion")
    assert "CodeSha256: !Ref ReconcileArtifactCodeSha256" in plan_version
    assert "ExpectedBoto3Version:" in source
    assert "ExpectedBotocoreVersion:" in source
    assert source.count("EXPECTED_BOTO3_VERSION: !Ref ExpectedBoto3Version") == 3
    assert source.count("EXPECTED_BOTOCORE_VERSION: !Ref ExpectedBotocoreVersion") == 3


def test_authority_environment_exactly_matches_immutable_broker_contract() -> None:
    source = _source(AUTHORITY_TEMPLATE)
    plan = _environment_keys(_resource(source, "PlanFunction"))
    repair = _environment_keys(_resource(source, "RepairFunction"))
    reconcile = _environment_keys(_resource(source, "ReconcileFunction"))

    assert plan == BROKER_ENVIRONMENT
    assert repair == BROKER_ENVIRONMENT | {"PLAN_FUNCTION_VERSION"}
    assert reconcile == BROKER_ENVIRONMENT | {
        "PLAN_FUNCTION_VERSION",
        "REPAIR_FUNCTION_VERSION",
    }
    for forbidden in (
        "AUTHORITY_ACCOUNT_ID",
        "AUTHORITY_REGION",
        "COLLECTOR_ROLE_NAME",
        "EXPECTED_EVENT_JSON",
        "FUNCTION_MODE",
        "FUNCTION_QUALIFIER",
        "MANAGEMENT_ACCOUNT_ID",
        "MUTATION_SERVICE_ROLE_ARN",
        "PRODUCTION_AUTHORIZED",
        "READBACK_SERVICE_ROLE_ARN",
        "REPAIR_EXECUTOR_POLICY_DIGEST",
        "REPAIR_INTENT_SHA256",
        "REPAIR_LEDGER_TABLE",
    ):
        assert forbidden not in plan | repair | reconcile
    assert "AllowedPattern: '^gug221-[a-f0-9]{64}$'" in source
    assert source.count(
        "PLAN_FUNCTION_VERSION: !GetAtt PlanFunctionVersion.Version"
    ) == 2
    assert source.count(
        "REPAIR_FUNCTION_VERSION: !GetAtt RepairFunctionVersion.Version"
    ) == 1


def test_authority_ledger_is_retained_kms_encrypted_and_stage_writer_bound() -> None:
    source = _source(AUTHORITY_TEMPLATE)
    ledger = _resource(source, "RepairLedger")
    assert "Type: AWS::DynamoDB::Table" in ledger
    assert "DeletionPolicy: Retain" in ledger
    assert "UpdateReplacePolicy: Retain" in ledger
    assert "DeletionProtectionEnabled: true" in ledger
    assert "PointInTimeRecoveryEnabled: true" in ledger
    assert "SSEEnabled: true" in ledger
    assert "SSEType: KMS" in ledger
    assert "KMSMasterKeyId: !GetAtt RepairLedgerKey.Arn" in ledger
    assert "Sid: DenyPlanCreationOutsidePlanExecution" in ledger
    assert "Action: dynamodb:PutItem" in ledger
    assert "aws:PrincipalArn: !GetAtt PlanExecutionRole.Arn" in ledger
    assert "Sid: DenyPlanConsumptionOutsideRepairExecution" in ledger
    assert "Action: dynamodb:UpdateItem" in ledger
    assert "aws:PrincipalArn: !GetAtt RepairExecutionRole.Arn" in ledger
    assert "Sid: DenyEveryUnsupportedLedgerMutation" in ledger
    for action in DYNAMODB_WRITES:
        assert action in ledger


def test_authority_plan_repair_and_reconcile_roles_are_strictly_separated() -> None:
    source = _source(AUTHORITY_TEMPLATE)
    plan = _resource(source, "PlanExecutionRole")
    repair = _resource(source, "RepairExecutionRole")
    reconcile = _resource(source, "ReconcileExecutionRole")
    plan_allow = plan[: plan.index("DenyEveryProtectedEffect")]
    repair_allow = repair[: repair.index("DenyDirectIdentityCenterAndRelay")]
    reconcile_allow = reconcile[: reconcile.index("DenyEveryProtectedEffect")]
    plan_actions = _listed_actions(plan_allow)
    repair_actions = _listed_actions(repair_allow)
    reconcile_actions = _listed_actions(reconcile_allow)

    assert {"dynamodb:GetItem", "dynamodb:PutItem"}.issubset(plan_actions)
    assert "dynamodb:UpdateItem" not in plan_actions
    assert {"dynamodb:GetItem", "dynamodb:UpdateItem"}.issubset(repair_actions)
    assert "dynamodb:PutItem" not in repair_actions
    assert not DYNAMODB_WRITES.intersection(reconcile_actions)
    assert "Effect: Allow\n                Action: sso:" not in plan + repair + reconcile
    assert "AssumeExactReadbackServiceRole" in plan
    assert "AssumeExactMutationServiceRole" in repair
    assert "AssumeExactReadbackServiceRole" in reconcile
    assert "sts:SetSourceIdentity" in plan
    assert "sts:SetSourceIdentity" in repair
    assert "sts:SetSourceIdentity" in reconcile
    assert (
        "role/scanalyze/platform-authority/"
        "ScanalyzeLambdaAuditRepairMutationServiceRole"
    ) in repair
    assert (
        "role/scanalyze/platform-authority/"
        "ScanalyzeLambdaAuditRepairReadbackServiceRole"
    ) in reconcile
    inspector_role = (
        "role/scanalyze/platform-authority/"
        "ScanalyzeLambdaAuditRepairAuthorityInspector"
    )
    for role in (plan, repair, reconcile):
        assert "AssumeExactInvocationAuthorityInspector" in role
        assert inspector_role in role
    reviewed_role_prefixes = {
        "role/aws-reserved/sso.amazonaws.com/"
        "AWSReservedSSO_ScanalyzeAuthorityLambdaAudit_*",
        "role/aws-reserved/sso.amazonaws.com/"
        "AWSReservedSSO_ScanalyzeLambdaAuditRepair_*",
    }
    for role_prefix in reviewed_role_prefixes:
        assert role_prefix in plan
        assert role_prefix in repair
        assert role_prefix in reconcile
    assert "CollectorRoleName:" not in source
    assert "Action: iam:ListRoles\n                Resource: '*'" in plan
    assert "Action: iam:ListRoles\n                Resource: '*'" in repair
    assert "Action: iam:ListRoles\n                Resource: '*'" in reconcile
    for action in ("iam:GetRole", "iam:GetRolePolicy", "iam:ListRolePolicies"):
        assert action in plan
        assert action in repair
        assert action in reconcile
    assert "lambda:GetFunctionEventInvokeConfig" in plan
    assert "lambda:GetFunctionEventInvokeConfig" in repair
    assert "lambda:GetFunctionEventInvokeConfig" in reconcile


def test_authority_has_four_exact_roles_and_management_has_two() -> None:
    authority = _source(AUTHORITY_TEMPLATE)
    management = _source(MANAGEMENT_TEMPLATE)
    assert authority.count("Type: AWS::IAM::Role\n") == 4
    assert management.count("Type: AWS::IAM::Role\n") == 2
    for logical_id, role_name in (
        ("PlanExecutionRole", "ScanalyzeLambdaAuditRepairPlan"),
        ("RepairExecutionRole", "ScanalyzeLambdaAuditRepairExecution"),
        ("ReconcileExecutionRole", "ScanalyzeLambdaAuditRepairReconcile"),
        (
            "InvocationAuthorityInspectorRole",
            "ScanalyzeLambdaAuditRepairAuthorityInspector",
        ),
    ):
        role = _resource(authority, logical_id)
        assert f"RoleName: {role_name}" in role
    for logical_id, role_name in (
        ("MutationServiceRole", "ScanalyzeLambdaAuditRepairMutationServiceRole"),
        ("ReadbackServiceRole", "ScanalyzeLambdaAuditRepairReadbackServiceRole"),
    ):
        role = _resource(management, logical_id)
        assert f"RoleName: {role_name}" in role


def test_invocation_authority_inspector_is_read_only_and_exactly_trusted() -> None:
    source = _source(AUTHORITY_TEMPLATE)
    inspector = _resource(source, "InvocationAuthorityInspectorRole")
    assert "Path: /scanalyze/platform-authority/" in inspector
    trust = inspector[: inspector.index("Policies:")]
    for execution_role in (
        "!GetAtt PlanExecutionRole.Arn",
        "!GetAtt RepairExecutionRole.Arn",
        "!GetAtt ReconcileExecutionRole.Arn",
    ):
        assert trust.count(execution_role) == 1
    assert "aws:PrincipalAccount: !Ref AuthorityAccountId" in trust
    assert "Principal:\n              AWS: '*'" not in trust
    assert "sts:AssumeRole" in trust
    assert "sts:SetSourceIdentity" in trust

    policy = _load_policy(
        "platform-authority-lambda-audit-repair-invocation-inspector-role.json"
    )
    allowed = set().union(*map(_actions, _allow_statements(policy)))
    assert "lambda:InvokeFunction" not in allowed
    assert "sts:AssumeRole" not in allowed
    assert not DYNAMODB_WRITES.intersection(allowed)
    assert not MUTATIONS.intersection(allowed)
    assert not any(
        action.startswith(("iam:Create", "iam:Delete", "iam:Put", "iam:Update"))
        for action in allowed
    )
    denied_assume = next(
        statement
        for statement in policy["Statement"]
        if statement["Sid"] == "DenyRoleChaining"
    )
    assert _actions(denied_assume) == {"sts:AssumeRole"}
    assert denied_assume["Resource"] == "*"


def test_delegation_principal_and_kms_inputs_match_runtime_exactness() -> None:
    source = _source(MANAGEMENT_TEMPLATE)
    assert "[0-9a-fA-F]" not in _resource(source, "RepairPrincipalId")
    assert "arn:aws:identitystore:::user/" in _resource(
        source, "RepairPrincipalUserArn"
    )
    kms_rule = _resource(source, "IdentityCenterKmsMustBeExactWhenEnabled")
    assert "!Equals [!Ref UseIdentityCenterCustomerManagedKms, 'false']" in kms_rule
    assert "!Equals [!Ref IdentityCenterKmsKeyArn, '']" in kms_rule
    assert "!Equals [!Ref UseIdentityCenterCustomerManagedKms, 'true']" in kms_rule
    assert "!Not [!Equals [!Ref IdentityCenterKmsKeyArn, '']]" in kms_rule


def test_management_service_role_trust_is_exact_and_not_human_assumable() -> None:
    source = _source(MANAGEMENT_TEMPLATE)
    mutation = _resource(source, "MutationServiceRole")
    readback = _resource(source, "ReadbackServiceRole")
    expected_mutation = (
        "arn:${AWS::Partition}:iam::042360977644:role/"
        "ScanalyzeLambdaAuditRepairExecution"
    )
    expected_readback = (
        "arn:${AWS::Partition}:iam::042360977644:role/"
        "ScanalyzeLambdaAuditRepairReconcile"
    )
    authority_root = "arn:${AWS::Partition}:iam::042360977644:root"
    assert mutation.count(expected_mutation) == 1
    assert readback.count(expected_readback) == 1
    assert mutation.count(authority_root) == 1
    assert readback.count(authority_root) == 1
    assert "Action:\n              - sts:AssumeRole\n              - sts:SetSourceIdentity" in mutation
    assert "Action:\n              - sts:AssumeRole\n              - sts:SetSourceIdentity" in readback
    assert "ArnEquals:\n                aws:PrincipalArn:" in mutation
    assert "ArnEquals:\n                aws:PrincipalArn:" in readback
    assert "Path: /scanalyze/platform-authority/" in mutation
    assert "Path: /scanalyze/platform-authority/" in readback
    assert "AWSReservedSSO_" not in mutation + readback
    assert "Principal:\n              AWS: '*'" not in mutation + readback


def test_management_stack_can_precede_authority_stack_without_weakening_trust() -> None:
    source = _source(MANAGEMENT_TEMPLATE)
    for role_name, exact_role in (
        (
            "MutationServiceRole",
            "ScanalyzeLambdaAuditRepairExecution",
        ),
        (
            "ReadbackServiceRole",
            "ScanalyzeLambdaAuditRepairReconcile",
        ),
    ):
        role = _resource(source, role_name)
        principal = role[role.index("Principal:") : role.index("Action:")]
        condition = role[role.index("Condition:") : role.index("Policies:")]
        assert "arn:${AWS::Partition}:iam::042360977644:root" in principal
        assert exact_role not in principal
        assert exact_role in condition
        assert "aws:PrincipalAccount: '042360977644'" in condition


def test_management_mutation_role_has_exactly_three_sso_mutations() -> None:
    mutation = _resource(_source(MANAGEMENT_TEMPLATE), "MutationServiceRole")
    allowed_prefix = mutation[: mutation.index("DenyEveryOtherIdentityCenterMutation")]
    observed = {
        action
        for action in _listed_actions(allowed_prefix)
        if action.startswith("sso:") and action not in SSO_READS and action != "sso:*"
    }
    assert observed == MUTATIONS
    effect = mutation[mutation.index("PerformOnlyThreeExactRepairMutations") :]
    effect = effect[: effect.index("ReadExactRepairPrincipal")]
    assert "Resource: '*'" not in effect
    assert "!Ref IdentityCenterInstanceArn" in effect
    assert "!Ref AuditPermissionSetArn" in effect
    assert "arn:${AWS::Partition}:sso:::account/${AuthorityAccountId}" in effect


def test_management_readback_covers_collector_and_invoker_permission_sets() -> None:
    source = _source(MANAGEMENT_TEMPLATE)
    for role_name in ("MutationServiceRole", "ReadbackServiceRole"):
        role = _resource(source, role_name)
        reads = role[role.index("ReadExactIdentityCenterObjects") :]
        reads = reads[: reads.index("ListAssignmentsAcrossObservedAccounts")]
        assert "!Ref AuditPermissionSetArn" in reads
        assert "!GetAtt RepairInvokerPermissionSet.PermissionSetArn" in reads
        assert "!Ref IdentityCenterInstanceArn" in reads
        assert "arn:${AWS::Partition}:sso:::account/" not in reads
        assert not UNUSED_READS.intersection(_listed_actions(reads))

        assignments = role[role.index("ListAssignmentsAcrossObservedAccounts") :]
        assignments = assignments[
            : assignments.index("ListExactPendingIdentityCenterOperations")
        ]
        assert "Action: sso:ListAccountAssignments" in assignments
        assert not _listed_actions(assignments)
        assert "!Ref IdentityCenterInstanceArn" in assignments
        assert "!Ref AuditPermissionSetArn" in assignments
        assert "!GetAtt RepairInvokerPermissionSet.PermissionSetArn" in assignments
        assert "arn:${AWS::Partition}:sso:::account/*" in assignments
        assert role.count("arn:${AWS::Partition}:sso:::account/*") == 1

        pending = role[role.index("ListExactPendingIdentityCenterOperations") :]
        pending = pending[: pending.index("ReadExactRepairPrincipal")]
        if role_name == "MutationServiceRole":
            pending = pending[: pending.index("PerformOnlyThreeExactRepairMutations")]
        assert _listed_actions(pending) == PENDING_OPERATION_READS
        assert "Resource: !Ref IdentityCenterInstanceArn" in pending
        assert "!Ref AuditPermissionSetArn" not in pending
        assert "!GetAtt RepairInvokerPermissionSet.PermissionSetArn" not in pending

        if role_name == "MutationServiceRole":
            mutation = role[role.index("PerformOnlyThreeExactRepairMutations") :]
            mutation = mutation[: mutation.index("ReadExactRepairPrincipal")]
            assert "arn:${AWS::Partition}:sso:::account/*" not in mutation
            assert "arn:${AWS::Partition}:sso:::account/${AuthorityAccountId}" in mutation


def test_management_readback_role_has_no_mutation_or_relay_authority() -> None:
    readback = _resource(_source(MANAGEMENT_TEMPLATE), "ReadbackServiceRole")
    allow_prefix = readback[: readback.index("DenyEveryProtectedEffectAndRelay")]
    assert not MUTATIONS.intersection(_listed_actions(allow_prefix))
    assert "Effect: Allow\n                Action: sts:AssumeRole" not in allow_prefix
    assert "Effect: Allow\n                Action: iam:" not in allow_prefix


def test_human_permission_set_can_only_invoke_exact_private_aliases() -> None:
    source = _source(MANAGEMENT_TEMPLATE)
    permission_set = _resource(source, "RepairInvokerPermissionSet")
    assert "Type: AWS::SSO::PermissionSet" in permission_set
    assert "Name: ScanalyzeLambdaAuditRepair" in permission_set
    assert "SessionDuration: PT1H" in permission_set
    allow = permission_set[
        permission_set.index("InvokeOnlyExactPrivatePepAliases") :
        permission_set.index("DenyEveryOtherLambdaInvocation")
    ]
    assert allow.count("lambda:InvokeFunction") == 1
    assert "lambda:InvokeFunctionUrl" not in allow
    assert "Resource: '*'" not in allow
    for arn_suffix in (
        "scanalyze-authority-lambda-audit-plan:plan-v1",
        "scanalyze-authority-lambda-audit-repair:repair-v1",
        "scanalyze-authority-lambda-audit-reconcile:reconcile-v1",
    ):
        assert arn_suffix in allow
    for denied in ("identitystore:*", "iam:*", "sso:*", "sts:AssumeRole"):
        assert denied in permission_set
    function_url_deny = permission_set[permission_set.index("DenyAllFunctionUrls") :]
    function_url_deny = function_url_deny[: function_url_deny.index("DenyRawControlPlaneAndRelay")]
    assert "Action: lambda:InvokeFunctionUrl" in function_url_deny
    assert "Resource: '*'" in function_url_deny
    legacy_async_deny = permission_set[
        permission_set.index("DenyAllLegacyAsyncInvocation") :
    ]
    legacy_async_deny = legacy_async_deny[
        : legacy_async_deny.index("DenyAllFunctionUrls")
    ]
    assert "Action: lambda:InvokeAsync" in legacy_async_deny
    assert "Resource: '*'" in legacy_async_deny
    not_resource_deny = permission_set[permission_set.index("DenyEveryOtherLambdaInvocation") :]
    not_resource_deny = not_resource_deny[
        : not_resource_deny.index("DenyAllLegacyAsyncInvocation")
    ]
    assert "lambda:InvokeFunctionUrl" not in not_resource_deny
    assert "lambda:InvokeAsync" not in not_resource_deny
    for denied_control in (
        "lambda:CreateEventSourceMapping",
        "lambda:DeleteEventSourceMapping",
        "lambda:DeleteFunctionEventInvokeConfig",
        "lambda:PutFunctionEventInvokeConfig",
        "lambda:UpdateEventSourceMapping",
        "lambda:UpdateFunctionEventInvokeConfig",
    ):
        assert denied_control in permission_set


def test_human_assignment_is_one_exact_user_in_authority_account() -> None:
    assignment = _resource(
        _source(MANAGEMENT_TEMPLATE), "RepairInvokerAssignment"
    )
    assert "Type: AWS::SSO::Assignment" in assignment
    assert "PrincipalId: !Ref RepairPrincipalId" in assignment
    assert "PrincipalType: USER" in assignment
    assert "TargetId: '042360977644'" in assignment
    assert "TargetType: AWS_ACCOUNT" in assignment


def test_optional_identity_center_cmk_is_exact_and_conditioned() -> None:
    source = _source(MANAGEMENT_TEMPLATE)
    assert "UseIdentityCenterCustomerManagedKms:" in source
    assert "IdentityCenterCustomerManagedKmsEnabled:" in source
    assert "IdentityCenterKmsMustBeExactWhenEnabled:" in source
    assert source.count("Action: kms:Decrypt") == 4
    assert source.count("Resource: !Ref IdentityCenterKmsKeyArn") == 4
    assert "kms:ViaService: sso.us-east-1.amazonaws.com" in source
    assert "kms:ViaService: identitystore.us-east-1.amazonaws.com" in source
    assert "kms:EncryptionContext:aws:sso:instance-arn" in source
    assert "kms:EncryptionContext:aws:identitystore:identitystore-arn" in source

    authority = _source(AUTHORITY_TEMPLATE)
    assert "AwsOwnedKmsMustNotCarryKeyArn:" in authority
    assert "CustomerManagedKmsRequiresExactKeyArn:" in authority
    assert "AWS_OWNED_KMS_KEY" in authority
    assert "CUSTOMER_MANAGED_KEY" in authority


def test_standalone_policy_artifacts_preserve_the_same_boundaries() -> None:
    names = {
        "invoker": "platform-authority-lambda-audit-repair-invoker-role.json",
        "authority_plan": (
            "platform-authority-lambda-audit-plan-authority-execution-role.json"
        ),
        "authority_repair": (
            "platform-authority-lambda-audit-repair-authority-execution-role.json"
        ),
        "authority_reconcile": (
            "platform-authority-lambda-audit-reconcile-authority-execution-role.json"
        ),
        "authority_inspector": (
            "platform-authority-lambda-audit-repair-invocation-inspector-role.json"
        ),
        "mutation": (
            "platform-authority-lambda-audit-repair-mutation-service-role.json"
        ),
        "readback": (
            "platform-authority-lambda-audit-repair-readback-service-role.json"
        ),
    }
    policies = {key: _load_policy(value) for key, value in names.items()}
    invoker_allowed = set().union(
        *map(_actions, _allow_statements(policies["invoker"]))
    )
    assert invoker_allowed == {"lambda:InvokeFunction"}
    assert not {
        "sso:*",
        "identitystore:*",
        "iam:*",
        "sts:AssumeRole",
    }.intersection(invoker_allowed)
    invoker_url_deny = next(
        statement
        for statement in policies["invoker"]["Statement"]
        if statement["Sid"] == "DenyAllFunctionUrls"
    )
    assert invoker_url_deny == {
        "Sid": "DenyAllFunctionUrls",
        "Effect": "Deny",
        "Action": "lambda:InvokeFunctionUrl",
        "Resource": "*",
    }
    invoker_async_deny = next(
        statement
        for statement in policies["invoker"]["Statement"]
        if statement["Sid"] == "DenyAllLegacyAsyncInvocation"
    )
    assert invoker_async_deny == {
        "Sid": "DenyAllLegacyAsyncInvocation",
        "Effect": "Deny",
        "Action": "lambda:InvokeAsync",
        "Resource": "*",
    }
    invoker_config_deny = next(
        statement
        for statement in policies["invoker"]["Statement"]
        if statement["Sid"] == "DenyLedgerWritesAndLambdaMutation"
    )
    assert {
        "lambda:CreateEventSourceMapping",
        "lambda:DeleteEventSourceMapping",
        "lambda:DeleteFunctionEventInvokeConfig",
        "lambda:PutFunctionEventInvokeConfig",
        "lambda:UpdateEventSourceMapping",
        "lambda:UpdateFunctionEventInvokeConfig",
    }.issubset(_actions(invoker_config_deny))

    mutation_allowed = set().union(
        *map(_actions, _allow_statements(policies["mutation"]))
    )
    observed_mutations = {
        action
        for action in mutation_allowed
        if action.startswith("sso:") and action not in SSO_READS
    }
    assert observed_mutations == MUTATIONS
    readback_allowed = set().union(
        *map(_actions, _allow_statements(policies["readback"]))
    )
    assert not MUTATIONS.intersection(readback_allowed)
    for service in (policies["mutation"], policies["readback"]):
        assert not UNUSED_READS.intersection(
            set().union(*map(_actions, _allow_statements(service)))
        )
        read_statement = next(
            statement
            for statement in service["Statement"]
            if statement["Sid"] == "ReadExactIdentityCenterObjects"
        )
        assert "${collector_permission_set_arn}" in read_statement["Resource"]
        assert "${repair_invoker_permission_set_arn}" in read_statement["Resource"]
        assert not any("account/" in item for item in read_statement["Resource"])
        assignment_statement = next(
            statement
            for statement in service["Statement"]
            if statement["Sid"] == "ListAssignmentsAcrossObservedAccounts"
        )
        assert _actions(assignment_statement) == {"sso:ListAccountAssignments"}
        assert set(assignment_statement["Resource"]) == {
            "${identity_center_instance_arn}",
            "${collector_permission_set_arn}",
            "${repair_invoker_permission_set_arn}",
            "arn:aws:sso:::account/*",
        }
        wildcard_resources = [
            resource
            for statement in _allow_statements(service)
            for resource in (
                statement.get("Resource", [])
                if isinstance(statement.get("Resource", []), list)
                else [statement.get("Resource")]
            )
            if isinstance(resource, str) and resource.endswith("account/*")
        ]
        assert wildcard_resources == ["arn:aws:sso:::account/*"]
        pending_statement = next(
            statement
            for statement in service["Statement"]
            if statement["Sid"] == "ListExactPendingIdentityCenterOperations"
        )
        assert _actions(pending_statement) == PENDING_OPERATION_READS
        assert pending_statement["Resource"] == "${identity_center_instance_arn}"
    reconcile_allowed = set().union(
        *map(_actions, _allow_statements(policies["authority_reconcile"]))
    )
    assert not DYNAMODB_WRITES.intersection(reconcile_allowed)
    plan_allowed = set().union(
        *map(_actions, _allow_statements(policies["authority_plan"]))
    )
    assert "dynamodb:PutItem" in plan_allowed
    assert "dynamodb:UpdateItem" not in plan_allowed
    repair_allowed = set().union(
        *map(_actions, _allow_statements(policies["authority_repair"]))
    )
    assert "dynamodb:UpdateItem" in repair_allowed
    assert "dynamodb:PutItem" not in repair_allowed
    assert "lambda:GetFunctionEventInvokeConfig" in plan_allowed
    assert "lambda:GetFunctionEventInvokeConfig" in repair_allowed
    assert "lambda:GetFunctionEventInvokeConfig" in reconcile_allowed
    for authority_policy in (
        policies["authority_plan"],
        policies["authority_repair"],
        policies["authority_reconcile"],
    ):
        runtime_inventory = next(
            statement
            for statement in authority_policy["Statement"]
            if statement["Sid"] == "ReadExactPepRuntimeConfiguration"
        )
        assert {
            "lambda:ListAliases",
            "lambda:ListVersionsByFunction",
        }.issubset(_actions(runtime_inventory))
        account_inventory = next(
            statement
            for statement in authority_policy["Statement"]
            if statement["Sid"] == "InventoryLambdaFunctionsAndEventSources"
        )
        assert _actions(account_inventory) == {
            "lambda:ListEventSourceMappings",
            "lambda:ListFunctions",
        }
        assert account_inventory["Resource"] == "*"
        role_read = next(
            statement
            for statement in authority_policy["Statement"]
            if statement["Sid"] == "ReadExactLocalIdentityCenterRoles"
        )
        assert set(role_read["Resource"]) == {
            "arn:aws:iam::042360977644:role/aws-reserved/sso.amazonaws.com/"
            "AWSReservedSSO_ScanalyzeAuthorityLambdaAudit_*",
            "arn:aws:iam::042360977644:role/aws-reserved/sso.amazonaws.com/"
            "AWSReservedSSO_ScanalyzeLambdaAuditRepair_*",
        }
        assert _actions(role_read) == {
            "iam:GetRole",
            "iam:GetRolePolicy",
            "iam:ListAttachedRolePolicies",
            "iam:ListRolePolicies",
        }
        assume_inspector = next(
            statement
            for statement in authority_policy["Statement"]
            if statement["Sid"] == "AssumeExactInvocationAuthorityInspector"
        )
        assert _actions(assume_inspector) == {
            "sts:AssumeRole",
            "sts:SetSourceIdentity",
        }
        assert assume_inspector["Resource"] == (
            "arn:aws:iam::042360977644:role/scanalyze/platform-authority/"
            "ScanalyzeLambdaAuditRepairAuthorityInspector"
        )
    inspector_allowed = set().union(
        *map(_actions, _allow_statements(policies["authority_inspector"]))
    )
    assert "lambda:InvokeFunction" not in inspector_allowed
    assert "sts:AssumeRole" not in inspector_allowed
    assert not DYNAMODB_WRITES.intersection(inspector_allowed)
    assert not MUTATIONS.intersection(inspector_allowed)
    repair_assume = next(
        statement
        for statement in policies["authority_repair"]["Statement"]
        if statement["Sid"] == "AssumeExactMutationServiceRole"
    )
    reconcile_assume = next(
        statement
        for statement in policies["authority_reconcile"]["Statement"]
        if statement["Sid"] == "AssumeExactReadbackServiceRole"
    )
    assert "role/scanalyze/platform-authority/" in repair_assume["Resource"]
    assert "role/scanalyze/platform-authority/" in reconcile_assume["Resource"]
    assert _actions(repair_assume) == {"sts:AssumeRole", "sts:SetSourceIdentity"}
    assert _actions(reconcile_assume) == {"sts:AssumeRole", "sts:SetSourceIdentity"}


def test_reviewed_package_exports_only_reviewed_private_handlers() -> None:
    source = _source(PACKAGE_MODULE)
    match = re.search(
        r"(?ms)^HANDLERS = \{(?P<body>.*?)^\}\n",
        source,
    )
    assert match is not None
    observed = dict(
        re.findall(r'^\s+"([a-z_]+)": "([^"]+)",$', match.group("body"), re.M)
    )
    assert observed == {
        "phase_b_broker": (
            "tooling.platform_authority_lambda_audit_repair_phase_b_runtime."
            "handler"
        ),
        "plan": (
            "tooling.platform_authority_lambda_audit_repair_broker_runtime."
            "plan_handler"
        ),
        "repair": (
            "tooling.platform_authority_lambda_audit_repair_broker_runtime."
            "repair_handler"
        ),
        "reconcile": (
            "tooling.platform_authority_lambda_audit_repair_broker_runtime."
            "reconcile_handler"
        ),
    }


def test_no_allow_statement_grants_wildcard_mutation_authority() -> None:
    for name in (
        "platform-authority-lambda-audit-repair-invoker-role.json",
        "platform-authority-lambda-audit-plan-authority-execution-role.json",
        "platform-authority-lambda-audit-repair-authority-execution-role.json",
        "platform-authority-lambda-audit-reconcile-authority-execution-role.json",
        "platform-authority-lambda-audit-repair-invocation-inspector-role.json",
        "platform-authority-lambda-audit-repair-mutation-service-role.json",
        "platform-authority-lambda-audit-repair-readback-service-role.json",
    ):
        policy = _load_policy(name)
        for statement in _allow_statements(policy):
            actions = _actions(statement)
            if actions.intersection(MUTATIONS | DYNAMODB_WRITES | {"lambda:InvokeFunction"}):
                assert statement.get("Resource") != "*"
                assert "*" not in json.dumps(statement.get("Resource"))


def test_templates_are_exactly_account_and_region_bound() -> None:
    authority = _source(AUTHORITY_TEMPLATE)
    management = _source(MANAGEMENT_TEMPLATE)
    for source in (authority, management):
        assert AUTHORITY_ACCOUNT in source
        assert MANAGEMENT_ACCOUNT in source
        assert REGION in source
        assert "ProductionAuthorized:\n    Value: 'false'" in source
        assert "AccountAndRegionMustMatch:" in source
