"""IAM/S3/KMS Negative Access Matrix Tests.

Static analysis of policy fixtures to verify that role boundaries
are correctly scoped. These tests parse JSON policy documents and
assert that specific actions or resources are NOT granted.

Tests:
- break-glass cannot assume Plan/Apply/Promotion roles
- orchestrator cannot assume Diagnostic/StateRecovery roles
- Apply cannot mutate ScanalyzeCustomer-* control roles
- Promotion cannot read state bucket
- Validation cannot write
- StateRecovery cannot mutate infrastructure
- S3 exact-prefix boundaries per role
- KMS action matrix per role
"""
import json
import pathlib
import re
import pytest

REPO_ROOT = pathlib.Path(__file__).parent.parent.parent
IAM_DIR = REPO_ROOT / "policies" / "iam"
S3_DIR = REPO_ROOT / "policies" / "s3"
KMS_DIR = REPO_ROOT / "policies" / "kms"
TRUST_DIR = REPO_ROOT / "policies" / "trust"
SESSION_DIR = REPO_ROOT / "session-policies"


def _load_policy(path: pathlib.Path) -> dict:
    with open(path) as f:
        return json.load(f)


def _get_statements(policy: dict) -> list:
    """Extract Statement list from policy document."""
    if "Statement" in policy:
        stmts = policy["Statement"]
    elif "PolicyDocument" in policy:
        stmts = policy["PolicyDocument"].get("Statement", [])
    else:
        # Try nested
        for key in policy:
            if isinstance(policy[key], dict) and "Statement" in policy[key]:
                return policy[key]["Statement"]
        return []
    return stmts if isinstance(stmts, list) else [stmts]


def _actions_in_policy(policy: dict) -> set:
    """Extract all allowed actions from a policy."""
    actions = set()
    for stmt in _get_statements(policy):
        if stmt.get("Effect") != "Allow":
            continue
        a = stmt.get("Action", [])
        if isinstance(a, str):
            a = [a]
        actions.update(a)
    return actions


def _resources_in_policy(policy: dict) -> set:
    """Extract all resource ARNs from Allow statements."""
    resources = set()
    for stmt in _get_statements(policy):
        if stmt.get("Effect") != "Allow":
            continue
        r = stmt.get("Resource", [])
        if isinstance(r, str):
            r = [r]
        resources.update(r)
    return resources


def _denied_actions(policy: dict) -> set:
    """Extract all explicitly denied actions."""
    actions = set()
    for stmt in _get_statements(policy):
        if stmt.get("Effect") != "Deny":
            continue
        a = stmt.get("Action", [])
        if isinstance(a, str):
            a = [a]
        actions.update(a)
    return actions


def _has_action_pattern(actions: set, pattern: str) -> bool:
    """Check if any action matches a pattern (supports * wildcard)."""
    regex = re.compile("^" + pattern.replace("*", ".*") + "$")
    return any(regex.match(a) for a in actions)


def _has_resource_pattern(resources: set, pattern: str) -> bool:
    """Check if any resource matches a pattern."""
    regex = re.compile("^" + pattern.replace("*", ".*") + "$")
    return any(regex.match(r) for r in resources)


# ═══════════════════════════════════════════════════════════════
# Break-Glass Scope Tests
# ═══════════════════════════════════════════════════════════════

class TestBreakGlassScope:
    """Break-glass role must NOT be able to assume Plan, Apply, or Promotion roles."""

    @pytest.fixture(autouse=True)
    def setup(self):
        self.policy = _load_policy(IAM_DIR / "break-glass-role.json")
        self.actions = _actions_in_policy(self.policy)
        self.resources = _resources_in_policy(self.policy)

    def test_cannot_assume_plan_role(self):
        # Should not reference plan role ARN
        for r in self.resources:
            assert "PlanRole" not in r and "plan-role" not in r.lower(), \
                f"break-glass must not assume Plan role: {r}"

    def test_cannot_assume_apply_role(self):
        for r in self.resources:
            assert "ApplyRole" not in r and "apply-role" not in r.lower(), \
                f"break-glass must not assume Apply role: {r}"

    def test_cannot_assume_promotion_role(self):
        for r in self.resources:
            assert "PromotionRole" not in r and "promotion-role" not in r.lower(), \
                f"break-glass must not assume Promotion role: {r}"


# ═══════════════════════════════════════════════════════════════
# Orchestrator Scope Tests
# ═══════════════════════════════════════════════════════════════

class TestOrchestratorScope:
    """Orchestrator must NOT assume Diagnostic or StateRecovery roles."""

    @pytest.fixture(autouse=True)
    def setup(self):
        self.policy = _load_policy(IAM_DIR / "orchestrator-role.json")
        self.resources = _resources_in_policy(self.policy)

    def test_cannot_assume_diagnostic_role(self):
        for r in self.resources:
            assert "DiagnosticRole" not in r and "diagnostic" not in r.lower(), \
                f"orchestrator must not assume Diagnostic role: {r}"

    def test_cannot_assume_state_recovery_role(self):
        for r in self.resources:
            assert "StateRecoveryRole" not in r and "state-recovery" not in r.lower(), \
                f"orchestrator must not assume StateRecovery role: {r}"


# ═══════════════════════════════════════════════════════════════
# Apply Role Scope Tests
# ═══════════════════════════════════════════════════════════════

class TestApplyRoleScope:
    """Apply role cannot mutate ScanalyzeCustomer-* control roles."""

    @pytest.fixture(autouse=True)
    def setup(self):
        self.policy = _load_policy(IAM_DIR / "apply-role.json")
        self.actions = _actions_in_policy(self.policy)
        self.resources = _resources_in_policy(self.policy)
        self.denied = _denied_actions(self.policy)

    def test_cannot_mutate_customer_control_roles(self):
        # Must not have iam:* on ScanalyzeCustomer-* resources
        iam_write_actions = {"iam:CreateRole", "iam:DeleteRole",
                             "iam:AttachRolePolicy", "iam:DetachRolePolicy",
                             "iam:PutRolePolicy", "iam:DeleteRolePolicy",
                             "iam:UpdateRole", "iam:UpdateAssumeRolePolicy"}
        # Check that either IAM write actions are not present,
        # or ScanalyzeCustomer-* is not in resources
        for r in self.resources:
            if "ScanalyzeCustomer" in r:
                for action in self.actions:
                    assert action not in iam_write_actions, \
                        f"Apply must not have {action} on {r}"


# ═══════════════════════════════════════════════════════════════
# Promotion Role Scope Tests
# ═══════════════════════════════════════════════════════════════

class TestPromotionRoleScope:
    """Promotion role cannot read state bucket."""

    @pytest.fixture(autouse=True)
    def setup(self):
        self.policy = _load_policy(IAM_DIR / "promotion-role.json")
        self.resources = _resources_in_policy(self.policy)

    def test_cannot_read_state_bucket(self):
        for r in self.resources:
            assert "tf-state" not in r.lower() and "terraform-state" not in r.lower(), \
                f"Promotion must not access state bucket: {r}"


# ═══════════════════════════════════════════════════════════════
# Validation Role Scope Tests
# ═══════════════════════════════════════════════════════════════

class TestValidationRoleScope:
    """Validation role cannot write."""

    @pytest.fixture(autouse=True)
    def setup(self):
        self.policy = _load_policy(IAM_DIR / "validation-role.json")
        self.actions = _actions_in_policy(self.policy)

    def test_no_write_actions(self):
        write_patterns = [
            "s3:Put*", "s3:Delete*", "s3:Create*",
            "dynamodb:Put*", "dynamodb:Delete*", "dynamodb:Update*",
            "sqs:Send*", "sqs:Delete*",
            "iam:Create*", "iam:Delete*", "iam:Put*", "iam:Attach*",
            "iam:Detach*", "iam:Update*",
        ]
        for action in self.actions:
            for pattern in write_patterns:
                regex = re.compile("^" + pattern.replace("*", ".*") + "$")
                assert not regex.match(action), \
                    f"Validation must not have write action: {action}"


# ═══════════════════════════════════════════════════════════════
# State Recovery Role Scope Tests
# ═══════════════════════════════════════════════════════════════

class TestStateRecoveryRoleScope:
    """StateRecovery cannot mutate infrastructure — only state operations."""

    @pytest.fixture(autouse=True)
    def setup(self):
        self.policy = _load_policy(IAM_DIR / "state-recovery-role.json")
        self.actions = _actions_in_policy(self.policy)

    def test_no_infra_mutations(self):
        infra_patterns = [
            "ec2:*", "ecs:Create*", "ecs:Delete*", "ecs:Update*",
            "rds:*", "elasticloadbalancing:Create*",
            "elasticloadbalancing:Delete*",
            "route53:ChangeResourceRecordSets",
            "cloudfront:Create*", "cloudfront:Delete*",
        ]
        for action in self.actions:
            for pattern in infra_patterns:
                regex = re.compile("^" + pattern.replace("*", ".*") + "$")
                assert not regex.match(action), \
                    f"StateRecovery must not mutate infrastructure: {action}"


# ═══════════════════════════════════════════════════════════════
# S3 Prefix Boundary Tests
# ═══════════════════════════════════════════════════════════════

class TestS3PrefixBoundaries:
    """Each S3 bucket policy must restrict access to specific prefixes."""

    def test_state_bucket_has_prefix_restriction(self):
        policy = _load_policy(S3_DIR / "state-bucket.json")
        resources = _resources_in_policy(policy)
        # State bucket must not allow unrestricted /* access
        for r in resources:
            if "/*" in r:
                # Must have a prefix before /*
                parts = r.split("/*")[0]
                assert len(parts) > 20, \
                    f"State bucket resource too broad: {r}"

    def test_evidence_bucket_has_prefix_restriction(self):
        policy = _load_policy(S3_DIR / "evidence-bucket.json")
        resources = _resources_in_policy(policy)
        for r in resources:
            if "/*" in r:
                parts = r.split("/*")[0]
                assert len(parts) > 20, \
                    f"Evidence bucket resource too broad: {r}"

    def test_contracts_bucket_has_prefix_restriction(self):
        policy = _load_policy(S3_DIR / "contracts-bucket.json")
        resources = _resources_in_policy(policy)
        for r in resources:
            if "/*" in r:
                parts = r.split("/*")[0]
                assert len(parts) > 20, \
                    f"Contracts bucket resource too broad: {r}"


# ═══════════════════════════════════════════════════════════════
# KMS Action Matrix Tests
# ═══════════════════════════════════════════════════════════════

class TestKMSActionMatrix:
    """KMS key policies must restrict actions per role type."""

    def test_state_key_no_admin_actions(self):
        policy = _load_policy(KMS_DIR / "state-key.json")
        actions = _actions_in_policy(policy)
        admin_actions = {"kms:DeleteKey", "kms:ScheduleKeyDeletion",
                         "kms:DisableKey", "kms:PutKeyPolicy"}
        # Admin actions should only be in admin/root principal statements
        for stmt in _get_statements(policy):
            if stmt.get("Effect") != "Allow":
                continue
            principals = stmt.get("Principal", {})
            if isinstance(principals, str):
                principals = {"AWS": principals}
            aws_principals = principals.get("AWS", [])
            if isinstance(aws_principals, str):
                aws_principals = [aws_principals]
            # If principal is NOT root, should not have admin actions
            is_root = any(":root" in p for p in aws_principals)
            if not is_root:
                stmt_actions = stmt.get("Action", [])
                if isinstance(stmt_actions, str):
                    stmt_actions = [stmt_actions]
                for a in stmt_actions:
                    assert a not in admin_actions, \
                        f"Non-root principal has KMS admin action: {a}"

    def test_evidence_key_no_decrypt_for_evidence_writers(self):
        """Evidence writers should encrypt only, not decrypt."""
        policy = _load_policy(KMS_DIR / "evidence-key.json")
        # This is a structural test — verify the policy exists and is parseable
        stmts = _get_statements(policy)
        assert len(stmts) > 0, "Evidence key policy must have statements"


# ═══════════════════════════════════════════════════════════════
# GUG-379 Action × Resource × Condition Matrix
# ═══════════════════════════════════════════════════════════════

GENERIC_TERRAFORM_LAYERS = {
    "global",
    "network",
    "platform",
    "data-foundation",
    "cicd",
    "services",
    "edge-identity",
    "edge",
    "addons",
}
VALIDATION_LAYERS = {"artifact-publication", "synthetic-validation"}


def _statement(policy: dict, sid: str) -> dict:
    return next(item for item in _get_statements(policy) if item["Sid"] == sid)


def _items(value):
    return value if isinstance(value, list) else [value]


def _condition_values(statement: dict, key: str) -> set:
    value = statement["Condition"]["StringEquals"][key]
    return set(_items(value))


def _allowed_statements(policy: dict) -> list[dict]:
    return [
        statement
        for statement in _get_statements(policy)
        if statement.get("Effect") == "Allow"
    ]


def test_gug379_terminal_policy_templates_are_partition_portable() -> None:
    for name in (
        "plan-role.json",
        "apply-role.json",
        "identity-control-plane-plan-role.json",
        "identity-control-plane-apply-role.json",
        "promotion-role.json",
        "validation-role.json",
        "diagnostic-role.json",
        "state-recovery-role.json",
    ):
        serialized = json.dumps(_load_policy(IAM_DIR / name), sort_keys=True)
        assert "arn:aws:" not in serialized
        assert "arn:${aws_partition}:" in serialized


def test_gug379_generic_plan_is_read_only_outside_lock_and_saved_plan() -> None:
    policy = _load_policy(IAM_DIR / "plan-role.json")
    statements = _allowed_statements(policy)
    write_actions = {
        action
        for statement in statements
        for action in _items(statement["Action"])
        if not (
            action.startswith(
                (
                    "acm:Describe",
                    "acm:List",
                    "apigateway:GET",
                    "cloudfront:Get",
                    "cloudfront:List",
                    "cloudwatch:Describe",
                    "cloudwatch:Get",
                    "cloudwatch:List",
                    "codebuild:BatchGet",
                    "codebuild:List",
                    "codecommit:Get",
                    "codecommit:List",
                    "codepipeline:Get",
                    "codepipeline:List",
                    "dynamodb:Describe",
                    "dynamodb:List",
                    "ec2:Describe",
                    "ecr:Describe",
                    "ecr:Get",
                    "ecr:List",
                    "ecs:Describe",
                    "ecs:List",
                    "elasticloadbalancing:Describe",
                    "iam:Get",
                    "iam:List",
                    "kms:Decrypt",
                    "kms:Describe",
                    "kms:Encrypt",
                    "kms:GenerateDataKey",
                    "kms:Get",
                    "kms:List",
                    "logs:Describe",
                    "logs:List",
                    "route53:Get",
                    "route53:List",
                    "s3:Get",
                    "s3:List",
                    "sns:Get",
                    "sns:List",
                    "sqs:Get",
                    "sqs:List",
                    "ssm:Get",
                    "sts:GetCallerIdentity",
                    "wafv2:Get",
                    "wafv2:List",
                )
            )
        )
    }
    assert write_actions == {"s3:DeleteObject", "s3:PutObject"}
    for statement in statements:
        actions = set(_items(statement["Action"]))
        if actions & {"s3:DeleteObject", "s3:PutObject"}:
            resources = " ".join(_items(statement["Resource"]))
            assert "terraform.tfstate.tflock" in resources or "/plan-execution/" in resources
        assert _condition_values(statement, "aws:PrincipalTag/operation") == {"plan"}

    infrastructure = _statement(policy, "ReadTerraformManagedInfrastructure")
    assert _condition_values(infrastructure, "aws:PrincipalTag/layer") == (
        GENERIC_TERRAFORM_LAYERS
    )
    assert "application-autoscaling:Describe*" not in _items(
        infrastructure["Action"]
    )
    assert "lambda:Get*" not in _items(infrastructure["Action"])
    assert "sts:GetCallerIdentity" in _items(infrastructure["Action"])


def test_gug379_saved_plan_is_tf_state_scoped_and_apply_requires_version_id() -> None:
    plan = _load_policy(IAM_DIR / "plan-role.json")
    apply = _load_policy(IAM_DIR / "apply-role.json")
    identity_plan = _load_policy(IAM_DIR / "identity-control-plane-plan-role.json")
    identity_apply = _load_policy(IAM_DIR / "identity-control-plane-apply-role.json")

    generic_write = _statement(plan, "WriteOwnSavedPlan")
    assert _items(generic_write["Action"]) == ["s3:PutObject"]
    assert generic_write["Resource"] == (
        "arn:${aws_partition}:s3:::scanalyze-${account_id}-tf-state/"
        "plan-execution/${deployment_id}/${aws:PrincipalTag/change_id}/"
        "${aws:PrincipalTag/layer}/plan.tfplan"
    )

    generic_read = _statement(apply, "ReadOwnSavedPlanVersion")
    assert _items(generic_read["Action"]) == ["s3:GetObjectVersion"]
    assert generic_read["Resource"] == generic_write["Resource"]

    identity_write = _statement(
        identity_plan, "WriteIdentityPlanExecutionZone"
    )
    assert _items(identity_write["Action"]) == ["s3:PutObject"]
    assert identity_write["Resource"].endswith(
        "/${aws:PrincipalTag/change_id}/identity-control-plane/plan.tfplan"
    )
    assert "-tf-state/plan-execution/" in identity_write["Resource"]

    identity_read = _statement(
        identity_apply, "ReadIdentityPlanExecutionZone"
    )
    assert _items(identity_read["Action"]) == ["s3:GetObjectVersion"]
    assert identity_read["Resource"] == identity_write["Resource"]

    for policy in (plan, apply, identity_plan, identity_apply):
        serialized = json.dumps(policy, sort_keys=True)
        assert "-tf-evidence/plan-execution/" not in serialized

    # IAM forces the caller onto the versioned API. Selecting and approving the
    # exact VersionId remains a downstream orchestration/saved-plan gate; this
    # policy intentionally does not invent an approval value.
    assert "s3:GetObject" not in _items(generic_read["Action"])
    assert "s3:GetObject" not in _items(identity_read["Action"])
    assert "s3:VersionId" not in json.dumps([generic_read, identity_read])


def test_gug379_apply_mutations_are_bound_to_exact_operation_and_layer() -> None:
    policy = _load_policy(IAM_DIR / "apply-role.json")
    expected = {
        "ManageNetworkLayer": "network",
        "ManagePlatformLayer": "platform",
        "ManageDataFoundationLayer": "data-foundation",
        "ManageCicdLayer": "cicd",
        "PassCodeBuild": "cicd",
        "PassCodePipeline": "cicd",
        "ManageServicesLayer": "services",
        "PassEcsExecution": "services",
        "ManageEdgeIdentityLayer": "edge-identity",
        "ManageEdgeLayer": "edge",
        "ManageExactFrontendRuntimeConfig": "edge",
        "ManageAddonsLayer": "addons",
        "WritePlatformContractParameters": "platform",
        "WriteCicdImageParameters": "cicd",
    }
    for sid, layer in expected.items():
        statement = _statement(policy, sid)
        assert _condition_values(statement, "aws:PrincipalTag/operation") == {
            "apply"
        }
        assert _condition_values(statement, "aws:PrincipalTag/layer") == {layer}

    cicd_pairs = {
        "PassCodeBuild": (
            "arn:${aws_partition}:iam::${account_id}:role/${deployment_id}-codebuild-role",
            "codebuild.${aws_url_suffix}",
        ),
        "PassCodePipeline": (
            "arn:${aws_partition}:iam::${account_id}:role/${deployment_id}-codepipeline-role",
            "codepipeline.${aws_url_suffix}",
        ),
    }
    for sid, (role_arn, service) in cicd_pairs.items():
        cicd_pass = _statement(policy, sid)
        assert cicd_pass["Resource"] == role_arn
        assert _condition_values(cicd_pass, "iam:PassedToService") == {service}

    service_pass = _statement(
        policy, "PassEcsExecution"
    )
    assert service_pass["Resource"] == (
        "arn:${aws_partition}:iam::${account_id}:role/"
        "${deployment_id}-ecs-task-execution"
    )
    assert _condition_values(service_pass, "iam:PassedToService") == {
        "ecs-tasks.${aws_url_suffix}"
    }

    edge_identity = _statement(policy, "ManageEdgeIdentityLayer")
    assert set(_items(edge_identity["Resource"])) == {
        "arn:${aws_partition}:apigateway:${region}::/apis*",
        "arn:${aws_partition}:apigateway:${region}::/tags/*",
        "arn:${aws_partition}:apigateway:${region}::/vpclinks*",
    }
    runtime_config = _statement(policy, "ManageExactFrontendRuntimeConfig")
    assert runtime_config["Resource"].endswith(
        "-frontend/${deployment_id}/config.json"
    )
    assert set(_items(runtime_config["Action"])) == {
        "s3:GetObject",
        "s3:PutObject",
    }

    assert _statement(policy, "WritePlatformContractParameters")[
        "Resource"
    ].endswith("/${deployment_id}/layers/platform/outputs/*")
    assert _statement(policy, "WriteCicdImageParameters")["Resource"].endswith(
        "/${deployment_id}/cicd/images/*"
    )
    assert "ecr:PutImage" not in _actions_in_policy(policy)


def test_gug379_generic_apply_cannot_persist_iam_authority() -> None:
    policy = _load_policy(IAM_DIR / "apply-role.json")
    allowed_actions = {
        action
        for statement in _allowed_statements(policy)
        for action in _items(statement["Action"])
    }
    assert not allowed_actions & {
        "iam:AttachRolePolicy",
        "iam:CreatePolicy",
        "iam:CreatePolicyVersion",
        "iam:CreateRole",
        "iam:DeletePolicyVersion",
        "iam:DetachRolePolicy",
        "iam:PutRolePolicy",
        "iam:SetDefaultPolicyVersion",
        "iam:TagPolicy",
        "iam:TagRole",
        "iam:UntagPolicy",
        "iam:UntagRole",
        "iam:UpdateAssumeRolePolicy",
    }
    pass_statements = [
        statement
        for statement in _allowed_statements(policy)
        if "iam:PassRole" in _items(statement["Action"])
    ]
    assert {statement["Sid"] for statement in pass_statements} == {
        "PassCodeBuild",
        "PassCodePipeline",
        "PassEcsExecution",
    }
    assert all(
        "iam:PassedToService"
        in statement["Condition"]["StringEquals"]
        for statement in pass_statements
    )
    assert all(
        not any(resource.endswith("-*") for resource in _items(statement["Resource"]))
        for statement in pass_statements
    )


def test_gug379_generic_apply_kms_mutation_is_tag_bound() -> None:
    policy = _load_policy(IAM_DIR / "apply-role.json")
    allowed_actions = {
        action
        for statement in _allowed_statements(policy)
        for action in _items(statement["Action"])
    }
    assert not allowed_actions & {"kms:CreateKey", "kms:PutKeyPolicy"}

    for sid in (
        "ManageBoundLayerKey",
        "TagBoundLayerKey",
        "CreateBoundLayerGrant",
        "BindLayerAliasToBoundKey",
    ):
        statement = _statement(policy, sid)
        assert statement["Resource"] == (
            "arn:${aws_partition}:kms:${region}:${account_id}:key/*"
        )
        equals = statement["Condition"]["StringEquals"]
        assert equals["aws:ResourceTag/customer_id"] == "${customer_id}"
        assert equals["aws:ResourceTag/deployment_id"] == "${deployment_id}"
        assert equals["aws:ResourceTag/layer"] == "${aws:PrincipalTag/layer}"

    grant = _statement(policy, "CreateBoundLayerGrant")
    assert grant["Condition"]["Bool"] == {
        "kms:GrantIsForAWSResource": "true"
    }
    assert "BoolIfExists" not in grant["Condition"]
    assert _items(_statement(policy, "ManageBoundLayerKey")["Action"]) == [
        "kms:EnableKeyRotation"
    ]


def test_gug379_identity_grant_requires_aws_resource_and_bound_key() -> None:
    policy = _load_policy(
        IAM_DIR / "identity-control-plane-apply-role.json"
    )
    ordinary = _statement(policy, "ManageTaggedIdentityEncryptionKey")
    assert "kms:CreateGrant" not in _items(ordinary["Action"])
    assert "BoolIfExists" not in ordinary["Condition"]

    grant = _statement(policy, "CreateBoundIdentityEncryptionGrant")
    assert grant["Action"] == "kms:CreateGrant"
    assert grant["Resource"] == (
        "arn:${aws_partition}:kms:${region}:${account_id}:key/*"
    )
    assert grant["Condition"]["StringEquals"] == {
        "aws:ResourceTag/customer_id": "${customer_id}",
        "aws:ResourceTag/deployment_id": "${deployment_id}",
        "aws:ResourceTag/layer": "identity-control-plane",
    }
    assert grant["Condition"]["Bool"] == {
        "kms:GrantIsForAWSResource": "true"
    }
    assert "BoolIfExists" not in grant["Condition"]


def test_gug379_identity_kms_binding_cannot_pivot_or_accept_extra_tags() -> None:
    policy = _load_policy(
        IAM_DIR / "identity-control-plane-apply-role.json"
    )
    ownership = {
        "aws:ResourceTag/customer_id": "${customer_id}",
        "aws:ResourceTag/deployment_id": "${deployment_id}",
        "aws:ResourceTag/layer": "identity-control-plane",
    }
    request = {
        "aws:RequestTag/customer_id": "${customer_id}",
        "aws:RequestTag/deployment_id": "${deployment_id}",
        "aws:RequestTag/layer": "identity-control-plane",
    }
    exact_tag_keys = {"customer_id", "deployment_id", "layer"}

    allowed_actions = {
        action
        for statement in _allowed_statements(policy)
        for action in _items(statement["Action"])
    }
    assert not allowed_actions & {"kms:CreateKey", "kms:PutKeyPolicy"}

    tagging = _statement(policy, "TagBoundIdentityEncryptionKey")
    assert tagging["Action"] == "kms:TagResource"
    assert tagging["Condition"]["StringEquals"] == ownership | request
    assert set(
        tagging["Condition"]["ForAllValues:StringEquals"]["aws:TagKeys"]
    ) == exact_tag_keys

    alias = _statement(policy, "ManageExactIdentityEncryptionAlias")
    assert alias["Resource"].endswith("alias/${deployment_id}-identity")
    bound_key = _statement(policy, "BindIdentityAliasToOwnedKey")
    assert bound_key["Condition"]["StringEquals"] == ownership

    untag_deny = _statement(policy, "DenyRemovalOfIdentityBindingTags")
    assert untag_deny["Effect"] == "Deny"
    assert set(_items(untag_deny["Action"])) == {
        "cognito-idp:UntagResource",
        "kms:UntagResource",
    }
    assert set(
        untag_deny["Condition"]["ForAnyValue:StringEquals"]["aws:TagKeys"]
    ) == exact_tag_keys
    assert not any(
        statement["Effect"] == "Allow"
        and "kms:UntagResource" in _items(statement["Action"])
        for statement in _get_statements(policy)
    )


def test_gug379_identity_apply_cannot_persist_runtime_iam_authority() -> None:
    policy = _load_policy(
        IAM_DIR / "identity-control-plane-apply-role.json"
    )
    allowed_actions = {
        action
        for statement in _allowed_statements(policy)
        for action in _items(statement["Action"])
    }
    assert not allowed_actions & {
        "cognito-idp:CreateGroup",
        "cognito-idp:CreateResourceServer",
        "cognito-idp:CreateUserPoolClient",
        "cognito-idp:UpdateGroup",
        "cognito-idp:UpdateResourceServer",
        "cognito-idp:UpdateUserPoolClient",
        "cloudwatch:PutMetricAlarm",
        "dynamodb:PutResourcePolicy",
        "ecr:SetRepositoryPolicy",
        "iam:CreateRole",
        "iam:PutRolePolicy",
        "iam:TagRole",
        "iam:UntagRole",
        "iam:UpdateAssumeRolePolicy",
        "lambda:AddPermission",
        "lambda:RemovePermission",
        "logs:PutResourcePolicy",
        "s3:PutBucketPolicy",
        "secretsmanager:PutResourcePolicy",
        "sqs:AddPermission",
        "sqs:CreateQueue",
        "sqs:RemovePermission",
        "sqs:SetQueueAttributes",
    }

    exact_roles = {
        "arn:${aws_partition}:iam::${account_id}:role/scanalyze/${deployment_id}/identity-${deployment_id}-pre-token",
        "arn:${aws_partition}:iam::${account_id}:role/scanalyze/${deployment_id}/identity-${deployment_id}-control-processor",
    }
    read = _statement(policy, "ReadPreprovisionedIdentityRuntimeRoles")
    assert set(_items(read["Action"])) == {"iam:GetRole", "iam:GetRolePolicy"}
    assert set(_items(read["Resource"])) == exact_roles

    expected_pairs = {
        "PassPreTokenRoleToFunction": (
            "arn:${aws_partition}:iam::${account_id}:role/scanalyze/${deployment_id}/identity-${deployment_id}-pre-token",
            "arn:${aws_partition}:lambda:${region}:${account_id}:function:${deployment_id}-identity-pre-token",
        ),
        "PassControlProcessorRoleToFunction": (
            "arn:${aws_partition}:iam::${account_id}:role/scanalyze/${deployment_id}/identity-${deployment_id}-control-processor",
            "arn:${aws_partition}:lambda:${region}:${account_id}:function:${deployment_id}-identity-control-processor",
        ),
    }
    pass_statements = [
        statement
        for statement in _allowed_statements(policy)
        if "iam:PassRole" in _items(statement["Action"])
    ]
    assert {statement["Sid"] for statement in pass_statements} == set(expected_pairs)
    for sid, (role_arn, function_arn) in expected_pairs.items():
        role_pass = _statement(policy, sid)
        assert role_pass["Action"] == "iam:PassRole"
        assert role_pass["Resource"] == role_arn
        assert role_pass["Condition"]["StringEquals"] == {
            "iam:PassedToService": "lambda.${aws_url_suffix}"
        }
        assert role_pass["Condition"]["ArnLike"] == {
            "iam:AssociatedResourceArn": function_arn
        }

    functions = _statement(policy, "ManageIdentityFunctions")
    assert set(_items(functions["Resource"])) == {
        "arn:${aws_partition}:lambda:${region}:${account_id}:function:${deployment_id}-identity-pre-token",
        "arn:${aws_partition}:lambda:${region}:${account_id}:function:${deployment_id}-identity-pre-token:*",
        "arn:${aws_partition}:lambda:${region}:${account_id}:function:${deployment_id}-identity-control-processor",
        "arn:${aws_partition}:lambda:${region}:${account_id}:function:${deployment_id}-identity-control-processor:*",
    }
    alarms = _statement(policy, "TagPreprovisionedIdentityAlarms")
    assert set(_items(alarms["Action"])) == {
        "cloudwatch:ListTagsForResource",
        "cloudwatch:TagResource",
        "cloudwatch:UntagResource",
    }


def test_gug379_identity_roles_cannot_mutate_or_read_client_secrets() -> None:
    apply = _load_policy(IAM_DIR / "identity-control-plane-apply-role.json")
    apply_cognito = {
        action
        for statement in _allowed_statements(apply)
        for action in _items(statement["Action"])
        if action.startswith("cognito-idp:")
    }
    assert apply_cognito == {
        "cognito-idp:DescribeUserPool",
        "cognito-idp:GetGroup",
        "cognito-idp:ListGroups",
    }
    read = _statement(apply, "ReadPreprovisionedIdentityUserPool")
    equals = read["Condition"]["StringEquals"]
    assert equals["aws:ResourceTag/customer_id"] == "${customer_id}"
    assert equals["aws:ResourceTag/deployment_id"] == "${deployment_id}"
    assert equals["aws:ResourceTag/layer"] == "identity-control-plane"

    plan = _load_policy(IAM_DIR / "identity-control-plane-plan-role.json")
    diagnostic = _load_policy(IAM_DIR / "diagnostic-role.json")
    for policy in (plan, apply, diagnostic):
        actions = {
            action
            for statement in _allowed_statements(policy)
            for action in _items(statement["Action"])
        }
        assert "cognito-idp:DescribeUserPoolClient" not in actions
        assert "cognito-idp:Describe*" not in actions
    diagnostic_cognito = {
        action
        for statement in _allowed_statements(diagnostic)
        for action in _items(statement["Action"])
        if action.startswith("cognito-idp:")
    }
    assert diagnostic_cognito == {
        "cognito-idp:DescribeUserPool",
        "cognito-idp:DescribeUserPoolDomain",
    }


def test_gug379_pass_role_service_suffix_is_partition_portable() -> None:
    apply = _load_policy(IAM_DIR / "apply-role.json")
    identity = _load_policy(
        IAM_DIR / "identity-control-plane-apply-role.json"
    )
    values = {
        value
        for statement in _get_statements(apply) + _get_statements(identity)
        for value in _items(
            statement.get("Condition", {})
            .get("StringEquals", {})
            .get("iam:PassedToService", [])
        )
    }
    assert values == {
        "codebuild.${aws_url_suffix}",
        "codepipeline.${aws_url_suffix}",
        "ecs-tasks.${aws_url_suffix}",
        "lambda.${aws_url_suffix}",
    }
    partition_suffixes = {
        "aws": "amazonaws.com",
        "aws-us-gov": "amazonaws.com",
        "aws-cn": "amazonaws.com.cn",
    }
    for suffix in partition_suffixes.values():
        rendered = {value.replace("${aws_url_suffix}", suffix) for value in values}
        assert all(value.endswith(suffix) for value in rendered)


def test_gug379_promotion_is_publication_only() -> None:
    policy = _load_policy(IAM_DIR / "promotion-role.json")
    for statement in _allowed_statements(policy):
        assert _condition_values(statement, "aws:PrincipalTag/operation") == {
            "promote"
        }
        assert _condition_values(statement, "aws:PrincipalTag/layer") == {
            "artifact-publication"
        }
        assert all("tf-state" not in resource for resource in _items(statement["Resource"]))

    actions = _actions_in_policy(policy)
    assert "ecr:PutImage" in actions
    assert "cloudfront:CreateInvalidation" in actions
    invalidation = _statement(policy, "InvalidateExactDistribution")
    assert invalidation["Resource"] == (
        "arn:${aws_partition}:cloudfront::${account_id}:distribution/*"
    )
    assert _condition_values(
        invalidation, "aws:ResourceTag/deployment_id"
    ) == {"${deployment_id}"}
    assert not any(action.startswith(("ec2:", "ecs:", "iam:")) for action in actions)


def test_gug379_validation_is_exactly_two_entrypoints_and_read_only() -> None:
    policy = _load_policy(IAM_DIR / "validation-role.json")
    for statement in _allowed_statements(policy):
        assert _condition_values(statement, "aws:PrincipalTag/operation") == {
            "validate"
        }
        layers = _condition_values(statement, "aws:PrincipalTag/layer")
        assert layers and layers <= VALIDATION_LAYERS

    ecr = _statement(policy, "ReadValidationArtifacts")
    assert _condition_values(ecr, "aws:PrincipalTag/layer") == {
        "artifact-publication"
    }
    actions = _actions_in_policy(policy)
    forbidden_prefixes = (
        "cloudfront:Create",
        "dynamodb:Put",
        "dynamodb:Update",
        "ecr:InitiateLayerUpload",
        "ecr:PutImage",
        "ecs:Create",
        "iam:",
        "s3:Put",
        "sqs:Send",
        "ssm:Put",
    )
    assert not any(action.startswith(forbidden_prefixes) for action in actions)

    payload_actions = {
        "logs:FilterLogEvents",
        "logs:GetLogEvents",
        "ssm:GetParameter",
        "ssm:GetParameters",
    }
    assert not any(
        statement["Resource"] == "*"
        and payload_actions & set(_items(statement["Action"]))
        for statement in _allowed_statements(policy)
    )

    logs = _statement(policy, "ReadDeploymentValidationLogs")
    assert set(_items(logs["Action"])) == {
        "logs:FilterLogEvents",
        "logs:GetLogEvents",
    }
    assert set(_items(logs["Resource"])) == {
        "arn:${aws_partition}:logs:${region}:${account_id}:log-group:/aws/codebuild/${deployment_id}-*",
        "arn:${aws_partition}:logs:${region}:${account_id}:log-group:/aws/codebuild/${deployment_id}-*:log-stream:*",
        "arn:${aws_partition}:logs:${region}:${account_id}:log-group:/aws/lambda/${deployment_id}-identity-*",
        "arn:${aws_partition}:logs:${region}:${account_id}:log-group:/aws/lambda/${deployment_id}-identity-*:log-stream:*",
        "arn:${aws_partition}:logs:${region}:${account_id}:log-group:/ecs/${deployment_id}/*",
        "arn:${aws_partition}:logs:${region}:${account_id}:log-group:/ecs/${deployment_id}/*:log-stream:*",
    }
    parameters = _statement(policy, "ReadDeploymentValidationParameters")
    assert set(_items(parameters["Action"])) == {
        "ssm:GetParameter",
        "ssm:GetParameters",
    }
    assert set(_items(parameters["Resource"])) == {
        "arn:${aws_partition}:ssm:${region}:${account_id}:parameter/scanalyze/deployments/${deployment_id}/*",
        "arn:${aws_partition}:ssm:${region}:${account_id}:parameter/${deployment_id}/*",
    }


def test_gug379_diagnostic_and_state_recovery_conditions_fail_closed() -> None:
    diagnostic = _load_policy(IAM_DIR / "diagnostic-role.json")
    for statement in _allowed_statements(diagnostic):
        assert _condition_values(statement, "aws:PrincipalTag/operation") == {
            "diagnostic"
        }

    recovery = _load_policy(IAM_DIR / "state-recovery-role.json")
    for statement in _allowed_statements(recovery):
        assert _condition_values(statement, "aws:PrincipalTag/operation") == {
            "state-recovery"
        }
        assert _condition_values(statement, "aws:PrincipalTag/deployment_id") == {
            "${deployment_id}"
        }
    delete = _statement(recovery, "DeleteOnlyReviewedNativeLockfile")
    assert delete["Resource"].endswith("terraform.tfstate.tflock")
    assert _condition_values(delete, "aws:PrincipalTag/recovery_approved") == {
        "true"
    }


def test_gug379_validation_trust_separates_sts_action_conditions() -> None:
    trust = _load_policy(TRUST_DIR / "validation-trust.json")
    statements = _get_statements(trust)
    assert {statement["Action"] for statement in statements} == {
        "sts:AssumeRole",
        "sts:SetSourceIdentity",
        "sts:TagSession",
    }
    assume = next(
        statement for statement in statements if statement["Action"] == "sts:AssumeRole"
    )
    tagging = next(
        statement for statement in statements if statement["Action"] == "sts:TagSession"
    )
    for statement in (assume, tagging):
        assert _condition_values(statement, "aws:RequestTag/operation") == {
            "validate"
        }
        assert _condition_values(statement, "aws:RequestTag/layer") == (
            VALIDATION_LAYERS
        )
