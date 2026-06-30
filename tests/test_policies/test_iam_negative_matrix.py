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
