from __future__ import annotations

import copy
import importlib.util
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from tooling.founder_bootstrap_pep import (
    AUTHORITY_ACCOUNT_ID,
    AUTHORITY_REGION,
    EXPECTED_RESOURCE_CHANGES,
    FOUNDER_APPLY_PERMISSION_SET,
    FOUNDER_PLAN_PERMISSION_SET,
    MANAGEMENT_IDENTITY_ADMIN_PERMISSION_SET,
    MANAGEMENT_SEED_PERMISSION_SET,
    MANAGEMENT_ACCOUNT_ID,
    PEP_TABLE_NAME,
    FounderPepAuthorizationError,
    FounderPepBinding,
    AwsCliFounderPepStore,
    build_founder_pep_revocation,
    build_founder_pep_intent,
    build_founder_pep_ledger,
    claim_founder_apply,
    claim_founder_plan,
    finalize_founder_outcome,
    finalize_founder_plan,
    finalize_founder_revocation,
    render_live_founder_policy,
    run_founder_apply_once,
    run_founder_plan_once,
    validate_founder_pep_intent,
    validate_founder_pep_ledger,
)
from tooling.platform_authority_bootstrap import (
    PUBLIC_ACCESS_BLOCK,
    BootstrapBinding,
    build_bootstrap_plan,
    canonical_digest,
)


REPO_ROOT = Path(__file__).resolve().parents[2]
TEMPLATE = REPO_ROOT / "bootstrap/cfn-platform-authority-founder-pep.yaml"
PLAN_POLICY = REPO_ROOT / "policies/iam/platform-authority-founder-live-plan-role.json"
APPLY_POLICY = REPO_ROOT / "policies/iam/platform-authority-founder-live-apply-role.json"
SEED_POLICY = REPO_ROOT / "policies/iam/platform-authority-founder-pep-management-seed-role.json"
IDENTITY_ADMIN_POLICY = REPO_ROOT / "policies/iam/platform-authority-founder-pep-identity-admin-role.json"
SEED_SCRIPT = REPO_ROOT / "scripts/deployment/founder-bootstrap-pep-seed.py"
PEP_SCRIPT = REPO_ROOT / "scripts/deployment/founder-bootstrap-pep.py"
NOW = datetime(2030, 1, 1, tzinfo=UTC)
EXCEPTION_ID = "founder-20300101"
CHANGE_SET_NAME = f"scanalyze-founder-bootstrap-{EXCEPTION_ID}"
CHANGE_SET_ID = (
    f"arn:aws:cloudformation:{AUTHORITY_REGION}:{AUTHORITY_ACCOUNT_ID}:"
    f"changeSet/{CHANGE_SET_NAME}/00000000-0000-4000-8000-000000000000"
)
PLAN_ARN = (
    f"arn:aws:sts::{AUTHORITY_ACCOUNT_ID}:assumed-role/"
    f"AWSReservedSSO_{FOUNDER_PLAN_PERMISSION_SET}_0123456789abcdef/operator"
)
APPLY_ARN = (
    f"arn:aws:sts::{AUTHORITY_ACCOUNT_ID}:assumed-role/"
    f"AWSReservedSSO_{FOUNDER_APPLY_PERMISSION_SET}_fedcba9876543210/operator"
)


def _intent(**overrides: object) -> dict:
    values: dict[str, object] = {
        "exception_id": EXCEPTION_ID,
        "operator_id": "operator-1001",
        "operator_identity_store_user_id": "00000000-0000-4000-8000-000000000001",
        "founder_plan_principal_arn": PLAN_ARN,
        "founder_apply_principal_arn": APPLY_ARN,
        "risk_acceptance_id": "gug-211-founder-risk",
        "template_sha256": "a" * 64,
        "normal_plan_revoked_at": NOW - timedelta(hours=13),
        "plan_not_before": NOW,
        "plan_expires_at": NOW + timedelta(minutes=20),
        "apply_not_before": NOW + timedelta(minutes=25),
        "apply_expires_at": NOW + timedelta(minutes=35),
        "deny_retain_until": NOW + timedelta(hours=13),
        "created_at": NOW - timedelta(minutes=1),
    }
    values.update(overrides)
    return build_founder_pep_intent(**values)  # type: ignore[arg-type]


def _ledger(intent: dict | None = None) -> dict:
    return build_founder_pep_ledger(intent=intent or _intent(), created_at=NOW)


def _reseal_ledger(ledger: dict) -> dict:
    candidate = {key: value for key, value in ledger.items() if key != "ledger_digest"}
    candidate["ledger_digest"] = canonical_digest(candidate)
    return candidate


def test_binding_is_exact_and_has_no_customer_or_shared_services_authority() -> None:
    binding = FounderPepBinding()
    assert binding.management_account_id == MANAGEMENT_ACCOUNT_ID
    assert binding.authority_account_id == AUTHORITY_ACCOUNT_ID
    assert binding.region == AUTHORITY_REGION
    assert binding.table_name == PEP_TABLE_NAME

    for field, bad in (
        ("management_account_id", "111122223333"),
        ("authority_account_id", "444455556666"),
        ("region", "us-west-2"),
        ("table_name", "request-selected"),
    ):
        with pytest.raises(FounderPepAuthorizationError):
            FounderPepBinding(**{field: bad})


def test_intent_binds_one_operator_exact_roles_windows_and_expected_resources() -> None:
    intent = _intent()
    validate_founder_pep_intent(intent)

    assert intent["approval_mode"] == "SINGLE_OPERATOR_FOUNDER_EXCEPTION"
    assert intent["independent_approval_present"] is False
    assert intent["production"] is False
    assert intent["authority_account_id"] == AUTHORITY_ACCOUNT_ID
    assert intent["change_set_name"] == CHANGE_SET_NAME
    assert intent["plan_attempt_limit"] == 1
    assert intent["apply_attempt_limit"] == 1
    assert len(intent["expected_resource_changes"]) == 4
    assert "operator_identity_store_user_id" not in intent
    assert "founder_plan_principal_arn" not in intent
    assert "founder_apply_principal_arn" not in intent


@pytest.mark.parametrize(
    ("field", "value", "message"),
    (
        ("founder_apply_principal_arn", PLAN_ARN, "principal"),
        ("plan_not_before", NOW - timedelta(hours=2), "quarantine"),
        ("plan_expires_at", NOW + timedelta(hours=1), "Plan window"),
        ("apply_not_before", NOW + timedelta(minutes=20), "gap"),
        ("apply_expires_at", NOW + timedelta(hours=1), "Apply window"),
        ("deny_retain_until", NOW + timedelta(hours=1), "retention"),
    ),
)
def test_intent_rejects_ambiguous_or_unbounded_authority(
    field: str, value: object, message: str
) -> None:
    with pytest.raises(FounderPepAuthorizationError, match=message):
        _intent(**{field: value})


def test_intent_tampering_and_unknown_fields_fail_closed() -> None:
    intent = _intent()
    tampered = copy.deepcopy(intent)
    tampered["authority_account_id"] = "444455556666"
    with pytest.raises(FounderPepAuthorizationError):
        validate_founder_pep_intent(tampered)

    extra = copy.deepcopy(intent)
    extra["legacy_bypass"] = True
    with pytest.raises(FounderPepAuthorizationError, match="unexpected"):
        validate_founder_pep_intent(extra)


def test_ledger_consumes_plan_and_apply_exactly_once() -> None:
    intent = _intent()
    prepared = _ledger(intent)
    claimed_plan = claim_founder_plan(
        intent=intent,
        ledger=prepared,
        caller_arn=PLAN_ARN,
        now=NOW + timedelta(minutes=1),
    )
    assert claimed_plan["state"] == "PLAN_ATTEMPTED"
    assert claimed_plan["plan_attempt_count"] == 1
    assert claimed_plan["version"] == 2

    with pytest.raises(FounderPepAuthorizationError, match="already consumed"):
        claim_founder_plan(
            intent=intent,
            ledger=claimed_plan,
            caller_arn=PLAN_ARN,
            now=NOW + timedelta(minutes=2),
        )

    reviewed = finalize_founder_plan(
        intent=intent,
        ledger=claimed_plan,
        change_set_id=CHANGE_SET_ID,
        plan_record_digest="sha256:" + "b" * 64,
        exception_digest="sha256:" + "c" * 64,
        now=NOW + timedelta(minutes=3),
    )
    assert reviewed["state"] == "PLAN_REVIEWED"

    claimed_apply = claim_founder_apply(
        intent=intent,
        ledger=reviewed,
        caller_arn=APPLY_ARN,
        change_set_id=CHANGE_SET_ID,
        now=NOW + timedelta(minutes=26),
    )
    assert claimed_apply["state"] == "APPLY_ATTEMPTED"
    assert claimed_apply["apply_attempt_count"] == 1

    with pytest.raises(FounderPepAuthorizationError, match="already consumed"):
        claim_founder_apply(
            intent=intent,
            ledger=claimed_apply,
            caller_arn=APPLY_ARN,
            change_set_id=CHANGE_SET_ID,
            now=NOW + timedelta(minutes=27),
        )


def test_lost_or_ambiguous_effect_is_uncertain_and_never_retryable() -> None:
    intent = _intent()
    plan_claim = claim_founder_plan(
        intent=intent,
        ledger=_ledger(intent),
        caller_arn=PLAN_ARN,
        now=NOW + timedelta(minutes=1),
    )
    uncertain_plan = finalize_founder_outcome(
        intent=intent,
        ledger=plan_claim,
        outcome="UNCERTAIN",
        now=NOW + timedelta(minutes=2),
    )
    assert uncertain_plan["state"] == "UNCERTAIN"
    with pytest.raises(FounderPepAuthorizationError):
        claim_founder_plan(
            intent=intent,
            ledger=uncertain_plan,
            caller_arn=PLAN_ARN,
            now=NOW + timedelta(minutes=3),
        )


def test_success_is_not_closed_until_assignment_revocation_is_durably_bound() -> None:
    intent = _intent()
    claimed_plan = claim_founder_plan(
        intent=intent,
        ledger=_ledger(intent),
        caller_arn=PLAN_ARN,
        now=NOW + timedelta(minutes=1),
    )
    reviewed = finalize_founder_plan(
        intent=intent,
        ledger=claimed_plan,
        change_set_id=CHANGE_SET_ID,
        plan_record_digest="sha256:" + "b" * 64,
        exception_digest="sha256:" + "c" * 64,
        now=NOW + timedelta(minutes=2),
    )
    claimed_apply = claim_founder_apply(
        intent=intent,
        ledger=reviewed,
        caller_arn=APPLY_ARN,
        change_set_id=CHANGE_SET_ID,
        now=NOW + timedelta(minutes=26),
    )
    succeeded = finalize_founder_outcome(
        intent=intent,
        ledger=claimed_apply,
        outcome="SUCCEEDED",
        now=NOW + timedelta(minutes=30),
    )
    assert succeeded["state"] == "SUCCEEDED"
    assert succeeded["revocation_digest"] is None
    plan_policy = render_live_founder_policy(
        mode="plan",
        intent=intent,
        operator_identity_store_user_id="00000000-0000-4000-8000-000000000001",
    )
    apply_policy = render_live_founder_policy(
        mode="apply",
        intent=intent,
        operator_identity_store_user_id="00000000-0000-4000-8000-000000000001",
    )
    with pytest.raises(FounderPepAuthorizationError, match="assignment revocation"):
        build_founder_pep_revocation(
            intent=intent,
            ledger=succeeded,
            founder_plan_policy=plan_policy,
            founder_apply_policy=apply_policy,
            normal_plan_assignment_count=0,
            founder_plan_assignment_count=0,
            founder_apply_assignment_count=1,
            founder_plan_deny_retained=True,
            founder_apply_deny_retained=True,
            verified_at=NOW + timedelta(minutes=34),
        )
    receipt = build_founder_pep_revocation(
        intent=intent,
        ledger=succeeded,
        founder_plan_policy=plan_policy,
        founder_apply_policy=apply_policy,
        normal_plan_assignment_count=0,
        founder_plan_assignment_count=0,
        founder_apply_assignment_count=0,
        founder_plan_deny_retained=True,
        founder_apply_deny_retained=True,
        verified_at=NOW + timedelta(minutes=34),
    )
    closed = finalize_founder_revocation(
        intent=intent,
        ledger=succeeded,
        receipt=receipt,
        now=NOW + timedelta(minutes=34),
    )
    assert closed["state"] == "REVOKED"
    assert closed["outcome"] == "SUCCEEDED"
    assert closed["revocation_digest"] == receipt["revocation_digest"]


def test_wrong_role_window_change_set_or_digest_is_denied() -> None:
    intent = _intent()
    with pytest.raises(FounderPepAuthorizationError, match="Plan principal"):
        claim_founder_plan(
            intent=intent,
            ledger=_ledger(intent),
            caller_arn=APPLY_ARN,
            now=NOW + timedelta(minutes=1),
        )
    with pytest.raises(FounderPepAuthorizationError, match="outside"):
        claim_founder_plan(
            intent=intent,
            ledger=_ledger(intent),
            caller_arn=PLAN_ARN,
            now=NOW - timedelta(seconds=1),
        )

    claimed = claim_founder_plan(
        intent=intent,
        ledger=_ledger(intent),
        caller_arn=PLAN_ARN,
        now=NOW + timedelta(minutes=1),
    )
    with pytest.raises(FounderPepAuthorizationError, match="Change Set"):
        finalize_founder_plan(
            intent=intent,
            ledger=claimed,
            change_set_id=CHANGE_SET_ID.replace(CHANGE_SET_NAME, "foreign"),
            plan_record_digest="sha256:" + "b" * 64,
            exception_digest="sha256:" + "c" * 64,
            now=NOW + timedelta(minutes=2),
        )


def test_aws_store_uses_create_only_and_compare_and_swap_without_scan() -> None:
    commands: list[list[str]] = []

    def runner(command: list[str] | tuple[str, ...]) -> str:
        commands.append(list(command))
        return "{}"

    store = AwsCliFounderPepStore(
        region=AUTHORITY_REGION,
        authority_account_id=AUTHORITY_ACCOUNT_ID,
        table_name=PEP_TABLE_NAME,
        runner=runner,
    )
    intent = _intent()
    before = _ledger(intent)
    after = claim_founder_plan(
        intent=intent,
        ledger=before,
        caller_arn=PLAN_ARN,
        now=NOW + timedelta(minutes=1),
    )
    store.create_ledger(before)
    store.replace_ledger(
        ledger=after,
        expected_version=before["version"],
        expected_digest=before["ledger_digest"],
        expected_state=before["state"],
        expected_plan_attempt_count=0,
        expected_apply_attempt_count=0,
    )

    serialized = "\n".join(" ".join(command) for command in commands)
    assert "dynamodb put-item" in serialized
    assert "attribute_not_exists(exception_id)" in serialized
    assert "#version = :expected_version" in serialized
    assert "#digest = :expected_digest" in serialized
    assert "#state = :expected_state" in serialized
    assert "#plan = :expected_plan" in serialized
    assert "#apply = :expected_apply" in serialized
    assert " scan " not in f" {serialized.lower()} "
    assert f"--table-name {PEP_TABLE_NAME}" in serialized
    assert all(command.count("--region") == 1 for command in commands)


def test_effects_run_only_after_durable_claim_and_uncertainty_is_terminal() -> None:
    intent = _intent()
    prepared = _ledger(intent)
    events: list[str] = []

    class Store:
        current = prepared

        def get_ledger(self, exception_id: str) -> dict:
            assert exception_id == EXCEPTION_ID
            events.append("read")
            return self.current

        def replace_ledger(self, *, ledger: dict, **_: object) -> None:
            events.append(f"cas:{ledger['state']}")
            self.current = ledger

    store = Store()

    def plan_effect() -> dict[str, str]:
        events.append("plan-effect")
        return {
            "change_set_id": CHANGE_SET_ID,
            "plan_record_digest": "sha256:" + "b" * 64,
            "exception_digest": "sha256:" + "c" * 64,
        }

    run_founder_plan_once(
        intent=intent,
        store=store,  # type: ignore[arg-type]
        caller_arn=PLAN_ARN,
        now=NOW + timedelta(minutes=1),
        effect=plan_effect,
    )
    assert events == ["read", "cas:PLAN_ATTEMPTED", "plan-effect", "cas:PLAN_REVIEWED"]

    events.clear()

    def lost_apply_response() -> None:
        events.append("apply-effect")
        raise TimeoutError

    with pytest.raises(FounderPepAuthorizationError, match="retry is forbidden"):
        run_founder_apply_once(
            intent=intent,
            store=store,  # type: ignore[arg-type]
            caller_arn=APPLY_ARN,
            change_set_id=CHANGE_SET_ID,
            now=NOW + timedelta(minutes=26),
            effect=lost_apply_response,
        )
    assert events == ["read", "cas:APPLY_ATTEMPTED", "apply-effect", "cas:UNCERTAIN"]
    assert store.current["apply_attempt_count"] == 1


def test_lost_final_cas_response_is_reconciled_without_repeating_the_effect() -> None:
    intent = _intent()
    events: list[str] = []

    class Store:
        current = _ledger(intent)
        writes = 0

        def get_ledger(self, _: str) -> dict:
            events.append("read")
            return self.current

        def replace_ledger(self, *, ledger: dict, **_: object) -> None:
            self.writes += 1
            self.current = ledger
            events.append(f"cas:{ledger['state']}")
            if self.writes == 2:
                raise TimeoutError("response lost after durable write")

    store = Store()
    reviewed = run_founder_plan_once(
        intent=intent,
        store=store,  # type: ignore[arg-type]
        caller_arn=PLAN_ARN,
        now=NOW + timedelta(minutes=1),
        effect=lambda: {
            "change_set_id": CHANGE_SET_ID,
            "plan_record_digest": "sha256:" + "b" * 64,
            "exception_digest": "sha256:" + "c" * 64,
        },
    )
    assert reviewed["state"] == "PLAN_REVIEWED"
    assert store.current["ledger_digest"] == reviewed["ledger_digest"]
    assert events.count("cas:PLAN_REVIEWED") == 1


def test_failed_final_cas_is_closed_as_uncertain_without_repeating_the_effect() -> None:
    intent = _intent()

    class Store:
        current = _ledger(intent)
        writes = 0

        def get_ledger(self, _: str) -> dict:
            return self.current

        def replace_ledger(self, *, ledger: dict, **_: object) -> None:
            self.writes += 1
            if self.writes == 2:
                raise TimeoutError("final CAS failed before write")
            self.current = ledger

    store = Store()
    effects = 0

    def effect() -> dict[str, str]:
        nonlocal effects
        effects += 1
        return {
            "change_set_id": CHANGE_SET_ID,
            "plan_record_digest": "sha256:" + "b" * 64,
            "exception_digest": "sha256:" + "c" * 64,
        }

    with pytest.raises(FounderPepAuthorizationError, match="retry is forbidden"):
        run_founder_plan_once(
            intent=intent,
            store=store,  # type: ignore[arg-type]
            caller_arn=PLAN_ARN,
            now=NOW + timedelta(minutes=1),
            effect=effect,
        )
    assert effects == 1
    assert store.current["state"] == "UNCERTAIN"
    assert store.current["plan_attempt_count"] == 1


def test_live_policies_bind_exact_table_subject_time_and_change_set() -> None:
    intent = _intent()
    plan = render_live_founder_policy(
        mode="plan",
        intent=intent,
        operator_identity_store_user_id="00000000-0000-4000-8000-000000000001",
    )
    apply = render_live_founder_policy(
        mode="apply",
        intent=intent,
        operator_identity_store_user_id="00000000-0000-4000-8000-000000000001",
    )
    serialized = json.dumps({"plan": plan, "apply": apply})
    table_arn = (
        f"arn:aws:dynamodb:{AUTHORITY_REGION}:{AUTHORITY_ACCOUNT_ID}:table/{PEP_TABLE_NAME}"
    )
    assert "${" not in serialized
    assert table_arn in serialized
    assert CHANGE_SET_NAME in serialized
    assert "identitystore:UserId" in serialized
    assert "aws:CurrentTime" in serialized
    assert "DenyOfflineOnly" not in serialized
    assert "organizations:" not in serialized
    assert "sso:" not in serialized
    assert "sso-admin:" not in serialized
    assert "s3:PutAccountPublicAccessBlock" not in _allowed_actions(plan)
    assert "s3:PutAccountPublicAccessBlock" not in _allowed_actions(apply)
    assert "cloudformation:ExecuteChangeSet" not in _allowed_actions(plan)
    assert "cloudformation:CreateChangeSet" not in _allowed_actions(apply)


def test_seed_template_is_exact_retained_and_protected() -> None:
    text = TEMPLATE.read_text(encoding="utf-8")
    assert "AWS::DynamoDB::Table" in text
    assert PEP_TABLE_NAME in text
    assert "DeletionProtectionEnabled: true" in text
    assert "PointInTimeRecoveryEnabled: true" in text
    assert "SSEEnabled: true" in text
    assert "DeletionPolicy: Retain" in text
    assert "UpdateReplacePolicy: Retain" in text
    assert "PAY_PER_REQUEST" in text
    assert "AWS::IAM::" not in text
    assert "AWS::Lambda::" not in text
    assert "AWS::S3::Bucket" not in text


def test_management_seed_targets_only_the_authority_account_and_never_auto_deploys() -> None:
    text = SEED_SCRIPT.read_text(encoding="utf-8")
    assert 'MANAGEMENT_ACCOUNT_ID = "839393571433"' in text
    assert f'AUTHORITY_ACCOUNT_ID = "{AUTHORITY_ACCOUNT_ID}"' in text
    assert '"@@assign": "all"' in text
    assert "AccountFilterType=INTERSECTION" in text
    assert "Enabled=false,RetainStacksOnAccountRemoval=true" in text
    assert "FailureToleranceCount=0,MaxConcurrentCount=1" in text
    assert "490332586151" not in text
    assert "905418363887" not in text
    assert "540150372644" not in text

    policy_text = SEED_POLICY.read_text(encoding="utf-8")
    policy = json.loads(policy_text)
    allowed = _allowed_actions(policy)
    assert "iam:CreateRole" not in allowed
    assert "sso:CreatePermissionSet" not in allowed
    assert "sso-admin:CreatePermissionSet" not in allowed
    assert "organizations:CreateAccount" not in allowed
    assert "cloudformation:ExecuteChangeSet" not in allowed
    assert "490332586151" not in policy_text
    assert "905418363887" not in policy_text
    assert "540150372644" not in policy_text
    assert len(MANAGEMENT_SEED_PERMISSION_SET) <= 32

    spec = importlib.util.spec_from_file_location(
        "gug211_founder_bootstrap_pep_seed_identity",
        SEED_SCRIPT,
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    exact_arn = (
        f"arn:aws:sts::{MANAGEMENT_ACCOUNT_ID}:assumed-role/"
        f"AWSReservedSSO_{MANAGEMENT_SEED_PERMISSION_SET}_0123456789abcdef/operator"
    )
    admin_arn = exact_arn.replace(MANAGEMENT_SEED_PERMISSION_SET, "AWSAdministratorAccess")
    assert module.MANAGEMENT_SEED_ARN.fullmatch(exact_arn)
    assert module.MANAGEMENT_SEED_ARN.fullmatch(admin_arn) is None


def test_management_seed_binds_required_policy_tagging_to_exact_create_request() -> None:
    policy = json.loads(SEED_POLICY.read_text(encoding="utf-8"))
    create_statement = next(
        statement
        for statement in policy["Statement"]
        if statement.get("Sid") == "CreateOnlyTaggedS3OrganizationPolicy"
    )
    assert create_statement["Action"] == [
        "organizations:CreatePolicy",
        "organizations:TagResource",
    ]
    assert create_statement["Resource"] == "*"
    assert create_statement["Condition"] == {
        "StringEquals": {
            "organizations:PolicyType": "S3_POLICY",
            "aws:RequestTag/managed_by": "scanalyze-founder-pep",
            "aws:RequestTag/work_package": "GUG-211",
        },
        "ForAllValues:StringEquals": {
            "aws:TagKeys": ["managed_by", "work_package"]
        },
    }
    deny_statement = next(
        statement
        for statement in policy["Statement"]
        if statement.get("Sid") == "DenyUnreviewedOrganizationMutations"
    )
    assert "organizations:TagResource" in deny_statement["NotAction"]
    assert "organizations:UntagResource" not in _allowed_actions(policy)
    assert "organizations:UpdatePolicy" not in _allowed_actions(policy)


def test_management_seed_does_not_treat_access_denied_as_stackset_absence() -> None:
    spec = importlib.util.spec_from_file_location(
        "gug211_founder_bootstrap_pep_seed",
        SEED_SCRIPT,
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    class DeniedClient:
        def run(self, *parts: str, allow_failure: bool = False) -> tuple[int, dict, str]:
            assert parts[:2] == ("cloudformation", "describe-stack-set")
            assert allow_failure is True
            return 254, {}, "AccessDeniedException"

    with pytest.raises(module.SeedAuthorizationError, match="lookup failed closed"):
        module._ensure_stack_set(
            DeniedClient(),
            {
                "stacksets_trusted_access_enabled": True,
                "template_sha256": "a" * 64,
            },
        )


def test_management_seed_rejects_foreign_or_noncurrent_stackset_readback() -> None:
    spec = importlib.util.spec_from_file_location(
        "gug211_founder_bootstrap_pep_seed_readback",
        SEED_SCRIPT,
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    preflight = {
        "authority_ou_id": "ou-abcd-01234567",
        "template_sha256": module._template_sha256(),
    }

    class Client:
        def __init__(self, summary: dict) -> None:
            self.summary = summary

        def run(self, *parts: str, allow_failure: bool = False) -> tuple[int, dict, str]:
            del allow_failure
            if parts[:2] == ("cloudformation", "describe-stack-set"):
                return 0, {
                    "StackSet": {
                        "StackSetName": module.STACK_SET_NAME,
                        "PermissionModel": "SERVICE_MANAGED",
                        "Status": "ACTIVE",
                        "AutoDeployment": {
                            "Enabled": False,
                            "RetainStacksOnAccountRemoval": True,
                        },
                        "TemplateBody": TEMPLATE.read_text(encoding="utf-8"),
                        "Parameters": [
                            {
                                "ParameterKey": "AuthorityAccountId",
                                "ParameterValue": AUTHORITY_ACCOUNT_ID,
                            }
                        ],
                        "Tags": [
                            {"Key": "managed_by", "Value": "cloudformation-stacksets"},
                            {"Key": "service", "Value": "scanalyze-platform-authority"},
                            {"Key": "work_package", "Value": "GUG-211"},
                        ],
                    }
                }, ""
            assert parts[:2] == ("cloudformation", "list-stack-instances")
            return 0, {"Summaries": [self.summary]}, ""

    exact = {
        "Account": AUTHORITY_ACCOUNT_ID,
        "Region": AUTHORITY_REGION,
        "OrganizationalUnitId": preflight["authority_ou_id"],
        "StackId": "arn:aws:cloudformation:us-east-1:042360977644:stack/exact/uuid",
        "Status": "CURRENT",
        "StackInstanceStatus": {"DetailedStatus": "SUCCEEDED"},
    }
    assert module._inspect_stack_set(Client(exact), preflight) == [exact]

    foreign = {**exact, "Account": "905418363887"}
    with pytest.raises(module.SeedAuthorizationError, match="foreign or ambiguous"):
        module._inspect_stack_set(Client(foreign), preflight)

    outdated = {**exact, "Status": "OUTDATED"}
    with pytest.raises(module.SeedAuthorizationError, match="CURRENT/SUCCEEDED"):
        module._inspect_stack_set(Client(outdated), preflight)


def test_identity_admin_policy_is_account_bound_and_has_no_directory_or_iam_mutations() -> None:
    policy_text = IDENTITY_ADMIN_POLICY.read_text(encoding="utf-8")
    policy = json.loads(policy_text)
    allowed = _allowed_actions(policy)
    assert "arn:aws:sso:::account/042360977644" in policy_text
    assert "490332586151" not in policy_text
    assert "905418363887" not in policy_text
    assert "540150372644" not in policy_text
    assert all(not action.startswith("identitystore:") for action in allowed)
    assert all(not action.startswith("iam:") for action in allowed)
    assert "sso:CreateAccountAssignment" in allowed
    assert "sso:DeleteAccountAssignment" in allowed
    assert "sso:CreateInstance" not in allowed
    assert "sso:UpdateInstance" not in allowed
    assert "sso:CreatePermissionSet" in allowed
    assert "sso:ListManagedPoliciesInPermissionSet" in allowed
    assert "sso:ListCustomerManagedPolicyReferencesInPermissionSet" in allowed
    assert "sso:GetPermissionsBoundaryForPermissionSet" in allowed
    assert "sso:AttachManagedPolicyToPermissionSet" not in allowed
    assert "sso:AttachCustomerManagedPolicyReferenceToPermissionSet" not in allowed
    assert "sso:PutPermissionsBoundaryToPermissionSet" not in allowed
    assert len(MANAGEMENT_IDENTITY_ADMIN_PERMISSION_SET) == 32
    tagged_mutations = [
        statement
        for statement in policy["Statement"]
        if statement.get("Sid") in {
            "ManageOnlyTaggedFounderPermissionSets",
            "AssignProvisionAndRevokeOnlyTaggedFounderPermissionSets",
        }
    ]
    assert len(tagged_mutations) == 2
    assert all(
        statement["Condition"]["StringEquals"]
        == {
            "aws:ResourceTag/managed_by": "scanalyze-founder-pep",
            "aws:ResourceTag/work_package": "GUG-211",
        }
        for statement in tagged_mutations
    )


def test_identity_lifecycle_rejects_generic_administrator_session(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    spec = importlib.util.spec_from_file_location(
        "gug211_founder_bootstrap_pep_identity_role",
        PEP_SCRIPT,
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    for name in (*module.FORBIDDEN_CREDENTIAL_ENV, "AWS_REGION", "AWS_DEFAULT_REGION"):
        monkeypatch.delenv(name, raising=False)

    class Client:
        def __init__(self, permission_set: str) -> None:
            self.permission_set = permission_set

        def run(self, service: str, operation: str) -> dict:
            assert (service, operation) == ("sts", "get-caller-identity")
            return {
                "Account": MANAGEMENT_ACCOUNT_ID,
                "Arn": (
                    f"arn:aws:sts::{MANAGEMENT_ACCOUNT_ID}:assumed-role/"
                    f"AWSReservedSSO_{self.permission_set}_0123456789abcdef/operator"
                ),
            }

    exact = module._management_identity(Client(MANAGEMENT_IDENTITY_ADMIN_PERMISSION_SET))
    assert MANAGEMENT_IDENTITY_ADMIN_PERMISSION_SET in exact
    with pytest.raises(FounderPepAuthorizationError, match="reviewed SSO role"):
        module._management_identity(Client("AWSAdministratorAccess"))


def test_identity_inventory_rejects_foreign_gug211_permission_set() -> None:
    spec = importlib.util.spec_from_file_location(
        "gug211_founder_bootstrap_pep_foreign_inventory",
        PEP_SCRIPT,
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    permission_set_arn = (
        "arn:aws:sso:::permissionSet/ssoins-0123456789abcdef/ps-0123456789abcdef"
    )

    class Client:
        def run(self, service: str, operation: str, *args: str) -> dict:
            assert service == "sso-admin"
            if operation == "list-permission-sets":
                return {"PermissionSets": [permission_set_arn]}
            if operation == "describe-permission-set":
                return {
                    "PermissionSet": {
                        "Name": "ScanalyzeForeignFounderRole",
                        "PermissionSetArn": permission_set_arn,
                    }
                }
            assert operation == "list-tags-for-resource"
            return {
                "Tags": [
                    {"Key": "managed_by", "Value": "scanalyze-founder-pep"},
                    {"Key": "work_package", "Value": "GUG-211"},
                ]
            }

    with pytest.raises(FounderPepAuthorizationError, match="foreign GUG-211"):
        module._permission_set_records(
            Client(), "arn:aws:sso:::instance/ssoins-0123456789abcdef"
        )


def test_identity_center_lifecycle_is_direct_user_only_and_revocation_windows_are_exact() -> None:
    spec = importlib.util.spec_from_file_location("gug211_founder_bootstrap_pep", PEP_SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    source = PEP_SCRIPT.read_text(encoding="utf-8")
    assert '"--principal-type", "USER"' in source
    assert '"--principal-type", "GROUP"' not in source
    assert "create-group" not in source
    assert "create-group-membership" not in source

    intent = _intent()
    module._validate_revocation_window(
        intent=intent, mode="plan", now=NOW + timedelta(minutes=20)
    )
    module._validate_revocation_window(
        intent=intent, mode="apply", now=NOW + timedelta(minutes=34)
    )
    with pytest.raises(FounderPepAuthorizationError, match="closeout window"):
        module._validate_revocation_window(
            intent=intent, mode="plan", now=NOW + timedelta(minutes=19)
        )
    with pytest.raises(FounderPepAuthorizationError, match="closeout window"):
        module._validate_revocation_window(
            intent=intent, mode="apply", now=NOW + timedelta(minutes=35)
        )

    principal = module._principal_arn_from_permission_set(
        "arn:aws:sso:::permissionSet/ssoins-0123456789abcdef/ps-fedcba9876543210",
        name=FOUNDER_PLAN_PERMISSION_SET,
        session_name="founder.operator",
    )
    assert principal == (
        f"arn:aws:sts::{AUTHORITY_ACCOUNT_ID}:assumed-role/"
        f"AWSReservedSSO_{FOUNDER_PLAN_PERMISSION_SET}_fedcba9876543210/founder.operator"
    )


def test_identity_center_optional_read_swallows_only_resource_not_found(monkeypatch: pytest.MonkeyPatch) -> None:
    spec = importlib.util.spec_from_file_location("gug211_founder_bootstrap_pep_optional", PEP_SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    client = module.AwsCli(profile="reviewed-management-profile")

    class Result:
        returncode = 254
        stdout = ""

        def __init__(self, stderr: str) -> None:
            self.stderr = stderr

    monkeypatch.setattr(module.subprocess, "run", lambda *args, **kwargs: Result("ResourceNotFoundException"))
    assert client.run_optional_not_found("sso-admin", "get-permissions-boundary-for-permission-set") is None

    monkeypatch.setattr(module.subprocess, "run", lambda *args, **kwargs: Result("AccessDeniedException"))
    with pytest.raises(module.AwsEffectError, match="AWS operation failed"):
        client.run_optional_not_found("sso-admin", "get-permissions-boundary-for-permission-set")


def test_policy_templates_remain_reviewable_and_disjoint() -> None:
    plan = json.loads(PLAN_POLICY.read_text(encoding="utf-8"))
    apply = json.loads(APPLY_POLICY.read_text(encoding="utf-8"))
    plan_text = json.dumps(plan)
    apply_text = json.dumps(apply)
    assert "cloudformation:CreateChangeSet" in _allowed_actions(plan)
    assert "cloudformation:ExecuteChangeSet" not in _allowed_actions(plan)
    assert "dynamodb:PutItem" in _allowed_actions(plan)
    assert "cloudformation:ExecuteChangeSet" in _allowed_actions(apply)
    assert "cloudformation:CreateChangeSet" not in _allowed_actions(apply)
    assert "dynamodb:PutItem" in _allowed_actions(apply)
    for policy, text in ((plan, plan_text), (apply, apply_text)):
        allowed = _allowed_actions(policy)
        assert "dynamodb:Scan" not in allowed
        assert "dynamodb:DeleteItem" not in allowed
        assert "cloudformation:DeleteStack" not in allowed
        assert all(not action.startswith("iam:") for action in allowed)
        assert all(not action.startswith("organizations:") for action in allowed)
        metadata = next(
            statement
            for statement in policy["Statement"]
            if statement.get("Action") == "dynamodb:DescribeTable"
        )
        item_access = next(
            statement
            for statement in policy["Statement"]
            if statement.get("Action") == ["dynamodb:GetItem", "dynamodb:PutItem"]
        )
        assert "Condition" not in metadata
        assert item_access["Condition"] == {
            "ForAllValues:StringEquals": {
                "dynamodb:LeadingKeys": ["${exception_id}"]
            }
        }


def test_apply_readback_proves_exact_backend_controls() -> None:
    spec = importlib.util.spec_from_file_location(
        "gug211_founder_bootstrap_pep_cli",
        REPO_ROOT / "scripts/deployment/founder-bootstrap-pep.py",
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    bucket = f"scanalyze-platform-authority-{AUTHORITY_ACCOUNT_ID}-{AUTHORITY_REGION}-state"
    key_arn = (
        f"arn:aws:kms:{AUTHORITY_REGION}:{AUTHORITY_ACCOUNT_ID}:"
        "key/00000000-0000-4000-8000-000000000001"
    )
    binding = BootstrapBinding(
        authority_account_id=AUTHORITY_ACCOUNT_ID,
        region=AUTHORITY_REGION,
        stack_name="scanalyze-platform-authority-state-backend",
        state_bucket_name=bucket,
        state_key="platform-authority/terraform.tfstate",
        destination_account_ids=("905418363887", "540150372644"),
    )
    plan = build_bootstrap_plan(
        binding=binding,
        caller_account_id=AUTHORITY_ACCOUNT_ID,
        caller_arn=PLAN_ARN,
        template_sha256="a" * 64,
        change_set_id=CHANGE_SET_ID,
        change_set_type="CREATE",
        resource_changes=EXPECTED_RESOURCE_CHANGES,
        account_public_access_block_before=PUBLIC_ACCESS_BLOCK,
        created_at=NOW,
        expires_at=NOW + timedelta(minutes=30),
        initiator_id="operator-1001",
    )
    backend = (
        f'bucket              = "{bucket}"\n'
        'key                 = "platform-authority/terraform.tfstate"\n'
        f'region              = "{AUTHORITY_REGION}"\n'
        "encrypt             = true\n"
        f'kms_key_id          = "{key_arn}"\n'
        "use_lockfile        = true\n"
        f'allowed_account_ids = ["{AUTHORITY_ACCOUNT_ID}"]\n'
    )
    stack = {
        "StackStatus": "CREATE_COMPLETE",
        "Outputs": [
            {"OutputKey": key, "OutputValue": value}
            for key, value in {
                "AuthorityAccountId": AUTHORITY_ACCOUNT_ID,
                "AuthorityRegion": AUTHORITY_REGION,
                "StateBucketName": bucket,
                "StateBucketArn": f"arn:aws:s3:::{bucket}",
                "StateKmsKeyArn": key_arn,
                "StateKey": "platform-authority/terraform.tfstate",
                "AccountPublicAccessBlockRequired": "true",
                "BackendConfig": backend,
            }.items()
        ],
    }
    tags = [
        {"Key": key, "Value": value}
        for key, value in {
            "managed_by": "cloudformation",
            "service": "scanalyze-platform-authority",
            "data_class": "control-metadata",
            "account_id": AUTHORITY_ACCOUNT_ID,
            "region": AUTHORITY_REGION,
        }.items()
    ]
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": sid,
                "Effect": "Deny",
                "Resource": [f"arn:aws:s3:::{bucket}", key_arn, plan["state_key"]],
            }
            for sid in (
                "DenyInsecureTransport",
                "DenyCrossAccountAccess",
                "DenyUnencryptedObjectWrites",
                "DenyWrongKmsKey",
                "DenyUnexpectedObjectKeys",
                "DenyStateDeletion",
            )
        ],
    }
    key_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "EnableAuthorityAccountIamPermissions",
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{AUTHORITY_ACCOUNT_ID}:root"},
                "Action": "kms:*",
                "Resource": "*",
            }
        ],
    }

    class FakeClient:
        def __init__(self, override: tuple[tuple[str, str], dict] | None = None) -> None:
            self.override = override

        def run(self, service: str, operation: str, *args: str) -> dict:
            del args
            responses = {
                ("s3api", "get-bucket-location"): {"LocationConstraint": None},
                ("s3api", "get-public-access-block"): {
                    "PublicAccessBlockConfiguration": PUBLIC_ACCESS_BLOCK
                },
                ("s3api", "get-bucket-versioning"): {"Status": "Enabled"},
                ("s3api", "get-bucket-ownership-controls"): {
                    "OwnershipControls": {
                        "Rules": [{"ObjectOwnership": "BucketOwnerEnforced"}]
                    }
                },
                ("s3api", "get-bucket-encryption"): {
                    "ServerSideEncryptionConfiguration": {
                        "Rules": [
                            {
                                "ApplyServerSideEncryptionByDefault": {
                                    "SSEAlgorithm": "aws:kms",
                                    "KMSMasterKeyID": key_arn,
                                },
                                "BucketKeyEnabled": True,
                            }
                        ]
                    }
                },
                ("s3api", "get-bucket-lifecycle-configuration"): {
                    "Rules": [
                        {
                            "ID": "RetainNoncurrentStateVersions",
                            "Status": "Enabled",
                            "NoncurrentVersionExpiration": {"NoncurrentDays": 365},
                        },
                        {
                            "ID": "AbortIncompleteMultipartUploads",
                            "Status": "Enabled",
                            "AbortIncompleteMultipartUpload": {"DaysAfterInitiation": 7},
                        },
                    ]
                },
                ("s3api", "get-bucket-tagging"): {"TagSet": tags},
                ("s3api", "get-bucket-policy-status"): {
                    "PolicyStatus": {"IsPublic": False}
                },
                ("s3api", "get-bucket-policy"): {"Policy": json.dumps(policy)},
                ("kms", "describe-key"): {
                    "KeyMetadata": {
                        "Arn": key_arn,
                        "AWSAccountId": AUTHORITY_ACCOUNT_ID,
                        "KeyState": "Enabled",
                        "KeyUsage": "ENCRYPT_DECRYPT",
                        "KeySpec": "SYMMETRIC_DEFAULT",
                        "MultiRegion": False,
                    }
                },
                ("kms", "get-key-rotation-status"): {"KeyRotationEnabled": True},
                ("kms", "get-key-policy"): {"Policy": json.dumps(key_policy)},
                ("kms", "list-resource-tags"): {
                    "Tags": [
                        {"TagKey": item["Key"], "TagValue": item["Value"]}
                        for item in tags
                    ]
                },
            }
            key = (service, operation)
            if self.override is not None and self.override[0] == key:
                return self.override[1]
            return responses[key]

    verification = module._verify_backend_controls(
        FakeClient(),
        stack=stack,
        plan=plan,
        caller_arn=APPLY_ARN,
    )
    assert verification["controls"]["kms_rotation_enabled"] is True
    assert verification["verification_digest"].startswith("sha256:")

    with pytest.raises(FounderPepAuthorizationError, match="versioning"):
        module._verify_backend_controls(
            FakeClient((("s3api", "get-bucket-versioning"), {"Status": "Suspended"})),
            stack=stack,
            plan=plan,
            caller_arn=APPLY_ARN,
        )


def test_change_set_readback_binds_the_exact_original_template_digest() -> None:
    spec = importlib.util.spec_from_file_location(
        "gug211_founder_bootstrap_pep_template_readback",
        PEP_SCRIPT,
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    template_body = TEMPLATE.read_text(encoding="utf-8")
    intent = _intent(template_sha256=module._sha256(TEMPLATE))

    class FakeClient:
        def __init__(self, body: object) -> None:
            self.body = body

        def run(self, service: str, operation: str, *args: str) -> dict:
            assert service == "cloudformation"
            if operation == "get-template":
                assert "--template-stage" in args and "Original" in args
                return {"TemplateBody": self.body}
            assert operation == "describe-change-set"
            return {
                "ChangeSetId": CHANGE_SET_ID,
                "ChangeSetName": CHANGE_SET_NAME,
                "StackName": "scanalyze-platform-authority-state-backend",
                "Status": "CREATE_COMPLETE",
                "ExecutionStatus": "AVAILABLE",
                "Tags": [
                    {"Key": "managed_by", "Value": "cloudformation"},
                    {"Key": "service", "Value": "scanalyze-platform-authority"},
                    {"Key": "work_package", "Value": "GUG-206"},
                ],
                "Changes": [
                    {
                        "ResourceChange": {
                            "Action": item["action"],
                            "LogicalResourceId": item["logical_resource_id"],
                            "ResourceType": item["resource_type"],
                            "Replacement": item["replacement"],
                        }
                    }
                    for item in EXPECTED_RESOURCE_CHANGES
                ],
            }

    described = module._describe_change_set(
        FakeClient(template_body), change_set_id=CHANGE_SET_ID, intent=intent
    )
    assert described["ChangeSetId"] == CHANGE_SET_ID

    with pytest.raises(FounderPepAuthorizationError, match="template digest"):
        module._describe_change_set(
            FakeClient(template_body + "\n# tampered"),
            change_set_id=CHANGE_SET_ID,
            intent=intent,
        )
    with pytest.raises(FounderPepAuthorizationError, match="unavailable"):
        module._describe_change_set(
            FakeClient({"not": "a string"}),
            change_set_id=CHANGE_SET_ID,
            intent=intent,
        )


def _allowed_actions(policy: dict) -> set[str]:
    return {
        action
        for statement in policy["Statement"]
        if statement["Effect"] == "Allow"
        for action in (
            [statement["Action"]]
            if isinstance(statement["Action"], str)
            else statement["Action"]
        )
    }


def test_ledger_validation_rejects_legacy_missing_or_conflicting_state() -> None:
    ledger = _ledger()
    validate_founder_pep_ledger(ledger)
    for mutation in (
        lambda value: value.pop("intent_digest"),
        lambda value: value.update({"plan_attempt_count": 1}),
        lambda value: value.update({"state": "SUCCEEDED"}),
        lambda value: value.update({"legacy_retry": True}),
    ):
        candidate = copy.deepcopy(ledger)
        mutation(candidate)
        with pytest.raises(FounderPepAuthorizationError):
            validate_founder_pep_ledger(candidate)


def test_ledger_validation_enforces_versions_timestamps_and_apply_bindings() -> None:
    prepared = _ledger()
    wrong_version = copy.deepcopy(prepared)
    wrong_version["version"] = 2
    with pytest.raises(FounderPepAuthorizationError, match="version"):
        validate_founder_pep_ledger(_reseal_ledger(wrong_version))

    backwards = copy.deepcopy(prepared)
    backwards["updated_at"] = (NOW - timedelta(seconds=1)).isoformat().replace("+00:00", "Z")
    with pytest.raises(FounderPepAuthorizationError, match="before creation"):
        validate_founder_pep_ledger(_reseal_ledger(backwards))

    unexpected_start = copy.deepcopy(prepared)
    unexpected_start["execution_started_at"] = NOW.isoformat().replace("+00:00", "Z")
    with pytest.raises(FounderPepAuthorizationError, match="unexpected Apply"):
        validate_founder_pep_ledger(_reseal_ledger(unexpected_start))

    intent = _intent()
    plan_claim = claim_founder_plan(
        intent=intent,
        ledger=_ledger(intent),
        caller_arn=PLAN_ARN,
        now=NOW + timedelta(minutes=1),
    )
    reviewed = finalize_founder_plan(
        intent=intent,
        ledger=plan_claim,
        change_set_id=CHANGE_SET_ID,
        plan_record_digest="sha256:" + "b" * 64,
        exception_digest="sha256:" + "c" * 64,
        now=NOW + timedelta(minutes=2),
    )
    apply_claim = claim_founder_apply(
        intent=intent,
        ledger=reviewed,
        caller_arn=APPLY_ARN,
        change_set_id=CHANGE_SET_ID,
        now=NOW + timedelta(minutes=26),
    )
    uncertain = finalize_founder_outcome(
        intent=intent,
        ledger=apply_claim,
        outcome="UNCERTAIN",
        now=NOW + timedelta(minutes=27),
    )
    uncertain["change_set_id"] = None
    with pytest.raises(FounderPepAuthorizationError, match="Change Set"):
        validate_founder_pep_ledger(_reseal_ledger(uncertain))

    with pytest.raises(FounderPepAuthorizationError, match="monotonic"):
        finalize_founder_outcome(
            intent=intent,
            ledger=apply_claim,
            outcome="UNCERTAIN",
            now=NOW + timedelta(minutes=25),
        )
