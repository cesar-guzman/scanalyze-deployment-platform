"""GUG-220 fail-closed Lambda audit permission-set contracts."""
from __future__ import annotations

import copy
import json
import subprocess
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator, FormatChecker, ValidationError
import tooling.platform_authority_lambda_audit_permission_set as audit_permission_set

from tooling.platform_authority_lambda_audit_permission_set import (
    AUTHORITY_ACCOUNT_ID,
    AUTHORITY_REGION,
    COLLECTOR_PERMISSION_SET_DESCRIPTION,
    COLLECTOR_PERMISSION_SET_NAME,
    EXPECTED_TAGS,
    MANAGEMENT_ACCOUNT_ID,
    AuditPermissionSetError,
    build_execution_ledger,
    build_provisioning_intent,
    build_provisioning_receipt,
    canonical_digest,
    digest_text,
    exact_permission_set_readback,
    render_exact_collector_policy,
    required_provisioning_actions,
    PROVISIONING_SOURCE_PATHS,
    validate_provisioning_source_commit_binding,
    validate_intent_execution_binding,
    validate_execution_ledger,
    validate_provisioning_intent,
    validate_provisioning_receipt,
)


REPO_ROOT = Path(__file__).resolve().parents[2]
INTENT_SCHEMA = REPO_ROOT / "schemas/platform-authority-lambda-audit-provisioning-intent.v1.schema.json"
RECEIPT_SCHEMA = REPO_ROOT / "schemas/platform-authority-lambda-audit-provisioning-receipt.v1.schema.json"
LEDGER_SCHEMA = REPO_ROOT / "schemas/platform-authority-lambda-audit-execution-ledger.v1.schema.json"
SYNTHETIC_PRINCIPAL = "synthetic-user-id"
SYNTHETIC_INSTANCE_ARN = "arn:aws:sso:::instance/ssoins-0123456789abcdef"
SYNTHETIC_IDENTITY_STORE_ID = "d-0123456789"
SYNTHETIC_SAML_PROVIDER_ARN = (
    "arn:aws:iam::042360977644:saml-provider/"
    "AWSSSO_0123456789abcdef_DO_NOT_DELETE"
)
SYNTHETIC_SOURCE_COMMIT = "a" * 40
NOW = datetime(2026, 7, 21, 12, 0, tzinfo=UTC)


def _intent() -> dict[str, Any]:
    return build_provisioning_intent(
        principal_id=SYNTHETIC_PRINCIPAL,
        identity_center_instance_arn=SYNTHETIC_INSTANCE_ARN,
        identity_store_id=SYNTHETIC_IDENTITY_STORE_ID,
        saml_provider_arn=SYNTHETIC_SAML_PROVIDER_ARN,
        source_commit=SYNTHETIC_SOURCE_COMMIT,
        execution_ledger_directory_id="/private/gug-220-ledgers",
        created_at=NOW,
        repo_root=REPO_ROOT,
    )


def _permission_set() -> dict[str, Any]:
    return {
        "PermissionSetArn": (
            "arn:aws:sso:::permissionSet/ssoins-0123456789abcdef/"
            "ps-fedcba9876543210"
        ),
        "Name": COLLECTOR_PERMISSION_SET_NAME,
        "Description": COLLECTOR_PERMISSION_SET_DESCRIPTION,
        "SessionDuration": "PT1H",
    }


def _assignment(permission_set_arn: str) -> dict[str, str]:
    return {
        "AccountId": AUTHORITY_ACCOUNT_ID,
        "PermissionSetArn": permission_set_arn,
        "PrincipalType": "USER",
        "PrincipalId": SYNTHETIC_PRINCIPAL,
    }


@pytest.mark.parametrize("schema_path", (INTENT_SCHEMA, RECEIPT_SCHEMA, LEDGER_SCHEMA))
def test_gug220_schemas_are_valid_draft_2020_12(schema_path: Path) -> None:
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)


def test_generated_records_validate_against_their_schemas() -> None:
    intent = _intent()
    ledger = build_execution_ledger(intent=intent, created_at=NOW)
    receipt = build_provisioning_receipt(
        intent=intent,
        status="PLAN_ONLY",
        permission_set_arn=None,
        role_arn=None,
        aws_mutation_attempted=False,
        ambiguous_response=False,
        binding_written=False,
        created_at=NOW,
    )
    for record, schema_path in (
        (intent, INTENT_SCHEMA),
        (ledger, LEDGER_SCHEMA),
        (receipt, RECEIPT_SCHEMA),
    ):
        validator = Draft202012Validator(
            json.loads(schema_path.read_text(encoding="utf-8")),
            format_checker=FormatChecker(),
        )
        validator.validate(record)


def test_readback_incomplete_receipt_is_ambiguous_without_claiming_a_write() -> None:
    intent = _intent()
    receipt = build_provisioning_receipt(
        intent=intent,
        status="READBACK_INCOMPLETE",
        permission_set_arn=_permission_set()["PermissionSetArn"],
        role_arn=None,
        aws_mutation_attempted=False,
        ambiguous_response=True,
        binding_written=False,
        created_at=NOW,
    )

    Draft202012Validator(
        json.loads(RECEIPT_SCHEMA.read_text(encoding="utf-8")),
        format_checker=FormatChecker(),
    ).validate(receipt)
    assert validate_provisioning_receipt(receipt, intent=intent)["status"] == (
        "READBACK_INCOMPLETE"
    )


def test_intent_is_digest_sealed_and_does_not_publish_raw_identity() -> None:
    intent = _intent()
    serialized = json.dumps(intent, sort_keys=True)

    assert intent["intent_digest"] == canonical_digest(
        {key: value for key, value in intent.items() if key != "intent_digest"}
    )
    assert SYNTHETIC_PRINCIPAL not in serialized
    assert AUTHORITY_ACCOUNT_ID not in serialized
    assert MANAGEMENT_ACCOUNT_ID not in serialized
    assert intent["principal_type"] == "USER"
    assert intent["direct_assignment_count"] == 1
    assert intent["provisioned_account_count"] == 1
    assert intent["independent_review_present"] is False
    assert intent["protected_retirement_authorized"] is False


def test_execution_ledger_is_digest_sealed_and_forbids_retry() -> None:
    intent = _intent()
    ledger = build_execution_ledger(intent=intent, created_at=NOW)

    assert validate_execution_ledger(ledger, intent=intent)["status"] == (
        "MUTATION_WINDOW_CONSUMED"
    )
    assert ledger["mutation_attempt_limit"] == 1
    assert ledger["mutation_retry_authorized"] is False

    ledger["mutation_retry_authorized"] = True
    ledger["ledger_digest"] = canonical_digest(
        {key: value for key, value in ledger.items() if key != "ledger_digest"}
    )
    with pytest.raises(AuditPermissionSetError):
        validate_execution_ledger(ledger, intent=intent)


def test_intent_is_bound_to_live_identity_center_and_expires_in_15_minutes() -> None:
    intent = _intent()

    assert intent["identity_center_instance_arn_digest"] == digest_text(
        SYNTHETIC_INSTANCE_ARN
    )
    assert intent["identity_store_id_digest"] == digest_text(
        SYNTHETIC_IDENTITY_STORE_ID
    )
    assert intent["saml_provider_arn_digest"] == digest_text(
        SYNTHETIC_SAML_PROVIDER_ARN
    )
    assert intent["source_commit"] == SYNTHETIC_SOURCE_COMMIT
    assert intent["created_at"] == "2026-07-21T12:00:00Z"
    assert intent["expires_at"] == "2026-07-21T12:15:00Z"
    validate_intent_execution_binding(
        intent,
        now=NOW + timedelta(minutes=14, seconds=59),
        identity_center_instance_arn=SYNTHETIC_INSTANCE_ARN,
        identity_store_id=SYNTHETIC_IDENTITY_STORE_ID,
        saml_provider_arn=SYNTHETIC_SAML_PROVIDER_ARN,
    )


def test_source_commit_binding_rejects_dirty_or_rebound_runtime(
    tmp_path: Path,
) -> None:
    repository = tmp_path / "repo"
    repository.mkdir()
    subprocess.run(["git", "init", "-q", repository], check=True)
    subprocess.run(
        ["git", "-C", repository, "config", "user.email", "test@example.invalid"],
        check=True,
    )
    subprocess.run(
        ["git", "-C", repository, "config", "user.name", "Synthetic Test"],
        check=True,
    )
    for relative in PROVISIONING_SOURCE_PATHS:
        target = repository / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(f"synthetic:{relative.as_posix()}\n", encoding="utf-8")
    subprocess.run(["git", "-C", repository, "add", "--all"], check=True)
    subprocess.run(
        ["git", "-C", repository, "commit", "-q", "-m", "synthetic baseline"],
        check=True,
    )
    source_commit = subprocess.run(
        ["git", "-C", repository, "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    validate_provisioning_source_commit_binding(
        source_commit=source_commit,
        repo_root=repository,
    )

    dirty = repository / PROVISIONING_SOURCE_PATHS[-1]
    dirty.write_text("unreviewed expansion\n", encoding="utf-8")
    with pytest.raises(
        AuditPermissionSetError,
        match="SOURCE_COMMIT_BINDING_INVALID",
    ):
        validate_provisioning_source_commit_binding(
            source_commit=source_commit,
            repo_root=repository,
        )

    subprocess.run(["git", "-C", repository, "add", "--all"], check=True)
    subprocess.run(
        ["git", "-C", repository, "commit", "-q", "-m", "unreviewed rebound"],
        check=True,
    )
    with pytest.raises(
        AuditPermissionSetError,
        match="SOURCE_COMMIT_BINDING_INVALID",
    ):
        validate_provisioning_source_commit_binding(
            source_commit=source_commit,
            repo_root=repository,
        )


def test_source_commit_binding_rejects_nonexistent_commit(tmp_path: Path) -> None:
    repository = tmp_path / "repo"
    repository.mkdir()
    subprocess.run(["git", "init", "-q", repository], check=True)

    with pytest.raises(
        AuditPermissionSetError,
        match="SOURCE_COMMIT_BINDING_INVALID",
    ):
        validate_provisioning_source_commit_binding(
            source_commit="f" * 40,
            repo_root=repository,
        )


def test_sealed_policy_rejects_a_rendered_digest_outside_the_intent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    intent = _intent()
    intent["collector_inline_policy_digest"] = "sha256:" + "f" * 64
    monkeypatch.setattr(
        audit_permission_set,
        "validate_provisioning_source_commit_binding",
        lambda **_: None,
    )

    with pytest.raises(
        AuditPermissionSetError,
        match="SEALED_COLLECTOR_POLICY_MISMATCH",
    ):
        audit_permission_set.sealed_collector_policy_for_intent(
            intent,
            repo_root=REPO_ROOT,
        )


@pytest.mark.parametrize(
    ("now", "instance_arn", "identity_store_id", "saml_provider_arn"),
    (
        (
            NOW + timedelta(minutes=15),
            SYNTHETIC_INSTANCE_ARN,
            SYNTHETIC_IDENTITY_STORE_ID,
            SYNTHETIC_SAML_PROVIDER_ARN,
        ),
        (
            NOW + timedelta(minutes=1),
            "arn:aws:sso:::instance/ssoins-fedcba9876543210",
            SYNTHETIC_IDENTITY_STORE_ID,
            SYNTHETIC_SAML_PROVIDER_ARN,
        ),
        (
            NOW + timedelta(minutes=1),
            SYNTHETIC_INSTANCE_ARN,
            "d-9876543210",
            SYNTHETIC_SAML_PROVIDER_ARN,
        ),
        (
            NOW + timedelta(minutes=1),
            SYNTHETIC_INSTANCE_ARN,
            SYNTHETIC_IDENTITY_STORE_ID,
            (
                "arn:aws:iam::042360977644:saml-provider/"
                "AWSSSO_fedcba9876543210_DO_NOT_DELETE"
            ),
        ),
    ),
    ids=(
        "expired",
        "instance-rebound",
        "identity-store-rebound",
        "saml-provider-rebound",
    ),
)
def test_intent_execution_binding_rejects_expiry_or_rebinding(
    now: datetime,
    instance_arn: str,
    identity_store_id: str,
    saml_provider_arn: str,
) -> None:
    with pytest.raises(AuditPermissionSetError):
        validate_intent_execution_binding(
            _intent(),
            now=now,
            identity_center_instance_arn=instance_arn,
            identity_store_id=identity_store_id,
            saml_provider_arn=saml_provider_arn,
        )


def test_collector_policy_reuses_the_exact_gug219_template() -> None:
    rendered = render_exact_collector_policy(REPO_ROOT)
    statements = rendered["Statement"]
    serialized = json.dumps(rendered, sort_keys=True)

    assert "sso-admin:" not in serialized
    assert "lambda:InvokeFunction" not in serialized
    assert {
        "Sid": "DenyRoleChaining",
        "Effect": "Deny",
        "Action": "sts:AssumeRole",
        "Resource": "*",
    } in statements
    allowed_actions = {
        action
        for statement in statements
        if statement["Effect"] == "Allow"
        for action in (
            statement["Action"]
            if isinstance(statement["Action"], list)
            else [statement["Action"]]
        )
    }
    deny_unreviewed = next(
        item for item in statements if item["Sid"] == "DenyUnreviewedActions"
    )
    assert set(deny_unreviewed["NotAction"]) == allowed_actions
    assert next(
        item for item in statements if item["Sid"] == "ListAccountLambdaSurface"
    )["Resource"] == f"arn:aws:lambda:*:{AUTHORITY_ACCOUNT_ID}:function:*"
    assert next(
        item
        for item in statements
        if item["Sid"] == "DiscoverCompleteLambdaSurface"
    )["Resource"] == "*"
    assert next(
        item
        for item in statements
        if item["Sid"] == "DenyGetPolicyOutsideExactBroker"
    ) == {
        "Sid": "DenyGetPolicyOutsideExactBroker",
        "Effect": "Deny",
        "Action": "lambda:GetPolicy",
        "NotResource": [
            audit_permission_set.target_binding().function_arn,
            f"{audit_permission_set.target_binding().function_arn}:*",
        ],
    }
    assert next(
        item
        for item in statements
        if item["Sid"] == "DenyFunctionReadsOutsideAuthorityAccount"
    ) == {
        "Sid": "DenyFunctionReadsOutsideAuthorityAccount",
        "Effect": "Deny",
        "Action": [
            "lambda:ListAliases",
            "lambda:ListFunctionEventInvokeConfigs",
            "lambda:ListFunctionUrlConfigs",
            "lambda:ListVersionsByFunction",
        ],
        "NotResource": (
            f"arn:aws:lambda:*:{AUTHORITY_ACCOUNT_ID}:function:*"
        ),
    }
    assert any(item["Effect"] == "Deny" for item in statements)


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("permission_set_name", "AdministratorAccess"),
        ("session_duration", "PT8H"),
        ("relay_state_present", True),
        ("managed_policy_arns", ["arn:aws:iam::aws:policy/ReadOnlyAccess"]),
        ("permissions_boundary_present", True),
        ("direct_assignment_count", 2),
        ("independent_review_present", True),
        ("protected_retirement_authorized", True),
    ),
)
def test_intent_rejects_authority_expansion(field: str, value: object) -> None:
    intent = _intent()
    intent[field] = value
    intent["intent_digest"] = canonical_digest(
        {key: item for key, item in intent.items() if key != "intent_digest"}
    )

    with pytest.raises(AuditPermissionSetError):
        validate_provisioning_intent(intent, repo_root=REPO_ROOT)


def test_readback_accepts_only_the_sealed_policy_without_rerender(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    permission_set = _permission_set()
    policy = render_exact_collector_policy(REPO_ROOT)
    monkeypatch.setattr(
        audit_permission_set,
        "render_exact_collector_policy",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("readback must not reopen the worktree")
        ),
    )

    result = exact_permission_set_readback(
        permission_set=permission_set,
        tags=[{"Key": key, "Value": value} for key, value in EXPECTED_TAGS.items()],
        inline_policy=policy,
        managed_policies=[],
        customer_managed_policy_references=[],
        permissions_boundary=None,
        assignments=[_assignment(permission_set["PermissionSetArn"])],
        provisioned_account_ids=[AUTHORITY_ACCOUNT_ID],
        expected_principal_id=SYNTHETIC_PRINCIPAL,
        expected_inline_policy=policy,
    )

    assert result["permission_set_arn"] == permission_set["PermissionSetArn"]
    assert result["collector_inline_policy_digest"] == canonical_digest(policy)


@pytest.mark.parametrize(
    "mutation",
    (
        "description",
        "relay",
        "tags",
        "inline_policy",
        "managed_policy",
        "customer_policy",
        "boundary",
        "foreign_assignment",
        "foreign_account",
    ),
)
def test_readback_rejects_drift(mutation: str) -> None:
    permission_set = _permission_set()
    tags = [{"Key": key, "Value": value} for key, value in EXPECTED_TAGS.items()]
    policy = render_exact_collector_policy(REPO_ROOT)
    managed: list[dict[str, str]] = []
    customer: list[dict[str, str]] = []
    boundary: dict[str, str] | None = None
    assignments = [_assignment(permission_set["PermissionSetArn"])]
    accounts = [AUTHORITY_ACCOUNT_ID]

    if mutation == "description":
        permission_set["Description"] = "drift"
    elif mutation == "relay":
        permission_set["RelayState"] = "https://example.invalid"
    elif mutation == "tags":
        tags[0]["Value"] = "foreign"
    elif mutation == "inline_policy":
        policy = copy.deepcopy(policy)
        policy["Statement"][0]["Action"] = "sso-admin:ListInstances"
    elif mutation == "managed_policy":
        managed = [{"Arn": "arn:aws:iam::aws:policy/ReadOnlyAccess"}]
    elif mutation == "customer_policy":
        customer = [{"Name": "foreign", "Path": "/"}]
    elif mutation == "boundary":
        boundary = {"ManagedPolicyArn": "arn:aws:iam::aws:policy/ReadOnlyAccess"}
    elif mutation == "foreign_assignment":
        assignments[0]["PrincipalId"] = "foreign-user"
    else:
        accounts = [AUTHORITY_ACCOUNT_ID, "111122223333"]

    with pytest.raises(AuditPermissionSetError):
        exact_permission_set_readback(
            permission_set=permission_set,
            tags=tags,
            inline_policy=policy,
            managed_policies=managed,
            customer_managed_policy_references=customer,
            permissions_boundary=boundary,
            assignments=assignments,
            provisioned_account_ids=accounts,
            expected_principal_id=SYNTHETIC_PRINCIPAL,
            expected_inline_policy=render_exact_collector_policy(REPO_ROOT),
        )


def test_receipt_cannot_overclaim_live_or_independent_approval() -> None:
    intent = _intent()
    receipt = build_provisioning_receipt(
        intent=intent,
        status="READBACK_VERIFIED",
        permission_set_arn=_permission_set()["PermissionSetArn"],
        role_arn=(
            "arn:aws:iam::042360977644:role/aws-reserved/sso.amazonaws.com/"
            "AWSReservedSSO_ScanalyzeAuthorityLambdaAudit_0123456789abcdef"
        ),
        aws_mutation_attempted=True,
        ambiguous_response=False,
        binding_written=True,
        created_at=NOW,
    )

    assert validate_provisioning_receipt(receipt, intent=intent)["status"] == (
        "READBACK_VERIFIED"
    )
    assert receipt["approval_authorized"] is False
    assert receipt["protected_retirement_authorized"] is False
    assert receipt["production_authorized"] is False
    assert AUTHORITY_ACCOUNT_ID not in json.dumps(receipt, sort_keys=True)

    receipt["production_authorized"] = True
    receipt["receipt_digest"] = canonical_digest(
        {key: value for key, value in receipt.items() if key != "receipt_digest"}
    )
    with pytest.raises(AuditPermissionSetError):
        validate_provisioning_receipt(receipt, intent=intent)


@pytest.mark.parametrize(
    ("permission_set_arn", "role_arn"),
    (
        (
            None,
            "arn:aws:iam::042360977644:role/aws-reserved/sso.amazonaws.com/"
            "AWSReservedSSO_ScanalyzeAuthorityLambdaAudit_0123456789abcdef",
        ),
        (_permission_set()["PermissionSetArn"], None),
        (
            "not-an-arn",
            "arn:aws:iam::042360977644:role/aws-reserved/sso.amazonaws.com/"
            "AWSReservedSSO_ScanalyzeAuthorityLambdaAudit_0123456789abcdef",
        ),
        (
            _permission_set()["PermissionSetArn"],
            "arn:aws:iam::111122223333:role/aws-reserved/sso.amazonaws.com/"
            "AWSReservedSSO_ScanalyzeAuthorityLambdaAudit_0123456789abcdef",
        ),
    ),
    ids=(
        "missing-permission-set",
        "missing-role",
        "malformed-permission-set",
        "foreign-role",
    ),
)
def test_readback_verified_builder_requires_both_verified_resources(
    permission_set_arn: str | None,
    role_arn: str | None,
) -> None:
    with pytest.raises(AuditPermissionSetError):
        build_provisioning_receipt(
            intent=_intent(),
            status="READBACK_VERIFIED",
            permission_set_arn=permission_set_arn,
            role_arn=role_arn,
            aws_mutation_attempted=True,
            ambiguous_response=False,
            binding_written=False,
            created_at=NOW,
        )


@pytest.mark.parametrize(
    ("permission_set_arn", "role_arn"),
    (
        ("not-an-arn", None),
        (None, "not-an-arn"),
        ({"unexpected": "shape"}, None),
    ),
)
def test_non_verified_receipt_rejects_any_malformed_observed_arn(
    permission_set_arn: object,
    role_arn: object,
) -> None:
    with pytest.raises(AuditPermissionSetError):
        build_provisioning_receipt(
            intent=_intent(),
            status="BLOCKED_DRIFT",
            permission_set_arn=permission_set_arn,  # type: ignore[arg-type]
            role_arn=role_arn,  # type: ignore[arg-type]
            aws_mutation_attempted=False,
            ambiguous_response=False,
            binding_written=False,
            created_at=NOW,
        )


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("permission_set_arn_digest", None),
        ("collector_role_iam_arn_digest", None),
        ("account_assignment_verified", False),
        ("permission_set_provisioning_verified", False),
        ("collector_role_verified", False),
        ("ambiguous_response", True),
    ),
)
def test_readback_verified_schema_and_semantics_require_complete_proof(
    field: str,
    value: object,
) -> None:
    receipt = build_provisioning_receipt(
        intent=_intent(),
        status="READBACK_VERIFIED",
        permission_set_arn=_permission_set()["PermissionSetArn"],
        role_arn=(
            "arn:aws:iam::042360977644:role/aws-reserved/sso.amazonaws.com/"
            "AWSReservedSSO_ScanalyzeAuthorityLambdaAudit_0123456789abcdef"
        ),
        aws_mutation_attempted=True,
        ambiguous_response=False,
        binding_written=False,
        created_at=NOW,
    )
    receipt[field] = value
    receipt["receipt_digest"] = canonical_digest(
        {key: item for key, item in receipt.items() if key != "receipt_digest"}
    )

    validator = Draft202012Validator(
        json.loads(RECEIPT_SCHEMA.read_text(encoding="utf-8")),
        format_checker=FormatChecker(),
    )
    with pytest.raises(ValidationError):
        validator.validate(receipt)
    with pytest.raises(AuditPermissionSetError):
        validate_provisioning_receipt(receipt, intent=_intent())


def test_non_verified_receipt_cannot_claim_verified_role() -> None:
    intent = _intent()
    receipt = build_provisioning_receipt(
        intent=intent,
        status="PLAN_ONLY",
        permission_set_arn=None,
        role_arn=None,
        aws_mutation_attempted=False,
        ambiguous_response=False,
        binding_written=False,
        created_at=NOW,
    )
    receipt["collector_role_verified"] = True
    receipt["receipt_digest"] = canonical_digest(
        {key: item for key, item in receipt.items() if key != "receipt_digest"}
    )

    validator = Draft202012Validator(
        json.loads(RECEIPT_SCHEMA.read_text(encoding="utf-8")),
        format_checker=FormatChecker(),
    )
    with pytest.raises(ValidationError):
        validator.validate(receipt)
    with pytest.raises(AuditPermissionSetError):
        validate_provisioning_receipt(receipt, intent=intent)


@pytest.mark.parametrize(
    ("status", "attempted", "ambiguous"),
    (
        ("PLAN_ONLY", True, False),
        ("BLOCKED_DRIFT", True, False),
        ("UNCERTAIN_RECONCILE_ONLY", False, False),
        ("READBACK_INCOMPLETE", True, True),
        ("READBACK_INCOMPLETE", False, False),
    ),
)
def test_receipt_status_cannot_contradict_effect_evidence(
    status: str,
    attempted: bool,
    ambiguous: bool,
) -> None:
    with pytest.raises(AuditPermissionSetError):
        build_provisioning_receipt(
            intent=_intent(),
            status=status,
            permission_set_arn=None,
            role_arn=None,
            aws_mutation_attempted=attempted,
            ambiguous_response=ambiguous,
            binding_written=False,
            created_at=NOW,
        )


@pytest.mark.parametrize(
    ("partial_state", "expected"),
    (
        (
            {
                "inline_policy_present": False,
                "assignment_present": True,
                "provisioning_present": True,
            },
            ("put_inline_policy", "provision"),
        ),
        (
            {
                "inline_policy_present": True,
                "assignment_present": False,
                "provisioning_present": True,
            },
            ("create_assignment",),
        ),
        (
            {
                "inline_policy_present": True,
                "assignment_present": True,
                "provisioning_present": False,
            },
            ("provision",),
        ),
    ),
)
def test_required_provisioning_actions_are_ordered_and_policy_change_reprovisions(
    partial_state: dict[str, bool],
    expected: tuple[str, ...],
) -> None:
    assert required_provisioning_actions(partial_state) == expected
