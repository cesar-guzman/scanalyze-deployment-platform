"""Fail-closed GUG-221 two-phase handoff and provider evidence tests."""

from __future__ import annotations

from copy import deepcopy
from datetime import UTC, datetime, timedelta
import inspect
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest


ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import tooling.platform_authority_lambda_audit_repair_change_set as module  # noqa: E402
from tooling.platform_authority_lambda_audit_permission_set import (  # noqa: E402
    COLLECTOR_PERMISSION_SET_DESCRIPTION,
    COLLECTOR_PERMISSION_SET_NAME,
    EXPECTED_TAGS,
    SESSION_DURATION,
)
from tooling.platform_authority_lambda_audit_repair_change_set import (  # noqa: E402
    AUTHORITY_ACCOUNT_ID,
    DEPLOYMENT_CONTRACT_TYPE,
    EXPECTED_MANAGEMENT_PROFILE,
    EXPECTED_PROFILE,
    MANAGEMENT_ACCOUNT_ID,
    REGION,
    ChangeSetHandoffError,
    _gug220_ledger_parameter_digest,
    _require_fresh_gug220_evidence,
    collect_gug220_live_evidence_read_only,
    read_private_json,
    validate_deployment_contract,
    validate_gug220_evidence_chain,
)
from tooling.platform_authority_lambda_invocation_authority import (  # noqa: E402
    canonical_digest,
    digest_text,
)


NOW = datetime(2026, 7, 22, 12, 30, tzinfo=UTC)
INSTANCE_ARN = "arn:aws:sso:::instance/ssoins-1234567890abcdef"
STORE_ID = "d-0123456789"
PRINCIPAL_ID = "0123456789-12345678-1234-1234-1234-123456789abc"
COLLECTOR_ARN = (
    "arn:aws:sso:::permissionSet/ssoins-1234567890abcdef/"
    "ps-1234567890abcdef"
)
SAML_ARN = (
    "arn:aws:iam::042360977644:saml-provider/"
    "AWSSSO_0123456789abcdef_DO_NOT_DELETE"
)


def _contract() -> dict:
    return {
        "artifact_type": DEPLOYMENT_CONTRACT_TYPE,
        "schema_version": 1,
        "work_package": "GUG-221",
        "authority_account_id": AUTHORITY_ACCOUNT_ID,
        "management_account_id": MANAGEMENT_ACCOUNT_ID,
        "source_commit": "1" * 40,
        "repair_not_before": "2026-07-22T12:30:00Z",
        "repair_not_after": "2026-07-22T12:45:00Z",
        "delegation_change_set_creator_arn": (
            "arn:aws:sts::839393571433:assumed-role/"
            "AWSReservedSSO_ScanalyzeFounderPepSeed_0123456789abcdef/"
            "synthetic@example.invalid"
        ),
        "delegation_change_set_executor_arn": (
            "arn:aws:sts::839393571433:assumed-role/"
            "AWSReservedSSO_ScanalyzeFounderPepSeed_0123456789abcdef/"
            "synthetic@example.invalid"
        ),
        "pep_change_set_creator_arn": (
            "arn:aws:sts::042360977644:assumed-role/"
            "AWSReservedSSO_ScanalyzeFounderBootstrapPlan_0123456789abcdef/"
            "synthetic@example.invalid"
        ),
        "production_status": "NO-GO",
    }


def _chain() -> tuple[dict, dict, dict]:
    intent = {
        "intent_digest": "sha256:" + "a" * 64,
        "identity_center_instance_arn_digest": digest_text(INSTANCE_ARN),
        "identity_store_id_digest": digest_text(STORE_ID),
        "saml_provider_arn_digest": digest_text(SAML_ARN),
        "principal_id_digest": digest_text(PRINCIPAL_ID),
        "collector_inline_policy_digest": "sha256:" + "b" * 64,
        "expected_tags_digest": canonical_digest(EXPECTED_TAGS),
    }
    ledger = {
        "ledger_digest": "sha256:" + "c" * 64,
        "status": "MUTATION_WINDOW_CONSUMED",
        "mutation_attempt_limit": 1,
        "mutation_retry_authorized": False,
    }
    receipt = {
        "receipt_digest": "sha256:" + "d" * 64,
        "status": "UNCERTAIN_RECONCILE_ONLY",
        "permission_set_arn_digest": digest_text(COLLECTOR_ARN),
        "aws_mutation_attempted": True,
        "ambiguous_response": True,
        "mutation_retry_attempted": False,
    }
    return intent, ledger, receipt


class Sts:
    def __init__(self, account: str) -> None:
        self.account = account

    def get_caller_identity(self) -> dict:
        if self.account == MANAGEMENT_ACCOUNT_ID:
            role = "AWSReservedSSO_AWSReadOnlyAccess_0123456789abcdef"
        else:
            role = "AWSReservedSSO_AWSReadOnlyAccess_1c38063fd41ea692"
        return {
            "Account": self.account,
            "Arn": (
                f"arn:aws:sts::{self.account}:assumed-role/{role}/"
                "synthetic@example.invalid"
            ),
        }


class SsoAdmin:
    def __init__(
        self,
        *,
        pending: bool = False,
        assigned_account: str | None = None,
        repeated_instance_token: bool = False,
        duplicate_instance: bool = False,
        customer_kms_arn: str | None = None,
    ) -> None:
        self.pending = pending
        self.assigned_account = assigned_account
        self.repeated_instance_token = repeated_instance_token
        self.duplicate_instance = duplicate_instance
        self.customer_kms_arn = customer_kms_arn

    def list_instances(self, **kwargs: object) -> dict:
        if self.repeated_instance_token:
            assert kwargs in ({}, {"NextToken": "repeat"})
        else:
            assert not kwargs
        instance = {
            "InstanceArn": INSTANCE_ARN,
            "IdentityStoreId": STORE_ID,
            "OwnerAccountId": MANAGEMENT_ACCOUNT_ID,
            "Status": "ACTIVE",
        }
        result = {"Instances": [instance] * (2 if self.duplicate_instance else 1)}
        if self.repeated_instance_token:
            result["NextToken"] = "repeat"
        return result

    def describe_instance(self, **kwargs: object) -> dict:
        assert kwargs == {"InstanceArn": INSTANCE_ARN}
        encryption = (
            {
                "KeyType": "CUSTOMER_MANAGED_KEY",
                "KmsKeyArn": self.customer_kms_arn,
                "EncryptionStatus": "ENABLED",
            }
            if self.customer_kms_arn
            else {
                "KeyType": "AWS_OWNED_KMS_KEY",
                "EncryptionStatus": "ENABLED",
            }
        )
        return {
            "InstanceArn": INSTANCE_ARN,
            "IdentityStoreId": STORE_ID,
            "OwnerAccountId": MANAGEMENT_ACCOUNT_ID,
            "Status": "ACTIVE",
            "EncryptionConfigurationDetails": encryption,
        }

    def list_permission_sets(self, **kwargs: object) -> dict:
        assert kwargs == {"InstanceArn": INSTANCE_ARN}
        return {"PermissionSets": [COLLECTOR_ARN]}

    def describe_permission_set(self, **kwargs: object) -> dict:
        assert kwargs == {
            "InstanceArn": INSTANCE_ARN,
            "PermissionSetArn": COLLECTOR_ARN,
        }
        return {
            "PermissionSet": {
                "PermissionSetArn": COLLECTOR_ARN,
                "Name": COLLECTOR_PERMISSION_SET_NAME,
                "Description": COLLECTOR_PERMISSION_SET_DESCRIPTION,
                "SessionDuration": SESSION_DURATION,
            }
        }

    def list_tags_for_resource(self, **kwargs: object) -> dict:
        assert kwargs == {"InstanceArn": INSTANCE_ARN, "ResourceArn": COLLECTOR_ARN}
        return {
            "Tags": [
                {"Key": key, "Value": value}
                for key, value in sorted(EXPECTED_TAGS.items())
            ]
        }

    def get_inline_policy_for_permission_set(self, **kwargs: object) -> dict:
        return {}

    def list_managed_policies_in_permission_set(self, **kwargs: object) -> dict:
        return {"AttachedManagedPolicies": []}

    def list_customer_managed_policy_references_in_permission_set(
        self, **kwargs: object
    ) -> dict:
        return {"CustomerManagedPolicyReferences": []}

    def get_permissions_boundary_for_permission_set(self, **kwargs: object) -> dict:
        return {}

    def list_account_assignments(self, **kwargs: object) -> dict:
        assert kwargs["PermissionSetArn"] == COLLECTOR_ARN
        assignments = []
        if kwargs["AccountId"] == self.assigned_account:
            assignments = [
                {
                    "AccountId": kwargs["AccountId"],
                    "PermissionSetArn": COLLECTOR_ARN,
                    "PrincipalType": "USER",
                    "PrincipalId": PRINCIPAL_ID,
                }
            ]
        return {"AccountAssignments": assignments}

    def list_accounts_for_provisioned_permission_set(self, **kwargs: object) -> dict:
        return {"AccountIds": []}

    def list_account_assignment_creation_status(self, **kwargs: object) -> dict:
        pending = [{"Status": "IN_PROGRESS", "RequestId": "synthetic"}] if self.pending else []
        return {"AccountAssignmentsCreationStatus": pending}

    def list_account_assignment_deletion_status(self, **kwargs: object) -> dict:
        return {"AccountAssignmentsDeletionStatus": []}

    def list_permission_set_provisioning_status(self, **kwargs: object) -> dict:
        return {"PermissionSetsProvisioningStatus": []}


class IdentityStore:
    malformed_extra = False

    def list_users(self, **kwargs: object) -> dict:
        users: list[object] = [{"UserId": PRINCIPAL_ID}]
        if self.malformed_extra:
            users.append({"UserName": "malformed"})
        return {"Users": users}

    def describe_user(self, **kwargs: object) -> dict:
        return {"UserId": PRINCIPAL_ID}


class Organizations:
    def __init__(
        self, *, states: tuple[str, str] = ("ACTIVE", "ACTIVE"), status_only: bool = False
    ) -> None:
        self.states = states
        self.status_only = status_only

    def list_accounts(self, **kwargs: object) -> dict:
        assert not kwargs
        state_key = "Status" if self.status_only else "State"
        return {
            "Accounts": [
                {"Id": MANAGEMENT_ACCOUNT_ID, state_key: self.states[0]},
                {"Id": AUTHORITY_ACCOUNT_ID, state_key: self.states[1]},
            ]
        }


class Kms:
    def __init__(self, *, key_arn: str | None = None, enabled: bool = True) -> None:
        self.key_arn = key_arn
        self.enabled = enabled

    def describe_key(self, **kwargs: object) -> dict:
        if self.key_arn is None:  # pragma: no cover - AWS-owned path
            raise AssertionError("AWS-owned KMS must not call DescribeKey")
        assert kwargs == {"KeyId": self.key_arn}
        return {
            "KeyMetadata": {
                "Arn": self.key_arn,
                "AWSAccountId": MANAGEMENT_ACCOUNT_ID,
                "Enabled": self.enabled,
                "KeyManager": "CUSTOMER",
                "KeyState": "Enabled" if self.enabled else "Disabled",
                "KeyUsage": "ENCRYPT_DECRYPT",
                "Origin": "AWS_KMS",
                "MultiRegion": False,
            }
        }


class Iam:
    def __init__(self, *, rotating_saml: bool = False) -> None:
        self.rotating_saml = rotating_saml
        self.saml_reads = 0

    def list_saml_providers(self, **kwargs: object) -> dict:
        assert not kwargs
        return {"SAMLProviderList": [{"Arn": SAML_ARN}], "IsTruncated": False}

    def get_saml_provider(self, **kwargs: object) -> dict:
        assert kwargs == {"SAMLProviderArn": SAML_ARN}
        self.saml_reads += 1
        suffix = str(self.saml_reads) if self.rotating_saml else "stable"
        return {"SAMLMetadataDocument": "<xml>" + suffix + "</xml>"}

    def list_roles(self, **kwargs: object) -> dict:
        assert kwargs == {"PathPrefix": "/aws-reserved/sso.amazonaws.com/"}
        return {"Roles": [], "IsTruncated": False}


def _collect(
    monkeypatch: pytest.MonkeyPatch,
    *,
    identitystore: IdentityStore | None = None,
    iam: Iam | None = None,
    sso: SsoAdmin | None = None,
    kms: Kms | None = None,
    organizations: Organizations | None = None,
) -> tuple[dict, tuple[dict, dict, dict]]:
    chain = _chain()
    monkeypatch.setattr(
        module,
        "_validate_gug220_consumed_chain",
        lambda **kwargs: chain,
    )
    evidence = collect_gug220_live_evidence_read_only(
        source_root=ROOT,
        deployment_contract=_contract(),
        gug220_intent=chain[0],
        gug220_ledger=chain[1],
        gug220_receipt=chain[2],
        management_profile_name=EXPECTED_MANAGEMENT_PROFILE,
        authority_profile_name=EXPECTED_PROFILE,
        region=REGION,
        management_sts_client=Sts(MANAGEMENT_ACCOUNT_ID),
        management_sso_admin_client=sso or SsoAdmin(),
        management_identitystore_client=identitystore or IdentityStore(),
        management_kms_client=kms or Kms(),
        management_organizations_client=organizations or Organizations(),
        authority_sts_client=Sts(AUTHORITY_ACCOUNT_ID),
        authority_iam_client=iam or Iam(),
        now=NOW,
    )
    return dict(evidence), chain


def test_provider_collector_derives_exact_partial_state_twice(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    evidence, chain = _collect(monkeypatch)
    assert evidence["identity_center_instance_arn"] == INSTANCE_ARN
    assert evidence["identity_store_id"] == STORE_ID
    assert evidence["principal_id"] == PRINCIPAL_ID
    assert evidence["collector_permission_set_arn"] == COLLECTOR_ARN
    assert evidence["collector_account_assignments"] == []
    assert evidence["collector_provisioned_account_ids"] == []
    assert evidence["collector_role_present"] is False
    assert evidence["identity_center_kms_mode"] == "AWS_OWNED_KMS_KEY"
    assert evidence["identity_center_kms_key_arn"] is None
    derived = validate_gug220_evidence_chain(
        source_root=ROOT,
        deployment_contract=_contract(),
        intent=chain[0],
        ledger=chain[1],
        receipt=chain[2],
        evidence=evidence,
    )
    assert derived["original_gug220_ledger_digest"] == "sha256:" + "c" * 64
    handoff = module.build_delegation_parameter_handoff(
        source_root=ROOT,
        deployment_contract=_contract(),
        gug220_intent=chain[0],
        gug220_ledger=chain[1],
        gug220_receipt=chain[2],
        gug220_evidence=evidence,
        delegation_template_bytes=(
            ROOT / module.DELEGATION_TEMPLATE_PATH
        ).read_bytes(),
    )
    assert len(handoff["parameters"]) == 10
    assert handoff["authority_status"] == "NON_AUTHORITATIVE_DERIVATION_ONLY"


def test_offline_self_digested_evidence_cannot_authorize(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fresh, chain = _collect(monkeypatch)
    forged = deepcopy(fresh)
    forged["collector_permission_set_metadata_sha256"] = "f" * 64
    forged["provider_state_sha256"] = "e" * 64
    forged["evidence_digest"] = canonical_digest(
        {key: value for key, value in forged.items() if key != "evidence_digest"}
    )
    validate_gug220_evidence_chain(
        source_root=ROOT,
        deployment_contract=_contract(),
        intent=chain[0],
        ledger=chain[1],
        receipt=chain[2],
        evidence=forged,
    )
    with pytest.raises(
        ChangeSetHandoffError, match="GUG220_EVIDENCE_PROVIDER_READBACK_DRIFT"
    ):
        _require_fresh_gug220_evidence(
            supplied=forged,
            fresh=fresh,
            validation_kwargs={
                "source_root": ROOT,
                "deployment_contract": _contract(),
                "intent": chain[0],
                "ledger": chain[1],
                "receipt": chain[2],
            },
        )


def test_two_provider_snapshots_must_be_identical(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with pytest.raises(
        ChangeSetHandoffError,
        match="GUG220_PROVIDER_STATE_CHANGED_DURING_READBACK",
    ):
        _collect(monkeypatch, iam=Iam(rotating_saml=True))


def test_malformed_extra_provider_entries_fail_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    identitystore = IdentityStore()
    identitystore.malformed_extra = True
    with pytest.raises(
        ChangeSetHandoffError, match="GUG220_PRINCIPAL_ENUMERATION_MALFORMED"
    ):
        _collect(monkeypatch, identitystore=identitystore)


def test_pending_identity_center_operation_blocks_snapshot(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with pytest.raises(ChangeSetHandoffError, match="GUG220_PENDING_OPERATION_PRESENT"):
        _collect(monkeypatch, sso=SsoAdmin(pending=True))


def test_assignment_in_any_organization_account_blocks_snapshot(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with pytest.raises(ChangeSetHandoffError, match="GUG220_PARTIAL_STATE_DRIFT"):
        _collect(
            monkeypatch,
            sso=SsoAdmin(assigned_account=MANAGEMENT_ACCOUNT_ID),
        )


@pytest.mark.parametrize(
    "state",
    ["PENDING_ACTIVATION", "ACTIVE", "SUSPENDED", "PENDING_CLOSURE", "CLOSED"],
)
def test_organization_account_state_contract_accepts_current_aws_states(
    monkeypatch: pytest.MonkeyPatch, state: str
) -> None:
    evidence, _ = _collect(
        monkeypatch,
        organizations=Organizations(states=(state, "ACTIVE")),
    )
    assert evidence["collector_account_assignments"] == []


def test_deprecated_organization_account_status_field_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with pytest.raises(
        ChangeSetHandoffError,
        match="GUG220_ORGANIZATION_ACCOUNT_ENUMERATION_MALFORMED",
    ):
        _collect(monkeypatch, organizations=Organizations(status_only=True))


def test_repeated_provider_pagination_token_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with pytest.raises(ChangeSetHandoffError, match="PROVIDER_PAGINATION_INVALID"):
        _collect(monkeypatch, sso=SsoAdmin(repeated_instance_token=True))


def test_provider_digest_match_must_be_unique(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with pytest.raises(ChangeSetHandoffError, match="GUG220_INSTANCE_NOT_UNIQUE"):
        _collect(monkeypatch, sso=SsoAdmin(duplicate_instance=True))


def test_customer_managed_identity_center_key_requires_exact_describe_key(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    key_arn = (
        "arn:aws:kms:us-east-1:839393571433:key/"
        "12345678-1234-4234-8234-123456789abc"
    )
    evidence, _ = _collect(
        monkeypatch,
        sso=SsoAdmin(customer_kms_arn=key_arn),
        kms=Kms(key_arn=key_arn),
    )
    assert evidence["identity_center_kms_mode"] == "CUSTOMER_MANAGED_KEY"
    assert evidence["identity_center_kms_key_arn"] == key_arn

    with pytest.raises(ChangeSetHandoffError, match="GUG220_INSTANCE_KMS_KEY_DRIFT"):
        _collect(
            monkeypatch,
            sso=SsoAdmin(customer_kms_arn=key_arn),
            kms=Kms(key_arn=key_arn, enabled=False),
        )


def test_deployment_contract_rejects_raw_authority() -> None:
    contract = _contract()
    validate_deployment_contract(contract)
    for field, value in (
        ("principal_id", PRINCIPAL_ID),
        ("collector_permission_set_arn", COLLECTOR_ARN),
        ("repair_invoker_permission_set_arn", COLLECTOR_ARN),
        ("gug220_ledger_digest", "sha256:" + "c" * 64),
        ("identity_center_instance_arn", INSTANCE_ARN),
    ):
        forged = {**contract, field: value}
        with pytest.raises(ChangeSetHandoffError, match="DEPLOYMENT_CONTRACT_INVALID"):
            validate_deployment_contract(forged)


def test_gug220_digest_is_prefixed_in_evidence_and_plain_only_at_cfn_boundary() -> None:
    prefixed = "sha256:" + "c" * 64
    assert _gug220_ledger_parameter_digest(prefixed) == "c" * 64
    for invalid in ("c" * 64, "sha256:" + "C" * 64, "sha512:" + "c" * 64):
        with pytest.raises(ChangeSetHandoffError, match="GUG220_LEDGER_DIGEST_INVALID"):
            _gug220_ledger_parameter_digest(invalid)


def test_private_json_rejects_duplicate_keys(tmp_path: Path) -> None:
    source = tmp_path / "source"
    private = tmp_path / "private"
    source.mkdir()
    private.mkdir(mode=0o700)
    path = private / "duplicate.json"
    path.write_text('{"a":1,"a":2}', encoding="utf-8")
    path.chmod(0o600)
    with pytest.raises(ChangeSetHandoffError, match="PRIVATE_INPUT_DUPLICATE_KEY"):
        read_private_json(path, source_root=source)


def test_reviewed_policy_is_loaded_from_exact_git_object(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    policy = repo / (
        "policies/iam/platform-authority-lambda-audit-repair-invoker-role.json"
    )
    policy.parent.mkdir(parents=True)
    policy.write_text('{"Version":"reviewed"}', encoding="utf-8")
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    subprocess.run(["git", "add", "--", policy.relative_to(repo)], cwd=repo, check=True)
    subprocess.run(
        [
            "git",
            "-c",
            "user.name=Scanalyze Test",
            "-c",
            "user.email=scanalyze-test@example.invalid",
            "-c",
            "commit.gpgsign=false",
            "commit",
            "-qm",
            "test: seed reviewed policy",
        ],
        cwd=repo,
        check=True,
    )
    source_commit = subprocess.check_output(
        ["git", "rev-parse", "HEAD"], cwd=repo, text=True
    ).strip()

    policy.write_text('{"Version":"worktree-drift"}', encoding="utf-8")

    assert module._repair_invoker_policy(repo, source_commit) == {
        "Version": "reviewed"
    }


def test_signed_receipt_requires_fresh_provider_equality() -> None:
    local = json.loads(
        (
            ROOT
            / "fixtures/valid/"
            "platform-authority-lambda-audit-repair-signed-artifact-v1-synthetic.json"
        ).read_text(encoding="utf-8")
    )
    local.pop("_test_metadata")
    fresh = deepcopy(local)
    fresh["evaluated_at"] = "2026-07-22T12:30:00Z"
    module._require_fresh_signed_receipt(
        local_receipt=local,
        fresh_receipt=fresh,
    )
    assert module._signed_receipt_binding_digest(local) == (
        module._signed_receipt_binding_digest(fresh)
    )
    fresh["verifier"]["caller_arn"] = (
        "arn:aws:sts::042360977644:assumed-role/"
        "AWSReservedSSO_AWSReadOnlyAccess_1c38063fd41ea692/"
        "other.synthetic@example.invalid"
    )
    with pytest.raises(
        ChangeSetHandoffError,
        match="SIGNED_RECEIPT_PROVIDER_READBACK_DRIFT",
    ):
        module._require_fresh_signed_receipt(
            local_receipt=local,
            fresh_receipt=fresh,
        )


def test_phase_b_refreshes_signed_receipt_inside_verifier_boundary(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    local = json.loads(
        (
            ROOT
            / "fixtures/valid/"
            "platform-authority-lambda-audit-repair-signed-artifact-v1-synthetic.json"
        ).read_text(encoding="utf-8")
    )
    local.pop("_test_metadata")
    fresh = deepcopy(local)
    fresh["evaluated_at"] = "2026-07-22T12:30:00Z"
    calls: list[dict] = []

    def collect(**kwargs: object) -> dict:
        calls.append(dict(kwargs))
        return fresh

    monkeypatch.setattr(module, "build_signed_artifact_receipt_from_aws", collect)
    sts = object()
    signer = object()
    s3 = object()
    result = module.refresh_signed_artifact_receipt_read_only(
        source_root=ROOT,
        local_receipt=local,
        sts_client=sts,
        signer_client=signer,
        s3_client=s3,
        now=NOW,
    )
    assert result == fresh
    assert len(calls) == 1
    assert calls[0]["sts_client"] is sts
    assert calls[0]["signer_client"] is signer
    assert calls[0]["s3_client"] is s3
    assert calls[0]["profile_name"] == EXPECTED_PROFILE


def _delegation_change_set_arn() -> str:
    return (
        "arn:aws:cloudformation:us-east-1:839393571433:changeSet/"
        "gug221-lambda-audit-repair-delegation-create/"
        "12345678-1234-4234-8234-123456789abc"
    )


def _delegation_stack_arn() -> str:
    return (
        "arn:aws:cloudformation:us-east-1:839393571433:stack/"
        "scanalyze-platform-authority-lambda-audit-repair-delegation/"
        "12345678-1234-4234-8234-123456789abc"
    )


def _delegation_metadata() -> dict:
    return {
        "ChangeSetId": _delegation_change_set_arn(),
        "ChangeSetName": module.DELEGATION_CHANGE_SET_NAME,
        "StackId": _delegation_stack_arn(),
        "StackName": module.DELEGATION_STACK_NAME,
        "ChangeSetType": "CREATE",
        "Status": "CREATE_COMPLETE",
        "ExecutionStatus": "AVAILABLE",
        "Capabilities": ["CAPABILITY_NAMED_IAM"],
        "CreationTime": NOW,
        "Description": (
            "GUG-221 reviewed " + module.DELEGATION_CHANGE_SET_NAME
        ),
        "Parameters": [{"ParameterKey": "A", "ParameterValue": "B"}],
        "Tags": [{"Key": "work_package", "Value": "GUG-221"}],
        "OnStackFailure": "ROLLBACK",
        "ImportExistingResources": False,
        "RollbackConfiguration": {
            "RollbackTriggers": [],
            "MonitoringTimeInMinutes": 0,
        },
        "NotificationARNs": [],
        "IncludeNestedStacks": False,
        "Changes": [],
    }


def _create_event(
    *,
    change_set_arn: str,
    template: bytes,
    parameters: list[dict[str, str]],
    tags: dict[str, str],
) -> dict:
    request = {
        "stackName": module.DELEGATION_STACK_NAME,
        "changeSetName": module.DELEGATION_CHANGE_SET_NAME,
        "changeSetType": "CREATE",
        "description": (
            "GUG-221 reviewed " + module.DELEGATION_CHANGE_SET_NAME
        ),
        "templateBody": template.decode("utf-8"),
        "parameters": [
            {
                "parameterKey": item["ParameterKey"],
                "parameterValue": item["ParameterValue"],
            }
            for item in parameters
        ],
        "capabilities": ["CAPABILITY_NAMED_IAM"],
        "notificationARNs": [],
        "rollbackConfiguration": {
            "rollbackTriggers": [],
            "monitoringTimeInMinutes": 0,
        },
        "includeNestedStacks": False,
        "importExistingResources": False,
        "onStackFailure": "ROLLBACK",
        "tags": [
            {"key": key, "value": value} for key, value in sorted(tags.items())
        ],
    }
    event = {
        "eventSource": "cloudformation.amazonaws.com",
        "eventName": "CreateChangeSet",
        "eventCategory": "Management",
        "awsRegion": REGION,
        "recipientAccountId": MANAGEMENT_ACCOUNT_ID,
        "readOnly": False,
        "userIdentity": {"arn": _contract()["delegation_change_set_creator_arn"]},
        "requestParameters": request,
        "responseElements": {"id": change_set_arn},
    }
    return {
        "EventId": "event-123",
        "EventTime": NOW,
        "CloudTrailEvent": json.dumps(event),
    }


class CloudTrail:
    def __init__(self, events: list[dict]) -> None:
        self.events = events

    def lookup_events(self, **kwargs: object) -> dict:
        assert kwargs["LookupAttributes"] == [
            {"AttributeKey": "EventName", "AttributeValue": "CreateChangeSet"}
        ]
        return {"Events": self.events}


def _delegation_review_receipt() -> dict:
    change_set = {
        "arn": _delegation_change_set_arn(),
        "uuid": "12345678-1234-4234-8234-123456789abc",
        "name": module.DELEGATION_CHANGE_SET_NAME,
        "stack_arn": _delegation_stack_arn(),
        "stack_name": module.DELEGATION_STACK_NAME,
        "type": "CREATE",
        "status": "CREATE_COMPLETE",
        "execution_status": "AVAILABLE",
        "on_stack_failure": "ROLLBACK",
        "capabilities": ["CAPABILITY_NAMED_IAM"],
        "tags": module._permission_set_tags(_contract()["source_commit"]),
        "parameters_sha256": "a" * 64,
        "resource_changes": [
            {
                "logical_resource_id": logical_id,
                "resource_type": resource_type,
                "action": "Add",
                "replacement": "False",
            }
            for logical_id, resource_type in sorted(
                {
                    "MutationServiceRole": "AWS::IAM::Role",
                    "ReadbackServiceRole": "AWS::IAM::Role",
                    "RepairInvokerAssignment": "AWS::SSO::Assignment",
                    "RepairInvokerPermissionSet": "AWS::SSO::PermissionSet",
                }.items()
            )
        ],
        "create_event": {
            "event_id": "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
            "event_time": "2026-07-22T12:30:00Z",
            "event_digest": "b" * 64,
        },
    }
    contract_digest = module._digest(_contract())
    receipt = {
        "artifact_type": module.DELEGATION_CHANGE_SET_RECEIPT_TYPE,
        "schema_version": 1,
        "work_package": "GUG-221",
        "phase": "A_DELEGATION_CHANGE_SET",
        "source_commit": _contract()["source_commit"],
        "deployment_contract_sha256": contract_digest,
        "gug220_intent_sha256": "c" * 64,
        "gug220_ledger_sha256": "d" * 64,
        "gug220_receipt_sha256": "e" * 64,
        "gug220_evidence_sha256": "f" * 64,
        "gug220_provider_state_sha256": "0" * 64,
        "parameter_handoff_sha256": "1" * 64,
        "template_sha256": "2" * 64,
        "change_set": change_set,
        "execution_contract": {},
        "verifier": {},
        "evaluated_at": "2026-07-22T12:31:00Z",
        "evidence_status": "DELEGATION_CHANGE_SET_READ_ONLY_VERIFIED",
        "authority_status": "REVIEW_EVIDENCE_ONLY_NOT_EXECUTION_AUTHORITY",
        "production_status": "NO-GO",
    }
    receipt["verifier"] = {
        "profile": EXPECTED_MANAGEMENT_PROFILE,
        "account_id": MANAGEMENT_ACCOUNT_ID,
        "caller_arn": Sts(MANAGEMENT_ACCOUNT_ID).get_caller_identity()["Arn"],
    }
    receipt["execution_contract"] = module._delegation_execution_contract(
        source_commit=receipt["source_commit"],
        deployment_contract_sha256=receipt["deployment_contract_sha256"],
        parameter_handoff_sha256=receipt["parameter_handoff_sha256"],
        template_sha256=receipt["template_sha256"],
        change_set=change_set,
        executor_arn=_contract()["delegation_change_set_executor_arn"],
    )
    return receipt


def _execute_event(*, actor_arn: str | None = None, token: str | None = None) -> dict:
    receipt = _delegation_review_receipt()
    execution = receipt["execution_contract"]
    event = {
        "eventSource": "cloudformation.amazonaws.com",
        "eventName": "ExecuteChangeSet",
        "eventCategory": "Management",
        "awsRegion": REGION,
        "recipientAccountId": MANAGEMENT_ACCOUNT_ID,
        "readOnly": False,
        "userIdentity": {
            "arn": actor_arn or _contract()["delegation_change_set_executor_arn"]
        },
        "requestParameters": {
            "changeSetName": _delegation_change_set_arn(),
            "stackName": _delegation_stack_arn(),
            "clientRequestToken": token or execution["client_request_token"],
        },
        "responseElements": None,
    }
    return {
        "EventId": "11111111-2222-4333-8444-555555555555",
        "EventTime": NOW,
        "CloudTrailEvent": json.dumps(event),
    }


class ExecuteCloudTrail:
    def __init__(self, events: list[dict]) -> None:
        self.events = events

    def lookup_events(self, **kwargs: object) -> dict:
        assert kwargs["LookupAttributes"] == [
            {"AttributeKey": "EventName", "AttributeValue": "ExecuteChangeSet"}
        ]
        return {"Events": self.events}


class StackEvents:
    def __init__(self, *, foreign_token: bool = False) -> None:
        receipt = _delegation_review_receipt()
        token = receipt["execution_contract"]["client_request_token"]
        expected = {
            module.DELEGATION_STACK_NAME: "AWS::CloudFormation::Stack",
            "MutationServiceRole": "AWS::IAM::Role",
            "ReadbackServiceRole": "AWS::IAM::Role",
            "RepairInvokerAssignment": "AWS::SSO::Assignment",
            "RepairInvokerPermissionSet": "AWS::SSO::PermissionSet",
        }
        self.events = [
            {
                "EventId": f"{logical_id}-complete",
                "Timestamp": NOW,
                "StackId": _delegation_stack_arn(),
                "StackName": module.DELEGATION_STACK_NAME,
                "LogicalResourceId": logical_id,
                "PhysicalResourceId": (
                    _delegation_stack_arn()
                    if logical_id == module.DELEGATION_STACK_NAME
                    else f"synthetic-{logical_id}"
                ),
                "ResourceType": resource_type,
                "ResourceStatus": "CREATE_COMPLETE",
                "ClientRequestToken": (
                    "foreign-token"
                    if foreign_token and logical_id == "MutationServiceRole"
                    else token
                ),
            }
            for logical_id, resource_type in expected.items()
        ]
        self.events.append(
            {
                "EventId": "review-in-progress",
                "Timestamp": NOW,
                "StackId": _delegation_stack_arn(),
                "StackName": module.DELEGATION_STACK_NAME,
                "LogicalResourceId": module.DELEGATION_STACK_NAME,
                "PhysicalResourceId": _delegation_stack_arn(),
                "ResourceType": "AWS::CloudFormation::Stack",
                "ResourceStatus": "REVIEW_IN_PROGRESS",
                "ClientRequestToken": "provider-create-token",
            }
        )

    def describe_stack_events(self, **kwargs: object) -> dict:
        assert kwargs == {"StackName": _delegation_stack_arn()}
        return {"StackEvents": self.events}


def test_cloudtrail_create_proof_is_exact_and_unique() -> None:
    change_set_arn = _delegation_change_set_arn()
    template = b"Resources: {}\n"
    parameters = [{"ParameterKey": "A", "ParameterValue": "B"}]
    tags = {"work_package": "GUG-221"}
    event = _create_event(
        change_set_arn=change_set_arn,
        template=template,
        parameters=parameters,
        tags=tags,
    )
    proof = module._verify_create_change_set_event(
        cloudtrail_client=CloudTrail([event]),
        account_id=MANAGEMENT_ACCOUNT_ID,
        creator_arn=_contract()["delegation_change_set_creator_arn"],
        change_set_arn=change_set_arn,
        change_set_name=module.DELEGATION_CHANGE_SET_NAME,
        stack_name=module.DELEGATION_STACK_NAME,
        reviewed_template_bytes=template,
        parameters=parameters,
        tags=tags,
        creation_time=NOW,
    )
    assert proof["event_id"] == "event-123"

    duplicate = deepcopy(event)
    duplicate["EventId"] = "event-456"
    with pytest.raises(
        ChangeSetHandoffError,
        match="CLOUDTRAIL_CREATE_EVENT_NOT_UNIQUE",
    ):
        module._verify_create_change_set_event(
            cloudtrail_client=CloudTrail([event, duplicate]),
            account_id=MANAGEMENT_ACCOUNT_ID,
            creator_arn=_contract()["delegation_change_set_creator_arn"],
            change_set_arn=change_set_arn,
            change_set_name=module.DELEGATION_CHANGE_SET_NAME,
            stack_name=module.DELEGATION_STACK_NAME,
            reviewed_template_bytes=template,
            parameters=parameters,
            tags=tags,
            creation_time=NOW,
        )


def test_delegation_execution_token_and_cloudtrail_proof_are_exact() -> None:
    receipt = _delegation_review_receipt()
    execution = receipt["execution_contract"]
    assert execution["client_request_token"].startswith("gug221-a-")
    assert len(execution["client_request_token"]) == 57
    module._validate_delegation_change_set_receipt_binding(
        receipt=receipt,
        deployment_contract=_contract(),
    )
    proof = module._verify_execute_change_set_event(
        cloudtrail_client=ExecuteCloudTrail([_execute_event()]),
        deployment_contract=_contract(),
        change_set_receipt=receipt,
        stack_creation_time=NOW,
        verification_time=NOW,
    )
    assert proof["event_id"] == "11111111-2222-4333-8444-555555555555"


def test_delegation_execution_rejects_wrong_actor_and_duplicate_token() -> None:
    foreign_actor = (
        "arn:aws:sts::839393571433:assumed-role/"
        "AWSReservedSSO_ScanalyzeFounderPepSeed_0123456789abcdef/"
        "foreign@example.invalid"
    )
    with pytest.raises(
        ChangeSetHandoffError,
        match="CLOUDTRAIL_EXECUTE_EVENT_DRIFT",
    ):
        module._verify_execute_change_set_event(
            cloudtrail_client=ExecuteCloudTrail(
                [_execute_event(actor_arn=foreign_actor)]
            ),
            deployment_contract=_contract(),
            change_set_receipt=_delegation_review_receipt(),
            stack_creation_time=NOW,
            verification_time=NOW,
        )
    duplicate = deepcopy(_execute_event())
    duplicate["EventId"] = "66666666-7777-4888-8999-aaaaaaaaaaaa"
    with pytest.raises(
        ChangeSetHandoffError,
        match="CLOUDTRAIL_EXECUTE_EVENT_NOT_UNIQUE",
    ):
        module._verify_execute_change_set_event(
            cloudtrail_client=ExecuteCloudTrail([_execute_event(), duplicate]),
            deployment_contract=_contract(),
            change_set_receipt=_delegation_review_receipt(),
            stack_creation_time=NOW,
            verification_time=NOW,
        )


def test_delegation_execution_allows_review_longer_than_five_minutes() -> None:
    receipt = _delegation_review_receipt()
    delayed_execution = NOW + timedelta(hours=2)
    event = _execute_event()
    event["EventTime"] = delayed_execution

    proof = module._verify_execute_change_set_event(
        cloudtrail_client=ExecuteCloudTrail([event]),
        deployment_contract=_contract(),
        change_set_receipt=receipt,
        stack_creation_time=NOW,
        verification_time=delayed_execution,
    )

    assert proof["event_time"] == "2026-07-22T14:30:00Z"


def test_phase_b_execution_binding_excludes_only_observation_time() -> None:
    execution = json.loads(
        (
            ROOT
            / "fixtures/valid/"
            "platform-authority-lambda-audit-repair-delegation-"
            "execution-receipt-v1-synthetic.json"
        ).read_text(encoding="utf-8")
    )
    later_observation = deepcopy(execution)
    later_observation["evaluated_at"] = "2026-07-22T14:30:00Z"

    assert module._delegation_execution_receipt_binding_digest(
        execution
    ) == module._delegation_execution_receipt_binding_digest(later_observation)

    live = json.loads(
        (
            ROOT
            / "fixtures/valid/"
            "platform-authority-lambda-audit-repair-delegation-"
            "live-receipt-v1-synthetic.json"
        ).read_text(encoding="utf-8")
    )
    live["delegation_execution_receipt"] = execution
    live["delegation_execution_receipt_sha256"] = (
        module._delegation_execution_receipt_binding_digest(execution)
    )
    refreshed = deepcopy(live)
    refreshed["evaluated_at"] = "2026-07-22T14:31:00Z"
    refreshed["delegation_execution_receipt"] = later_observation

    assert module.canonical_json(
        module._delegation_live_receipt_binding_projection(live)
    ) == module.canonical_json(
        module._delegation_live_receipt_binding_projection(refreshed)
    )
    assert module._delegation_live_receipt_binding_digest(
        live
    ) == module._delegation_live_receipt_binding_digest(refreshed)

    drifted = deepcopy(refreshed)
    drifted["delegation_execution_receipt"]["execute_event"][
        "event_digest"
    ] = "f" * 64
    assert module.canonical_json(
        module._delegation_live_receipt_binding_projection(live)
    ) != module.canonical_json(
        module._delegation_live_receipt_binding_projection(drifted)
    )
    assert module._delegation_live_receipt_binding_digest(
        live
    ) != module._delegation_live_receipt_binding_digest(drifted)


def test_stack_events_bind_every_terminal_resource_to_execution_token() -> None:
    execution = _delegation_review_receipt()["execution_contract"]
    proof = module._verify_stack_operation_events(
        cloudformation_client=StackEvents(),
        stack_arn=_delegation_stack_arn(),
        client_request_token=execution["client_request_token"],
        execute_event_time=NOW,
        expected_resource_types={
            "MutationServiceRole": "AWS::IAM::Role",
            "ReadbackServiceRole": "AWS::IAM::Role",
            "RepairInvokerAssignment": "AWS::SSO::Assignment",
            "RepairInvokerPermissionSet": "AWS::SSO::PermissionSet",
        },
    )
    assert proof["stack_event_count"] == 5
    assert len(proof["terminal_resources"]) == 5
    with pytest.raises(
        ChangeSetHandoffError,
        match="DELEGATION_STACK_EVENT_TOKEN_DRIFT",
    ):
        module._verify_stack_operation_events(
            cloudformation_client=StackEvents(foreign_token=True),
            stack_arn=_delegation_stack_arn(),
            client_request_token=execution["client_request_token"],
            execute_event_time=NOW,
            expected_resource_types={
                "MutationServiceRole": "AWS::IAM::Role",
                "ReadbackServiceRole": "AWS::IAM::Role",
                "RepairInvokerAssignment": "AWS::SSO::Assignment",
                "RepairInvokerPermissionSet": "AWS::SSO::PermissionSet",
            },
        )


def test_execution_contract_is_bound_to_reviewed_change_set() -> None:
    receipt = _delegation_review_receipt()
    forged = deepcopy(receipt)
    forged["change_set"]["parameters_sha256"] = "9" * 64
    with pytest.raises(
        ChangeSetHandoffError,
        match="DELEGATION_EXECUTION_CONTRACT_INVALID",
    ):
        module._validate_delegation_change_set_receipt_binding(
            receipt=forged,
            deployment_contract=_contract(),
        )


def test_cloudtrail_rejects_role_arn_and_metadata_rejects_hidden_options() -> None:
    change_set_arn = _delegation_change_set_arn()
    template = b"Resources: {}\n"
    parameters = [{"ParameterKey": "A", "ParameterValue": "B"}]
    tags = {"work_package": "GUG-221"}
    event = _create_event(
        change_set_arn=change_set_arn,
        template=template,
        parameters=parameters,
        tags=tags,
    )
    decoded = json.loads(event["CloudTrailEvent"])
    decoded["requestParameters"]["roleARN"] = (
        "arn:aws:iam::839393571433:role/foreign"
    )
    event["CloudTrailEvent"] = json.dumps(decoded)
    with pytest.raises(ChangeSetHandoffError, match="CLOUDTRAIL_CREATE_EVENT_DRIFT"):
        module._verify_create_change_set_event(
            cloudtrail_client=CloudTrail([event]),
            account_id=MANAGEMENT_ACCOUNT_ID,
            creator_arn=_contract()["delegation_change_set_creator_arn"],
            change_set_arn=change_set_arn,
            change_set_name=module.DELEGATION_CHANGE_SET_NAME,
            stack_name=module.DELEGATION_STACK_NAME,
            reviewed_template_bytes=template,
            parameters=parameters,
            tags=tags,
            creation_time=NOW,
        )

    metadata = _delegation_metadata()
    module._core_change_set_metadata(
        metadata,
        change_set_arn=change_set_arn,
        change_set_name=module.DELEGATION_CHANGE_SET_NAME,
        stack_name=module.DELEGATION_STACK_NAME,
        change_set_arn_re=module._DELEGATION_CHANGE_SET_ARN_RE,
        stack_arn_re=module._DELEGATION_STACK_ARN_RE,
    )
    for field, value in (
        ("RoleARN", "arn:aws:iam::839393571433:role/foreign"),
        ("DeploymentMode", {"FailoverMode": "ON_DEMAND"}),
    ):
        forged = {**metadata, field: value}
        with pytest.raises(ChangeSetHandoffError, match="CHANGE_SET_METADATA_INVALID"):
            module._core_change_set_metadata(
                forged,
                change_set_arn=change_set_arn,
                change_set_name=module.DELEGATION_CHANGE_SET_NAME,
                stack_name=module.DELEGATION_STACK_NAME,
                change_set_arn_re=module._DELEGATION_CHANGE_SET_ARN_RE,
                stack_arn_re=module._DELEGATION_STACK_ARN_RE,
            )


class PaginatedChangeSet:
    def __init__(self) -> None:
        self.calls = 0

    def describe_change_set(self, **kwargs: object) -> dict:
        self.calls += 1
        response = _delegation_metadata()
        if self.calls == 1:
            assert "NextToken" not in kwargs
            response["NextToken"] = "next"
        else:
            assert kwargs["NextToken"] == "next"
            response["Parameters"] = [
                {"ParameterKey": "A", "ParameterValue": "FOREIGN"}
            ]
        return response


def test_change_set_pagination_rejects_metadata_drift() -> None:
    with pytest.raises(ChangeSetHandoffError, match="CHANGE_SET_PAGINATION_DRIFT"):
        module._read_change_set_pages(
            cloudformation_client=PaginatedChangeSet(),
            change_set_arn=_delegation_change_set_arn(),
            change_set_name=module.DELEGATION_CHANGE_SET_NAME,
            stack_name=module.DELEGATION_STACK_NAME,
            change_set_arn_re=module._DELEGATION_CHANGE_SET_ARN_RE,
            stack_arn_re=module._DELEGATION_STACK_ARN_RE,
        )


def test_change_set_masked_parameter_is_never_accepted() -> None:
    with pytest.raises(ChangeSetHandoffError, match="CHANGE_SET_PARAMETER_MASKED"):
        module._normalize_parameters(
            [{"ParameterKey": "A", "ParameterValue": "****"}],
            expected_keys=("A",),
        )


def test_templates_keep_compared_parameters_visible_and_broker_digest_plain() -> None:
    pep = (
        ROOT / "bootstrap/cfn-platform-authority-lambda-audit-repair-pep.yaml"
    ).read_text(encoding="utf-8")
    delegation = (
        ROOT / "bootstrap/cfn-platform-authority-lambda-audit-repair-delegation.yaml"
    ).read_text(encoding="utf-8")
    assert "NoEcho:" not in pep
    assert "NoEcho:" not in delegation
    assert "AllowedPattern: '^[a-f0-9]{64}$'" in pep


def test_cli_and_module_expose_no_change_set_mutations() -> None:
    module_source = Path(module.__file__).read_text(encoding="utf-8")
    cli_source = (
        ROOT / "scripts/deployment/platform-authority-lambda-audit-repair-change-set.py"
    ).read_text(encoding="utf-8")
    for forbidden in (
        "create_change_set(",
        "execute_change_set(",
        "delete_change_set(",
        '"create-change-set"',
        '"execute-change-set"',
        '"delete-change-set"',
    ):
        assert forbidden not in module_source
        assert forbidden not in cli_source
    pep_parameters = inspect.signature(
        module.verify_pep_change_set_read_only
    ).parameters
    assert "signed_receipt" in pep_parameters
    assert "fresh_signed_receipt" not in pep_parameters
    assert "authority_signer_client" in pep_parameters
    assert "authority_s3_client" in pep_parameters
    assert "management_cloudtrail_client" in pep_parameters
    live_parameters = inspect.signature(module.readback_delegation_live).parameters
    assert "delegation_change_set_receipt" in live_parameters
    assert "cloudtrail_client" in live_parameters
    assert '"gug220_provider_state_sha256"' in module_source
