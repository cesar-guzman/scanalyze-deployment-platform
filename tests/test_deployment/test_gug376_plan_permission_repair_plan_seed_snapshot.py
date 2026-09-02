from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
from pathlib import Path
import stat
from types import SimpleNamespace
from typing import Any, Mapping

import pytest

from tooling import platform_authority_plan_permission_repair as repair
from tooling import platform_authority_plan_permission_repair_broker_config as config
from tooling import platform_authority_plan_permission_repair_deployment_route as route
from tooling import (
    platform_authority_plan_permission_repair_plan_seed_snapshot as subject,
)


SOURCE_COMMIT = "1" * 40
CHANGE_SET_NAME = "scanalyze-platform-authority-bootstrap-20300101000000"
INSTANCE_ARN = "arn:aws:sso:::instance/ssoins-0123456789ABCDEF"
STORE_ID = "d-0123456789"
PERMISSION_SET_ARN = (
    "arn:aws:sso:::permissionSet/ssoins-0123456789ABCDEF/"
    "ps-0123456789ABCDEF"
)
PRINCIPAL_ID = "01234567-89ab-cdef-0123-456789abcdef"
ROLE_NAME = "AWSReservedSSO_ScanalyzeAuthorityBootstrapPlan_0123456789ABCDEF"
ROLE_ARN = (
    "arn:aws:iam::042360977644:role/aws-reserved/sso.amazonaws.com/" + ROLE_NAME
)
SAML_PROVIDER_ARN = (
    "arn:aws:iam::042360977644:saml-provider/"
    "AWSSSO_scanalyze_DO_NOT_DELETE"
)
NOW = datetime(2026, 8, 30, 18, 0, tzinfo=timezone.utc)
REPO_ROOT = Path(__file__).resolve().parents[2]
POLICY_BYTES = (REPO_ROOT / subject.POLICY_SOURCE_PATH).read_bytes()


class ResourceNotFound(Exception):
    response = {"Error": {"Code": "ResourceNotFoundException"}}


class AccessDenied(Exception):
    response = {"Error": {"Code": "AccessDenied"}}


class FakeGit:
    def __init__(self, root: Path) -> None:
        self._root = root
        self.branch_name = "main"
        self.head_commit = SOURCE_COMMIT
        self.origin_commit = SOURCE_COMMIT
        self.working_status = ""

    def root(self) -> Path:
        return self._root

    def branch(self) -> str:
        return self.branch_name

    def head(self) -> str:
        return self.head_commit

    def origin_main(self) -> str:
        return self.origin_commit

    def status(self) -> str:
        return self.working_status

    def read_at(self, commit: str, path: str) -> bytes:
        assert commit == SOURCE_COMMIT
        assert path == subject.POLICY_SOURCE_PATH
        return POLICY_BYTES


class Sts:
    def __init__(
        self,
        timeline: list[str],
        account_id: str,
        *,
        sso_role: str,
        caller_account: str | None = None,
    ) -> None:
        self.meta = SimpleNamespace(
            endpoint_url=f"https://sts.{subject.EXPECTED_REGION}.amazonaws.com"
        )
        self.timeline = timeline
        self.account_id = account_id
        self.sso_role = sso_role
        self.caller_account = caller_account or account_id

    def get_caller_identity(self) -> dict[str, str]:
        self.timeline.append(f"call:{self.account_id}:sts:GetCallerIdentity")
        return {
            "Account": self.caller_account,
            "Arn": (
                f"arn:aws:sts::{self.account_id}:assumed-role/"
                f"AWSReservedSSO_{self.sso_role}_0123456789ABCDEF/cesar"
            ),
            "UserId": "synthetic",
        }


class Sso:
    def __init__(
        self,
        timeline: list[str],
        predecessor: Mapping[str, Any],
    ) -> None:
        self.meta = SimpleNamespace(
            endpoint_url="https://sso.us-east-1.amazonaws.com"
        )
        self.timeline = timeline
        self.inline_policy = deepcopy(dict(predecessor))
        self.managed: list[Any] = []
        self.customer: list[Any] = []
        self.accounts = [route.AUTHORITY_ACCOUNT_ID]
        self.assignments: list[dict[str, str]] = [
            {
                "AccountId": route.AUTHORITY_ACCOUNT_ID,
                "PermissionSetArn": PERMISSION_SET_ARN,
                "PrincipalType": "USER",
                "PrincipalId": PRINCIPAL_ID,
            }
        ]
        self.pending: dict[str, list[dict[str, str]]] = {
            "creation": [],
            "deletion": [],
            "provisioning": [],
        }
        self.tags: list[dict[str, str]] = [
            {"Key": "managed_by", "Value": "terraform"},
            {"Key": "work_package", "Value": "GUG-376"},
        ]
        self.permission_sets = [PERMISSION_SET_ARN]
        self.next_token_cycle = False

    def _record(self, operation: str) -> None:
        self.timeline.append("call:sso:" + operation)

    def list_instances(self, **request: Any) -> dict[str, Any]:
        self._record("ListInstances")
        if self.next_token_cycle:
            return {
                "Instances": [
                    {"InstanceArn": INSTANCE_ARN, "IdentityStoreId": STORE_ID}
                ],
                "NextToken": "cycle",
            }
        return {
            "Instances": [
                {"InstanceArn": INSTANCE_ARN, "IdentityStoreId": STORE_ID}
            ]
        }

    def describe_instance(self, **request: Any) -> dict[str, Any]:
        self._record("DescribeInstance")
        return {
            "InstanceArn": INSTANCE_ARN,
            "IdentityStoreId": STORE_ID,
            "OwnerAccountId": route.MANAGEMENT_ACCOUNT_ID,
            "Status": "ACTIVE",
            "EncryptionConfigurationDetails": {
                "EncryptionStatus": "ENABLED",
                "KeyType": "AWS_OWNED_KMS_KEY",
                "KmsKeyArn": None,
            },
        }

    def list_permission_sets(self, **request: Any) -> dict[str, Any]:
        self._record("ListPermissionSets")
        return {"PermissionSets": list(self.permission_sets)}

    def describe_permission_set(self, **request: Any) -> dict[str, Any]:
        self._record("DescribePermissionSet")
        return {
            "PermissionSet": {
                "PermissionSetArn": request["PermissionSetArn"],
                "Name": repair.PLAN_PERMISSION_SET_NAME,
                "Description": "Reviewed Scanalyze authority bootstrap Plan",
                "SessionDuration": repair.PLAN_SESSION_DURATION,
                "RelayState": None,
            }
        }

    def list_tags_for_resource(self, **request: Any) -> dict[str, Any]:
        self._record("ListTagsForResource")
        return {"Tags": deepcopy(self.tags)}

    def get_inline_policy_for_permission_set(self, **request: Any) -> dict[str, Any]:
        self._record("GetInlinePolicyForPermissionSet")
        return {"InlinePolicy": json.dumps(self.inline_policy)}

    def list_managed_policies_in_permission_set(self, **request: Any) -> dict[str, Any]:
        self._record("ListManagedPoliciesInPermissionSet")
        return {"AttachedManagedPolicies": deepcopy(self.managed)}

    def list_customer_managed_policy_references_in_permission_set(
        self, **request: Any
    ) -> dict[str, Any]:
        self._record("ListCustomerManagedPolicyReferencesInPermissionSet")
        return {"CustomerManagedPolicyReferences": deepcopy(self.customer)}

    def get_permissions_boundary_for_permission_set(self, **request: Any) -> Any:
        self._record("GetPermissionsBoundaryForPermissionSet")
        raise ResourceNotFound()

    def list_accounts_for_provisioned_permission_set(
        self, **request: Any
    ) -> dict[str, Any]:
        self._record("ListAccountsForProvisionedPermissionSet")
        return {"AccountIds": list(self.accounts)}

    def list_account_assignments(self, **request: Any) -> dict[str, Any]:
        self._record("ListAccountAssignments")
        return {"AccountAssignments": deepcopy(self.assignments)}

    def list_account_assignment_creation_status(self, **request: Any) -> dict[str, Any]:
        self._record("ListAccountAssignmentCreationStatus")
        return {"AccountAssignmentsCreationStatus": deepcopy(self.pending["creation"])}

    def list_account_assignment_deletion_status(self, **request: Any) -> dict[str, Any]:
        self._record("ListAccountAssignmentDeletionStatus")
        return {"AccountAssignmentsDeletionStatus": deepcopy(self.pending["deletion"])}

    def list_permission_set_provisioning_status(self, **request: Any) -> dict[str, Any]:
        self._record("ListPermissionSetProvisioningStatus")
        return {"PermissionSetsProvisioningStatus": deepcopy(self.pending["provisioning"])}

    def describe_account_assignment_creation_status(self, **request: Any) -> dict[str, Any]:
        self._record("DescribeAccountAssignmentCreationStatus")
        return {
            "AccountAssignmentCreationStatus": {
                "RequestId": request["AccountAssignmentCreationRequestId"],
                "Status": "IN_PROGRESS",
                "PermissionSetArn": PERMISSION_SET_ARN,
            }
        }

    def describe_account_assignment_deletion_status(self, **request: Any) -> dict[str, Any]:
        self._record("DescribeAccountAssignmentDeletionStatus")
        return {
            "AccountAssignmentDeletionStatus": {
                "RequestId": request["AccountAssignmentDeletionRequestId"],
                "Status": "IN_PROGRESS",
                "PermissionSetArn": PERMISSION_SET_ARN,
            }
        }

    def describe_permission_set_provisioning_status(self, **request: Any) -> dict[str, Any]:
        self._record("DescribePermissionSetProvisioningStatus")
        return {
            "PermissionSetProvisioningStatus": {
                "RequestId": request["ProvisionPermissionSetRequestId"],
                "Status": "IN_PROGRESS",
                "PermissionSetArn": PERMISSION_SET_ARN,
            }
        }


class IdentityStore:
    def __init__(self, timeline: list[str]) -> None:
        self.meta = SimpleNamespace(
            endpoint_url="https://identitystore.us-east-1.amazonaws.com"
        )
        self.timeline = timeline
        self.user_id = PRINCIPAL_ID

    def describe_user(self, **request: Any) -> dict[str, str]:
        self.timeline.append("call:identitystore:DescribeUser")
        return {"UserId": self.user_id, "UserName": "private-user"}


class Iam:
    def __init__(
        self,
        timeline: list[str],
        predecessor: Mapping[str, Any],
    ) -> None:
        self.meta = SimpleNamespace(endpoint_url="https://iam.amazonaws.com")
        self.timeline = timeline
        self.inline_policy = deepcopy(dict(predecessor))
        self.attached: list[Any] = []
        self.policy_names = [repair.PLAN_ROLE_INLINE_POLICY_NAME]
        self.trust: dict[str, Any] = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Federated": SAML_PROVIDER_ARN},
                    "Action": ["sts:AssumeRoleWithSAML", "sts:TagSession"],
                    "Condition": {
                        "StringEquals": {"SAML:aud": repair.SAML_AUDIENCE}
                    },
                }
            ],
        }
        self.endpoint_url = "https://iam.amazonaws.com"

    def _record(self, operation: str) -> None:
        self.timeline.append("call:iam:" + operation)

    def list_roles(self, **request: Any) -> dict[str, Any]:
        self._record("ListRoles")
        return {
            "Roles": [
                {
                    "RoleName": ROLE_NAME,
                    "Arn": ROLE_ARN,
                    "Path": "/aws-reserved/sso.amazonaws.com/",
                }
            ],
            "IsTruncated": False,
        }

    def get_role(self, **request: Any) -> dict[str, Any]:
        self._record("GetRole")
        return {
            "Role": {
                "RoleName": ROLE_NAME,
                "Arn": ROLE_ARN,
                "Path": "/aws-reserved/sso.amazonaws.com/",
                "AssumeRolePolicyDocument": deepcopy(self.trust),
            }
        }

    def list_attached_role_policies(self, **request: Any) -> dict[str, Any]:
        self._record("ListAttachedRolePolicies")
        return {"AttachedPolicies": deepcopy(self.attached), "IsTruncated": False}

    def list_role_policies(self, **request: Any) -> dict[str, Any]:
        self._record("ListRolePolicies")
        return {"PolicyNames": list(self.policy_names), "IsTruncated": False}

    def get_role_policy(self, **request: Any) -> dict[str, Any]:
        self._record("GetRolePolicy")
        return {
            "RoleName": ROLE_NAME,
            "PolicyName": repair.PLAN_ROLE_INLINE_POLICY_NAME,
            "PolicyDocument": deepcopy(self.inline_policy),
        }


class FakeSession:
    def __init__(
        self,
        *,
        profile: str,
        account_id: str,
        sso_role: str,
        clients: Mapping[str, Any],
        timeline: list[str],
    ) -> None:
        self.profile_name = profile
        self.region_name = subject.EXPECTED_REGION
        self._clients = dict(clients)
        self._timeline = timeline
        session_name = "scanalyze-" + account_id
        self._session = SimpleNamespace(
            full_config={
                "profiles": {
                    profile: {
                        "region": subject.EXPECTED_REGION,
                        "sso_account_id": account_id,
                        "sso_role_name": sso_role,
                        "sso_session": session_name,
                    }
                },
                "sso_sessions": {
                    session_name: {
                        "sso_start_url": "https://scanalyze.awsapps.com/start",
                        "sso_region": subject.EXPECTED_REGION,
                    }
                },
            }
        )
        self.credential_method = "sso"

    def get_credentials(self) -> Any:
        return SimpleNamespace(method=self.credential_method)

    def client(self, service: str, **kwargs: Any) -> Any:
        assert kwargs == {"region_name": subject.EXPECTED_REGION, "config": "config"}
        self._timeline.append(f"client:{self.profile_name}:{service}")
        return self._clients[service]


class World:
    def __init__(self, tmp_path: Path) -> None:
        self.timeline: list[str] = []
        self.git = FakeGit(tmp_path)
        self.predecessor, self.target = subject._source_policies(  # noqa: SLF001
            git=self.git,
            source_commit=SOURCE_COMMIT,
            bootstrap_change_set_name=CHANGE_SET_NAME,
        )
        self.sso = Sso(self.timeline, self.predecessor)
        self.identitystore = IdentityStore(self.timeline)
        self.iam = Iam(self.timeline, self.predecessor)
        self.management_sts = Sts(
            self.timeline,
            route.MANAGEMENT_ACCOUNT_ID,
            sso_role=subject.MANAGEMENT_SSO_ROLE,
        )
        self.authority_sts = Sts(
            self.timeline,
            route.AUTHORITY_ACCOUNT_ID,
            sso_role=subject.AUTHORITY_SSO_ROLE,
        )
        self.management_session = FakeSession(
            profile=subject.MANAGEMENT_PROFILE,
            account_id=route.MANAGEMENT_ACCOUNT_ID,
            sso_role=subject.MANAGEMENT_SSO_ROLE,
            clients={
                "sts": self.management_sts,
                "sso-admin": self.sso,
                "identitystore": self.identitystore,
            },
            timeline=self.timeline,
        )
        self.authority_session = FakeSession(
            profile=subject.AUTHORITY_PROFILE,
            account_id=route.AUTHORITY_ACCOUNT_ID,
            sso_role=subject.AUTHORITY_SSO_ROLE,
            clients={"sts": self.authority_sts, "iam": self.iam},
            timeline=self.timeline,
        )

    def session(self, profile: str, region: str) -> FakeSession:
        assert region == subject.EXPECTED_REGION
        return {
            subject.MANAGEMENT_PROFILE: self.management_session,
            subject.AUTHORITY_PROFILE: self.authority_session,
        }[profile]

    def capture(self, tmp_path: Path, **overrides: Any) -> dict[str, Any]:
        arguments = {
            "source_root": tmp_path,
            "source_commit": SOURCE_COMMIT,
            "bootstrap_change_set_name": CHANGE_SET_NAME,
            "authority_profile": subject.AUTHORITY_PROFILE,
            "management_profile": subject.MANAGEMENT_PROFILE,
            "region": subject.EXPECTED_REGION,
            "git": self.git,
            "session_factory": self.session,
            "config_factory": lambda: "config",
            "clock": lambda: NOW,
            "environment": {},
        }
        arguments.update(overrides)
        return subject.capture_plan_seed_snapshot(**arguments)


def test_capture_proves_exact_predecessor_and_sts_is_first(tmp_path: Path) -> None:
    world = World(tmp_path)

    snapshot = world.capture(tmp_path)

    assert snapshot == config.validate_plan_snapshot(
        snapshot, source_commit=SOURCE_COMMIT, now=NOW
    )
    assert snapshot["bootstrap_change_set_name"] == CHANGE_SET_NAME
    assert snapshot["current_policy_digest"] == repair.canonical_digest(
        world.predecessor
    )
    assert snapshot["desired_policy_digest"] == repair.canonical_digest(world.target)
    assert snapshot["current_policy_digest"] != snapshot["desired_policy_digest"]
    assert snapshot["aws_mutations"] == 0
    calls = [item for item in world.timeline if item.startswith("call:")]
    assert calls[:2] == [
        f"call:{route.MANAGEMENT_ACCOUNT_ID}:sts:GetCallerIdentity",
        f"call:{route.AUTHORITY_ACCOUNT_ID}:sts:GetCallerIdentity",
    ]
    assert snapshot["aws_calls"] == len(calls)
    assert snapshot["production_status"] == "NO-GO"


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("authority_profile", "default"),
        ("management_profile", "default"),
        ("management_profile", "839393571433_AWSAdministratorAccess"),
        ("management_profile", "839393571433_ScanalyzeFounderPepIdentityAdmin"),
        ("management_profile", "839393571433_ScanalyzeFounderPepSeed"),
        ("management_profile", "839393571433_ScanalyzeAuthorityBootstrapPlan"),
        ("management_profile", "839393571433_ScanalyzeSandboxDeploy"),
        ("management_profile", "839393571433_ScanalyzeSandboxDestroy"),
        ("management_profile", subject.AUTHORITY_PROFILE),
        ("region", "us-west-2"),
    ),
)
def test_exact_profiles_and_region_are_mandatory(
    tmp_path: Path, field: str, value: str
) -> None:
    world = World(tmp_path)
    with pytest.raises(subject.PlanSeedSnapshotError) as captured:
        world.capture(tmp_path, **{field: value})
    assert captured.value.code == "SNAPSHOT_INPUT_INVALID"
    assert world.timeline == []


def test_ambient_credentials_and_profiles_are_rejected(tmp_path: Path) -> None:
    world = World(tmp_path)
    for environment in (
        {"AWS_ACCESS_KEY_ID": "redacted"},
        {"AWS_PROFILE": subject.AUTHORITY_PROFILE},
        {"AWS_ENDPOINT_URL_SSO": "https://example.invalid"},
    ):
        with pytest.raises(subject.PlanSeedSnapshotError) as captured:
            world.capture(tmp_path, environment=environment)
        assert captured.value.code in {
            "AWS_ENVIRONMENT_UNSAFE",
            "AMBIENT_AWS_PROFILE_FORBIDDEN",
        }
    assert world.timeline == []


def test_non_sso_credential_source_is_rejected_before_sts(tmp_path: Path) -> None:
    world = World(tmp_path)
    world.management_session.credential_method = "env"
    with pytest.raises(subject.PlanSeedSnapshotError) as captured:
        world.capture(tmp_path)
    assert captured.value.code == "AWS_CREDENTIAL_SOURCE_INVALID"
    assert world.timeline == []


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("source_profile", subject.AUTHORITY_PROFILE),
        ("role_arn", "arn:aws:iam::839393571433:role/ReadOnlyChain"),
        ("credential_source", "Environment"),
    ),
)
def test_chained_management_profile_is_rejected_before_sts(
    tmp_path: Path,
    field: str,
    value: str,
) -> None:
    world = World(tmp_path)
    profile = world.management_session._session.full_config["profiles"][  # noqa: SLF001
        subject.MANAGEMENT_PROFILE
    ]
    profile[field] = value

    with pytest.raises(subject.PlanSeedSnapshotError) as captured:
        world.capture(tmp_path)

    assert captured.value.code == "AWS_PROFILE_CONFIGURATION_INVALID"
    assert world.timeline == []


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("sso_account_id", route.AUTHORITY_ACCOUNT_ID),
        ("sso_role_name", "AWSAdministratorAccess"),
        ("sso_role_name", "ScanalyzeFounderPepIdentityAdmin"),
        ("region", "us-west-2"),
    ),
)
def test_management_profile_contract_drift_is_rejected_before_sts(
    tmp_path: Path,
    field: str,
    value: str,
) -> None:
    world = World(tmp_path)
    profile = world.management_session._session.full_config["profiles"][  # noqa: SLF001
        subject.MANAGEMENT_PROFILE
    ]
    profile[field] = value

    with pytest.raises(subject.PlanSeedSnapshotError) as captured:
        world.capture(tmp_path)

    assert captured.value.code == "AWS_PROFILE_CONFIGURATION_INVALID"
    assert world.timeline == []


def test_wrong_sts_account_blocks_all_inventory_clients(tmp_path: Path) -> None:
    world = World(tmp_path)
    world.management_sts.caller_account = "000000000000"
    with pytest.raises(subject.PlanSeedSnapshotError) as captured:
        world.capture(tmp_path)
    assert captured.value.code == "STS_IDENTITY_INVALID"
    assert not any("sso-admin" in item or item.endswith(":iam") for item in world.timeline)


def test_endpoint_drift_is_rejected(tmp_path: Path) -> None:
    world = World(tmp_path)
    world.authority_sts.meta.endpoint_url = "https://sts.us-west-2.amazonaws.com"
    with pytest.raises(subject.PlanSeedSnapshotError) as captured:
        world.capture(tmp_path)
    assert captured.value.code == "AWS_ENDPOINT_INVALID"


def test_provider_failure_is_public_safe(tmp_path: Path) -> None:
    world = World(tmp_path)

    def denied(**_request: Any) -> Any:
        raise AccessDenied()

    world.sso.list_instances = denied  # type: ignore[method-assign]
    with pytest.raises(subject.PlanSeedSnapshotError) as captured:
        world.capture(tmp_path)
    assert captured.value.code == "AWS_READ_FAILED"


@pytest.mark.parametrize("surface", ("permission_set", "generated_role"))
def test_both_live_policies_must_equal_the_git_predecessor(
    tmp_path: Path, surface: str
) -> None:
    world = World(tmp_path)
    drift = deepcopy(world.predecessor)
    drift["Statement"] = [*drift["Statement"], {"Effect": "Allow", "Action": "*", "Resource": "*"}]
    if surface == "permission_set":
        world.sso.inline_policy = drift
        expected = "LIVE_PERMISSION_SET_POLICY_NOT_PREDECESSOR"
    else:
        world.iam.inline_policy = drift
        expected = "LIVE_GENERATED_ROLE_POLICY_NOT_PREDECESSOR"
    with pytest.raises(subject.PlanSeedSnapshotError) as captured:
        world.capture(tmp_path)
    assert captured.value.code == expected


def test_duplicate_policy_json_keys_are_rejected(tmp_path: Path) -> None:
    world = World(tmp_path)

    def duplicate(**_request: Any) -> dict[str, str]:
        return {
            "InlinePolicy": (
                '{"Version":"2012-10-17","Version":"2012-10-17",'
                '"Statement":[]}'
            )
        }

    world.sso.get_inline_policy_for_permission_set = duplicate  # type: ignore[method-assign]
    with pytest.raises(subject.PlanSeedSnapshotError) as captured:
        world.capture(tmp_path)
    assert captured.value.code == "POLICY_READBACK_MALFORMED"


@pytest.mark.parametrize("surface", ("permission_set", "generated_role"))
def test_foreign_policy_authority_is_rejected(tmp_path: Path, surface: str) -> None:
    world = World(tmp_path)
    if surface == "permission_set":
        world.sso.managed = [{"Arn": "arn:aws:iam::aws:policy/ReadOnlyAccess"}]
        expected = "FOREIGN_PERMISSION_SET_AUTHORITY"
    else:
        world.iam.attached = [{"PolicyArn": "arn:aws:iam::aws:policy/ReadOnlyAccess"}]
        expected = "FOREIGN_GENERATED_ROLE_AUTHORITY"
    with pytest.raises(subject.PlanSeedSnapshotError) as captured:
        world.capture(tmp_path)
    assert captured.value.code == expected


def test_exact_single_user_assignment_and_target_account_are_required(
    tmp_path: Path,
) -> None:
    world = World(tmp_path)
    world.sso.accounts.append("000000000000")
    with pytest.raises(subject.PlanSeedSnapshotError) as captured:
        world.capture(tmp_path)
    assert captured.value.code == "PROVISIONED_ACCOUNT_SET_INVALID"

    world = World(tmp_path)
    world.sso.assignments[0]["PrincipalType"] = "GROUP"
    with pytest.raises(subject.PlanSeedSnapshotError) as captured:
        world.capture(tmp_path)
    assert captured.value.code == "PLAN_ASSIGNMENT_SET_INVALID"


def test_pending_operation_is_described_and_blocks_snapshot(tmp_path: Path) -> None:
    world = World(tmp_path)
    world.sso.pending["provisioning"] = [
        {"RequestId": "request-1", "Status": "IN_PROGRESS"}
    ]
    with pytest.raises(subject.PlanSeedSnapshotError) as captured:
        world.capture(tmp_path)
    assert captured.value.code == "PLAN_PENDING_OPERATION"
    assert "call:sso:DescribePermissionSetProvisioningStatus" in world.timeline


def test_saml_trust_must_be_exact(tmp_path: Path) -> None:
    world = World(tmp_path)
    world.iam.trust["Statement"][0]["Action"].append("sts:AssumeRole")
    with pytest.raises(subject.PlanSeedSnapshotError) as captured:
        world.capture(tmp_path)
    assert captured.value.code == "SAML_TRUST_MISMATCH"


def test_pagination_cycle_fails_closed(tmp_path: Path) -> None:
    world = World(tmp_path)
    world.sso.next_token_cycle = True
    with pytest.raises(subject.PlanSeedSnapshotError) as captured:
        world.capture(tmp_path)
    assert captured.value.code == "AWS_PAGINATION_INVALID"


def test_git_must_be_exact_clean_main(tmp_path: Path) -> None:
    world = World(tmp_path)
    world.git.working_status = "?? untracked"
    with pytest.raises(subject.PlanSeedSnapshotError) as captured:
        world.capture(tmp_path)
    assert captured.value.code == "SOURCE_NOT_EXACT_CLEAN_MAIN"
    assert world.timeline == []


def test_private_snapshot_is_create_only_owner_only_and_durable(
    tmp_path: Path,
) -> None:
    source_root = tmp_path / "source"
    source_root.mkdir()
    world = World(source_root)
    snapshot = world.capture(source_root)
    private_root = tmp_path / "private"

    destination = subject.write_private_snapshot(
        private_root=private_root,
        output_name=subject.DEFAULT_OUTPUT_NAME,
        snapshot=snapshot,
        source_commit=SOURCE_COMMIT,
        now=NOW,
    )

    assert stat.S_IMODE(private_root.stat().st_mode) == 0o700
    assert stat.S_IMODE(destination.stat().st_mode) == 0o600
    assert json.loads(destination.read_text()) == snapshot
    original = destination.read_bytes()
    with pytest.raises(subject.PlanSeedSnapshotError) as captured:
        subject.write_private_snapshot(
            private_root=private_root,
            output_name=subject.DEFAULT_OUTPUT_NAME,
            snapshot=snapshot,
            source_commit=SOURCE_COMMIT,
            now=NOW,
        )
    assert captured.value.code == "PRIVATE_SNAPSHOT_EXISTS"
    assert destination.read_bytes() == original


def test_private_snapshot_fsyncs_file_then_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source_root = tmp_path / "source"
    source_root.mkdir()
    world = World(source_root)
    snapshot = world.capture(source_root)
    private_root = tmp_path / "private"
    real_fsync = subject.os.fsync
    events: list[str] = []

    def tracked_fsync(descriptor: int) -> None:
        mode = subject.os.fstat(descriptor).st_mode
        events.append("directory" if stat.S_ISDIR(mode) else "file")
        real_fsync(descriptor)

    monkeypatch.setattr(subject.os, "fsync", tracked_fsync)
    subject.write_private_snapshot(
        private_root=private_root,
        output_name=subject.DEFAULT_OUTPUT_NAME,
        snapshot=snapshot,
        source_commit=SOURCE_COMMIT,
        now=NOW,
    )

    assert events == ["file", "directory"]


def test_private_root_symlink_is_rejected(tmp_path: Path) -> None:
    source_root = tmp_path / "source"
    source_root.mkdir()
    world = World(source_root)
    snapshot = world.capture(source_root)
    real = tmp_path / "real"
    real.mkdir(mode=0o700)
    alias = tmp_path / "alias"
    alias.symlink_to(real, target_is_directory=True)
    with pytest.raises(subject.PlanSeedSnapshotError) as captured:
        subject.write_private_snapshot(
            private_root=alias,
            output_name=subject.DEFAULT_OUTPUT_NAME,
            snapshot=snapshot,
            source_commit=SOURCE_COMMIT,
            now=NOW,
        )
    assert captured.value.code == "PRIVATE_ROOT_INVALID"


def _load_cli() -> Any:
    path = (
        REPO_ROOT
        / "scripts/deployment/"
        "platform-authority-plan-permission-repair-plan-seed-snapshot.py"
    )
    spec = importlib.util.spec_from_file_location("gug376_plan_seed_cli", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize(
    "relative_path",
    [
        "docs/deployment/platform-authority-bootstrap-plan-permission-repair.md",
        "docs/operations/platform-authority-bootstrap-plan-permission-repair.md",
    ],
)
def test_runbooks_require_connected_plan_snapshot_before_broker_config(
    relative_path: str,
) -> None:
    text = (REPO_ROOT / relative_path).read_text(encoding="utf-8")
    producer = text.index(
        "platform-authority-plan-permission-repair-plan-seed-snapshot.py"
    )
    consumer = text.index("  materialize-broker-config", producer)
    block = text[producer:consumer]
    for fragment in (
        '--bootstrap-change-set-name "$BOOTSTRAP_CHANGE_SET_NAME"',
        '--private-root "$PRIVATE_ROUTE_ROOT"',
        '--output-name "$PLAN_SEED_SNAPSHOT_NAME"',
        "--authority-profile 042360977644_AWSReadOnlyAccess",
        "--management-profile 839393571433_ReadOnlyAccess",
        "--region us-east-1",
    ):
        assert fragment in block
    narrative = text[consumer : consumer + 2_500]
    consumer_block = text[consumer : consumer + 800]
    assert '--plan-snapshot-name "$PLAN_SEED_SNAPSHOT_NAME"' in consumer_block
    assert "read-only" in narrative
    assert "plan_snapshot" in narrative
    assert "must omit" in narrative
    assert "15-minute" in narrative
    assert "no AWS mutation" in narrative or "writes no AWS state" in narrative


@pytest.mark.parametrize(
    "relative_path",
    [
        "docs/deployment/platform-authority-bootstrap-plan-permission-repair.md",
        "docs/operations/platform-authority-bootstrap-plan-permission-repair.md",
    ],
)
def test_runbooks_define_private_fail_closed_alias_invocation(
    relative_path: str,
) -> None:
    text = (REPO_ROOT / relative_path).read_text(encoding="utf-8")
    for fragment in (
        "aws sso login --profile \"$BROKER_PROFILE\"",
        "aws sso login --profile \"$BROKER_RECOVERY_PROFILE\"",
        "aws sso login --profile \"$REPAIR_PROFILE\"",
        "042360977644_ScanalyzeGug376BrokerInvoker",
        "042360977644_ScanalyzeGug376BrokerSeedCleanup",
        "042360977644_ScanalyzeBootstrapPlanRepair",
        "042360977644_ScanalyzeAuthorityBootstrapPlan",
        "--payload '{}'",
        "--cli-binary-format raw-in-base64-out",
        "AWS_RETRY_MODE=standard AWS_MAX_ATTEMPTS=1 aws lambda invoke",
        "--no-cli-pager --cli-connect-timeout 5 --cli-read-timeout 900",
        "AWS_RETRY_MODE=standard AWS_MAX_ATTEMPTS=1 aws sts get-caller-identity",
        'chmod 600 "$BROKER_IDENTITY_FILE"',
        'chmod 600 "$BROKER_RECOVERY_IDENTITY_FILE"',
        'chmod 600 "$REPAIR_IDENTITY_FILE"',
        'chmod 600 "$NORMAL_PLAN_IDENTITY_FILE" "$NORMAL_PLAN_PREFLIGHT_FILE"',
        'AWSReservedSSO_ScanalyzeGug376BrokerInvoker_[0-9A-Fa-f]{16}',
        'AWSReservedSSO_ScanalyzeGug376BrokerSeedCleanup_[0-9A-Fa-f]{16}',
        'AWSReservedSSO_ScanalyzeBootstrapPlanRepair_[0-9A-Fa-f]{16}',
        'AWSReservedSSO_ScanalyzeAuthorityBootstrapPlan_[0-9A-Fa-f]{16}',
        'PLAN_SEED_SNAPSHOT_FILE="$PRIVATE_ROUTE_ROOT/$PLAN_SEED_SNAPSHOT_NAME"',
        'NORMAL_PLAN_GENERATED_ROLE_NAME="$(jq -er',
        'NORMAL_PLAN_GENERATED_ROLE_ARN="$(jq -er',
        'jq -ecj --arg role "$NORMAL_PLAN_GENERATED_ROLE_NAME"',
        "{caller_arn:$arn}",
        'NORMAL_PLAN_CALLER_ARN_DIGEST="sha256:$(',
        'LAST_BROKER_PAYLOAD_FILE="$payload_file"',
        '.normal_plan_caller_arn_digest == $digest',
        '.receipt_digest | test("^sha256:[0-9a-f]{64}$")',
        '.Account == "042360977644"',
        "--region us-east-1",
        'chmod 600 "$payload_file" "$metadata_file"',
        'has("FunctionError") | not',
        "jq -e",
        "PLAN_VERIFIED",
        "REPAIR_VERIFIED",
        "RECONCILE_VERIFIED",
        "SCANALYZE_GUG274_SDK_RUNTIME_ROOT='<absolute-reviewed-gug274-sdk-runtime-root>'",
        'aws sso login --profile "$NORMAL_PLAN_PROFILE"',
        'AWS_PROFILE="$NORMAL_PLAN_PROFILE" AWS_REGION=us-east-1',
        "platform-authority-bootstrap.py preflight-recovery",
        "--destination-account-id 839393571433",
        "PASS: zero active Change Sets verified across all pages",
        "NO_CHANGE: recovery preflight performed no AWS mutation",
        "never repeat",
        "non-production",
    ):
        assert fragment in text
    for alias in (
        "seed-revoke-create-v1",
        "seed-revoke-execute-v1",
        "delegation-create-v1",
        "delegation-execute-v1",
        "pep-create-v1",
        "pep-execute-v1",
        "closeout-gate-v1",
        "delegation-revoke-create-v1",
        "delegation-revoke-execute-v1",
        "route-revoke-create-v1",
        "route-revoke-execute-v1",
        "recover-v1",
        "create-dispatch-recovery-v1",
        "execute-dispatch-recovery-v1",
        "plan-v1",
        "repair-v1",
        "reconcile-v1",
    ):
        assert alias in text
    ordered_commands = [
        (
            'complete_broker_bounded "$EXECUTE_RECOVERY_FUNCTION" '
            '"$RECOVERY_ALIAS" "$EXECUTE_RECOVERY_RECEIPT_ALIAS" '
            "pep-execute-v1 PEP_EXECUTE_DISPATCHED PEP_TERMINAL route"
        ),
        (
            "invoke_repair scanalyze-platform-authority-plan-policy-plan "
            "plan-v1 plan PLAN_VERIFIED"
        ),
        (
            "invoke_repair scanalyze-platform-authority-plan-policy-repair "
            "repair-v1 repair REPAIR_VERIFIED"
        ),
        (
            "invoke_repair scanalyze-platform-authority-plan-policy-reconcile "
            "reconcile-v1 reconcile RECONCILE_VERIFIED"
        ),
        'aws sso login --profile "$NORMAL_PLAN_PROFILE"',
        "scripts/deployment/platform-authority-bootstrap.py preflight-recovery",
        (
            "invoke_closeout_bounded"
        ),
        (
            'invoke_broker_once "$CREATOR_FUNCTION" '
            "delegation-revoke-create-v1 "
            "DELEGATION_REVOKE_CREATE_DISPATCHED"
        ),
        (
            'complete_broker_bounded "$EXECUTE_RECOVERY_FUNCTION" '
            '"$RECOVERY_ALIAS" "$EXECUTE_RECOVERY_RECEIPT_ALIAS" '
            "route-revoke-execute-v1 ROUTE_REVOKE_EXECUTE_DISPATCHED "
            "ROUTE_REVOKED recovery"
        ),
    ]
    positions = [text.index(command) for command in ordered_commands]
    assert positions == sorted(positions)
    delegation_terminal = text.index(
        'complete_broker_bounded "$EXECUTE_RECOVERY_FUNCTION" '
        '"$RECOVERY_ALIAS" "$EXECUTE_RECOVERY_RECEIPT_ALIAS" '
        "delegation-execute-v1 DELEGATION_EXECUTE_DISPATCHED "
        "DELEGATION_TERMINAL route"
    )
    repair_login = text.index('aws sso login --profile "$REPAIR_PROFILE"')
    plan_invoke = text.index(ordered_commands[1])
    assert delegation_terminal < repair_login < plan_invoke
    success_path = text[positions[0] : positions[-1]]
    assert "905418363887" not in success_path
    assert 'NORMAL_PLAN_CALLER_ARN="' not in text
    assert '--arg caller "$NORMAL_PLAN_CALLER_ARN"' not in text

    helper_start = text.index("invoke_closeout_bounded() {")
    helper_end = text.index("\n}\n\ninvoke_closeout_bounded", helper_start) + 2
    helper = text[helper_start:helper_end]
    for fragment in (
        "CLOSEOUT_MAX_ATTEMPTS=24",
        "CLOSEOUT_BACKOFF_SECONDS=20",
        "CLOSEOUT_PROOF_BUDGET_SECONDS=780",
        'CLOSEOUT_ROUTE_NOT_AFTER="$(jq -er',
        'test "$now_epoch" -lt "$((CLOSEOUT_ROUTE_DEADLINE_EPOCH - 60))"',
        'test "$now_epoch" -lt "$CLOSEOUT_PROOF_DEADLINE_EPOCH"',
        'mktemp "$PRIVATE_ROUTE_ROOT/closeout-gate-v1.payload.XXXXXX"',
        'mktemp "$PRIVATE_ROUTE_ROOT/closeout-gate-v1.metadata.XXXXXX"',
        'chmod 600 "$payload_file" "$metadata_file"',
        "AWS_RETRY_MODE=standard AWS_MAX_ATTEMPTS=1 aws lambda invoke",
        "--qualifier closeout-gate-v1",
        "--payload '{}'",
        '.FunctionError == "Unhandled"',
        'GUG376_ROUTE_BROKER_READ_ONLY_PENDING:NORMAL_PLAN_PROOF_PENDING',
        'sleep "$CLOSEOUT_BACKOFF_SECONDS"',
    ):
        assert fragment in text[helper_start - 1_500 : helper_end]
    assert "CLOSEOUT_EVIDENCE_PENDING" not in helper
    assert "invoke_repair" not in helper
    assert "plan-v1" not in helper
    assert "repair-v1" not in helper
    assert "reconcile-v1" not in helper
    assert text.count("\ninvoke_closeout_bounded\n") == 1

    completion_start = text.index("complete_broker_bounded() {")
    completion_end = text.index(
        "\n}\n\ninvoke_broker_once", completion_start
    ) + 2
    completion = text[completion_start:completion_end]
    for fragment in (
        "BROKER_COMPLETION_MAX_ATTEMPTS=90",
        "BROKER_COMPLETION_BACKOFF_SECONDS=20",
        "BROKER_COMPLETION_BUDGET_SECONDS=1800",
        'BROKER_ROUTE_NOT_AFTER="$(jq -er',
        'BROKER_RECOVERY_NOT_AFTER="$(jq -er',
        'route) absolute_deadline_epoch="$BROKER_ROUTE_DEADLINE_EPOCH"',
        'recovery) absolute_deadline_epoch="$BROKER_RECOVERY_DEADLINE_EPOCH"',
        'test "$now_epoch" -lt "$((absolute_deadline_epoch - 60))"',
        'test "$now_epoch" -lt "$local_deadline_epoch"',
        'mktemp "$PRIVATE_ROUTE_ROOT/${dispatched_alias_name}.completion.payload.XXXXXX"',
        'mktemp "$PRIVATE_ROUTE_ROOT/${dispatched_alias_name}.completion.metadata.XXXXXX"',
        '--function-name "$recovery_function_name" --qualifier "$recovery_qualifier"',
        '--profile "$BROKER_RECOVERY_PROFILE" --region us-east-1',
        '--arg alias "$expected_receipt_alias" --arg state "$expected_state"',
        '.errorType == "RouteBrokerReadOnlyPending"',
        "^GUG376_ROUTE_BROKER_READ_ONLY_PENDING:",
    ):
        assert fragment in text[completion_start - 3_000 : completion_end]
    assert text.count("\ninvoke_broker_once ") == 10
    assert text.count("\ncomplete_broker_bounded ") == 10
    assert '\ninvoke_broker "' not in text
    completion_calls = [
        line
        for line in text.splitlines()
        if line.startswith("complete_broker_bounded ")
    ]
    assert all(len(line.split()) == 8 for line in completion_calls)
    for line in completion_calls:
        assert '"$RECOVERY_ALIAS"' in line
        if '"$CREATE_RECOVERY_FUNCTION"' in line:
            assert '"$CREATE_RECOVERY_RECEIPT_ALIAS"' in line
            assert "-create-v1 " in line
        else:
            assert '"$EXECUTE_RECOVERY_FUNCTION"' in line
            assert '"$EXECUTE_RECOVERY_RECEIPT_ALIAS"' in line
            assert "-execute-v1 " in line
    assert all(line.endswith(" route") for line in completion_calls[:-1])
    assert completion_calls[-1].endswith(" ROUTE_REVOKED recovery")
    assert "aws_mutations == 1" in text[
        text.index("invoke_broker_once() {") : completion_start
    ]
    assert "aws_mutations == 0" in completion
    assert '--profile "$BROKER_PROFILE"' not in completion


def test_runbook_normal_plan_digest_matches_canonical_python_bytes() -> None:
    caller = (
        "arn:aws:sts::042360977644:assumed-role/"
        f"{ROLE_NAME}/cesar.guzman"
    )
    canonical = json.dumps(
        {"caller_arn": caller},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    assert canonical == ('{"caller_arn":"' + caller + '"}').encode("utf-8")
    assert "sha256:" + hashlib.sha256(canonical).hexdigest() == route.digest_value(
        {"caller_arn": caller}
    )


def test_deployment_and_operations_runbooks_have_identical_broker_stage_order() -> None:
    paths = (
        REPO_ROOT
        / "docs/deployment/platform-authority-bootstrap-plan-permission-repair.md",
        REPO_ROOT
        / "docs/operations/platform-authority-bootstrap-plan-permission-repair.md",
    )
    sequences = []
    for path in paths:
        lines = path.read_text(encoding="utf-8").splitlines()
        sequences.append(
            [
                line
                for line in lines
                if line.startswith("invoke_broker_once ")
                or line.startswith("complete_broker_bounded ")
                or line == "invoke_closeout_bounded"
            ]
        )
    assert sequences[0] == sequences[1]


def test_make_status_separates_read_only_inventory_from_offline_check() -> None:
    makefile = (REPO_ROOT / "Makefile").read_text(encoding="utf-8")
    status = next(
        line for line in makefile.splitlines()
        if "GUG-376 Plan repair status:" in line
    )
    for claim in (
        "READ_ONLY_INVENTORY_AWS_CALLS=9",
        "CHECK_AWS_CALLS=0",
        "AWS_MUTATIONS=0",
        "LIVE_RUN_NOT_EXECUTED",
        "NOT_DEPLOYED",
        "PRODUCTION_NO_GO",
    ):
        assert claim in status
    assert " / AWS_CALLS=0 / " not in status


def test_cli_prints_only_public_safe_summary(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    cli = _load_cli()
    source_root = tmp_path / "source"
    source_root.mkdir()
    private_root = tmp_path / "private"
    snapshot = {
        "record_type": config.PLAN_SNAPSHOT_RECORD_TYPE,
        "source_commit": SOURCE_COMMIT,
        "snapshot_digest": "sha256:" + "1" * 64,
        "current_policy_digest": "sha256:" + "2" * 64,
        "desired_policy_digest": "sha256:" + "3" * 64,
        "aws_calls": 22,
        "private_principal": PRINCIPAL_ID,
    }
    monkeypatch.setattr(subject, "capture_plan_seed_snapshot", lambda **_: snapshot)
    monkeypatch.setattr(
        subject,
        "write_private_snapshot",
        lambda **_: private_root / subject.DEFAULT_OUTPUT_NAME,
    )

    result = cli.main(
        [
            "--source-root",
            str(source_root),
            "--source-commit",
            SOURCE_COMMIT,
            "--bootstrap-change-set-name",
            CHANGE_SET_NAME,
            "--private-root",
            str(private_root),
            "--authority-profile",
            subject.AUTHORITY_PROFILE,
            "--management-profile",
            subject.MANAGEMENT_PROFILE,
            "--region",
            subject.EXPECTED_REGION,
        ]
    )

    captured = capsys.readouterr()
    assert result == 0
    assert captured.err == ""
    assert PRINCIPAL_ID not in captured.out
    assert ROLE_ARN not in captured.out
    assert json.loads(captured.out)["production_status"] == "NO-GO"


def test_cli_argument_errors_are_stable(capsys: pytest.CaptureFixture[str]) -> None:
    cli = _load_cli()
    assert cli.main([]) == 2
    assert json.loads(capsys.readouterr().err) == {"error": "CLI_ARGUMENTS_INVALID"}


@pytest.mark.parametrize(
    ("option", "value"),
    (
        ("--authority-profile", "default"),
        ("--management-profile", "839393571433_AWSAdministratorAccess"),
        ("--management-profile", "839393571433_ScanalyzeFounderPepIdentityAdmin"),
        ("--management-profile", "839393571433_ScanalyzeFounderPepSeed"),
        ("--region", "us-west-2"),
    ),
)
def test_cli_rejects_non_contract_identity_before_capture(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    option: str,
    value: str,
) -> None:
    cli = _load_cli()
    called = False

    def unexpected_capture(**_arguments: Any) -> dict[str, Any]:
        nonlocal called
        called = True
        return {}

    monkeypatch.setattr(subject, "capture_plan_seed_snapshot", unexpected_capture)
    arguments = [
        "--source-root",
        str(tmp_path),
        "--source-commit",
        SOURCE_COMMIT,
        "--bootstrap-change-set-name",
        CHANGE_SET_NAME,
        "--private-root",
        str(tmp_path / "private"),
        "--authority-profile",
        subject.AUTHORITY_PROFILE,
        "--management-profile",
        subject.MANAGEMENT_PROFILE,
        "--region",
        subject.EXPECTED_REGION,
    ]
    option_index = arguments.index(option)
    arguments[option_index + 1] = value

    assert cli.main(arguments) == 2
    assert json.loads(capsys.readouterr().err) == {"error": "CLI_ARGUMENTS_INVALID"}
    assert called is False


def test_no_mutating_aws_api_names_are_reachable() -> None:
    source = Path(subject.__file__).read_text(encoding="utf-8")
    forbidden = (
        ".put_inline_policy_to_permission_set(",
        ".provision_permission_set(",
        ".create_account_assignment(",
        ".delete_account_assignment(",
        ".create_permission_set(",
        ".update_permission_set(",
        ".delete_permission_set(",
        ".put_role_policy(",
        ".attach_role_policy(",
    )
    assert not any(item in source for item in forbidden)
    assert "aws_mutations\": 0" in source
