"""Focused offline integration tests for GUG-393 private input discovery."""

from __future__ import annotations

import copy
from datetime import UTC, datetime, timedelta
import os
from pathlib import Path
import stat
from typing import Any, Mapping

import pytest

from tests.test_deployment import (
    test_gug376_authority_inventory_collector as authority_data,
)
from tests.test_deployment import (
    test_gug376_identity_center_inventory_collector as identity_data,
)
from tooling.platform_authority_gug365_upstream_inventory import (
    canonical_digest,
    canonical_json,
)
from tooling.platform_authority_gug376_authority_inventory_collector import (
    capture_live as capture_authority_live,
    read_private_json,
    write_private_json,
)
from tooling.platform_authority_gug376_identity_center_inventory_collector import (
    capture_live as capture_identity_live,
)
from tooling.platform_authority_gug376_live_readonly_orchestrator import (
    CallLedger,
)
from tooling import platform_authority_gug376_live_provider as provider_module
from tooling import platform_authority_gug393_discovery_budget as budget_module
from tooling import (
    platform_authority_gug393_private_input_discovery as discovery,
)


AUTHORITY_ACCOUNT = "222222222222"
IDENTITY_ACCOUNT = "111111111111"
SOURCE_SHA = "a" * 40
TREE_SHA = "b" * 40
START = datetime.now(UTC).replace(microsecond=0) - timedelta(minutes=1)
END = START + timedelta(minutes=10)
HOST_DIGEST = discovery.operational_host_digest()
APPROVAL_DIGEST = canonical_digest({"approval": "gug393-discovery"})
ZERO_DIGEST = "sha256:" + "0" * 64


def _stamp(value: datetime) -> str:
    return value.astimezone(UTC).replace(microsecond=0).isoformat().replace(
        "+00:00", "Z"
    )


def _root(tmp_path: Path, name: str = "private") -> Path:
    root = tmp_path / name
    root.mkdir(mode=0o700, parents=True)
    root.chmod(0o700)
    return root


def test_operational_host_digest_distinguishes_equivalent_runtime_hosts(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(discovery.platform, "node", lambda: "gug393-host-a")
    first = discovery.operational_host_digest()
    monkeypatch.setattr(discovery.platform, "node", lambda: "gug393-host-b")
    second = discovery.operational_host_digest()
    assert first != second

    monkeypatch.setattr(discovery.platform, "node", lambda: "")
    with pytest.raises(
        discovery.PrivateInputDiscoveryError,
        match="HOST_BINDING_UNAVAILABLE",
    ):
        discovery.operational_host_digest()


def _sdk_root(tmp_path: Path) -> Path:
    root = tmp_path / "sdk-runtime"
    root.mkdir(mode=0o700, exist_ok=True)
    root.chmod(0o700)
    return root.resolve(strict=True)


@pytest.fixture(autouse=True)
def _closed_test_context(monkeypatch: pytest.MonkeyPatch) -> None:
    for key in tuple(os.environ):
        if key.startswith("AWS_") or key in {
            "BOTO_CONFIG",
            "REQUESTS_CA_BUNDLE",
            "SSL_CERT_FILE",
            "SSL_CERT_DIR",
        }:
            monkeypatch.delenv(key)
    monkeypatch.setattr(authority_data, "ACCOUNT", AUTHORITY_ACCOUNT)
    monkeypatch.setattr(authority_data, "START", START)
    monkeypatch.setattr(identity_data, "START", START)
    monkeypatch.setattr(
        discovery,
        "_observed_utc_now",
        lambda: START + timedelta(minutes=4),
    )


def _budget() -> dict[str, Any]:
    return {
        "record_type": budget_module.RECORD_TYPE,
        "schema_version": budget_module.SCHEMA_VERSION,
        "max_network_calls": 4,
        "max_provider_calls": 4,
        "max_credential_vending_calls": 0,
        "max_page_calls": 4,
        "max_response_bytes": 500,
        "max_total_response_bytes": 1_000,
        "maximum_cost_usd": "0.000001140",
        "cost_model": {
            "fixed_run_cost_usd_upper": "0.000000100",
            "per_network_attempt_cost_usd_upper": "0.000000010",
            "per_projected_response_byte_cost_usd_upper": "0.000000001",
            "pricing_reference_digest": canonical_digest(
                {"pricing": "owner-reviewed"}
            ),
            "valid_from": _stamp(START - timedelta(minutes=1)),
            "valid_until": _stamp(END + timedelta(minutes=1)),
        },
    }


def _source_contract() -> discovery.DerivedSourceContract:
    authority_plan = authority_data._live_plan()  # noqa: SLF001
    identity_plan = identity_data._live_plan()  # noqa: SLF001
    body: dict[str, Any] = {
        "record_type": discovery.SOURCE_CONTRACT_TYPE,
        "schema_version": 2,
        "implementation_issue": discovery.IMPLEMENTATION_ISSUE,
        "parent_issue": discovery.PARENT_ISSUE,
        "live_issue": discovery.LIVE_ISSUE,
        "selector_source_commit_sha": SOURCE_SHA,
        "selector_source_tree_sha": TREE_SHA,
        "executor_source_commit_sha": SOURCE_SHA,
        "executor_source_tree_sha": TREE_SHA,
        "gug363_plan_digest": canonical_digest({"plan": "gug363"}),
        "gug365_plan_digest": canonical_digest({"plan": "gug365"}),
        "source_bundle_digest": canonical_digest({"bundle": "reviewed"}),
        "authority_account_id": AUTHORITY_ACCOUNT,
        "identity_center_account_id": IDENTITY_ACCOUNT,
        "authority_targets": copy.deepcopy(authority_plan["targets"]),
        "identity_center_private_targets": copy.deepcopy(
            identity_plan["private_targets"]
        ),
        "identity_center_kms_binding_digest": canonical_digest(
            {
                "binding_name": "identity_center_kms_key_arn",
                "identity_center_instance_arn": identity_data.INSTANCE,
                "mode": identity_plan["private_targets"][
                    "identity_center_kms_mode"
                ],
                "key_arn": identity_plan["private_targets"][
                    "identity_center_kms_key_arn"
                ],
            }
        ),
        "identity_center_source_expectations": {
            "instance_arn": identity_data.INSTANCE,
            "application_arn": identity_data.APP,
            "generated_role_arns": {
                "retire_approve": authority_plan["targets"][
                    "retire_approve_generated_role_arn"
                ],
                "retire_class": authority_plan["targets"][
                    "retire_class_generated_role_arn"
                ],
            },
        },
        "selector_provenance": {},
        "fixed_source_digest": canonical_digest({"fixed": "scanalyze"}),
        "read_only": True,
        "aws_calls": 0,
        "aws_mutations": 0,
        "deployment_authorized": False,
        "production_status": "NO-GO",
    }
    document = {**body, "source_contract_digest": canonical_digest(body)}
    return discovery.DerivedSourceContract(
        discovery._SOURCE_CONTRACT_SENTINEL,  # noqa: SLF001
        document,
    )


def _profiles() -> dict[str, Any]:
    authority_plan = authority_data._live_plan()  # noqa: SLF001
    identity_plan = identity_data._live_plan()  # noqa: SLF001
    return {
        "authority": {
            "name": "scanalyze-authority-readonly",
            "source": "DIRECT_SSO",
            "chain_depth": 0,
            "expected_account_id": AUTHORITY_ACCOUNT,
            "expected_principal_arn": authority_plan["expected_principal_arn"],
            "expected_sso_role_name": "ScanalyzeAuthorityReadOnly",
            "authority_verification_digest": authority_plan[
                "authority_verification_digest"
            ],
        },
        "identity_center": {
            "name": "scanalyze-identity-readonly",
            "source": "DIRECT_SSO",
            "chain_depth": 0,
            "expected_account_id": IDENTITY_ACCOUNT,
            "expected_principal_arn": identity_plan["expected_principal_arn"],
            "expected_sso_role_name": "ScanalyzeIdentityReadOnly",
            "authority_verification_digest": identity_plan[
                "authority_verification_digest"
            ],
        },
    }


def _materialize(
    root: Path,
    *,
    approval_reference_digest: str = APPROVAL_DIGEST,
    request_file: str = discovery.DEFAULT_REQUEST_FILE,
    checkpoint_file: str = discovery.DEFAULT_CHECKPOINT_FILE,
) -> discovery.MaterializedDiscoveryRequest:
    return discovery.materialize_discovery_request(
        source_contract=_source_contract(),
        profiles=_profiles(),
        discovery_budget=_budget(),
        sdk_runtime_root=str(_sdk_root(root.parent)),
        private_root=root,
        source_commit_sha=SOURCE_SHA,
        source_tree_sha=TREE_SHA,
        host_digest=HOST_DIGEST,
        not_before=_stamp(START),
        expires_at=_stamp(END),
        approval_reference_digest=approval_reference_digest,
        request_file=request_file,
        owner_checkpoint_file=checkpoint_file,
    )


def _claim(
    root: Path, materialized: discovery.MaterializedDiscoveryRequest
) -> tuple[dict[str, Any], discovery.DiscoveryExecutionCapability]:
    request = materialized.request
    checkpoint = materialized.owner_checkpoint
    return discovery.read_and_claim_discovery_request(
        private_root=root,
        request_file=request["request_file"],
        owner_checkpoint_file=request["owner_checkpoint_file"],
        expected_request_digest=request["request_digest"],
        expected_checkpoint_digest=checkpoint["checkpoint_digest"],
        approval_reference_digest=request["approval_reference_digest"],
        source_commit_sha=SOURCE_SHA,
        source_tree_sha=TREE_SHA,
        host_digest=HOST_DIGEST,
        now=START + timedelta(minutes=2),
    )


def _provider_binding(request: dict[str, Any]) -> dict[str, Any]:
    profiles = request["profiles"]
    return {
        "sdk_runtime_root": request["sdk_runtime_root"],
        "authority_profile": profiles["authority"]["name"],
        "identity_center_profile": profiles["identity_center"]["name"],
        "authority_expected_account_id": profiles["authority"][
            "expected_account_id"
        ],
        "authority_expected_principal_digest": profiles["authority"][
            "expected_principal_digest"
        ],
        "authority_expected_sso_role_name_digest": profiles["authority"][
            "expected_sso_role_name_digest"
        ],
        "identity_expected_account_id": profiles["identity_center"][
            "expected_account_id"
        ],
        "identity_expected_principal_digest": profiles["identity_center"][
            "expected_principal_digest"
        ],
        "identity_expected_sso_role_name_digest": profiles["identity_center"][
            "expected_sso_role_name_digest"
        ],
        "authority_verification_digest": profiles["authority"][
            "authority_verification_digest"
        ],
        "identity_authority_verification_digest": profiles["identity_center"][
            "authority_verification_digest"
        ],
        "budget_digest": request["budget_digest"],
    }


class _ObservedDiscoverySession:
    def __init__(
        self,
        owner: provider_module.LiveProviderFactory,
        *,
        capture_index: int,
        policy_digest: str,
    ) -> None:
        self._owner = owner
        self._capture_index = capture_index
        self._policy_digest = policy_digest
        self._session_digest = canonical_digest(
            {"capture_index": capture_index, "stage": "discovery"}
        )
        self._stage = "discovery"
        self._identity_validated = True
        owner._record(
            domain="identity_center",
            session_digest=self._session_digest,
            operation="sts:GetCallerIdentity",
            request_digest=canonical_digest({}),
            response_digest=canonical_digest({"identity": "validated"}),
            outcome="SUCCESS",
        )

    def _record(self, operation: str, request: Mapping[str, Any], value: Any) -> None:
        self._owner._record(
            domain="identity_center",
            session_digest=self._session_digest,
            operation=operation,
            request_digest=canonical_digest(request),
            response_digest=canonical_digest(value),
            outcome="SUCCESS",
        )

    def _paginate(self, **kwargs: Any) -> list[Any]:
        operation = kwargs["operation"]
        request = kwargs["request"]
        if operation == "sso:ListInstances":
            values: list[Any] = [
                {
                    "IdentityStoreId": identity_data.PRIVATE[
                        "identity_store_id"
                    ],
                    "InstanceArn": identity_data.INSTANCE,
                    "OwnerAccountId": identity_data.MGMT,
                    "Status": "ACTIVE",
                }
            ]
        elif operation == "sso:ListApplications":
            values = [
                {
                    "ApplicationArn": identity_data.APP,
                    "Name": identity_data.PRIVATE["application_name"],
                }
            ]
        elif operation == "sso:ListPermissionSets":
            values = [
                identity_data.TARGETS["retire_approve_permission_set_arn"],
                identity_data.TARGETS["retire_class_permission_set_arn"],
            ]
        else:  # pragma: no cover - the closed reader has only these pages
            raise AssertionError(operation)
        self._record(operation, request, values)
        return values

    def _invoke(self, **kwargs: Any) -> dict[str, Any]:
        operation = kwargs["operation"]
        request = kwargs["request"]
        if operation == "sso:DescribeInstance":
            assert request == {"InstanceArn": identity_data.INSTANCE}
            value = {
                "InstanceArn": identity_data.INSTANCE,
                "IdentityStoreId": identity_data.PRIVATE["identity_store_id"],
                "OwnerAccountId": identity_data.MGMT,
                "Status": "ACTIVE",
                "EncryptionConfigurationDetails": {
                    "KeyType": identity_data.LIVE_PRIVATE[
                        "identity_center_kms_mode"
                    ],
                    "KmsKeyArn": identity_data.LIVE_PRIVATE[
                        "identity_center_kms_key_arn"
                    ],
                    "EncryptionStatus": "ENABLED",
                },
            }
            self._record(operation, request, value)
            return value
        assert operation == "sso:DescribePermissionSet"
        arn = request["PermissionSetArn"]
        name = (
            identity_data.NAMES[0]
            if arn
            == identity_data.TARGETS["retire_approve_permission_set_arn"]
            else identity_data.NAMES[1]
        )
        value = {
            "PermissionSet": {
                "Name": name,
                "PermissionSetArn": arn,
            }
        }
        self._record(operation, request, value)
        return value


def _transition_attestation(
    factory: provider_module.LiveProviderFactory,
    *,
    capture_index: int,
    policy_digest: str,
) -> object:
    session = _ObservedDiscoverySession(
        factory,
        capture_index=capture_index,
        policy_digest=policy_digest,
    )
    reader = provider_module._IdentityDiscoveryReader(session)  # noqa: SLF001
    instances = reader.list_instances(None)["items"]
    described = reader.describe_instance(identity_data.INSTANCE)["value"]
    applications = reader.list_applications(
        identity_data.INSTANCE,
        identity_data.PRIVATE["application_name"],
        None,
    )["items"]
    permission_sets = reader.list_permission_sets(
        identity_data.INSTANCE,
        identity_data.NAMES,
        None,
    )["items"]
    observed = {
        "instances": instances,
        "applications": applications,
        "permission_sets": permission_sets,
    }
    assert observed == identity_data.DISCOVERY
    return reader.attest_transition(
        canonical_digest({"discovery": observed, "instance": described})
    )


def _reseal(value: dict[str, Any], field: str) -> None:
    value[field] = canonical_digest(
        {key: item for key, item in value.items() if key != field}
    )


def test_request_checkpoint_sealing_is_deterministic_and_tamper_evident(
    tmp_path: Path,
) -> None:
    root = _root(tmp_path)
    first = _materialize(root)
    second = _materialize(root)
    assert first == second

    request = first.request
    checkpoint = first.owner_checkpoint
    preliminary = {
        key: item
        for key, item in request.items()
        if key not in {"owner_checkpoint_digest", "request_digest"}
    }
    assert checkpoint["request_digest"] == canonical_digest(preliminary)
    assert request["owner_checkpoint_digest"] == checkpoint["checkpoint_digest"]
    assert checkpoint["checkpoint_digest"] == canonical_digest(
        {
            key: item
            for key, item in checkpoint.items()
            if key != "checkpoint_digest"
        }
    )
    assert request["request_digest"] == canonical_digest(
        {key: item for key, item in request.items() if key != "request_digest"}
    )

    unsealed = copy.deepcopy(request)
    unsealed["expires_at"] = _stamp(END - timedelta(minutes=1))
    with pytest.raises(
        discovery.PrivateInputDiscoveryError, match="DISCOVERY_REQUEST_INVALID"
    ):
        discovery.persist_discovery_request(
            root,
            discovery.MaterializedDiscoveryRequest(
                request=unsealed,
                owner_checkpoint=checkpoint,
            ),
        )

    self_sealed = copy.deepcopy(unsealed)
    _reseal(self_sealed, "request_digest")
    with pytest.raises(
        discovery.PrivateInputDiscoveryError,
        match="DISCOVERY_CHECKPOINT_BINDING_MISMATCH",
    ):
        discovery.persist_discovery_request(
            root,
            discovery.MaterializedDiscoveryRequest(
                request=self_sealed,
                owner_checkpoint=checkpoint,
            ),
        )


@pytest.mark.parametrize("field", ("request", "checkpoint"))
@pytest.mark.parametrize(
    "reserved_name", sorted(discovery.RESERVED_LIFECYCLE_OUTPUT_FILES)
)
def test_request_materialization_reserves_every_lifecycle_output_filename(
    tmp_path: Path, field: str, reserved_name: str
) -> None:
    root = _root(tmp_path)
    kwargs = (
        {"request_file": reserved_name}
        if field == "request"
        else {"checkpoint_file": reserved_name}
    )
    with pytest.raises(
        discovery.PrivateInputDiscoveryError, match="PRIVATE_OUTPUT_COLLISION"
    ):
        _materialize(root, **kwargs)


def test_request_materialization_rejects_placeholder_approval_and_cost_model(
    tmp_path: Path,
) -> None:
    root = _root(tmp_path)
    with pytest.raises(
        discovery.PrivateInputDiscoveryError,
        match="APPROVAL_REFERENCE_INVALID",
    ):
        _materialize(root, approval_reference_digest=ZERO_DIGEST)

    invalid_budget = _budget()
    invalid_budget["cost_model"]["pricing_reference_digest"] = ZERO_DIGEST
    with pytest.raises(
        discovery.PrivateInputDiscoveryError,
        match="DISCOVERY_COST_MODEL_INVALID",
    ):
        discovery.materialize_discovery_request(
            source_contract=_source_contract(),
            profiles=_profiles(),
            discovery_budget=invalid_budget,
            sdk_runtime_root=str(_sdk_root(tmp_path)),
            private_root=root,
            source_commit_sha=SOURCE_SHA,
            source_tree_sha=TREE_SHA,
            host_digest=HOST_DIGEST,
            not_before=_stamp(START),
            expires_at=_stamp(END),
            approval_reference_digest=APPROVAL_DIGEST,
        )

    assert list(root.iterdir()) == []


def test_request_persistence_rejects_a_preexisting_downstream_output(
    tmp_path: Path,
) -> None:
    root = _root(tmp_path)
    materialized = _materialize(root)
    write_private_json(
        root, discovery.DEFAULT_DECISION_FILE, {"preexisting": True}
    )

    with pytest.raises(
        discovery.PrivateInputDiscoveryError,
        match="PRIVATE_ARTIFACT_EXISTS",
    ):
        discovery.persist_discovery_request(root, materialized)

    assert not (root / discovery.DEFAULT_REQUEST_FILE).exists()
    assert not (root / discovery.DEFAULT_CHECKPOINT_FILE).exists()


def test_claim_rechecks_downstream_outputs_before_consuming_the_request(
    tmp_path: Path,
) -> None:
    root = _root(tmp_path)
    materialized = _materialize(root)
    discovery.persist_discovery_request(root, materialized)
    write_private_json(
        root, discovery.DEFAULT_DECISION_FILE, {"appeared_after_request": True}
    )

    with pytest.raises(
        discovery.PrivateInputDiscoveryError,
        match="PRIVATE_ARTIFACT_EXISTS",
    ):
        _claim(root, materialized)

    assert not (root / discovery.DEFAULT_CLAIM_FILE).exists()


def test_fixed_claim_is_create_only_and_capability_is_one_shot(
    tmp_path: Path,
) -> None:
    root = _root(tmp_path)
    materialized = _materialize(root)
    discovery.persist_discovery_request(root, materialized)

    with pytest.raises(
        discovery.PrivateInputDiscoveryError, match="PRIVATE_OUTPUT_COLLISION"
    ):
        discovery.read_and_claim_discovery_request(
            private_root=root,
            request_file=materialized.request["request_file"],
            owner_checkpoint_file=materialized.request["owner_checkpoint_file"],
            expected_request_digest=materialized.request["request_digest"],
            expected_checkpoint_digest=materialized.owner_checkpoint[
                "checkpoint_digest"
            ],
            approval_reference_digest=APPROVAL_DIGEST,
            source_commit_sha=SOURCE_SHA,
            source_tree_sha=TREE_SHA,
            host_digest=HOST_DIGEST,
            now=START + timedelta(minutes=2),
            claim_file="alternate-claim.json",
        )

    request, capability = _claim(root, materialized)
    claim_path = root / discovery.DEFAULT_CLAIM_FILE
    claim = read_private_json(root, discovery.DEFAULT_CLAIM_FILE)
    assert claim["request_digest"] == request["request_digest"]
    assert claim["checkpoint_digest"] == request["owner_checkpoint_digest"]
    assert stat.S_IMODE(root.stat().st_mode) == 0o700
    assert stat.S_IMODE(claim_path.stat().st_mode) == 0o600
    with pytest.raises(
        discovery.PrivateInputDiscoveryError, match="PRIVATE_ARTIFACT_EXISTS"
    ):
        _claim(root, materialized)

    gate = discovery.assert_preflight_provider_capability_bindings(
        capability, **_provider_binding(request)
    )
    assert callable(gate)
    discovery.claim_discovery_execution(capability)
    with pytest.raises(
        discovery.PrivateInputDiscoveryError,
        match="DISCOVERY_EXECUTION_CAPABILITY_CONSUMED",
    ):
        discovery.claim_discovery_execution(capability)
    with pytest.raises(
        discovery.PrivateInputDiscoveryError,
        match="DISCOVERY_EXECUTION_CAPABILITY_CONSUMED",
    ):
        discovery.assert_preflight_provider_capability_bindings(
            capability, **_provider_binding(request)
        )


def test_capability_revalidates_the_original_pair_not_a_resealed_replacement(
    tmp_path: Path,
) -> None:
    root = _root(tmp_path)
    original = _materialize(root)
    discovery.persist_discovery_request(root, original)
    request, capability = _claim(root, original)
    discovery.assert_preflight_provider_capability_bindings(
        capability, **_provider_binding(request)
    )

    replacement = _materialize(
        root,
        approval_reference_digest=canonical_digest(
            {"approval": "different-reviewed-pair"}
        ),
    )
    for name, value in (
        (replacement.request["request_file"], replacement.request),
        (
            replacement.request["owner_checkpoint_file"],
            replacement.owner_checkpoint,
        ),
    ):
        path = root / name
        path.write_text(canonical_json(value) + "\n", encoding="utf-8")
        path.chmod(0o600)

    with pytest.raises(
        discovery.PrivateInputDiscoveryError,
        match="DISCOVERY_CLAIM_BINDING_MISMATCH",
    ):
        discovery.claim_discovery_execution(capability)


def test_capability_revalidates_expiry_against_the_runtime_clock(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = _root(tmp_path)
    materialized = _materialize(root)
    discovery.persist_discovery_request(root, materialized)
    request, capability = _claim(root, materialized)
    monkeypatch.setattr(discovery, "_observed_utc_now", lambda: END)

    with pytest.raises(
        discovery.PrivateInputDiscoveryError,
        match="PROPOSAL_EXPIRED",
    ):
        discovery.assert_preflight_provider_capability_bindings(
            capability, **_provider_binding(request)
        )


def test_provider_session_gate_requires_claim_and_exact_bound_policy(
    tmp_path: Path,
) -> None:
    root = _root(tmp_path)
    materialized = _materialize(root)
    discovery.persist_discovery_request(root, materialized)
    request, capability = _claim(root, materialized)
    gate = discovery.assert_preflight_provider_capability_bindings(
        capability, **_provider_binding(request)
    )
    authority_plan, identity_plan = discovery.provisional_discovery_plans(
        request
    )

    with pytest.raises(
        discovery.PrivateInputDiscoveryError,
        match="DISCOVERY_PROVIDER_SESSION_NOT_AUTHORIZED",
    ):
        gate.authorize_session(
            domain="authority",
            capture_index=1,
            stage="authority",
            policy_digest=authority_plan["expected_policy_digest"],
        )

    discovery.claim_discovery_execution(capability)
    with pytest.raises(
        discovery.PrivateInputDiscoveryError,
        match="DISCOVERY_PROVIDER_POLICY_BINDING_MISMATCH",
    ):
        gate.authorize_session(
            domain="authority",
            capture_index=1,
            stage="authority",
            policy_digest=canonical_digest({"alternate": "read-only"}),
        )
    gate.authorize_session(
        domain="authority",
        capture_index=1,
        stage="authority",
        policy_digest=authority_plan["expected_policy_digest"],
    )
    with pytest.raises(
        discovery.PrivateInputDiscoveryError,
        match="DISCOVERY_PROVIDER_SESSION_NOT_AUTHORIZED",
    ):
        gate.authorize_session(
            domain="authority",
            capture_index=1,
            stage="authority",
            policy_digest=authority_plan["expected_policy_digest"],
        )

    gate.authorize_session(
        domain="identity_center",
        capture_index=1,
        stage="discovery",
        policy_digest=identity_plan["expected_discovery_policy_digest"],
    )
    with pytest.raises(
        discovery.PrivateInputDiscoveryError,
        match="DISCOVERY_TRANSITION_ATTESTATION_REQUIRED",
    ):
        discovery.authorize_exact_identity_plan(
            capability,
            capture_index=1,
            provisional_plan=identity_plan,
            targets=identity_data.LIVE_TARGETS,
            transition_attestation=object(),
        )


def test_exact_policy_requires_one_concrete_attested_discovery(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = _root(tmp_path)
    materialized = _materialize(root)
    discovery.persist_discovery_request(root, materialized)
    request, capability = _claim(root, materialized)
    shared_budget = budget_module.GlobalDiscoveryBudget(
        budget_module.validate_discovery_budget(request["discovery_budget"])
    )
    monkeypatch.setattr(provider_module, "_ambient_gate", lambda _: None)
    monkeypatch.setattr(
        provider_module,
        "_load_sdk",
        lambda _: provider_module._LoadedSdk(  # noqa: SLF001
            session_factory=lambda **_: None,
            config_factory=lambda **_: None,
            guard=lambda: None,
        ),
    )
    builder_arguments = _provider_binding(request)
    builder_arguments.pop("budget_digest")
    factory = provider_module.build_discovery_provider_factory(
        **builder_arguments,
        discovery_budget=shared_budget,
        execution_capability=capability,
    )
    assert discovery.approved_discovery_request(capability) == request
    discovery.claim_discovery_execution(capability)
    _, identity_plan = discovery.provisional_discovery_plans(request)
    gate = factory._config.validity_gate  # noqa: SLF001

    gate.authorize_session(
        domain="identity_center",
        capture_index=1,
        stage="discovery",
        policy_digest=identity_plan["expected_discovery_policy_digest"],
    )
    first_attestation = _transition_attestation(
        factory,
        capture_index=1,
        policy_digest=identity_plan["expected_discovery_policy_digest"],
    )
    attacker_targets = copy.deepcopy(identity_data.LIVE_TARGETS)
    attacker_targets["retire_approve_permission_set_arn"] = (
        "arn:aws:sso:::permissionSet/ssoins-1234567890abcdef/ps-foreign"
    )
    with pytest.raises(
        discovery.PrivateInputDiscoveryError,
        match="DISCOVERY_EXACT_POLICY_NOT_AUTHORIZED",
    ):
        discovery.authorize_exact_identity_plan(
            capability,
            capture_index=1,
            provisional_plan=identity_plan,
            targets=attacker_targets,
            transition_attestation=first_attestation,
        )

    gate.authorize_session(
        domain="identity_center",
        capture_index=2,
        stage="discovery",
        policy_digest=identity_plan["expected_discovery_policy_digest"],
    )
    second_attestation = _transition_attestation(
        factory,
        capture_index=2,
        policy_digest=identity_plan["expected_discovery_policy_digest"],
    )
    exact_plan = discovery.authorize_exact_identity_plan(
        capability,
        capture_index=2,
        provisional_plan=identity_plan,
        targets=identity_data.LIVE_TARGETS,
        transition_attestation=second_attestation,
    )
    gate.authorize_session(
        domain="identity_center",
        capture_index=2,
        stage="exact",
        policy_digest=exact_plan["expected_exact_policy_digest"],
    )
    with pytest.raises(
        provider_module.LiveProviderError,
        match="DISCOVERY_TRANSITION_ATTESTATION_CONSUMED",
    ):
        provider_module.consume_identity_discovery_transition_attestation(
            second_attestation,
            execution_capability=capability,
            capture_index=2,
            expected_policy_digest=identity_plan[
                "expected_discovery_policy_digest"
            ],
        )


def _proposal_context(
    tmp_path: Path,
) -> tuple[
    Path,
    dict[str, Any],
    discovery.DiscoveryExecutionCapability,
    list[dict[str, Any]],
    list[dict[str, Any]],
    dict[str, Any],
    dict[str, Any],
]:
    root = _root(tmp_path)
    materialized = _materialize(root)
    discovery.persist_discovery_request(root, materialized)
    request, capability = _claim(root, materialized)
    gate = discovery.assert_preflight_provider_capability_bindings(
        capability, **_provider_binding(request)
    )
    discovery.claim_discovery_execution(capability)
    authority_plan, identity_plan = discovery.provisional_discovery_plans(request)
    for capture_index in (1, 2):
        gate.authorize_session(
            domain="authority",
            capture_index=capture_index,
            stage="authority",
            policy_digest=authority_plan["expected_policy_digest"],
        )
        gate.authorize_session(
            domain="identity_center",
            capture_index=capture_index,
            stage="discovery",
            policy_digest=identity_plan["expected_discovery_policy_digest"],
        )

    authority_snapshots: list[dict[str, Any]] = []
    identity_snapshots: list[dict[str, Any]] = []
    for index, (authority_name, identity_name) in enumerate(
        zip(
            discovery.AUTHORITY_SNAPSHOT_FILES,
            discovery.IDENTITY_SNAPSHOT_FILES,
            strict=True,
        ),
        1,
    ):
        observed_at = START + timedelta(minutes=2, seconds=index)
        capture_authority_live(
            authority_plan,
            authority_data.Factory(
                authority_plan,
                session=canonical_digest({"authority_session": index}),
                observed=observed_at,
            ),
            private_root=root,
            artifact_name=authority_name,
            now=START + timedelta(seconds=30),
            validation_clock=lambda: START + timedelta(minutes=4),
        )
        authority_snapshots.append(read_private_json(root, authority_name))

        capture_identity_live(
            identity_plan,
            identity_data.Factory(
                seed=str(index),
                mode="live_absent",
                identity={"observed_at": observed_at},
            ),
            private_root=root,
            artifact_name=identity_name,
            now=START + timedelta(seconds=30),
            validation_clock=lambda: START + timedelta(minutes=4),
        )
        identity_snapshots.append(read_private_json(root, identity_name))

    provider_events = _provider_events(
        authority_snapshots, identity_snapshots
    )
    ledger = budget_module.GlobalDiscoveryBudget(
        budget_module.validate_discovery_budget(request["discovery_budget"])
    )
    for event in provider_events:
        ledger.reserve_provider_call(event["operation"], is_page=False)
        ledger.record_response(0)
    summary = ledger.summary()
    transcript = {
        "provider_calls": len(provider_events),
        "aws_calls": len(provider_events),
        "aws_mutations": 0,
        "live_provider_evidence": True,
        "transcript_digest": canonical_digest(provider_events),
    }
    return (
        root,
        request,
        capability,
        authority_snapshots,
        identity_snapshots,
        summary,
        transcript,
    )


class _OfflineAttestedProvider:
    def __init__(
        self,
        summary: dict[str, Any],
        transcript: dict[str, Any],
        provider_events: list[dict[str, Any]],
        budget_events: list[dict[str, Any]],
    ) -> None:
        self._summary = summary
        self._transcript = transcript
        self._provider_events = provider_events
        self._budget_events = budget_events

    def discovery_budget_summary(self) -> dict[str, Any]:
        return copy.deepcopy(self._summary)

    def transcript_summary(self) -> dict[str, Any]:
        return copy.deepcopy(self._transcript)

    def transcript_events(self) -> list[dict[str, Any]]:
        return copy.deepcopy(self._provider_events)

    def discovery_budget_evidence_events(self) -> list[dict[str, Any]]:
        return copy.deepcopy(self._budget_events)

    def evaluation_time(self) -> datetime:
        return START + timedelta(minutes=4)


def _provider_events(
    authority_snapshots: list[dict[str, Any]],
    identity_snapshots: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    sessions = [
        *(
            ("authority", snapshot["identity"]["session_id_digest"])
            for snapshot in authority_snapshots
        ),
        *(
            ("identity_center", session_digest)
            for snapshot in identity_snapshots
            for session_digest in snapshot["session_digests"]
        ),
    ]
    ledger = CallLedger("ATTESTED_LIVE")
    observed_at = _stamp(START + timedelta(minutes=2))
    for ordinal, (domain, session_digest) in enumerate(sessions, 1):
        ticket = ledger.authorize(
            domain=domain,
            session_digest=session_digest,
            operation="sts:GetCallerIdentity",
            retries=0,
            request={"offline_event": ordinal},
            started_at=observed_at,
        )
        ledger.complete(
            ticket,
            {"offline_response": ordinal},
            completed_at=observed_at,
        )
    return ledger.evidence_events()


def _budget_events(
    provider_events: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    for provider_event in provider_events:
        events.extend(
            (
                {
                    "ordinal": len(events) + 1,
                    "kind": "PROVIDER_CALL",
                    "operation": provider_event["operation"],
                    "page_call": False,
                },
                {
                    "ordinal": len(events) + 2,
                    "kind": "PROJECTED_RESPONSE",
                    "byte_count": 0,
                },
            )
        )
    return events


def _offline_provider(
    monkeypatch: pytest.MonkeyPatch,
    capability: discovery.DiscoveryExecutionCapability,
    summary: dict[str, Any],
    transcript: dict[str, Any],
    authority_snapshots: list[dict[str, Any]],
    identity_snapshots: list[dict[str, Any]],
) -> _OfflineAttestedProvider:
    provider_events = _provider_events(
        authority_snapshots, identity_snapshots
    )
    provider = _OfflineAttestedProvider(
        summary,
        transcript,
        provider_events,
        _budget_events(provider_events),
    )
    monkeypatch.setattr(
        provider_module,
        "is_attested_discovery_provider",
        lambda value, supplied_capability: (
            value is provider and supplied_capability is capability
        ),
    )
    return provider


def test_provider_summary_rejects_more_pages_than_provider_calls(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    (
        root,
        request,
        capability,
        authority_snapshots,
        identity_snapshots,
        summary,
        transcript,
    ) = _proposal_context(tmp_path)
    impossible = copy.deepcopy(summary)
    impossible["page_calls"] = impossible["provider_calls"] + 1
    _reseal(impossible, "summary_digest")
    provider = _offline_provider(
        monkeypatch,
        capability,
        impossible,
        transcript,
        authority_snapshots,
        identity_snapshots,
    )

    with pytest.raises(
        discovery.PrivateInputDiscoveryError,
        match="DISCOVERY_BUDGET_BINDING_INVALID",
    ):
        discovery.build_discovery_proposal(
            private_root=root,
            request=request,
            execution_capability=capability,
            authority_snapshots=authority_snapshots,
            identity_snapshots=identity_snapshots,
            provider_factory=provider,
        )


def test_resealed_proposal_cannot_hide_impossible_provider_counters(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    (
        root,
        request,
        capability,
        authority_snapshots,
        identity_snapshots,
        summary,
        transcript,
    ) = _proposal_context(tmp_path)
    provider = _offline_provider(
        monkeypatch,
        capability,
        summary,
        transcript,
        authority_snapshots,
        identity_snapshots,
    )
    proposal = discovery.build_discovery_proposal(
        private_root=root,
        request=request,
        execution_capability=capability,
        authority_snapshots=authority_snapshots,
        identity_snapshots=identity_snapshots,
        provider_factory=provider,
    )
    candidate = copy.deepcopy(proposal.private_candidate)
    candidate["provider_summary"]["network_calls"] += 100
    _reseal(candidate["provider_summary"], "summary_digest")
    _reseal(candidate, "proposal_digest")
    receipt = copy.deepcopy(proposal.public_receipt)
    receipt["proposal_digest"] = candidate["proposal_digest"]
    _reseal(receipt, "receipt_digest")

    with pytest.raises(
        discovery.PrivateInputDiscoveryError,
        match="DISCOVERY_BUDGET_BINDING_INVALID",
    ):
        discovery.persist_discovery_proposal(
            root,
            discovery.DiscoveryProposal(
                private_candidate=candidate,
                public_receipt=receipt,
            ),
        )
    assert not (root / discovery.DEFAULT_PROPOSAL_FILE).exists()


def test_proposal_build_seals_provider_evidence_before_proposal_persistence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    (
        root,
        request,
        capability,
        authority_snapshots,
        identity_snapshots,
        summary,
        transcript,
    ) = _proposal_context(tmp_path)
    provider = _offline_provider(
        monkeypatch,
        capability,
        summary,
        transcript,
        authority_snapshots,
        identity_snapshots,
    )

    proposal = discovery.build_discovery_proposal(
        private_root=root,
        request=request,
        execution_capability=capability,
        authority_snapshots=authority_snapshots,
        identity_snapshots=identity_snapshots,
        provider_factory=provider,
    )

    evidence_path = root / discovery.DEFAULT_PROVIDER_EVIDENCE_FILE
    evidence = read_private_json(
        root, discovery.DEFAULT_PROVIDER_EVIDENCE_FILE
    )
    assert evidence_path.is_file()
    assert stat.S_IMODE(evidence_path.stat().st_mode) == 0o600
    assert not (root / discovery.DEFAULT_PROPOSAL_FILE).exists()
    assert proposal.private_candidate["provider_evidence_file"] == (
        discovery.DEFAULT_PROVIDER_EVIDENCE_FILE
    )
    assert proposal.private_candidate["provider_evidence_digest"] == (
        evidence["provider_evidence_digest"]
    )
    assert proposal.private_candidate["created_at"] == evidence["sealed_at"]
    provider_events = discovery._decode_provider_event_journal(  # noqa: SLF001
        evidence["provider_events"]
    )
    budget_events = discovery._decode_budget_event_journal(  # noqa: SLF001
        evidence["budget_events"]
    )
    assert provider_events == provider.transcript_events()
    assert budget_events == provider.discovery_budget_evidence_events()
    assert discovery._encode_provider_event_journal(  # noqa: SLF001
        provider_events
    ) == evidence["provider_events"]
    assert discovery._encode_budget_event_journal(  # noqa: SLF001
        budget_events
    ) == evidence["budget_events"]


def test_compact_provider_evidence_fits_the_private_four_mib_ceiling() -> None:
    """The complete hard-ceiling journal must remain persistable."""

    maximum_digest = "sha256:" + "f" * 64
    maximum_stamp = "9999-12-31T23:59:59Z"
    page_operation = (
        "sso:ListCustomerManagedPolicyReferencesInPermissionSet"
    )
    non_page_operation = "sso:DescribePermissionSetProvisioningStatus"
    assert page_operation in provider_module.OPERATION_ALLOWLIST[
        "identity_center"
    ]
    assert non_page_operation in provider_module.OPERATION_ALLOWLIST[
        "identity_center"
    ]

    session_digests = [
        canonical_digest({"maximum_session": index}) for index in range(6)
    ]
    provider_events: list[dict[str, Any]] = []

    def append_provider_event(
        *,
        domain: str,
        session_digest: str,
        operation: str,
        pagination_stream_digest: str | None = None,
        page_token_digest: str | None = None,
        truncated: bool = False,
        next_token_digest: str | None = None,
    ) -> None:
        provider_events.append(
            {
                "ordinal": len(provider_events) + 1,
                "domain": domain,
                "session_digest": session_digest,
                "operation": operation,
                "request_digest": maximum_digest,
                "pagination_stream_digest": pagination_stream_digest,
                "page_token_digest": page_token_digest,
                "started_at": maximum_stamp,
                "response_digest": maximum_digest,
                "truncated": truncated,
                "next_token_digest": next_token_digest,
                "completed_at": maximum_stamp,
                "outcome": "SUCCESS",
                "complete": not truncated,
            }
        )

    for index, session_digest in enumerate(session_digests):
        append_provider_event(
            domain="authority" if index < 2 else "identity_center",
            session_digest=session_digest,
            operation="sts:GetCallerIdentity",
        )

    previous_token: str | None = None
    for page_index in range(budget_module.HARD_MAX_PAGE_CALLS):
        truncated = page_index + 1 < budget_module.HARD_MAX_PAGE_CALLS
        next_token = (
            canonical_digest({"maximum_page_token": page_index})
            if truncated
            else None
        )
        append_provider_event(
            domain="identity_center",
            session_digest=session_digests[-1],
            operation=page_operation,
            pagination_stream_digest=maximum_digest,
            page_token_digest=previous_token,
            truncated=truncated,
            next_token_digest=next_token,
        )
        previous_token = next_token

    while len(provider_events) < budget_module.HARD_MAX_PROVIDER_CALLS:
        append_provider_event(
            domain="identity_center",
            session_digest=session_digests[-1],
            operation=non_page_operation,
        )

    budget_events: list[dict[str, Any]] = [
        {
            "ordinal": ordinal,
            "kind": "CREDENTIAL_VEND",
            "operation": "sso:GetRoleCredentials",
        }
        for ordinal in range(
            1, budget_module.HARD_MAX_CREDENTIAL_VENDING_CALLS + 1
        )
    ]
    for provider_event in provider_events:
        budget_events.extend(
            (
                {
                    "ordinal": len(budget_events) + 1,
                    "kind": "PROVIDER_CALL",
                    "operation": provider_event["operation"],
                    "page_call": provider_event["operation"]
                    == page_operation,
                },
                {
                    "ordinal": len(budget_events) + 2,
                    "kind": "PROJECTED_RESPONSE",
                    "byte_count": 6_700,
                },
            )
        )

    provider_journal = discovery._encode_provider_event_journal(  # noqa: SLF001
        provider_events
    )
    budget_journal = discovery._encode_budget_event_journal(  # noqa: SLF001
        budget_events
    )
    summary_body = {
        "record_type": budget_module.SUMMARY_RECORD_TYPE,
        "budget_digest": maximum_digest,
        "cost_model_digest": maximum_digest,
        "provider_calls": budget_module.HARD_MAX_PROVIDER_CALLS,
        "credential_vending_calls": (
            budget_module.HARD_MAX_CREDENTIAL_VENDING_CALLS
        ),
        "network_calls": budget_module.HARD_MAX_NETWORK_CALLS,
        "page_calls": budget_module.HARD_MAX_PAGE_CALLS,
        "projected_response_bytes": (
            6_700 * budget_module.HARD_MAX_PROVIDER_CALLS
        ),
        "modeled_cost_nano_usd": 9_999_999_999_999_999_999,
    }
    provider_summary = {
        **summary_body,
        "summary_digest": canonical_digest(summary_body),
    }
    provider_transcript = {
        "provider_calls": budget_module.HARD_MAX_PROVIDER_CALLS,
        "aws_calls": budget_module.HARD_MAX_PROVIDER_CALLS,
        "aws_mutations": 0,
        "live_provider_evidence": True,
        "transcript_digest": canonical_digest(provider_events),
    }
    maximum_file_name = "a" * 127 + ".json"
    evidence_body: dict[str, Any] = {
        "record_type": discovery.PROVIDER_EVIDENCE_TYPE,
        "schema_version": 1,
        "implementation_issue": discovery.IMPLEMENTATION_ISSUE,
        "parent_issue": discovery.PARENT_ISSUE,
        "live_issue": discovery.LIVE_ISSUE,
        "source_commit_sha": "f" * 64,
        "source_tree_sha": "f" * 64,
        "source_contract_digest": maximum_digest,
        "request_file": maximum_file_name,
        "request_digest": maximum_digest,
        "owner_checkpoint_file": maximum_file_name,
        "checkpoint_digest": maximum_digest,
        "claim_digest": maximum_digest,
        "approval_reference_digest": maximum_digest,
        "budget_digest": maximum_digest,
        "private_root_digest": maximum_digest,
        "host_digest": maximum_digest,
        "authority_snapshot_digests": [maximum_digest, maximum_digest],
        "identity_center_snapshot_digests": [
            maximum_digest,
            maximum_digest,
        ],
        "budget_events": budget_journal,
        "provider_events": provider_journal,
        "provider_summary": provider_summary,
        "provider_transcript": provider_transcript,
        "not_before": maximum_stamp,
        "expires_at": maximum_stamp,
        "sealed_at": maximum_stamp,
        "read_only": True,
        "aws_mutations": 0,
        "repository_persisted": False,
    }
    evidence = {
        **evidence_body,
        "provider_evidence_digest": canonical_digest(evidence_body),
    }
    encoded = (canonical_json(evidence) + "\n").encode("utf-8")

    assert len(provider_journal["rows"]) == (
        budget_module.HARD_MAX_PROVIDER_CALLS
    )
    assert sum(
        row[2] is True
        for row in budget_journal["rows"]
        if row[0] == "P"
    ) == budget_module.HARD_MAX_PAGE_CALLS
    assert len(budget_journal["rows"]) == (
        budget_module.HARD_MAX_CREDENTIAL_VENDING_CALLS
        + 2 * budget_module.HARD_MAX_PROVIDER_CALLS
    )
    assert len(encoded) <= discovery.MAX_PRIVATE_JSON_BYTES


def test_proposal_rejects_a_nested_mutation_of_the_claimed_request(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    (
        root,
        request,
        capability,
        authority_snapshots,
        identity_snapshots,
        summary,
        transcript,
    ) = _proposal_context(tmp_path)
    request["discovery_budget"]["max_network_calls"] -= 1
    provider = _offline_provider(
        monkeypatch,
        capability,
        summary,
        transcript,
        authority_snapshots,
        identity_snapshots,
    )

    with pytest.raises(
        discovery.PrivateInputDiscoveryError,
        match="DISCOVERY_EXECUTION_CAPABILITY_REQUIRED",
    ):
        discovery.build_discovery_proposal(
            private_root=root,
            request=request,
            execution_capability=capability,
            authority_snapshots=authority_snapshots,
            identity_snapshots=identity_snapshots,
            provider_factory=provider,
        )


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("approval_reference_digest", "owner-ticket-without-a-digest"),
        ("approval_reference_digest", ZERO_DIGEST),
        ("approved_at", _stamp(START + timedelta(minutes=6))),
    ),
)
def test_approved_materialization_rejects_a_self_digested_invalid_decision(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    field: str,
    value: str,
) -> None:
    (
        root,
        request,
        capability,
        authority_snapshots,
        identity_snapshots,
        summary,
        transcript,
    ) = _proposal_context(tmp_path)
    provider = _offline_provider(
        monkeypatch,
        capability,
        summary,
        transcript,
        authority_snapshots,
        identity_snapshots,
    )
    proposal = discovery.build_discovery_proposal(
        private_root=root,
        request=request,
        execution_capability=capability,
        authority_snapshots=authority_snapshots,
        identity_snapshots=identity_snapshots,
        provider_factory=provider,
    )
    discovery.persist_discovery_proposal(root, proposal)
    candidate = proposal.private_candidate
    decision = discovery.materialize_owner_decision(
        private_root=root,
        source_commit_sha=SOURCE_SHA,
        source_tree_sha=TREE_SHA,
        candidate=candidate,
        expected_proposal_digest=candidate["proposal_digest"],
        approval_reference_digest=canonical_digest(
            {"owner_decision": "approved"}
        ),
        now=START + timedelta(minutes=4),
        expires_at=START + timedelta(minutes=7),
    )
    decision[field] = value
    _reseal(decision, "decision_digest")

    with pytest.raises(discovery.PrivateInputDiscoveryError):
        discovery.materialize_approved_gug392_inputs(
            private_root=root,
            source_commit_sha=SOURCE_SHA,
            source_tree_sha=TREE_SHA,
            candidate=candidate,
            decision=decision,
            expected_proposal_digest=candidate["proposal_digest"],
            expected_decision_digest=decision["decision_digest"],
            now=START + timedelta(minutes=4, seconds=1),
        )


def test_owner_decision_requires_a_distinct_post_proposal_approval(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    (
        root,
        request,
        capability,
        authority_snapshots,
        identity_snapshots,
        summary,
        transcript,
    ) = _proposal_context(tmp_path)
    provider = _offline_provider(
        monkeypatch,
        capability,
        summary,
        transcript,
        authority_snapshots,
        identity_snapshots,
    )
    proposal = discovery.build_discovery_proposal(
        private_root=root,
        request=request,
        execution_capability=capability,
        authority_snapshots=authority_snapshots,
        identity_snapshots=identity_snapshots,
        provider_factory=provider,
    )
    discovery.persist_discovery_proposal(root, proposal)
    candidate = proposal.private_candidate

    with pytest.raises(
        discovery.PrivateInputDiscoveryError,
        match="APPROVAL_REFERENCE_INVALID",
    ):
        discovery.materialize_owner_decision(
            private_root=root,
            source_commit_sha=SOURCE_SHA,
            source_tree_sha=TREE_SHA,
            candidate=candidate,
            expected_proposal_digest=candidate["proposal_digest"],
            approval_reference_digest=ZERO_DIGEST,
            now=START + timedelta(minutes=4),
            expires_at=START + timedelta(minutes=7),
        )

    with pytest.raises(
        discovery.PrivateInputDiscoveryError,
        match="OWNER_DECISION_APPROVAL_NOT_DISTINCT",
    ):
        discovery.materialize_owner_decision(
            private_root=root,
            source_commit_sha=SOURCE_SHA,
            source_tree_sha=TREE_SHA,
            candidate=candidate,
            expected_proposal_digest=candidate["proposal_digest"],
            approval_reference_digest=request["approval_reference_digest"],
            now=START + timedelta(minutes=4),
            expires_at=START + timedelta(minutes=7),
        )


def test_post_discovery_steps_require_the_same_source_and_host(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    (
        root,
        request,
        capability,
        authority_snapshots,
        identity_snapshots,
        summary,
        transcript,
    ) = _proposal_context(tmp_path)
    provider = _offline_provider(
        monkeypatch,
        capability,
        summary,
        transcript,
        authority_snapshots,
        identity_snapshots,
    )
    proposal = discovery.build_discovery_proposal(
        private_root=root,
        request=request,
        execution_capability=capability,
        authority_snapshots=authority_snapshots,
        identity_snapshots=identity_snapshots,
        provider_factory=provider,
    )
    discovery.persist_discovery_proposal(root, proposal)
    candidate = proposal.private_candidate
    approval_digest = canonical_digest(
        {"owner_decision": "same-source-and-host"}
    )

    with pytest.raises(
        discovery.PrivateInputDiscoveryError,
        match="SOURCE_BINDING_MISMATCH",
    ):
        discovery.materialize_owner_decision(
            private_root=root,
            source_commit_sha="c" * 40,
            source_tree_sha=TREE_SHA,
            candidate=candidate,
            expected_proposal_digest=candidate["proposal_digest"],
            approval_reference_digest=approval_digest,
            now=START + timedelta(minutes=4),
            expires_at=START + timedelta(minutes=7),
        )

    decision = discovery.materialize_owner_decision(
        private_root=root,
        source_commit_sha=SOURCE_SHA,
        source_tree_sha=TREE_SHA,
        candidate=candidate,
        expected_proposal_digest=candidate["proposal_digest"],
        approval_reference_digest=approval_digest,
        now=START + timedelta(minutes=4),
        expires_at=START + timedelta(minutes=7),
    )
    monkeypatch.setattr(
        discovery.platform, "node", lambda: "different-operation-host"
    )

    with pytest.raises(
        discovery.PrivateInputDiscoveryError,
        match="HOST_BINDING_INVALID",
    ):
        discovery.materialize_approved_gug392_inputs(
            private_root=root,
            source_commit_sha=SOURCE_SHA,
            source_tree_sha=TREE_SHA,
            candidate=candidate,
            decision=decision,
            expected_proposal_digest=candidate["proposal_digest"],
            expected_decision_digest=decision["decision_digest"],
            now=START + timedelta(minutes=4, seconds=1),
        )


def test_owner_decision_mints_a_fresh_post_discovery_plan_window(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    (
        root,
        request,
        capability,
        authority_snapshots,
        identity_snapshots,
        summary,
        transcript,
    ) = _proposal_context(tmp_path)
    provider = _offline_provider(
        monkeypatch,
        capability,
        summary,
        transcript,
        authority_snapshots,
        identity_snapshots,
    )
    proposal = discovery.build_discovery_proposal(
        private_root=root,
        request=request,
        execution_capability=capability,
        authority_snapshots=authority_snapshots,
        identity_snapshots=identity_snapshots,
        provider_factory=provider,
    )
    discovery.persist_discovery_proposal(root, proposal)
    approval_time = END + timedelta(minutes=1)
    decision_end = approval_time + timedelta(minutes=9)
    decision = discovery.materialize_owner_decision(
        private_root=root,
        source_commit_sha=SOURCE_SHA,
        source_tree_sha=TREE_SHA,
        candidate=proposal.private_candidate,
        expected_proposal_digest=proposal.private_candidate["proposal_digest"],
        approval_reference_digest=canonical_digest(
            {"owner_decision": "post-discovery-window"}
        ),
        now=approval_time,
        expires_at=decision_end,
    )
    materialized = discovery.materialize_approved_gug392_inputs(
        private_root=root,
        source_commit_sha=SOURCE_SHA,
        source_tree_sha=TREE_SHA,
        candidate=proposal.private_candidate,
        decision=decision,
        expected_proposal_digest=proposal.private_candidate["proposal_digest"],
        expected_decision_digest=decision["decision_digest"],
        now=approval_time + timedelta(seconds=1),
    )

    assert approval_time >= END
    assert materialized.authority_input["not_before"] == decision["approved_at"]
    assert materialized.authority_input["not_after"] == decision["expires_at"]
    assert materialized.identity_center_input["not_before"] == decision[
        "approved_at"
    ]
    assert materialized.identity_center_input["not_after"] == decision[
        "expires_at"
    ]
    assert materialized.authority_plan["not_before"] == decision["approved_at"]
    assert materialized.authority_plan["not_after"] == decision["expires_at"]
    assert materialized.identity_center_plan["not_before"] == decision[
        "approved_at"
    ]
    assert materialized.identity_center_plan["not_after"] == decision[
        "expires_at"
    ]


def test_owner_decision_and_materialization_reject_naive_clocks(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    (
        root,
        request,
        capability,
        authority_snapshots,
        identity_snapshots,
        summary,
        transcript,
    ) = _proposal_context(tmp_path)
    provider = _offline_provider(
        monkeypatch,
        capability,
        summary,
        transcript,
        authority_snapshots,
        identity_snapshots,
    )
    proposal = discovery.build_discovery_proposal(
        private_root=root,
        request=request,
        execution_capability=capability,
        authority_snapshots=authority_snapshots,
        identity_snapshots=identity_snapshots,
        provider_factory=provider,
    )
    discovery.persist_discovery_proposal(root, proposal)
    approval_digest = canonical_digest({"owner_decision": "aware-only"})
    with pytest.raises(
        discovery.PrivateInputDiscoveryError,
        match="OWNER_DECISION_EXPIRED",
    ):
        discovery.materialize_owner_decision(
            private_root=root,
            source_commit_sha=SOURCE_SHA,
            source_tree_sha=TREE_SHA,
            candidate=proposal.private_candidate,
            expected_proposal_digest=proposal.private_candidate[
                "proposal_digest"
            ],
            approval_reference_digest=approval_digest,
            now=datetime.now(),
            expires_at=START + timedelta(minutes=7),
        )
    with pytest.raises(
        discovery.PrivateInputDiscoveryError,
        match="OWNER_DECISION_EXPIRED",
    ):
        discovery.materialize_owner_decision(
            private_root=root,
            source_commit_sha=SOURCE_SHA,
            source_tree_sha=TREE_SHA,
            candidate=proposal.private_candidate,
            expected_proposal_digest=proposal.private_candidate[
                "proposal_digest"
            ],
            approval_reference_digest=approval_digest,
            now=START + timedelta(minutes=4),
            expires_at=datetime.now(),
        )

    decision = discovery.materialize_owner_decision(
        private_root=root,
        source_commit_sha=SOURCE_SHA,
        source_tree_sha=TREE_SHA,
        candidate=proposal.private_candidate,
        expected_proposal_digest=proposal.private_candidate["proposal_digest"],
        approval_reference_digest=approval_digest,
        now=START + timedelta(minutes=4),
        expires_at=START + timedelta(minutes=7),
    )
    with pytest.raises(
        discovery.PrivateInputDiscoveryError,
        match="OWNER_DECISION_EXPIRED",
    ):
        discovery.materialize_approved_gug392_inputs(
            private_root=root,
            source_commit_sha=SOURCE_SHA,
            source_tree_sha=TREE_SHA,
            candidate=proposal.private_candidate,
            decision=decision,
            expected_proposal_digest=proposal.private_candidate[
                "proposal_digest"
            ],
            expected_decision_digest=decision["decision_digest"],
            now=datetime.now(),
        )


def test_owner_decision_materializes_private_inputs_and_manifest_readback(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    (
        root,
        request,
        capability,
        authority_snapshots,
        identity_snapshots,
        summary,
        transcript,
    ) = _proposal_context(tmp_path)
    provider = _offline_provider(
        monkeypatch,
        capability,
        summary,
        transcript,
        authority_snapshots,
        identity_snapshots,
    )
    proposal = discovery.build_discovery_proposal(
        private_root=root,
        request=request,
        execution_capability=capability,
        authority_snapshots=authority_snapshots,
        identity_snapshots=identity_snapshots,
        provider_factory=provider,
    )
    discovery.persist_discovery_proposal(root, proposal)
    candidate = proposal.private_candidate
    owner_decision = discovery.materialize_owner_decision(
        private_root=root,
        source_commit_sha=SOURCE_SHA,
        source_tree_sha=TREE_SHA,
        candidate=candidate,
        expected_proposal_digest=candidate["proposal_digest"],
        approval_reference_digest=canonical_digest(
            {"owner_decision": "approved"}
        ),
        now=START + timedelta(minutes=4),
        expires_at=START + timedelta(minutes=7),
    )
    materialized = discovery.materialize_approved_gug392_inputs(
        private_root=root,
        source_commit_sha=SOURCE_SHA,
        source_tree_sha=TREE_SHA,
        candidate=candidate,
        decision=owner_decision,
        expected_proposal_digest=candidate["proposal_digest"],
        expected_decision_digest=owner_decision["decision_digest"],
        now=START + timedelta(minutes=4, seconds=1),
    )

    assert materialized.owner_decision == owner_decision
    assert "owner_decision" not in materialized.manifest
    decision_name = materialized.manifest["decision_file"]
    assert materialized.manifest["artifact_digests"][decision_name] == (
        canonical_digest(owner_decision)
    )

    discovery.persist_owner_decision(root, owner_decision)
    discovery.persist_approved_gug392_inputs(root, materialized)
    validated = discovery.validate_input_materialization_manifest(
        root, materialized.manifest
    )
    assert validated == materialized.manifest
    assert read_private_json(root, decision_name) == owner_decision
    assert "owner_decision" not in read_private_json(
        root, materialized.manifest["manifest_file"]
    )
    for name in (
        *materialized.manifest["artifact_digests"],
        materialized.manifest["manifest_file"],
    ):
        assert stat.S_IMODE((root / name).stat().st_mode) == 0o600
    assert stat.S_IMODE(root.stat().st_mode) == 0o700

    manifest_name = materialized.manifest["manifest_file"]
    (root / manifest_name).unlink()
    with pytest.raises(discovery.PrivateInputDiscoveryError):
        discovery.validate_input_materialization_manifest(
            root, materialized.manifest
        )
    write_private_json(root, manifest_name, {"tampered": True})
    with pytest.raises(
        discovery.PrivateInputDiscoveryError,
        match="DISCOVERY_MANIFEST_READBACK_MISMATCH",
    ):
        discovery.validate_input_materialization_manifest(
            root, materialized.manifest
        )


def test_private_proposal_decision_and_outputs_use_one_canonical_name_set(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    (
        root,
        request,
        capability,
        authority_snapshots,
        identity_snapshots,
        summary,
        transcript,
    ) = _proposal_context(tmp_path)
    provider = _offline_provider(
        monkeypatch,
        capability,
        summary,
        transcript,
        authority_snapshots,
        identity_snapshots,
    )
    proposal = discovery.build_discovery_proposal(
        private_root=root,
        request=request,
        execution_capability=capability,
        authority_snapshots=authority_snapshots,
        identity_snapshots=identity_snapshots,
        provider_factory=provider,
    )
    discovery.persist_discovery_proposal(root, proposal)
    decision = discovery.materialize_owner_decision(
        private_root=root,
        source_commit_sha=SOURCE_SHA,
        source_tree_sha=TREE_SHA,
        candidate=proposal.private_candidate,
        expected_proposal_digest=proposal.private_candidate["proposal_digest"],
        approval_reference_digest=canonical_digest(
            {"owner_decision": "approved"}
        ),
        now=START + timedelta(minutes=4),
        expires_at=START + timedelta(minutes=7),
    )

    with pytest.raises(
        discovery.PrivateInputDiscoveryError,
        match="PROPOSAL_FILE_INVALID",
    ):
        discovery.persist_discovery_proposal(
            root, proposal, proposal_file="alternate-proposal.json"
        )
    with pytest.raises(
        discovery.PrivateInputDiscoveryError,
        match="PRIVATE_OUTPUT_INVALID",
    ):
        discovery.persist_owner_decision(
            root, decision, decision_file="alternate-decision.json"
        )
    with pytest.raises(
        discovery.PrivateInputDiscoveryError,
        match="PRIVATE_OUTPUT_INVALID",
    ):
        discovery.materialize_approved_gug392_inputs(
            private_root=root,
            source_commit_sha=SOURCE_SHA,
            source_tree_sha=TREE_SHA,
            candidate=proposal.private_candidate,
            decision=decision,
            expected_proposal_digest=proposal.private_candidate[
                "proposal_digest"
            ],
            expected_decision_digest=decision["decision_digest"],
            now=START + timedelta(minutes=4, seconds=1),
            manifest_file="alternate-manifest.json",
        )
    assert not (root / "alternate-proposal.json").exists()
    assert not (root / "alternate-decision.json").exists()
    assert not (root / "alternate-manifest.json").exists()

    discovery.persist_owner_decision(root, decision)
    materialized = discovery.materialize_approved_gug392_inputs(
        private_root=root,
        source_commit_sha=SOURCE_SHA,
        source_tree_sha=TREE_SHA,
        candidate=proposal.private_candidate,
        decision=decision,
        expected_proposal_digest=proposal.private_candidate["proposal_digest"],
        expected_decision_digest=decision["decision_digest"],
        now=START + timedelta(minutes=4, seconds=1),
    )
    discovery.persist_approved_gug392_inputs(root, materialized)
    canonical_names = (
        discovery.DEFAULT_PROPOSAL_FILE,
        discovery.DEFAULT_DECISION_FILE,
        discovery.DEFAULT_AUTHORITY_INPUT_FILE,
        discovery.DEFAULT_IDENTITY_INPUT_FILE,
        discovery.DEFAULT_AUTHORITY_PLAN_FILE,
        discovery.DEFAULT_IDENTITY_PLAN_FILE,
        discovery.DEFAULT_MANIFEST_FILE,
    )
    before = {name: (root / name).read_bytes() for name in canonical_names}

    with pytest.raises(
        discovery.PrivateInputDiscoveryError,
        match="DISCOVERY_MATERIALIZATION_CAPABILITY_CONSUMED",
    ):
        discovery.persist_approved_gug392_inputs(root, materialized)

    with pytest.raises(
        discovery.PrivateInputDiscoveryError,
        match="PRIVATE_OUTPUT_INVALID",
    ):
        discovery.materialize_approved_gug392_inputs(
            private_root=root,
            source_commit_sha=SOURCE_SHA,
            source_tree_sha=TREE_SHA,
            candidate=proposal.private_candidate,
            decision=decision,
            expected_proposal_digest=proposal.private_candidate[
                "proposal_digest"
            ],
            expected_decision_digest=decision["decision_digest"],
            now=START + timedelta(minutes=4, seconds=2),
            authority_input_file="alternate-authority-input.json",
        )
    assert before == {name: (root / name).read_bytes() for name in canonical_names}
    assert not (root / "alternate-authority-input.json").exists()

    copied_root = _root(tmp_path, "private-copy")
    for name in (
        discovery.DEFAULT_PROPOSAL_FILE,
        discovery.DEFAULT_DECISION_FILE,
    ):
        write_private_json(copied_root, name, read_private_json(root, name))
    with pytest.raises(
        discovery.PrivateInputDiscoveryError,
        match="PRIVATE_ROOT_BINDING_MISMATCH",
    ):
        discovery.materialize_approved_gug392_inputs(
            private_root=copied_root,
            source_commit_sha=SOURCE_SHA,
            source_tree_sha=TREE_SHA,
            candidate=read_private_json(
                copied_root, discovery.DEFAULT_PROPOSAL_FILE
            ),
            decision=read_private_json(
                copied_root, discovery.DEFAULT_DECISION_FILE
            ),
            expected_proposal_digest=proposal.private_candidate[
                "proposal_digest"
            ],
            expected_decision_digest=decision["decision_digest"],
            now=START + timedelta(minutes=4, seconds=2),
        )
    assert {item.name for item in copied_root.iterdir()} == {
        discovery.DEFAULT_PROPOSAL_FILE,
        discovery.DEFAULT_DECISION_FILE,
    }


def test_approved_materialization_capability_cannot_be_constructed_by_caller(
    tmp_path: Path,
) -> None:
    root = _root(tmp_path)
    with pytest.raises(
        discovery.PrivateInputDiscoveryError,
        match="DISCOVERY_MATERIALIZATION_CAPABILITY_REQUIRED",
    ):
        discovery.MaterializedApprovedInputs(
            object(),
            authority_input={"forged": "authority-input"},
            identity_center_input={"forged": "identity-input"},
            authority_plan={"forged": "authority-plan"},
            identity_center_plan={"forged": "identity-plan"},
            owner_decision={"forged": "decision"},
            manifest={"forged": "manifest"},
        )
    assert list(root.iterdir()) == []


def _persisted_proposal_context(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> tuple[Path, dict[str, Any], discovery.DiscoveryProposal]:
    (
        root,
        request,
        capability,
        authority_snapshots,
        identity_snapshots,
        summary,
        transcript,
    ) = _proposal_context(tmp_path)
    provider = _offline_provider(
        monkeypatch,
        capability,
        summary,
        transcript,
        authority_snapshots,
        identity_snapshots,
    )
    proposal = discovery.build_discovery_proposal(
        private_root=root,
        request=request,
        execution_capability=capability,
        authority_snapshots=authority_snapshots,
        identity_snapshots=identity_snapshots,
        provider_factory=provider,
    )
    discovery.persist_discovery_proposal(root, proposal)
    return root, request, proposal


def _resealed_alternate_principal_proposal(
    candidate: Mapping[str, Any],
) -> dict[str, Any]:
    changed = copy.deepcopy(candidate)
    changed["authority_input"]["expected_principal_arn"] = (
        f"arn:aws:sts::{AUTHORITY_ACCOUNT}:assumed-role/"
        "UnexpectedReadOnly/alternate-session"
    )
    plans = discovery.materialize_live_plans(
        authority_input=changed["authority_input"],
        identity_center_input=changed["identity_center_input"],
    )
    changed["authority_plan"] = plans.authority_plan
    changed["identity_center_plan"] = plans.identity_center_plan
    _reseal(changed, "proposal_digest")
    return changed


def test_owner_decision_requires_the_canonical_persisted_proposal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    root, _, proposal = _persisted_proposal_context(tmp_path, monkeypatch)
    (root / discovery.DEFAULT_PROPOSAL_FILE).unlink()

    with pytest.raises(
        discovery.PrivateInputDiscoveryError,
        match="PROPOSAL_READBACK_MISMATCH",
    ):
        discovery.materialize_owner_decision(
            private_root=root,
            source_commit_sha=SOURCE_SHA,
            source_tree_sha=TREE_SHA,
            candidate=proposal.private_candidate,
            expected_proposal_digest=proposal.private_candidate[
                "proposal_digest"
            ],
            approval_reference_digest=canonical_digest(
                {"owner_decision": "missing-canonical-proposal"}
            ),
            now=START + timedelta(minutes=4),
            expires_at=START + timedelta(minutes=7),
        )


@pytest.mark.parametrize(
    "artifact_name",
    (
        discovery.DEFAULT_REQUEST_FILE,
        discovery.DEFAULT_CHECKPOINT_FILE,
        discovery.DEFAULT_CLAIM_FILE,
        discovery.DEFAULT_PROVIDER_EVIDENCE_FILE,
        *discovery.AUTHORITY_SNAPSHOT_FILES,
        *discovery.IDENTITY_SNAPSHOT_FILES,
    ),
)
def test_owner_decision_requires_every_canonical_provenance_artifact(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    artifact_name: str,
) -> None:
    root, _, proposal = _persisted_proposal_context(tmp_path, monkeypatch)
    (root / artifact_name).unlink()

    with pytest.raises(
        discovery.PrivateInputDiscoveryError,
        match="DISCOVERY_PROVENANCE_MISMATCH",
    ):
        discovery.materialize_owner_decision(
            private_root=root,
            source_commit_sha=SOURCE_SHA,
            source_tree_sha=TREE_SHA,
            candidate=proposal.private_candidate,
            expected_proposal_digest=proposal.private_candidate[
                "proposal_digest"
            ],
            approval_reference_digest=canonical_digest(
                {"owner_decision": "complete-provenance-required"}
            ),
            now=START + timedelta(minutes=4),
            expires_at=START + timedelta(minutes=7),
        )


@pytest.mark.parametrize(
    "mutation",
    ("provider_summary", "provider_transcript", "created_at"),
)
def test_owner_decision_rejects_resealed_proposal_owned_provider_evidence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mutation: str,
) -> None:
    root, _, proposal = _persisted_proposal_context(tmp_path, monkeypatch)
    changed = copy.deepcopy(proposal.private_candidate)
    if mutation == "provider_summary":
        changed["provider_summary"]["projected_response_bytes"] += 1
        changed["provider_summary"]["modeled_cost_nano_usd"] += 1
        _reseal(changed["provider_summary"], "summary_digest")
    elif mutation == "provider_transcript":
        changed["provider_transcript"]["transcript_digest"] = canonical_digest(
            {"resealed": "proposal-owned-transcript"}
        )
    else:
        changed["created_at"] = _stamp(START + timedelta(minutes=5))
    _reseal(changed, "proposal_digest")
    proposal_path = root / discovery.DEFAULT_PROPOSAL_FILE
    proposal_path.write_text(canonical_json(changed) + "\n", encoding="utf-8")
    proposal_path.chmod(0o600)

    with pytest.raises(
        discovery.PrivateInputDiscoveryError,
        match="DISCOVERY_PROVENANCE_MISMATCH",
    ):
        discovery.materialize_owner_decision(
            private_root=root,
            source_commit_sha=SOURCE_SHA,
            source_tree_sha=TREE_SHA,
            candidate=changed,
            expected_proposal_digest=changed["proposal_digest"],
            approval_reference_digest=canonical_digest(
                {"owner_decision": f"reject-{mutation}-reseal"}
            ),
            now=START + timedelta(minutes=5, seconds=1),
            expires_at=START + timedelta(minutes=8),
        )


def test_owner_decision_rejects_resealed_replacement_provider_evidence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    root, _, proposal = _persisted_proposal_context(tmp_path, monkeypatch)
    evidence = read_private_json(
        root, discovery.DEFAULT_PROVIDER_EVIDENCE_FILE
    )
    response_digest_index = evidence["provider_events"]["fields"].index(
        "response_digest"
    )
    evidence["provider_events"]["rows"][0][
        response_digest_index
    ] = canonical_digest(
        {"replacement": "provider-response"}
    )
    provider_events = discovery._decode_provider_event_journal(  # noqa: SLF001
        evidence["provider_events"]
    )
    evidence["provider_transcript"]["transcript_digest"] = canonical_digest(
        provider_events
    )
    _reseal(evidence, "provider_evidence_digest")
    evidence_path = root / discovery.DEFAULT_PROVIDER_EVIDENCE_FILE
    evidence_path.write_text(canonical_json(evidence) + "\n", encoding="utf-8")
    evidence_path.chmod(0o600)

    candidate = proposal.private_candidate
    with pytest.raises(
        discovery.PrivateInputDiscoveryError,
        match="DISCOVERY_PROVENANCE_MISMATCH",
    ):
        discovery.materialize_owner_decision(
            private_root=root,
            source_commit_sha=SOURCE_SHA,
            source_tree_sha=TREE_SHA,
            candidate=candidate,
            expected_proposal_digest=candidate["proposal_digest"],
            approval_reference_digest=canonical_digest(
                {"owner_decision": "reject-replaced-provider-evidence"}
            ),
            now=START + timedelta(minutes=4, seconds=1),
            expires_at=START + timedelta(minutes=7),
        )


def test_provider_evidence_rejects_a_resealed_cross_domain_session_reuse(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    root, request, _ = _persisted_proposal_context(tmp_path, monkeypatch)
    claim = read_private_json(root, discovery.DEFAULT_CLAIM_FILE)
    authority_snapshots = [
        read_private_json(root, name)
        for name in discovery.AUTHORITY_SNAPSHOT_FILES
    ]
    identity_snapshots = [
        read_private_json(root, name)
        for name in discovery.IDENTITY_SNAPSHOT_FILES
    ]
    evidence = read_private_json(
        root, discovery.DEFAULT_PROVIDER_EVIDENCE_FILE
    )

    authority_session = authority_snapshots[0]["identity"][
        "session_id_digest"
    ]
    replaced_identity_session = identity_snapshots[0]["session_digests"][0]
    identity_snapshots[0]["session_digests"][0] = authority_session
    identity_snapshots[0]["identities"][0][
        "session_id_digest"
    ] = authority_session
    _reseal(identity_snapshots[0], "snapshot_digest")

    provider_events = discovery._decode_provider_event_journal(  # noqa: SLF001
        evidence["provider_events"]
    )
    provider_events = [
        event
        for event in provider_events
        if not (
            event["domain"] == "identity_center"
            and event["session_digest"] == replaced_identity_session
        )
    ]
    for ordinal, event in enumerate(provider_events, 1):
        event["ordinal"] = ordinal
    budget_events = _budget_events(provider_events)
    evidence["provider_events"] = (
        discovery._encode_provider_event_journal(  # noqa: SLF001
            provider_events
        )
    )
    evidence["budget_events"] = (
        discovery._encode_budget_event_journal(  # noqa: SLF001
            budget_events
        )
    )
    evidence["provider_summary"] = (
        budget_module.replay_discovery_budget_evidence(
            budget_module.validate_discovery_budget(
                request["discovery_budget"]
            ),
            budget_events,
        )
    )
    evidence["provider_transcript"] = {
        "provider_calls": len(provider_events),
        "aws_calls": len(provider_events),
        "aws_mutations": 0,
        "live_provider_evidence": True,
        "transcript_digest": canonical_digest(provider_events),
    }
    evidence["identity_center_snapshot_digests"][0] = identity_snapshots[0][
        "snapshot_digest"
    ]
    _reseal(evidence, "provider_evidence_digest")

    assert discovery._validate_provider_transcript_events(  # noqa: SLF001
        provider_events,
        claimed_at=datetime.fromisoformat(
            claim["claimed_at"].replace("Z", "+00:00")
        ),
        sealed_at=datetime.fromisoformat(
            evidence["sealed_at"].replace("Z", "+00:00")
        ),
    ) == provider_events

    with pytest.raises(
        discovery.PrivateInputDiscoveryError,
        match="PROVIDER_EVIDENCE_INVALID",
    ):
        discovery._validate_provider_evidence_document(  # noqa: SLF001
            evidence,
            request=request,
            claim=claim,
            authority_snapshots=authority_snapshots,
            identity_snapshots=identity_snapshots,
        )


def test_provider_evidence_rejects_sts_completion_after_identity_observation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    root, request, _ = _persisted_proposal_context(tmp_path, monkeypatch)
    claim = read_private_json(root, discovery.DEFAULT_CLAIM_FILE)
    authority_snapshots = [
        read_private_json(root, name)
        for name in discovery.AUTHORITY_SNAPSHOT_FILES
    ]
    identity_snapshots = [
        read_private_json(root, name)
        for name in discovery.IDENTITY_SNAPSHOT_FILES
    ]
    evidence = read_private_json(
        root, discovery.DEFAULT_PROVIDER_EVIDENCE_FILE
    )
    observed_at = datetime.fromisoformat(
        identity_snapshots[-1]["identities"][-1]["observed_at"].replace(
            "Z", "+00:00"
        )
    )
    target_session = identity_snapshots[-1]["session_digests"][-1]
    provider_events = discovery._decode_provider_event_journal(  # noqa: SLF001
        evidence["provider_events"]
    )
    target_event = next(
        event
        for event in provider_events
        if event["operation"] == "sts:GetCallerIdentity"
        and event["session_digest"] == target_session
    )
    target_event["completed_at"] = _stamp(
        observed_at + timedelta(seconds=1)
    )
    evidence["provider_events"] = (
        discovery._encode_provider_event_journal(  # noqa: SLF001
            provider_events
        )
    )
    evidence["provider_transcript"]["transcript_digest"] = canonical_digest(
        provider_events
    )
    _reseal(evidence, "provider_evidence_digest")

    with pytest.raises(
        discovery.PrivateInputDiscoveryError,
        match="PROVIDER_EVIDENCE_INVALID",
    ):
        discovery._validate_provider_evidence_document(  # noqa: SLF001
            evidence,
            request=request,
            claim=claim,
            authority_snapshots=authority_snapshots,
            identity_snapshots=identity_snapshots,
        )


def test_owner_decision_rejects_a_resealed_semantic_proposal_mutation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    root, _, proposal = _persisted_proposal_context(tmp_path, monkeypatch)
    changed = _resealed_alternate_principal_proposal(
        proposal.private_candidate
    )
    proposal_path = root / discovery.DEFAULT_PROPOSAL_FILE
    proposal_path.write_text(canonical_json(changed) + "\n", encoding="utf-8")
    proposal_path.chmod(0o600)

    with pytest.raises(
        discovery.PrivateInputDiscoveryError,
        match="DISCOVERY_PROVENANCE_MISMATCH",
    ):
        discovery.materialize_owner_decision(
            private_root=root,
            source_commit_sha=SOURCE_SHA,
            source_tree_sha=TREE_SHA,
            candidate=changed,
            expected_proposal_digest=changed["proposal_digest"],
            approval_reference_digest=canonical_digest(
                {"owner_decision": "resealed-semantic-mutation"}
            ),
            now=START + timedelta(minutes=4),
            expires_at=START + timedelta(minutes=7),
        )


def test_materialization_rechecks_provenance_after_the_owner_decision(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    root, _, proposal = _persisted_proposal_context(tmp_path, monkeypatch)
    candidate = proposal.private_candidate
    decision = discovery.materialize_owner_decision(
        private_root=root,
        source_commit_sha=SOURCE_SHA,
        source_tree_sha=TREE_SHA,
        candidate=candidate,
        expected_proposal_digest=candidate["proposal_digest"],
        approval_reference_digest=canonical_digest(
            {"owner_decision": "approved-before-proposal-tamper"}
        ),
        now=START + timedelta(minutes=4),
        expires_at=START + timedelta(minutes=7),
    )
    changed = _resealed_alternate_principal_proposal(candidate)
    proposal_path = root / discovery.DEFAULT_PROPOSAL_FILE
    proposal_path.write_text(canonical_json(changed) + "\n", encoding="utf-8")
    proposal_path.chmod(0o600)

    with pytest.raises(
        discovery.PrivateInputDiscoveryError,
        match="DISCOVERY_PROVENANCE_MISMATCH",
    ):
        discovery.materialize_approved_gug392_inputs(
            private_root=root,
            source_commit_sha=SOURCE_SHA,
            source_tree_sha=TREE_SHA,
            candidate=changed,
            decision=decision,
            expected_proposal_digest=changed["proposal_digest"],
            expected_decision_digest=decision["decision_digest"],
            now=START + timedelta(minutes=4, seconds=1),
        )


def test_owner_decision_rejects_a_claim_after_the_snapshot_timeline(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    root, _, proposal = _persisted_proposal_context(tmp_path, monkeypatch)
    claim = read_private_json(root, discovery.DEFAULT_CLAIM_FILE)
    claim["claimed_at"] = _stamp(START + timedelta(minutes=5))
    _reseal(claim, "claim_digest")
    claim_path = root / discovery.DEFAULT_CLAIM_FILE
    claim_path.write_text(canonical_json(claim) + "\n", encoding="utf-8")
    claim_path.chmod(0o600)

    changed = copy.deepcopy(proposal.private_candidate)
    changed["claim_digest"] = claim["claim_digest"]
    _reseal(changed, "proposal_digest")
    proposal_path = root / discovery.DEFAULT_PROPOSAL_FILE
    proposal_path.write_text(canonical_json(changed) + "\n", encoding="utf-8")
    proposal_path.chmod(0o600)

    with pytest.raises(
        discovery.PrivateInputDiscoveryError,
        match="DISCOVERY_PROVENANCE_MISMATCH",
    ):
        discovery.materialize_owner_decision(
            private_root=root,
            source_commit_sha=SOURCE_SHA,
            source_tree_sha=TREE_SHA,
            candidate=changed,
            expected_proposal_digest=changed["proposal_digest"],
            approval_reference_digest=canonical_digest(
                {"owner_decision": "claim-after-evidence"}
            ),
            now=START + timedelta(minutes=4),
            expires_at=START + timedelta(minutes=7),
        )


def test_owner_decision_rejects_a_proposal_before_its_latest_snapshot(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    root, _, proposal = _persisted_proposal_context(tmp_path, monkeypatch)
    changed = copy.deepcopy(proposal.private_candidate)
    changed["created_at"] = _stamp(
        START + timedelta(minutes=2, seconds=1)
    )
    _reseal(changed, "proposal_digest")
    proposal_path = root / discovery.DEFAULT_PROPOSAL_FILE
    proposal_path.write_text(canonical_json(changed) + "\n", encoding="utf-8")
    proposal_path.chmod(0o600)

    with pytest.raises(
        discovery.PrivateInputDiscoveryError,
        match="DISCOVERY_PROVENANCE_MISMATCH",
    ):
        discovery.materialize_owner_decision(
            private_root=root,
            source_commit_sha=SOURCE_SHA,
            source_tree_sha=TREE_SHA,
            candidate=changed,
            expected_proposal_digest=changed["proposal_digest"],
            approval_reference_digest=canonical_digest(
                {"owner_decision": "proposal-before-evidence"}
            ),
            now=START + timedelta(minutes=4),
            expires_at=START + timedelta(minutes=7),
        )


def test_invalid_decision_binding_digest_is_not_reported_as_bad_approval(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    root, _, proposal = _persisted_proposal_context(tmp_path, monkeypatch)
    candidate = proposal.private_candidate
    decision = discovery.materialize_owner_decision(
        private_root=root,
        source_commit_sha=SOURCE_SHA,
        source_tree_sha=TREE_SHA,
        candidate=candidate,
        expected_proposal_digest=candidate["proposal_digest"],
        approval_reference_digest=canonical_digest(
            {"owner_decision": "valid-approval-invalid-binding-later"}
        ),
        now=START + timedelta(minutes=4),
        expires_at=START + timedelta(minutes=7),
    )
    decision["request_digest"] = "not-a-digest"
    _reseal(decision, "decision_digest")

    with pytest.raises(
        discovery.PrivateInputDiscoveryError,
        match="OWNER_DECISION_DIGEST_MISMATCH",
    ):
        discovery.materialize_approved_gug392_inputs(
            private_root=root,
            source_commit_sha=SOURCE_SHA,
            source_tree_sha=TREE_SHA,
            candidate=candidate,
            decision=decision,
            expected_proposal_digest=candidate["proposal_digest"],
            expected_decision_digest=decision["decision_digest"],
            now=START + timedelta(minutes=4, seconds=1),
        )
