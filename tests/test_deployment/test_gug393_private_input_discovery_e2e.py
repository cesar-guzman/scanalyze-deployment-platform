"""Offline end-to-end coverage for the sealed GUG-393 discovery lifecycle."""

from __future__ import annotations

import copy
from datetime import UTC, datetime, timedelta
import os
from pathlib import Path
import socket
from typing import Any, Mapping

import pytest

from tests.test_deployment import (
    test_gug376_live_readonly_orchestrator as collector_harness,
)
from tests.test_deployment import (
    test_gug392_live_request_materializer as gug392_data,
)
from tooling import platform_authority_gug376_live_provider as provider_module
from tooling import (
    platform_authority_gug376_live_request_materializer as gug392_materializer,
)
from tooling import platform_authority_gug393_discovery_budget as budget_module
from tooling import (
    platform_authority_gug393_private_input_discovery as discovery,
)
from tooling import (
    platform_authority_gug393_private_input_discovery_executor as executor,
)
from tooling.platform_authority_gug365_upstream_inventory import (
    canonical_digest,
    canonical_json,
)
from tooling.platform_authority_gug376_authority_inventory_collector import (
    read_private_json,
    write_private_json,
)


START = datetime.now(UTC).replace(microsecond=0) - timedelta(minutes=1)
END = START + timedelta(minutes=15)
PROVIDER_TIME = START + timedelta(minutes=7)
AUTHORITY_ACCOUNT = "222222222222"
IDENTITY_ACCOUNT = "111111111111"
SOURCE_SHA = "a" * 40
TREE_SHA = "b" * 40
HOST_DIGEST = discovery.operational_host_digest()
INITIAL_APPROVAL = canonical_digest({"approval": "gug393-preflight"})


def _stamp(value: datetime) -> str:
    return value.astimezone(UTC).replace(microsecond=0).isoformat().replace(
        "+00:00", "Z"
    )


def _root(tmp_path: Path) -> Path:
    root = tmp_path / "private"
    root.mkdir(mode=0o700)
    root.chmod(0o700)
    return root


def _sdk_root(tmp_path: Path) -> Path:
    root = tmp_path / "sdk-runtime"
    root.mkdir(mode=0o700)
    root.chmod(0o700)
    return root.resolve(strict=True)


def _budget_document() -> dict[str, Any]:
    return {
        "record_type": budget_module.RECORD_TYPE,
        "schema_version": budget_module.SCHEMA_VERSION,
        "max_network_calls": 256,
        "max_provider_calls": 256,
        "max_credential_vending_calls": 0,
        "max_page_calls": 192,
        "max_response_bytes": 64 * 1024,
        "max_total_response_bytes": 1024 * 1024,
        "maximum_cost_usd": "0.001000000",
        "cost_model": {
            "fixed_run_cost_usd_upper": "0.000000100",
            "per_network_attempt_cost_usd_upper": "0.000000000",
            "per_projected_response_byte_cost_usd_upper": "0.000000000",
            "pricing_reference_digest": canonical_digest(
                {"pricing": "gug393-owner-reviewed"}
            ),
            "valid_from": _stamp(START - timedelta(minutes=1)),
            "valid_until": _stamp(END + timedelta(minutes=1)),
        },
    }


def _owner_inputs(
    *, kms_mode: str = "CUSTOMER_MANAGED_KEY"
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    authority, identity = gug392_data._plan_inputs(exact=True)  # noqa: SLF001
    targets = authority["targets"]
    replacements = {
        "synthetic-private-artifacts": "scanalyze-gug393-private-artifacts",
        "synthetic-source": "scanalyze-gug393-source",
        "/synthetic": "/scanalyze-gug393",
    }
    for key, value in tuple(targets.items()):
        if isinstance(value, str):
            for source, target in replacements.items():
                value = value.replace(source, target)
            targets[key] = value
    authority["expected_principal_arn"] = (
        f"arn:aws:sts::{AUTHORITY_ACCOUNT}:"
        "assumed-role/ScanalyzeAuthorityReadOnly/operator"
    )
    identity["expected_principal_arn"] = (
        f"arn:aws:sts::{IDENTITY_ACCOUNT}:"
        "assumed-role/ScanalyzeIdentityReadOnly/operator"
    )
    identity["private_targets"]["application_name"] = "ScanalyzeAuthority"
    identity["private_targets"]["application_actor_policy_digest"] = (
        gug392_materializer.render_application_actor_policy(
            targets,
            authority_account_id=AUTHORITY_ACCOUNT,
        )[1]
    )

    exact_state = gug392_data._exact_expected_state()  # noqa: SLF001
    kms_key_arn = (
        identity["private_targets"]["identity_center_kms_key_arn"]
        if kms_mode == "CUSTOMER_MANAGED_KEY"
        else None
    )
    identity["private_targets"]["identity_center_kms_mode"] = kms_mode
    identity["private_targets"]["identity_center_kms_key_arn"] = kms_key_arn
    identity["private_targets"]["identity_center_kms_binding_digest"] = (
        canonical_digest(
            {
                "binding_name": "identity_center_kms_key_arn",
                "identity_center_instance_arn": gug392_data.IDENTITY_INSTANCE,
                "mode": kms_mode,
                "key_arn": kms_key_arn,
            }
        )
    )
    identity["expected_state"]["instance"]["encryption"] = {
        "key_type": kms_mode,
        "kms_key_arn": kms_key_arn,
        "status": "ENABLED",
    }
    exact_state["targets"]["identity_center_kms_mode"] = kms_mode
    exact_state["targets"]["identity_center_kms_key_arn"] = kms_key_arn
    exact_state["facts"]["instance"]["encryption"] = {
        "key_type": kms_mode,
        "kms_key_arn": kms_key_arn,
        "status": "ENABLED",
    }
    exact_state["facts"]["discovery"]["applications"][0]["name"] = (
        identity["private_targets"]["application_name"]
    )
    exact_state["facts"]["application"]["description"]["NameDigest"] = (
        canonical_digest(identity["private_targets"]["application_name"])
    )
    actor_policy = {
        "policy_digest": identity["private_targets"][
            "application_actor_policy_digest"
        ]
    }
    exact_state["facts"]["application"]["actor_policy"] = actor_policy
    exact_state["facts"]["application"]["authentication_methods"][0][
        "AuthenticationMethod"
    ]["Iam"]["ActorPolicy"] = actor_policy

    assert "synthetic" not in canonical_json(
        {"authority": authority, "identity": identity, "exact": exact_state}
    ).casefold()
    return authority, identity, exact_state


def _source_contract(
    authority: Mapping[str, Any],
    identity: Mapping[str, Any],
    exact_state: Mapping[str, Any],
) -> discovery.DerivedSourceContract:
    authority_targets = copy.deepcopy(authority["targets"])
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
        "authority_targets": authority_targets,
        "identity_center_private_targets": copy.deepcopy(
            identity["private_targets"]
        ),
        "identity_center_kms_binding_digest": canonical_digest(
            {
                "binding_name": "identity_center_kms_key_arn",
                "identity_center_instance_arn": gug392_data.IDENTITY_INSTANCE,
                "mode": identity["private_targets"]["identity_center_kms_mode"],
                "key_arn": identity["private_targets"][
                    "identity_center_kms_key_arn"
                ],
            }
        ),
        "identity_center_source_expectations": {
            "instance_arn": gug392_data.IDENTITY_INSTANCE,
            "application_arn": exact_state["targets"][
                "identity_center_application_arn"
            ],
            "generated_role_arns": {
                "retire_approve": authority_targets[
                    "retire_approve_generated_role_arn"
                ],
                "retire_class": authority_targets[
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


def _profiles(
    authority: Mapping[str, Any], identity: Mapping[str, Any]
) -> dict[str, Any]:
    return {
        "authority": {
            "name": "scanalyze-authority-readonly",
            "source": "DIRECT_SSO",
            "chain_depth": 0,
            "expected_account_id": AUTHORITY_ACCOUNT,
            "expected_principal_arn": authority["expected_principal_arn"],
            "expected_sso_role_name": "ScanalyzeAuthorityReadOnly",
            "authority_verification_digest": authority[
                "authority_verification_digest"
            ],
        },
        "identity_center": {
            "name": "scanalyze-identity-readonly",
            "source": "DIRECT_SSO",
            "chain_depth": 0,
            "expected_account_id": IDENTITY_ACCOUNT,
            "expected_principal_arn": identity["expected_principal_arn"],
            "expected_sso_role_name": "ScanalyzeIdentityReadOnly",
            "authority_verification_digest": identity[
                "authority_verification_digest"
            ],
        },
    }


def _provider_bindings(request: Mapping[str, Any]) -> dict[str, Any]:
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
        "identity_expected_sso_role_name_digest": profiles[
            "identity_center"
        ]["expected_sso_role_name_digest"],
        "authority_verification_digest": profiles["authority"][
            "authority_verification_digest"
        ],
        "identity_authority_verification_digest": profiles[
            "identity_center"
        ]["authority_verification_digest"],
        "budget_digest": request["budget_digest"],
    }


class _TransitionAttestation:
    def __init__(
        self,
        *,
        capability: discovery.DiscoveryExecutionCapability,
        capture_index: int,
        policy_digest: str,
        discovered: Mapping[str, Any],
    ) -> None:
        self.capability = capability
        self.capture_index = capture_index
        self.policy_digest = policy_digest
        self.discovered = copy.deepcopy(discovered)
        self.consumed = False


class _BudgetedActor(collector_harness._Actor):  # noqa: SLF001
    def call(
        self, operation: str, response: Any, *, token: Any = None
    ) -> Any:
        self.owner.discovery_budget.reserve_provider_call(
            operation, is_page=operation.split(":", 1)[1].startswith("List")
        )
        self.owner.attempts.append(
            (self.domain, self.capture, self.stage, operation)
        )
        call_time = _stamp(START + timedelta(minutes=4))
        ticket = self.ledger.authorize(
            domain=self.domain,
            session_digest=self.session,
            operation=operation,
            retries=0,
            request={"capture": self.capture, "stage": self.stage},
            page_token=token,
            started_at=call_time,
        )
        next_token = None
        truncated = False
        if isinstance(response, Mapping):
            next_token = response.get(
                "next_cursor", response.get("next_token")
            )
            truncated = bool(response.get("truncated"))
        response_digest = canonical_digest(
            {
                "domain": self.domain,
                "capture": self.capture,
                "stage": self.stage,
                "operation": operation,
                "token": token,
            }
        )
        self.ledger.complete(
            ticket,
            response_digest,
            complete=next_token is None,
            truncated=truncated,
            next_token=next_token,
            completed_at=call_time,
        )
        projected = canonical_json(
            {"operation": operation, "response_digest": response_digest}
        ).encode("utf-8")
        self.owner.discovery_budget.record_response(len(projected))
        self.owner.completed += 1
        return response


class _IdentityReader(gug392_data._LiveIdentityReader):  # noqa: SLF001
    def attest_transition(self, discovery_digest: str) -> object:
        discovered = copy.deepcopy(self._discovery())  # noqa: SLF001
        assert canonical_digest(
            {
                "discovery": discovered,
                "instance": copy.deepcopy(self._instance()),  # noqa: SLF001
            }
        ) == discovery_digest
        return _TransitionAttestation(
            capability=self.actor.owner.capability,
            capture_index=self.actor.capture,
            policy_digest=self.actor.digest,
            discovered=discovered,
        )


class _Session(collector_harness._Session):  # noqa: SLF001
    def open_reader(self) -> Any:
        self.actor.owner.reader_opens += 1
        return gug392_data._LiveAuthorityReader(  # noqa: SLF001
            self.actor, self.plan
        )

    def open_discovery(self) -> Any:
        self.actor.owner.reader_opens += 1
        return _IdentityReader(
            self.actor, self.plan, self.actor.owner.exact_state
        )

    def open_exact(self) -> Any:
        self.actor.owner.reader_opens += 1
        return _IdentityReader(
            self.actor, self.plan, self.actor.owner.exact_state
        )


class _SessionFactory:
    def __init__(
        self,
        owner: "_AttestedOfflineProvider",
        domain: str,
        capture_index: int,
        ledger: Any,
    ) -> None:
        self.owner = owner
        self.domain = domain
        self.capture_index = capture_index
        self.ledger = ledger

    def open_sts(
        self,
        *,
        policy: Mapping[str, Any],
        policy_digest: str,
        region: str,
        stage: str = "authority",
    ) -> _Session:
        assert canonical_digest(policy) == policy_digest
        assert region == "us-east-1"
        self.owner.capability_gate.authorize_session(
            domain=self.domain,
            capture_index=self.capture_index,
            stage=stage,
            policy_digest=policy_digest,
        )
        self.owner.sessions.append(
            (self.domain, self.capture_index, stage)
        )
        actor = _BudgetedActor(
            self.owner,
            self.domain,
            self.capture_index,
            stage,
            self.ledger,
            policy_digest,
        )
        plan_name = (
            "authority_plan"
            if self.domain == "authority"
            else "identity_center_plan"
        )
        return _Session(actor, self.owner.config[plan_name])


class _AttestedOfflineProvider(collector_harness.FakeProvider):
    """Collector-complete provider fake with a real shared call ledger."""

    mode = "ATTESTED_DISCOVERY"
    concrete_provider = True
    discovery_provider = True

    def __init__(
        self,
        *,
        config: Mapping[str, Any],
        capability: discovery.DiscoveryExecutionCapability,
        capability_gate: Any,
        discovery_budget: budget_module.GlobalDiscoveryBudget,
        exact_state: Mapping[str, Any] | None,
    ) -> None:
        super().__init__(config)
        self.capability = capability
        self.capability_gate = capability_gate
        self.discovery_budget = discovery_budget
        self.exact_state = copy.deepcopy(exact_state)
        self.authority_role_fault = None
        self.sessions: list[tuple[str, int, str]] = []
        self._ledger: Any = None

    def build_authority(self, **kwargs: Any) -> _SessionFactory:
        self._ledger = kwargs["ledger"]
        assert kwargs["profile"] == self.config["profiles"]["authority"][
            "name"
        ]
        assert kwargs["retries"] == 0
        self.builds.append(("authority", kwargs["capture_index"]))
        return _SessionFactory(
            self, "authority", kwargs["capture_index"], kwargs["ledger"]
        )

    def build_identity(self, **kwargs: Any) -> _SessionFactory:
        self._ledger = kwargs["ledger"]
        assert kwargs["profile"] == self.config["profiles"][
            "identity_center"
        ]["name"]
        assert kwargs["retries"] == 0
        self.builds.append(("identity_center", kwargs["capture_index"]))
        return _SessionFactory(
            self,
            "identity_center",
            kwargs["capture_index"],
            kwargs["ledger"],
        )

    def evaluation_time(self) -> datetime:
        self.capability_gate()
        return PROVIDER_TIME

    def discovery_budget_summary(self) -> dict[str, Any]:
        return self.discovery_budget.summary()

    def transcript_summary(self) -> dict[str, Any]:
        calls, transcript_digest = self._ledger.finalize()
        return {
            "provider_calls": calls,
            "aws_calls": calls,
            "aws_mutations": 0,
            "live_provider_evidence": True,
            "transcript_digest": transcript_digest,
        }

    def transcript_events(self) -> list[dict[str, Any]]:
        return self._ledger.evidence_events()

    def discovery_budget_evidence_events(self) -> list[dict[str, Any]]:
        return self.discovery_budget.evidence_events()


@pytest.fixture(autouse=True)
def _closed_context(monkeypatch: pytest.MonkeyPatch) -> None:
    for key in tuple(os.environ):
        if key.startswith("AWS_") or key in {
            "BOTO_CONFIG",
            "REQUESTS_CA_BUNDLE",
            "SSL_CERT_FILE",
            "SSL_CERT_DIR",
        }:
            monkeypatch.delenv(key)
    monkeypatch.setattr(gug392_data, "AUTHORITY_ACCOUNT", AUTHORITY_ACCOUNT)
    monkeypatch.setattr(gug392_data, "IDENTITY_ACCOUNT", IDENTITY_ACCOUNT)
    monkeypatch.setattr(collector_harness, "START", START)
    monkeypatch.setattr(collector_harness, "END", END)
    monkeypatch.setattr(
        discovery,
        "_observed_utc_now",
        lambda: START + timedelta(minutes=8),
    )


def test_executor_rejects_preexisting_downstream_output_before_claim_or_calls(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = _root(tmp_path)
    write_private_json(
        root, discovery.DEFAULT_DECISION_FILE, {"preexisting": True}
    )
    capability = object()
    provider = object()
    claim_attempts: list[object] = []
    monkeypatch.setattr(
        executor,
        "is_attested_discovery_provider",
        lambda value, supplied: value is provider and supplied is capability,
    )
    monkeypatch.setattr(
        executor,
        "approved_discovery_request",
        lambda supplied: {
            "request_file": discovery.DEFAULT_REQUEST_FILE,
            "owner_checkpoint_file": discovery.DEFAULT_CHECKPOINT_FILE,
        }
        if supplied is capability
        else pytest.fail("wrong capability"),
    )
    monkeypatch.setattr(
        executor,
        "claim_discovery_execution",
        lambda supplied: claim_attempts.append(supplied),
    )

    with pytest.raises(
        discovery.PrivateInputDiscoveryError,
        match="PRIVATE_ARTIFACT_EXISTS",
    ):
        executor.execute_private_input_discovery(
            provider_factory=provider,  # type: ignore[arg-type]
            execution_capability=capability,  # type: ignore[arg-type]
            private_root=root,
            now=START + timedelta(minutes=3),
        )

    assert claim_attempts == []
    assert read_private_json(root, discovery.DEFAULT_DECISION_FILE) == {
        "preexisting": True
    }


@pytest.mark.parametrize(
    ("classification", "exact"),
    (("ABSENT_READY", False), ("EXACT_PRESENT_NO_TOUCH", True)),
)
@pytest.mark.parametrize(
    "kms_mode", ("AWS_OWNED_KMS_KEY", "CUSTOMER_MANAGED_KEY")
)
def test_private_discovery_runs_through_approved_gug392_inputs_offline(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    classification: str,
    exact: bool,
    kms_mode: str,
) -> None:
    monkeypatch.setattr(
        socket,
        "socket",
        lambda *_args, **_kwargs: pytest.fail("network access attempted"),
    )
    authority_input, identity_input, exact_state = _owner_inputs(
        kms_mode=kms_mode
    )
    root = _root(tmp_path)
    sdk_root = _sdk_root(tmp_path)
    materialized_request = discovery.materialize_discovery_request(
        source_contract=_source_contract(
            authority_input, identity_input, exact_state
        ),
        profiles=_profiles(authority_input, identity_input),
        discovery_budget=_budget_document(),
        sdk_runtime_root=str(sdk_root),
        private_root=root,
        source_commit_sha=SOURCE_SHA,
        source_tree_sha=TREE_SHA,
        host_digest=HOST_DIGEST,
        not_before=_stamp(START),
        expires_at=_stamp(END),
        approval_reference_digest=INITIAL_APPROVAL,
    )
    discovery.persist_discovery_request(root, materialized_request)
    request, capability = discovery.read_and_claim_discovery_request(
        private_root=root,
        request_file=discovery.DEFAULT_REQUEST_FILE,
        owner_checkpoint_file=discovery.DEFAULT_CHECKPOINT_FILE,
        expected_request_digest=materialized_request.request["request_digest"],
        expected_checkpoint_digest=materialized_request.owner_checkpoint[
            "checkpoint_digest"
        ],
        approval_reference_digest=INITIAL_APPROVAL,
        source_commit_sha=SOURCE_SHA,
        source_tree_sha=TREE_SHA,
        host_digest=HOST_DIGEST,
        now=START + timedelta(minutes=2),
    )
    capability_gate = discovery.assert_preflight_provider_capability_bindings(
        capability, **_provider_bindings(request)
    )
    shared_budget = budget_module.GlobalDiscoveryBudget(
        budget_module.validate_discovery_budget(request["discovery_budget"])
    )
    authority_plan, identity_plan = discovery.provisional_discovery_plans(
        request
    )
    config = {
        "profiles": {
            "authority": {"name": request["profiles"]["authority"]["name"]},
            "identity_center": {
                "name": request["profiles"]["identity_center"]["name"]
            },
        },
        "authority_plan": authority_plan,
        "identity_center_plan": identity_plan,
    }
    provider = _AttestedOfflineProvider(
        config=config,
        capability=capability,
        capability_gate=capability_gate,
        discovery_budget=shared_budget,
        exact_state=exact_state if exact else None,
    )

    def is_attested(value: object, supplied: object) -> bool:
        return value is provider and supplied is capability

    def consume_transition(
        value: object,
        *,
        execution_capability: object,
        capture_index: int,
        expected_policy_digest: str,
    ) -> dict[str, Any]:
        assert type(value) is _TransitionAttestation
        assert value.capability is execution_capability is capability
        assert value.capture_index == capture_index
        assert value.policy_digest == expected_policy_digest
        assert value.consumed is False
        value.consumed = True
        return copy.deepcopy(value.discovered)

    monkeypatch.setattr(executor, "is_attested_discovery_provider", is_attested)
    monkeypatch.setattr(
        provider_module, "is_attested_discovery_provider", is_attested
    )
    monkeypatch.setattr(
        provider_module,
        "consume_identity_discovery_transition_attestation",
        consume_transition,
    )

    proposal = executor.execute_private_input_discovery(
        provider_factory=provider,
        execution_capability=capability,
        private_root=root,
        now=START + timedelta(minutes=3),
    )
    candidate = proposal.private_candidate
    assert candidate["classification"] == classification
    assert read_private_json(root, discovery.DEFAULT_PROPOSAL_FILE) == candidate
    provider_evidence_path = root / discovery.DEFAULT_PROVIDER_EVIDENCE_FILE
    provider_evidence = read_private_json(
        root, discovery.DEFAULT_PROVIDER_EVIDENCE_FILE
    )
    assert provider_evidence_path.is_file()
    assert provider_evidence_path.stat().st_mode & 0o777 == 0o600
    assert provider_evidence["provider_evidence_digest"] == candidate[
        "provider_evidence_digest"
    ]
    assert provider_evidence["sealed_at"] == candidate["created_at"]
    provider_events = discovery._decode_provider_event_journal(  # noqa: SLF001
        provider_evidence["provider_events"]
    )
    budget_events = discovery._decode_budget_event_journal(  # noqa: SLF001
        provider_evidence["budget_events"]
    )
    assert provider_events == provider.transcript_events()
    assert budget_events == provider.discovery_budget_evidence_events()
    assert budget_module.replay_discovery_budget_evidence(
        budget_module.validate_discovery_budget(request["discovery_budget"]),
        budget_events,
    ) == candidate["provider_summary"]
    assert provider.builds == [
        ("authority", 1),
        ("authority", 2),
        ("identity_center", 1),
        ("identity_center", 2),
    ]
    expected_sessions = [
        ("authority", 1, "authority"),
        ("authority", 2, "authority"),
        ("identity_center", 1, "discovery"),
        *(([("identity_center", 1, "exact")]) if exact else []),
        ("identity_center", 2, "discovery"),
        *(([("identity_center", 2, "exact")]) if exact else []),
    ]
    assert provider.sessions == expected_sessions
    assert provider.completed == len(provider.attempts)
    assert provider.completed == candidate["provider_summary"]["provider_calls"]
    assert candidate["provider_transcript"]["provider_calls"] == (
        provider.completed
    )

    decision_approval = canonical_digest(
        {"approval": "gug393-owner-decision", "classification": classification}
    )
    assert decision_approval != INITIAL_APPROVAL
    decision = discovery.materialize_owner_decision(
        source_commit_sha=SOURCE_SHA,
        source_tree_sha=TREE_SHA,
        candidate=candidate,
        expected_proposal_digest=candidate["proposal_digest"],
        approval_reference_digest=decision_approval,
        now=START + timedelta(minutes=8),
        expires_at=START + timedelta(minutes=14),
        private_root=root,
    )
    discovery.persist_owner_decision(root, decision)
    approved = discovery.materialize_approved_gug392_inputs(
        source_commit_sha=SOURCE_SHA,
        source_tree_sha=TREE_SHA,
        candidate=candidate,
        decision=decision,
        expected_proposal_digest=candidate["proposal_digest"],
        expected_decision_digest=decision["decision_digest"],
        now=START + timedelta(minutes=8, seconds=1),
        private_root=root,
    )
    manifest = approved.manifest
    discovery.persist_approved_gug392_inputs(root, approved)
    assert discovery.validate_input_materialization_manifest(
        root, manifest
    ) == manifest
    assert read_private_json(root, manifest["decision_file"]) == decision

    persisted_authority_input = read_private_json(
        root, discovery.DEFAULT_AUTHORITY_INPUT_FILE
    )
    persisted_identity_input = read_private_json(
        root, discovery.DEFAULT_IDENTITY_INPUT_FILE
    )
    assert persisted_authority_input["not_before"] == decision["approved_at"]
    assert persisted_authority_input["not_after"] == decision["expires_at"]
    assert persisted_identity_input["not_before"] == decision["approved_at"]
    assert persisted_identity_input["not_after"] == decision["expires_at"]
    downstream_plans = gug392_materializer.materialize_live_plans(
        authority_input=persisted_authority_input,
        identity_center_input=persisted_identity_input,
    )
    assert downstream_plans.authority_plan == read_private_json(
        root, discovery.DEFAULT_AUTHORITY_PLAN_FILE
    )
    assert downstream_plans.identity_center_plan == read_private_json(
        root, discovery.DEFAULT_IDENTITY_PLAN_FILE
    )

    downstream_request = gug392_materializer.materialize_live_request(
        authority_plan=downstream_plans.authority_plan,
        identity_center_plan=downstream_plans.identity_center_plan,
        profiles={
            domain: {
                "name": request["profiles"][domain]["name"],
                "source": "DIRECT_SSO",
                "chain_depth": 0,
            }
            for domain in ("authority", "identity_center")
        },
        expected_sso_role_name_digests={
            domain: request["profiles"][domain][
                "expected_sso_role_name_digest"
            ]
            for domain in ("authority", "identity_center")
        },
        source_commit_sha=SOURCE_SHA,
        source_tree_sha=TREE_SHA,
        run_id=f"gug393-e2e-{'exact' if exact else 'absent'}-01",
        not_before=_stamp(START + timedelta(minutes=9)),
        expires_at=_stamp(START + timedelta(minutes=13)),
        host_digest=HOST_DIGEST,
        private_root_digest=gug392_materializer.private_root_binding_digest(
            root
        ),
        sdk_runtime_root=str(sdk_root),
        approval_reference_digest=canonical_digest(
            {"approval": "gug392-downstream", "classification": classification}
        ),
        request_file=f"gug392-e2e-{'exact' if exact else 'absent'}-request.json",
        owner_checkpoint_file=(
            f"gug392-e2e-{'exact' if exact else 'absent'}-checkpoint.json"
        ),
    )
    assert downstream_request.request["authority_plan"] == (
        downstream_plans.authority_plan
    )
    assert downstream_request.request["identity_center_plan"] == (
        downstream_plans.identity_center_plan
    )
    assert downstream_request.request["aws_mutations"] == 0
