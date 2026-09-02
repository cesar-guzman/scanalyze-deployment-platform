from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from tooling import platform_authority_gug395_preplan_collision_executor as executor
from tooling import platform_authority_gug395_preplan_collision_probe as contract
from tests.test_deployment import (
    test_gug395_preplan_collision_probe as probe_data,
)


NOW = datetime(2026, 8, 28, 1, 10, tzinfo=UTC)


def _digest(label: str) -> str:
    return contract.canonical_digest({"label": label})


class _Reader:
    def __init__(
        self,
        *,
        owner: "_Provider",
        domain: str,
        capture_index: int,
        facts: dict[str, Any],
    ) -> None:
        self._owner = owner
        self._domain = domain
        self._capture_index = capture_index
        self._facts = facts
        self.caps: dict[str, int] | None = None

    def read_collision_facts(
        self, targets: dict[str, Any], **caps: int
    ) -> dict[str, Any]:
        assert tuple(targets) == contract.TARGET_ORDER
        self.caps = caps
        self._owner.caps[(self._domain, self._capture_index)] = dict(caps)
        return self._facts


class _Session:
    def __init__(
        self,
        *,
        owner: "_Provider",
        domain: str,
        capture_index: int,
        facts: dict[str, Any],
    ) -> None:
        self._domain = domain
        self._capture_index = capture_index
        self._reader = _Reader(
            owner=owner,
            domain=domain,
            capture_index=capture_index,
            facts=facts,
        )

    def get_caller_identity(self) -> dict[str, Any]:
        return probe_data._identity(self._domain, self._capture_index)

    def open_collision_reader(self) -> _Reader:
        return self._reader


class _DomainFactory:
    def __init__(
        self,
        *,
        owner: "_Provider",
        domain: str,
        capture_index: int,
    ) -> None:
        self._owner = owner
        self._domain = domain
        self._capture_index = capture_index

    def open_sts(
        self,
        *,
        policy: dict[str, Any],
        policy_digest: str,
        region: str,
        stage: str,
    ) -> _Session:
        assert policy == self._owner.request["policies"][self._domain]
        assert policy_digest == self._owner.request["policy_digests"][
            self._domain
        ]
        assert region == contract.REGION
        assert stage == "collision_probe"
        self._owner.opened.append((self._domain, self._capture_index))
        if self._owner.fail_at == (self._domain, self._capture_index):
            raise executor.LiveProviderError("PROVIDER_READ_FAILED")
        collisions = (
            ["artifact_bucket"]
            if self._owner.collision and self._domain == "authority"
            else []
        )
        facts = probe_data._provider_facts(
            self._domain, collisions=collisions
        )
        return _Session(
            owner=self._owner,
            domain=self._domain,
            capture_index=self._capture_index,
            facts=facts,
        )


class _Provider:
    def __init__(
        self,
        *,
        request: dict[str, Any],
        collision: bool,
        fail_at: tuple[str, int] | None = None,
    ) -> None:
        self.request = request
        self.collision = collision
        self.fail_at = fail_at
        self.opened: list[tuple[str, int]] = []
        self.caps: dict[tuple[str, int], dict[str, int]] = {}

    def _build(
        self,
        domain: str,
        *,
        profile: str,
        capture_index: int,
        retries: int,
    ) -> _DomainFactory:
        assert profile == self.request["profiles"][domain]["name"]
        assert retries == 0
        return _DomainFactory(
            owner=self,
            domain=domain,
            capture_index=capture_index,
        )

    def build_authority(
        self,
        *,
        profile: str,
        ledger: contract.CollisionCallLedger,
        capture_index: int,
        retries: int,
    ) -> _DomainFactory:
        assert isinstance(ledger, contract.CollisionCallLedger)
        return self._build(
            "authority",
            profile=profile,
            capture_index=capture_index,
            retries=retries,
        )

    def build_identity(
        self,
        *,
        profile: str,
        ledger: contract.CollisionCallLedger,
        capture_index: int,
        retries: int,
    ) -> _DomainFactory:
        assert isinstance(ledger, contract.CollisionCallLedger)
        return self._build(
            "identity_center",
            profile=profile,
            capture_index=capture_index,
            retries=retries,
        )

    def transcript_summary(self) -> dict[str, Any]:
        return {"provider_calls": 8}

    def transcript_events(self) -> list[dict[str, int]]:
        return [{"ordinal": index} for index in range(1, 9)]

    def collision_budget_summary(self) -> dict[str, int]:
        return {"provider_calls": 8}

    def collision_budget_evidence_events(self) -> list[dict[str, int]]:
        return [{"ordinal": 1}]

    def collision_partial_transcript_summary(self) -> dict[str, Any]:
        return {
            "provider_calls": 1,
            "aws_calls": None,
            "aws_mutations": 0,
            "live_provider_evidence": False,
            "transcript_digest": _digest("partial-transcript"),
        }

    def collision_partial_transcript_events(self) -> list[dict[str, int]]:
        return [{"ordinal": 1}]

    def collision_budget_partial_evidence_events(self) -> list[dict[str, int]]:
        return [{"ordinal": 1, "kind": 1}]

    def evaluation_time(self) -> datetime:
        return NOW

    def failure_evaluation_time(self) -> datetime:
        return NOW


def _request() -> dict[str, Any]:
    return probe_data._request()


@pytest.fixture(autouse=True)
def _stub_session_transcript_segment_digest(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The orchestration doubles do not emulate SDK call journaling."""

    monkeypatch.setattr(
        executor,
        "_session_transcript_segment_digest",
        lambda ledger, identity: contract.canonical_digest(
            {"session": identity["session_id_digest"]}
        ),
    )
    monkeypatch.setattr(
        executor,
        "approved_collision_probe_claim_digest",
        lambda capability: _digest("capability-claim"),
    )


def test_non_attested_provider_is_sealed_as_zero_call_blocked_after_claim(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    capability = object()
    request = _request()
    lifecycle: list[str] = []
    captured: dict[str, Any] = {}
    persisted: list[contract.CollisionProbeResult] = []
    blocked = contract.CollisionProbeResult(
        private_evidence={"execution_status": contract.EXECUTION_BLOCKED},
        public_receipt={"status": "LIVE_READ_ONLY_PROBE_BLOCKED"},
    )

    monkeypatch.setattr(
        executor,
        "is_attested_collision_probe_provider",
        lambda provider, capability: False,
    )
    monkeypatch.setattr(
        executor, "approved_collision_probe_request", lambda supplied: request
    )
    monkeypatch.setattr(
        executor,
        "assert_collision_probe_private_root_binding",
        lambda supplied, root: lifecycle.append("bound"),
    )
    monkeypatch.setattr(
        executor,
        "claim_collision_probe_execution",
        lambda supplied: lifecycle.append("claimed"),
    )
    monkeypatch.setattr(
        executor,
        "assert_collision_probe_execution_active",
        lambda supplied: lifecycle.append("active"),
    )
    monkeypatch.setattr(
        executor,
        "complete_collision_probe_execution",
        lambda supplied: lifecycle.append("completed"),
    )

    def build_failure(**kwargs: Any) -> contract.CollisionProbeResult:
        captured.update(kwargs)
        return blocked

    monkeypatch.setattr(
        executor, "build_collision_probe_failure_result", build_failure
    )
    monkeypatch.setattr(
        executor,
        "persist_collision_probe_result",
        lambda *, private_root, result, expected_claim_digest: persisted.append(
            result
        ),
    )

    result = executor.execute_preplan_collision_probe(
        provider_factory=object(),  # type: ignore[arg-type]
        execution_capability=capability,  # type: ignore[arg-type]
        private_root=tmp_path,
        now=NOW,
    )

    assert result is blocked
    assert lifecycle == ["bound", "claimed", "active", "completed"]
    assert persisted == [blocked]
    assert captured["blocker_code"] == "ATTESTED_COLLISION_PROVIDER_REQUIRED"
    assert captured["transcript_events"] == []
    assert captured["budget_events"] == []


def test_private_root_mismatch_is_non_retryable_custody_corruption(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    request = _request()
    claimed = False
    persisted = False
    monkeypatch.setattr(
        executor, "approved_collision_probe_request", lambda supplied: request
    )

    def reject_root(capability: object, root: Path) -> None:
        raise contract.CollisionProbeError(
            "COLLISION_PRIVATE_ROOT_BINDING_MISMATCH"
        )

    def claim(capability: object) -> None:
        nonlocal claimed
        claimed = True

    def persist(**kwargs: Any) -> None:
        nonlocal persisted
        persisted = True

    monkeypatch.setattr(
        executor, "assert_collision_probe_private_root_binding", reject_root
    )
    monkeypatch.setattr(executor, "claim_collision_probe_execution", claim)
    monkeypatch.setattr(executor, "persist_collision_probe_result", persist)

    with pytest.raises(
        contract.CollisionProbeError,
        match="^COLLISION_PRIVATE_ROOT_BINDING_MISMATCH$",
    ):
        executor.execute_preplan_collision_probe(
            provider_factory=object(),  # type: ignore[arg-type]
            execution_capability=object(),  # type: ignore[arg-type]
            private_root=tmp_path,
            now=NOW,
        )

    assert claimed is False
    assert persisted is False


def test_source_failure_during_execution_claim_is_durable_zero_call_blocked(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    capability = object()
    request = _request()
    lifecycle: list[str] = []
    captured: dict[str, Any] = {}
    blocked = contract.CollisionProbeResult(
        private_evidence={"execution_status": contract.EXECUTION_BLOCKED},
        public_receipt={"status": "LIVE_READ_ONLY_PROBE_BLOCKED"},
    )
    monkeypatch.setattr(
        executor, "approved_collision_probe_request", lambda supplied: request
    )
    monkeypatch.setattr(
        executor,
        "assert_collision_probe_private_root_binding",
        lambda supplied, root: lifecycle.append("bound"),
    )

    def fail_claim(capability: object) -> None:
        lifecycle.append("claim-transitioned")
        raise contract.CollisionProbeError(
            "COLLISION_SOURCE_REVERIFICATION_MISMATCH"
        )

    monkeypatch.setattr(executor, "claim_collision_probe_execution", fail_claim)
    monkeypatch.setattr(
        executor,
        "assert_collision_probe_execution_active",
        lambda supplied: lifecycle.append("active"),
    )
    monkeypatch.setattr(
        executor,
        "is_attested_collision_probe_provider",
        lambda provider, supplied: pytest.fail(
            "attestation must not run after source claim failure"
        ),
    )
    monkeypatch.setattr(
        executor,
        "build_collision_probe_failure_result",
        lambda **kwargs: captured.update(kwargs) or blocked,
    )
    monkeypatch.setattr(
        executor,
        "persist_collision_probe_result",
        lambda *, private_root, result, expected_claim_digest: lifecycle.append(
            "persisted"
        ),
    )
    monkeypatch.setattr(
        executor,
        "complete_collision_probe_execution",
        lambda supplied: lifecycle.append("completed"),
    )

    result = executor.execute_preplan_collision_probe(
        provider_factory=object(),  # type: ignore[arg-type]
        execution_capability=capability,  # type: ignore[arg-type]
        private_root=tmp_path,
        now=NOW,
    )

    assert result is blocked
    assert lifecycle == [
        "bound",
        "claim-transitioned",
        "active",
        "persisted",
        "completed",
    ]
    assert captured["blocker_code"] == (
        "COLLISION_SOURCE_REVERIFICATION_MISMATCH"
    )
    assert captured["transcript_events"] == []
    assert captured["budget_events"] == []


@pytest.mark.parametrize(
    ("collision", "expected"),
    [
        (False, contract.ABSENT_READY),
        (True, contract.COLLISION_BLOCKED),
    ],
)
def test_executor_orchestrates_four_attested_sessions_and_persists_result(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    collision: bool,
    expected: str,
) -> None:
    capability = object()
    request = _request()
    provider = _Provider(request=request, collision=collision)
    lifecycle: list[str] = []
    persisted: list[contract.CollisionProbeResult] = []
    bound_roots: list[tuple[object, Path]] = []

    monkeypatch.setattr(
        executor,
        "is_attested_collision_probe_provider",
        lambda supplied, supplied_capability: (
            supplied is provider and supplied_capability is capability
        ),
    )
    monkeypatch.setattr(
        executor,
        "approved_collision_probe_request",
        lambda supplied: request if supplied is capability else None,
    )
    monkeypatch.setattr(
        executor,
        "assert_collision_probe_private_root_binding",
        lambda supplied, root: bound_roots.append((supplied, root)),
    )
    monkeypatch.setattr(
        executor,
        "claim_collision_probe_execution",
        lambda supplied: lifecycle.append("claimed"),
    )
    monkeypatch.setattr(
        executor,
        "complete_collision_probe_execution",
        lambda supplied: lifecycle.append("completed"),
    )

    def build_result(**kwargs: Any) -> contract.CollisionProbeResult:
        classification = contract.classify_collision_probe_snapshots(
            authority_snapshots=kwargs["authority_snapshots"],
            identity_center_snapshots=kwargs["identity_center_snapshots"],
        )
        return contract.CollisionProbeResult(
            private_evidence={"classification": classification},
            public_receipt={
                "classification": classification["classification"],
                "sealed_at": kwargs["sealed_at"],
            },
        )

    monkeypatch.setattr(executor, "build_collision_probe_result", build_result)
    monkeypatch.setattr(
        executor,
        "persist_collision_probe_result",
        lambda *, private_root, result, expected_claim_digest: persisted.append(
            result
        ),
    )

    result = executor.execute_preplan_collision_probe(
        provider_factory=provider,  # type: ignore[arg-type]
        execution_capability=capability,  # type: ignore[arg-type]
        private_root=tmp_path,
        now=NOW,
    )

    assert provider.opened == [
        ("authority", 1),
        ("authority", 2),
        ("identity_center", 1),
        ("identity_center", 2),
    ]
    assert lifecycle == ["claimed", "completed"]
    assert bound_roots == [(capability, tmp_path)]
    assert persisted == [result]
    assert result.public_receipt["classification"] == expected
    assert result.private_evidence["classification"]["evidence_stable"] is True
    assert result.public_receipt["sealed_at"] == "2026-08-28T01:10:00Z"
    authority_caps = {
        "max_owned_buckets": contract.MAX_OWNED_BUCKETS,
        "max_kms_keys": contract.MAX_KMS_KEYS,
        "max_signing_profiles": contract.MAX_SIGNING_PROFILES,
        "max_code_signing_configs": contract.MAX_CODE_SIGNING_CONFIGS,
    }
    identity_caps = {
        "max_applications": contract.MAX_APPLICATIONS,
        "max_permission_sets": contract.MAX_PERMISSION_SETS,
    }
    assert provider.caps == {
        ("authority", 1): authority_caps,
        ("authority", 2): authority_caps,
        ("identity_center", 1): identity_caps,
        ("identity_center", 2): identity_caps,
    }


def test_executor_persists_conservative_blocked_result_after_claim(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    capability = object()
    request = _request()
    provider = _Provider(
        request=request,
        collision=False,
        fail_at=("authority", 2),
    )
    lifecycle: list[str] = []
    failure_kwargs: dict[str, Any] = {}
    persisted: list[contract.CollisionProbeResult] = []

    monkeypatch.setattr(
        executor,
        "is_attested_collision_probe_provider",
        lambda supplied, supplied_capability: (
            supplied is provider and supplied_capability is capability
        ),
    )
    monkeypatch.setattr(
        executor,
        "assert_collision_probe_private_root_binding",
        lambda supplied, root: lifecycle.append("bound"),
    )
    monkeypatch.setattr(
        executor,
        "approved_collision_probe_request",
        lambda supplied: request,
    )
    monkeypatch.setattr(
        executor,
        "claim_collision_probe_execution",
        lambda supplied: lifecycle.append("claimed"),
    )
    monkeypatch.setattr(
        executor,
        "complete_collision_probe_execution",
        lambda supplied: lifecycle.append("completed"),
    )
    monkeypatch.setattr(
        executor,
        "build_collision_probe_result",
        lambda **kwargs: pytest.fail("success result must not be built"),
    )

    blocked = contract.CollisionProbeResult(
        private_evidence={"execution_status": contract.EXECUTION_BLOCKED},
        public_receipt={
            "status": "LIVE_READ_ONLY_PROBE_BLOCKED",
            "classification": contract.UNCERTAIN,
        },
    )

    def build_failure(**kwargs: Any) -> contract.CollisionProbeResult:
        failure_kwargs.update(kwargs)
        return blocked

    monkeypatch.setattr(
        executor, "build_collision_probe_failure_result", build_failure
    )
    monkeypatch.setattr(
        executor,
        "persist_collision_probe_result",
        lambda *, private_root, result, expected_claim_digest: persisted.append(
            result
        ),
    )

    result = executor.execute_preplan_collision_probe(
        provider_factory=provider,  # type: ignore[arg-type]
        execution_capability=capability,  # type: ignore[arg-type]
        private_root=tmp_path,
        now=NOW,
    )

    assert result is blocked
    assert provider.opened == [("authority", 1), ("authority", 2)]
    assert lifecycle == ["bound", "claimed", "completed"]
    assert persisted == [blocked]
    assert len(failure_kwargs["authority_snapshots"]) == 1
    assert failure_kwargs["identity_center_snapshots"] == []
    assert failure_kwargs["blocker_code"] == "PROVIDER_READ_FAILED"
    assert failure_kwargs["sealed_at"] == "2026-08-28T01:10:00Z"


def test_executor_rethrows_sanitized_blocker_if_failure_result_cannot_persist(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    capability = object()
    request = _request()
    provider = _Provider(
        request=request,
        collision=False,
        fail_at=("authority", 1),
    )
    completed = False

    monkeypatch.setattr(
        executor,
        "is_attested_collision_probe_provider",
        lambda supplied, supplied_capability: True,
    )
    monkeypatch.setattr(
        executor,
        "assert_collision_probe_private_root_binding",
        lambda supplied, root: None,
    )
    monkeypatch.setattr(
        executor, "approved_collision_probe_request", lambda supplied: request
    )
    monkeypatch.setattr(
        executor, "claim_collision_probe_execution", lambda supplied: None
    )

    def complete(capability: object) -> None:
        nonlocal completed
        completed = True

    monkeypatch.setattr(executor, "complete_collision_probe_execution", complete)
    monkeypatch.setattr(
        executor,
        "build_collision_probe_failure_result",
        lambda **kwargs: contract.CollisionProbeResult({}, {}),
    )

    def fail_persist(**kwargs: Any) -> None:
        raise RuntimeError("private target unavailable")

    monkeypatch.setattr(executor, "persist_collision_probe_result", fail_persist)

    with pytest.raises(
        contract.CollisionProbeError,
        match="^PROVIDER_READ_FAILED$",
    ):
        executor.execute_preplan_collision_probe(
            provider_factory=provider,  # type: ignore[arg-type]
            execution_capability=capability,  # type: ignore[arg-type]
            private_root=tmp_path,
            now=NOW,
        )

    assert completed is False


def test_pre_execution_provider_failure_is_persisted_as_zero_call_result(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    capability = object()
    request = _request()
    budget = contract.CollisionProbeBudget(request)
    lifecycle: list[str] = []
    persisted: list[contract.CollisionProbeResult] = []
    captured: dict[str, Any] = {}
    blocked = contract.CollisionProbeResult(
        private_evidence={"execution_status": contract.EXECUTION_BLOCKED},
        public_receipt={"status": "LIVE_READ_ONLY_PROBE_BLOCKED"},
    )

    monkeypatch.setattr(
        executor,
        "assert_collision_probe_private_root_binding",
        lambda supplied, root: lifecycle.append("bound"),
    )
    monkeypatch.setattr(
        executor,
        "approved_collision_probe_request",
        lambda supplied: request,
    )
    monkeypatch.setattr(
        executor,
        "claim_collision_probe_execution",
        lambda supplied: lifecycle.append("claimed"),
    )
    monkeypatch.setattr(
        executor,
        "assert_collision_probe_execution_active",
        lambda supplied: lifecycle.append("active"),
    )
    monkeypatch.setattr(
        executor,
        "complete_collision_probe_execution",
        lambda supplied: lifecycle.append("completed"),
    )

    def build_failure(**kwargs: Any) -> contract.CollisionProbeResult:
        captured.update(kwargs)
        return blocked

    monkeypatch.setattr(
        executor, "build_collision_probe_failure_result", build_failure
    )
    monkeypatch.setattr(
        executor,
        "persist_collision_probe_result",
        lambda *, private_root, result, expected_claim_digest: persisted.append(
            result
        ),
    )

    result = executor.persist_pre_execution_collision_probe_failure(
        execution_capability=capability,  # type: ignore[arg-type]
        private_root=tmp_path,
        budget=budget,
        blocker=executor.LiveProviderError("AWS_SDK_RUNTIME_ROOT_INVALID"),
        sealed_at=NOW,
    )

    assert result is blocked
    assert lifecycle == ["bound", "claimed", "active", "completed"]
    assert persisted == [blocked]
    assert captured["authority_snapshots"] == []
    assert captured["identity_center_snapshots"] == []
    assert captured["provider_summary"] == {
        "provider_calls": 0,
        "aws_calls": None,
        "aws_mutations": 0,
        "live_provider_evidence": False,
        "transcript_digest": contract.canonical_digest([]),
    }
    assert captured["transcript_events"] == []
    assert captured["budget_events"] == []
    assert captured["blocker_code"] == "AWS_SDK_RUNTIME_ROOT_INVALID"
