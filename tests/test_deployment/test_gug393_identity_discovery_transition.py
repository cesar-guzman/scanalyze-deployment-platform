"""Offline transition tests for the GUG-393 Identity Center preflight."""

from __future__ import annotations

import copy
from datetime import timedelta
import os
from pathlib import Path
from typing import Any, Mapping

import pytest

from tests.test_deployment import (
    test_gug376_identity_center_inventory_collector as identity_data,
)
from tooling.platform_authority_gug365_upstream_inventory import canonical_digest
from tooling.platform_authority_gug376_authority_inventory_collector import (
    read_private_json,
)
from tooling.platform_authority_gug376_identity_center_inventory_collector import (
    capture_live_discovery,
    plan_binding,
)
from tooling.platform_authority_gug393_private_input_discovery import (
    exact_probe_identity_plan,
)


def _root(tmp_path: Path) -> Path:
    root = tmp_path / "private"
    root.mkdir(mode=0o700)
    root.chmod(0o700)
    return root


def _provisional_plan() -> dict[str, Any]:
    plan = copy.deepcopy(identity_data._live_plan())  # noqa: SLF001
    pending = canonical_digest(
        {"issue": "GUG-393", "state": "FRESH_DISCOVERY_REQUIRED"}
    )
    plan["expected_exact_policy_digest"] = pending
    plan["expected_target_digest"] = pending
    plan["expected_facts_digest"] = pending
    return plan


@pytest.fixture(autouse=True)
def _closed_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    for key in tuple(os.environ):
        if key.startswith("AWS_") or key in {
            "BOTO_CONFIG",
            "REQUESTS_CA_BUNDLE",
            "SSL_CERT_FILE",
            "SSL_CERT_DIR",
        }:
            monkeypatch.delenv(key)


def test_exact_discovery_transitions_to_a_target_bound_plan_and_two_sessions(
    tmp_path: Path,
) -> None:
    plan = _provisional_plan()
    factory = identity_data.Factory(seed="1", mode="ok")
    root = _root(tmp_path)
    attestations: list[object] = []

    def exact_materializer(
        supplied_plan: Mapping[str, Any],
        targets: Mapping[str, Any],
        transition_attestation: object,
    ) -> Mapping[str, Any]:
        attestations.append(transition_attestation)
        return exact_probe_identity_plan(supplied_plan, targets)

    receipt = capture_live_discovery(
        plan,
        factory,
        private_root=root,
        artifact_name="exact.json",
        now=identity_data.START + timedelta(seconds=30),
        validation_clock=lambda: identity_data.START + timedelta(minutes=5),
        exact_plan_materializer=exact_materializer,
    )

    expected_plan = exact_probe_identity_plan(plan, identity_data.TARGETS)
    snapshot = read_private_json(root, "exact.json")
    assert snapshot["plan_binding_digest"] == plan_binding(expected_plan)[1]
    assert snapshot["target_digest"] == canonical_digest(identity_data.TARGETS)
    assert set(snapshot["policies"]) == {"discovery", "exact"}
    assert len(snapshot["identities"]) == len(snapshot["session_digests"]) == 2
    assert len(set(snapshot["session_digests"])) == 2
    assert len(attestations) == 1
    assert [event for event in factory.events if event.startswith("open_sts:")] == [
        "open_sts:discovery",
        "open_sts:exact",
    ]
    assert [event for event in factory.events if event.startswith("sts:")] == [
        "sts:discovery",
        "sts:exact",
    ]
    assert factory.events.index("sts:discovery") < factory.events.index(
        "open_discovery"
    )
    assert factory.events.index("sts:exact") < factory.events.index("open_exact")
    assert receipt["aws_calls"] == receipt["aws_mutations"] == 0
    assert snapshot["aws_mutations"] == 0


def test_absent_discovery_keeps_the_provisional_plan_and_one_session(
    tmp_path: Path,
) -> None:
    plan = _provisional_plan()
    factory = identity_data.Factory(seed="1", mode="live_absent")
    root = _root(tmp_path)
    materializer_calls: list[
        tuple[Mapping[str, Any], Mapping[str, Any], object]
    ] = []

    def exact_materializer(
        supplied_plan: Mapping[str, Any],
        targets: Mapping[str, Any],
        transition_attestation: object,
    ) -> Mapping[str, Any]:
        materializer_calls.append(
            (supplied_plan, targets, transition_attestation)
        )
        return exact_probe_identity_plan(supplied_plan, targets)

    receipt = capture_live_discovery(
        plan,
        factory,
        private_root=root,
        artifact_name="absent.json",
        now=identity_data.START + timedelta(seconds=30),
        validation_clock=lambda: identity_data.START + timedelta(minutes=5),
        exact_plan_materializer=exact_materializer,
    )

    snapshot = read_private_json(root, "absent.json")
    assert materializer_calls == []
    assert snapshot["classification"] == "ABSENT_READY"
    assert snapshot["plan_binding_digest"] == plan_binding(plan)[1]
    assert set(snapshot["policies"]) == {"discovery"}
    assert snapshot["targets"] == {}
    assert len(snapshot["identities"]) == len(snapshot["session_digests"]) == 1
    assert [event for event in factory.events if event.startswith("open_sts:")] == [
        "open_sts:discovery"
    ]
    assert [event for event in factory.events if event.startswith("sts:")] == [
        "sts:discovery"
    ]
    assert receipt["aws_calls"] == receipt["aws_mutations"] == 0
    assert snapshot["aws_mutations"] == 0
