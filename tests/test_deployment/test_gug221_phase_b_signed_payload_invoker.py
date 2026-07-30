from __future__ import annotations

import base64
from datetime import UTC, datetime
import json
from pathlib import Path
from typing import Any

import pytest

from tooling.platform_authority_lambda_audit_repair_phase_b_invoker import (
    PhaseBInvokerError,
    invoke_phase_b_broker,
)


ROOT = Path(__file__).resolve().parents[2]
NOW = datetime(2030, 1, 1, 0, 0, tzinfo=UTC)
EXECUTION_ID = "gug221-phase-b-" + ("a" * 64)


def evidence() -> dict[str, Any]:
    return json.loads(
        (
            ROOT
            / "fixtures/valid/"
            "platform-authority-lambda-audit-repair-phase-b-"
            "broker-topology-evidence-v1-synthetic.json"
        ).read_text(encoding="utf-8")
    )


class LambdaClient:
    def __init__(self, *, fail: bool = False) -> None:
        self.fail = fail
        self.calls: list[dict[str, Any]] = []

    def invoke(self, **kwargs: Any) -> dict[str, Any]:
        self.calls.append(kwargs)
        if self.fail:
            raise RuntimeError("ambiguous")
        return {"StatusCode": 200, "ExecutedVersion": "1", "Payload": b"{}"}


def test_invoker_delivers_fresh_signed_evidence_in_exact_synchronous_payload() -> None:
    current = evidence()
    topology = str(current["broker_topology_sha256"])
    client = LambdaClient()
    response = invoke_phase_b_broker(
        client=client,
        authorization_code="synthetic-one-shot-code",
        code_verifier="v" * 64,
        oauth_state="state-0123456789-abcdef-XYZ",
        broker_topology_evidence=current,
        execution_id=EXECUTION_ID,
        broker_topology_sha256=topology,
        now=NOW,
    )
    assert response["StatusCode"] == 200
    assert len(client.calls) == 1
    request = client.calls[0]
    assert request["FunctionName"] == (
        "scanalyze-platform-authority-gug221-phase-b-broker"
    )
    assert request["Qualifier"] == "broker-v1"
    assert request["InvocationType"] == "RequestResponse"
    payload = json.loads(request["Payload"])
    assert set(payload) == {
        "schema_version",
        "record_type",
        "authorization_code",
        "code_verifier",
        "oauth_state",
        "broker_topology_evidence",
    }
    assert payload["broker_topology_evidence"] == current
    context = json.loads(base64.b64decode(request["ClientContext"]))
    assert context == {
        "custom": {
            "transport": "REQUEST_RESPONSE",
            "execution_id": EXECUTION_ID,
            "broker_topology_sha256": topology,
        }
    }


@pytest.mark.parametrize(
    "mutation",
    [
        {"broker_topology_sha256": "sha256:" + ("9" * 64)},
        {"collected_at": "2029-12-31T23:50:00Z"},
        {"foreign": True},
    ],
)
def test_invoker_rejects_unbound_stale_or_expanded_evidence_before_lambda(
    mutation: dict[str, Any],
) -> None:
    current = {**evidence(), **mutation}
    client = LambdaClient()
    with pytest.raises(PhaseBInvokerError):
        invoke_phase_b_broker(
            client=client,
            authorization_code="synthetic-one-shot-code",
            code_verifier="v" * 64,
            oauth_state="state-0123456789-abcdef-XYZ",
            broker_topology_evidence=current,
            execution_id=EXECUTION_ID,
            broker_topology_sha256=str(
                evidence()["broker_topology_sha256"]
            ),
            now=NOW,
        )
    assert client.calls == []


def test_invoker_calls_lambda_once_and_marks_ambiguous_response_terminal() -> None:
    current = evidence()
    client = LambdaClient(fail=True)
    with pytest.raises(PhaseBInvokerError, match="PHASE_B_INVOKE_UNCERTAIN"):
        invoke_phase_b_broker(
            client=client,
            authorization_code="synthetic-one-shot-code",
            code_verifier="v" * 64,
            oauth_state="state-0123456789-abcdef-XYZ",
            broker_topology_evidence=current,
            execution_id=EXECUTION_ID,
            broker_topology_sha256=str(
                current["broker_topology_sha256"]
            ),
            now=NOW,
        )
    assert len(client.calls) == 1
