from __future__ import annotations

import base64
from datetime import UTC, datetime
import io
import json
from pathlib import Path
from typing import Any

import pytest

from tooling.platform_authority_lambda_audit_repair_phase_b_pep import (
    canonical_digest,
)
from tooling.platform_authority_lambda_audit_repair_phase_b_invoker import (
    PhaseBInvokerError,
    invoke_phase_b_broker,
)


ROOT = Path(__file__).resolve().parents[2]
NOW = datetime(2030, 1, 1, 0, 0, tzinfo=UTC)
EXECUTION_ID = "gug221-phase-b-" + ("a" * 64)
OTHER_EXECUTION_ID = "gug221-phase-b-" + ("b" * 64)
OTHER_TOPOLOGY = "sha256:" + ("9" * 64)
MAX_RESPONSE_PAYLOAD_BYTES = 64 * 1024


def evidence() -> dict[str, Any]:
    return json.loads(
        (
            ROOT
            / "fixtures/valid/"
            "platform-authority-lambda-audit-repair-phase-b-"
            "broker-topology-evidence-v1-synthetic.json"
        ).read_text(encoding="utf-8")
    )


def receipt_fixture(name: str) -> dict[str, Any]:
    return json.loads(
        (
            ROOT
            / "fixtures/valid"
            / (
                "platform-authority-lambda-audit-repair-phase-b-"
                f"{name}-v1-synthetic.json"
            )
        ).read_text(encoding="utf-8")
    )


def redigest(value: dict[str, Any]) -> None:
    unsigned = dict(value)
    unsigned.pop("receipt_digest", None)
    value["receipt_digest"] = canonical_digest(unsigned)


def accepted_body() -> dict[str, Any]:
    topology = evidence()
    proof = receipt_fixture("proof-receipt")
    effect = receipt_fixture("broker-effect-receipt")
    closure = receipt_fixture("closure-pending-receipt")
    binding_digest = "sha256:" + ("1" * 64)
    ledger_digest = "sha256:" + ("2" * 64)
    execution_request_digest = "sha256:" + ("3" * 64)
    topology_digest = str(topology["broker_topology_sha256"])
    provider_digest = str(topology["receipt_digest"])
    policy_fields = (
        "invoker_policy_sha256",
        "broker_policy_sha256",
        "proof_policy_sha256",
        "application_actor_policy_sha256",
    )

    proof.update(
        {
            "binding_digest": binding_digest,
            "execution_request_digest": execution_request_digest,
            "broker_topology_sha256": topology_digest,
            "broker_topology_provider_evidence_digest": provider_digest,
        }
    )
    closure.update(
        {
            "execution_id": EXECUTION_ID,
            "binding_digest": binding_digest,
            "ledger_digest": ledger_digest,
            "broker_topology_sha256": topology_digest,
            "broker_topology_provider_evidence_digest": provider_digest,
            "execution_status": "DISPATCH_ACCEPTED",
        }
    )
    for field_name in policy_fields:
        proof[field_name] = topology[field_name]
        effect[field_name] = topology[field_name]
    redigest(proof)
    redigest(closure)

    effect.update(
        {
            "status": "DISPATCH_ACCEPTED",
            "execution_id": EXECUTION_ID,
            "binding_digest": binding_digest,
            "proof_receipt_digest": proof["receipt_digest"],
            "ledger_digest": ledger_digest,
            "closure_pending_receipt_digest": closure["receipt_digest"],
            "execution_request_digest": execution_request_digest,
            "broker_topology_sha256": topology_digest,
            "broker_topology_provider_evidence_digest": provider_digest,
            "execution_ambiguous": False,
        }
    )
    redigest(effect)
    return {
        "identity_proof": proof,
        "broker_effect": effect,
        "closure_pending": closure,
    }


class LambdaClient:
    def __init__(
        self,
        *,
        fail: bool = False,
        response: dict[str, Any] | None = None,
    ) -> None:
        self.fail = fail
        self.response = response
        self.calls: list[dict[str, Any]] = []

    def invoke(self, **kwargs: Any) -> dict[str, Any]:
        self.calls.append(kwargs)
        if self.fail:
            raise RuntimeError("ambiguous")
        if self.response is not None:
            return self.response
        return {
            "StatusCode": 200,
            "ExecutedVersion": "1",
            "Payload": application_payload(200, accepted_body()),
        }


def application_payload(
    status_code: int,
    body: object,
    *,
    is_base64_encoded: bool = False,
) -> bytes:
    return json.dumps(
        {
            "statusCode": status_code,
            "headers": {
                "cache-control": "no-store",
                "content-type": "application/json",
                "pragma": "no-cache",
                "x-content-type-options": "nosniff",
            },
            "isBase64Encoded": is_base64_encoded,
            "body": json.dumps(body),
        }
    ).encode("utf-8")


def invoke_with(client: LambdaClient) -> dict[str, Any]:
    current = evidence()
    return dict(
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
    )


def client_with_payload(payload: object) -> LambdaClient:
    return LambdaClient(
        response={
            "StatusCode": 200,
            "ExecutedVersion": "1",
            "Payload": payload,
        }
    )


def assert_uncertain(client: LambdaClient) -> None:
    with pytest.raises(
        PhaseBInvokerError,
        match="^PHASE_B_INVOKE_UNCERTAIN$",
    ):
        invoke_with(client)
    assert len(client.calls) == 1


class ShortReadStream:
    def __init__(self, value: bytes) -> None:
        self.value = value
        self.offset = 0
        self.closed = False

    def tell(self) -> int:
        return self.offset

    def read(self, amount: int) -> bytes:
        if self.offset == 0:
            amount = max(1, len(self.value) // 2)
        result = self.value[self.offset : self.offset + amount]
        self.offset += len(result)
        return result

    def close(self) -> None:
        self.closed = True


class DeclaredLengthStream(io.BytesIO):
    def __init__(self, value: bytes, *, content_length: int) -> None:
        super().__init__(value)
        self.content_length = content_length


class FailingStream:
    def __init__(self) -> None:
        self.closed = False

    def tell(self) -> int:
        return 0

    def read(self, amount: int) -> bytes:
        del amount
        raise OSError("synthetic stream failure")

    def close(self) -> None:
        self.closed = True


class TextStream:
    def tell(self) -> int:
        return 0

    def read(self, amount: int) -> str:
        del amount
        return "{}"

    def close(self) -> None:
        pass


@pytest.mark.parametrize(
    ("status_code", "body", "expected_code"),
    [
        (
            202,
            {"status": "UNCERTAIN_RECONCILE_ONLY"},
            "PHASE_B_INVOKE_UNCERTAIN",
        ),
        (
            403,
            {"status": "DENY", "reason_code": "REQUEST_AUTHORITY_FORBIDDEN"},
            "PHASE_B_BROKER_DENIED",
        ),
        (
            500,
            {"status": "DENY", "reason_code": "PHASE_B_PEP_INTERNAL_ERROR"},
            "PHASE_B_INVOKE_UNCERTAIN",
        ),
    ],
)
def test_outer_success_never_promotes_non_200_broker_application_status(
    status_code: int,
    body: dict[str, Any],
    expected_code: str,
) -> None:
    client = LambdaClient(
        response={
            "StatusCode": 200,
            "ExecutedVersion": "1",
            "Payload": application_payload(status_code, body),
        }
    )

    with pytest.raises(PhaseBInvokerError, match=expected_code):
        invoke_with(client)

    assert len(client.calls) == 1


@pytest.mark.parametrize(
    "response",
    [
        {"StatusCode": 200, "ExecutedVersion": "1"},
        {"StatusCode": 200, "ExecutedVersion": "1", "Payload": b""},
        {"StatusCode": 200, "ExecutedVersion": "1", "Payload": b"{"},
    ],
)
def test_outer_success_rejects_missing_empty_or_malformed_application_payload(
    response: dict[str, Any],
) -> None:
    client = LambdaClient(response=response)

    with pytest.raises(
        PhaseBInvokerError,
        match="PHASE_B_INVOKE_UNCERTAIN",
    ):
        invoke_with(client)

    assert len(client.calls) == 1


def test_exact_application_success_accepts_bytes_and_streaming_body_shapes() -> None:
    raw = application_payload(200, accepted_body())
    mutable = bytearray(raw)

    assert invoke_with(client_with_payload(raw))["broker_effect"]["status"] == (
        "DISPATCH_ACCEPTED"
    )
    assert invoke_with(client_with_payload(mutable))["broker_effect"][
        "status"
    ] == "DISPATCH_ACCEPTED"
    assert mutable and set(mutable) == {0}
    assert invoke_with(client_with_payload(io.BytesIO(raw)))[
        "broker_effect"
    ]["status"] == "DISPATCH_ACCEPTED"


def test_application_payload_rejects_duplicate_keys_and_non_finite_numbers() -> None:
    duplicate = application_payload(200, accepted_body()).replace(
        b'"statusCode": 200',
        b'"statusCode": 200, "statusCode": 200',
        1,
    )
    non_finite_body = accepted_body()
    non_finite_body["broker_effect"]["attempts"] = float("nan")

    assert_uncertain(client_with_payload(duplicate))
    assert_uncertain(
        client_with_payload(application_payload(200, non_finite_body))
    )


@pytest.mark.parametrize(
    "body",
    [
        [],
        {},
        {"identity_proof": {}, "broker_effect": {}, "closure_pending": {}, "x": 1},
    ],
)
def test_application_body_requires_one_exact_top_level_object(
    body: object,
) -> None:
    assert_uncertain(client_with_payload(application_payload(200, body)))


def test_application_envelope_rejects_missing_empty_or_malformed_body() -> None:
    valid = json.loads(application_payload(200, accepted_body()))
    missing = dict(valid)
    missing.pop("body")
    empty = {**valid, "body": ""}
    malformed = {**valid, "body": "{"}

    for value in (missing, empty, malformed):
        assert_uncertain(
            client_with_payload(json.dumps(value).encode("utf-8"))
        )


def test_application_envelope_rejects_oversized_body() -> None:
    value = json.loads(application_payload(200, accepted_body()))
    value["body"] = "x" * (48 * 1024 + 1)

    assert_uncertain(
        client_with_payload(json.dumps(value).encode("utf-8"))
    )


def test_application_envelope_requires_exact_keys_headers_and_plain_json() -> None:
    valid = json.loads(application_payload(200, accepted_body()))
    extra = {**valid, "foreign": True}
    wrong_headers = {
        **valid,
        "headers": {"content-type": "application/json"},
    }

    assert_uncertain(
        client_with_payload(json.dumps(extra).encode("utf-8"))
    )
    assert_uncertain(
        client_with_payload(json.dumps(wrong_headers).encode("utf-8"))
    )
    assert_uncertain(
        client_with_payload(
            application_payload(
                200,
                accepted_body(),
                is_base64_encoded=True,
            )
        )
    )


def test_application_payload_rejects_oversized_and_non_byte_values() -> None:
    assert_uncertain(
        client_with_payload(b"x" * (MAX_RESPONSE_PAYLOAD_BYTES + 1))
    )
    assert_uncertain(client_with_payload("not-bytes"))
    assert_uncertain(client_with_payload(TextStream()))


def test_application_payload_rejects_stream_exception_and_short_read() -> None:
    failing = FailingStream()
    partial = ShortReadStream(application_payload(200, accepted_body()))

    assert_uncertain(client_with_payload(failing))
    assert failing.closed is True
    assert_uncertain(client_with_payload(partial))
    assert partial.closed is True


def test_application_payload_rejects_truncated_and_repeated_streams() -> None:
    raw = application_payload(200, accepted_body())
    truncated = DeclaredLengthStream(raw, content_length=len(raw) + 1)
    repeated = io.BytesIO(raw)
    assert repeated.read(1) == b"{"

    assert_uncertain(client_with_payload(truncated))
    assert_uncertain(client_with_payload(repeated))


def test_application_success_binds_expected_execution_id() -> None:
    body = accepted_body()
    effect = body["broker_effect"]
    assert isinstance(effect, dict)
    effect["execution_id"] = OTHER_EXECUTION_ID
    redigest(effect)

    assert_uncertain(client_with_payload(application_payload(200, body)))


def test_application_success_binds_expected_topology_digest() -> None:
    body = accepted_body()
    proof = body["identity_proof"]
    effect = body["broker_effect"]
    closure = body["closure_pending"]
    assert isinstance(proof, dict)
    assert isinstance(effect, dict)
    assert isinstance(closure, dict)
    for receipt in (proof, effect, closure):
        receipt["broker_topology_sha256"] = OTHER_TOPOLOGY
    redigest(proof)
    redigest(closure)
    effect["proof_receipt_digest"] = proof["receipt_digest"]
    effect["closure_pending_receipt_digest"] = closure["receipt_digest"]
    redigest(effect)

    assert_uncertain(client_with_payload(application_payload(200, body)))


def test_application_success_rejects_malformed_receipt_binding() -> None:
    body = accepted_body()
    effect = body["broker_effect"]
    assert isinstance(effect, dict)
    effect["proof_receipt_digest"] = "sha256:" + ("0" * 64)
    redigest(effect)

    assert_uncertain(client_with_payload(application_payload(200, body)))


@pytest.mark.parametrize(
    "response",
    [
        {"StatusCode": 202, "Payload": application_payload(200, accepted_body())},
        {
            "StatusCode": 200.0,
            "Payload": application_payload(200, accepted_body()),
        },
        {
            "StatusCode": 200,
            "FunctionError": "Unhandled",
            "Payload": application_payload(200, accepted_body()),
        },
    ],
)
def test_outer_transport_failures_remain_uncertain(
    response: dict[str, Any],
) -> None:
    assert_uncertain(LambdaClient(response=response))


def test_diagnostics_never_expose_secrets_or_raw_payload() -> None:
    secrets = (
        "synthetic-one-shot-code",
        "v" * 64,
        "state-0123456789-abcdef-XYZ",
    )
    raw = (
        b'{"statusCode":200,"headers":{},"isBase64Encoded":false,"body":"'
        + "|".join(secrets).encode("utf-8")
        + b'"}'
    )
    client = client_with_payload(raw)

    with pytest.raises(PhaseBInvokerError) as caught:
        invoke_with(client)

    assert str(caught.value) == "PHASE_B_INVOKE_UNCERTAIN"
    assert all(secret not in str(caught.value) for secret in secrets)
    assert len(client.calls) == 1


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
    assert set(response) == {
        "identity_proof",
        "broker_effect",
        "closure_pending",
    }
    assert response["broker_effect"]["status"] == "DISPATCH_ACCEPTED"
    assert response["broker_effect"]["execution_id"] == EXECUTION_ID
    assert response["broker_effect"]["broker_topology_sha256"] == topology
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
