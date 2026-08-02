from __future__ import annotations

import base64
from collections.abc import Iterator, Mapping
from copy import deepcopy
from datetime import UTC, datetime
import io
import json
from pathlib import Path
from typing import Any

from botocore.response import StreamingBody
import pytest

from tooling.platform_authority_lambda_audit_repair_phase_b_pep import (
    broker_topology_signature_digest,
    canonical_digest,
)
from tooling.platform_authority_lambda_audit_repair_phase_b_invoker import (
    CLOSURE_RECEIPT_KEYS,
    EFFECT_RECEIPT_KEYS,
    PROOF_RECEIPT_KEYS,
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
            "broker-topology-evidence-v2-synthetic.json"
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
            "ExecutedVersion": "7",
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
            "ExecutedVersion": "7",
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
        self._content_length = len(value)
        self.offset = 0
        self.closed = False
        self.read_calls = 0

    def tell(self) -> int:
        return self.offset

    def read(self, amount: int) -> bytes:
        self.read_calls += 1
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
        self._content_length = 1
        self.closed = False
        self.read_calls = 0

    def tell(self) -> int:
        return 0

    def read(self, amount: int) -> bytes:
        del amount
        self.read_calls += 1
        raise OSError("synthetic stream failure")

    def close(self) -> None:
        self.closed = True


class TextStream:
    _content_length = 2

    def __init__(self) -> None:
        self.read_calls = 0

    def tell(self) -> int:
        return 0

    def read(self, amount: int) -> str:
        del amount
        self.read_calls += 1
        return "{}"

    def close(self) -> None:
        pass


class ReadOnceStream:
    def __init__(self, value: bytes) -> None:
        self._content_length = len(value)
        self.value = value
        self.read_calls = 0
        self.offset = 0
        self.closed = False

    def tell(self) -> int:
        return self.offset

    def read(self, amount: int) -> bytes:
        self.read_calls += 1
        if self.read_calls > 1:
            raise AssertionError("second read is forbidden")
        result = self.value[:amount]
        self.offset += len(result)
        return result

    def close(self) -> None:
        self.closed = True


class AmbiguousLengthStream:
    def __init__(self, value: bytes) -> None:
        self.value = value
        self.read_calls = 0

    def tell(self) -> int:
        return 0

    def read(self, amount: int) -> bytes:
        self.read_calls += 1
        return self.value[:amount]


class CountingBytesIO(io.BytesIO):
    def __init__(self, value: bytes) -> None:
        super().__init__(value)
        self.read_calls = 0

    def read(self, amount: int = -1) -> bytes:
        self.read_calls += 1
        if self.read_calls > 1:
            raise AssertionError("second raw-stream read is forbidden")
        return super().read(amount)


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
        (
            418,
            {"status": "DENY", "reason_code": "UNKNOWN_STATUS"},
            "PHASE_B_INVOKE_UNCERTAIN",
        ),
        (
            True,
            {"status": "DENY", "reason_code": "BOOLEAN_STATUS"},
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
            "ExecutedVersion": "7",
            "Payload": application_payload(status_code, body),
        }
    )

    with pytest.raises(PhaseBInvokerError, match=expected_code):
        invoke_with(client)

    assert len(client.calls) == 1


@pytest.mark.parametrize(
    "response",
    [
        {"StatusCode": 200, "ExecutedVersion": "7"},
        {"StatusCode": 200, "ExecutedVersion": "7", "Payload": b""},
        {"StatusCode": 200, "ExecutedVersion": "7", "Payload": b"{"},
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


def test_real_streaming_body_is_bounded_and_read_exactly_once() -> None:
    raw = application_payload(200, accepted_body())
    source = CountingBytesIO(raw)
    payload = StreamingBody(source, len(raw))

    assert invoke_with(client_with_payload(payload))["broker_effect"][
        "status"
    ] == "DISPATCH_ACCEPTED"
    assert source.read_calls == 1


def test_stream_second_read_trap_accepts_complete_first_read() -> None:
    stream = ReadOnceStream(application_payload(200, accepted_body()))

    assert invoke_with(client_with_payload(stream))["broker_effect"][
        "status"
    ] == "DISPATCH_ACCEPTED"
    assert stream.read_calls == 1
    assert stream.closed is True


def test_stream_without_trustworthy_length_is_reconcile_only() -> None:
    stream = AmbiguousLengthStream(application_payload(200, accepted_body()))

    assert_uncertain(client_with_payload(stream))
    assert stream.read_calls == 0


@pytest.mark.parametrize(
    "non_finite",
    (float("nan"), float("inf"), float("-inf")),
)
def test_application_payload_rejects_duplicate_keys_and_non_finite_numbers(
    non_finite: float,
) -> None:
    duplicate = application_payload(200, accepted_body()).replace(
        b'"statusCode": 200',
        b'"statusCode": 200, "statusCode": 200',
        1,
    )
    non_finite_body = accepted_body()
    non_finite_body["broker_effect"]["attempts"] = non_finite

    assert_uncertain(client_with_payload(duplicate))
    assert_uncertain(
        client_with_payload(application_payload(200, non_finite_body))
    )


def test_application_payload_rejects_duplicate_header_keys() -> None:
    duplicate = application_payload(200, accepted_body()).replace(
        b'"cache-control": "no-store"',
        b'"cache-control": "no-store", "cache-control": "no-store"',
        1,
    )

    assert_uncertain(client_with_payload(duplicate))


def test_application_payload_rejects_invalid_utf8_trailing_data_and_nested_duplicates() -> None:
    valid = json.loads(application_payload(200, accepted_body()))
    valid["body"] = (
        '{"identity_proof":{},"identity_proof":{},'
        '"broker_effect":{},"closure_pending":{}}'
    )

    assert_uncertain(client_with_payload(b"\xff"))
    assert_uncertain(
        client_with_payload(
            application_payload(200, accepted_body()) + b" trailing"
        )
    )
    assert_uncertain(
        client_with_payload(json.dumps(valid).encode("utf-8"))
    )
    for non_object in (b"[]", b"null", b"true", b"1"):
        assert_uncertain(client_with_payload(non_object))


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
    non_string = {**valid, "body": {}}

    for value in (missing, empty, malformed, non_string):
        assert_uncertain(
            client_with_payload(json.dumps(value).encode("utf-8"))
        )


def test_malformed_broker_denial_is_uncertain_not_sanitized_denial() -> None:
    assert_uncertain(
        client_with_payload(
            application_payload(
                403,
                {
                    "status": "DENY",
                    "reason_code": "REQUEST_AUTHORITY_FORBIDDEN",
                    "raw": "forbidden",
                },
            )
        )
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


@pytest.mark.parametrize(
    "mutation",
    ("missing", "extra", "non_string", "wrong_case"),
)
def test_application_envelope_rejects_every_header_drift(
    mutation: str,
) -> None:
    valid = json.loads(application_payload(200, accepted_body()))
    headers = dict(valid["headers"])
    if mutation == "missing":
        headers.pop("pragma")
    elif mutation == "extra":
        headers["x-extra"] = "forbidden"
    elif mutation == "non_string":
        headers["pragma"] = 1
    else:
        headers["Content-Type"] = headers.pop("content-type")
    valid["headers"] = headers

    assert_uncertain(
        client_with_payload(json.dumps(valid).encode("utf-8"))
    )


def test_application_payload_rejects_oversized_and_non_byte_values() -> None:
    assert_uncertain(
        client_with_payload(b"x" * (MAX_RESPONSE_PAYLOAD_BYTES + 1))
    )
    assert_uncertain(client_with_payload("not-bytes"))
    assert_uncertain(client_with_payload(memoryview(b"{}")))
    assert_uncertain(client_with_payload(TextStream()))


def test_application_payload_rejects_stream_exception_and_short_read() -> None:
    failing = FailingStream()
    partial = ShortReadStream(application_payload(200, accepted_body()))

    assert_uncertain(client_with_payload(failing))
    assert failing.read_calls == 1
    assert failing.closed is True
    assert_uncertain(client_with_payload(partial))
    assert partial.read_calls == 1
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
    "case",
    (
        "proof_digest",
        "effect_digest",
        "closure_digest",
        "provider_evidence",
        "policy",
        "binding",
        "proof_link",
        "closure_link",
        "ledger_link",
        "execution_request_link",
        "uncertain_body",
        "retry_permitted",
        "attempts",
        "gate_not_consumed",
        "production_overclaim",
        "serialized_identity_context",
        "authority_revoked",
    ),
)
def test_application_success_rejects_forged_or_spliced_receipt_sets(
    case: str,
) -> None:
    body = accepted_body()
    proof = body["identity_proof"]
    effect = body["broker_effect"]
    closure = body["closure_pending"]
    assert isinstance(proof, dict)
    assert isinstance(effect, dict)
    assert isinstance(closure, dict)

    if case == "proof_digest":
        proof["receipt_digest"] = OTHER_TOPOLOGY
    elif case == "effect_digest":
        effect["receipt_digest"] = OTHER_TOPOLOGY
    elif case == "closure_digest":
        closure["receipt_digest"] = OTHER_TOPOLOGY
    elif case == "provider_evidence":
        foreign = "sha256:" + ("8" * 64)
        for receipt in (proof, effect, closure):
            receipt["broker_topology_provider_evidence_digest"] = foreign
        redigest(proof)
        redigest(closure)
        effect["proof_receipt_digest"] = proof["receipt_digest"]
        effect["closure_pending_receipt_digest"] = closure["receipt_digest"]
        redigest(effect)
    elif case == "policy":
        proof["broker_policy_sha256"] = "9" * 64
        effect["broker_policy_sha256"] = "9" * 64
        redigest(proof)
        effect["proof_receipt_digest"] = proof["receipt_digest"]
        redigest(effect)
    elif case == "binding":
        effect["binding_digest"] = "sha256:" + ("8" * 64)
        redigest(effect)
    elif case == "proof_link":
        effect["proof_receipt_digest"] = OTHER_TOPOLOGY
        redigest(effect)
    elif case == "closure_link":
        effect["closure_pending_receipt_digest"] = OTHER_TOPOLOGY
        redigest(effect)
    elif case == "ledger_link":
        effect["ledger_digest"] = "sha256:" + ("8" * 64)
        redigest(effect)
    elif case == "execution_request_link":
        effect["execution_request_digest"] = "sha256:" + ("8" * 64)
        redigest(effect)
    elif case == "uncertain_body":
        effect["status"] = "UNCERTAIN_RECONCILE_ONLY"
        effect["execution_ambiguous"] = True
        closure["execution_status"] = "UNCERTAIN_RECONCILE_ONLY"
        redigest(closure)
        effect["closure_pending_receipt_digest"] = closure["receipt_digest"]
        redigest(effect)
    elif case == "retry_permitted":
        effect["retry_permitted"] = True
        redigest(effect)
    elif case == "attempts":
        effect["attempts"] = 2
        redigest(effect)
    elif case == "gate_not_consumed":
        effect["one_shot_execution_gate_consumed"] = False
        redigest(effect)
    elif case == "production_overclaim":
        effect["production_status"] = "GO"
        redigest(effect)
    elif case == "serialized_identity_context":
        proof["identity_context_serialized"] = True
        redigest(proof)
        effect["proof_receipt_digest"] = proof["receipt_digest"]
        redigest(effect)
    else:
        closure["authority_revoked"] = True
        redigest(closure)
        effect["closure_pending_receipt_digest"] = closure["receipt_digest"]
        redigest(effect)

    assert_uncertain(client_with_payload(application_payload(200, body)))


def test_receipts_for_a_foreign_alias_version_cannot_be_spliced() -> None:
    body = accepted_body()
    proof = body["identity_proof"]
    effect = body["broker_effect"]
    closure = body["closure_pending"]
    assert isinstance(proof, dict)
    assert isinstance(effect, dict)
    assert isinstance(closure, dict)
    foreign_evidence = evidence()
    foreign_evidence["broker_alias_function_version"] = "8"
    foreign_digest = broker_topology_signature_digest(foreign_evidence)

    for receipt in (proof, effect, closure):
        receipt["broker_topology_provider_evidence_digest"] = foreign_digest
    redigest(proof)
    redigest(closure)
    effect["proof_receipt_digest"] = proof["receipt_digest"]
    effect["closure_pending_receipt_digest"] = closure["receipt_digest"]
    redigest(effect)

    assert_uncertain(client_with_payload(application_payload(200, body)))


@pytest.mark.parametrize(
    "response",
    [
        [],
        {},
        {"StatusCode": True, "ExecutedVersion": "7", "Payload": b"{}"},
        {"StatusCode": 202, "Payload": application_payload(200, accepted_body())},
        {
            "StatusCode": 200.0,
            "Payload": application_payload(200, accepted_body()),
        },
        {
            "StatusCode": 200,
            "Payload": application_payload(200, accepted_body()),
        },
        {
            "StatusCode": 200,
            "FunctionError": "Unhandled",
            "Payload": application_payload(200, accepted_body()),
        },
        {
            "StatusCode": 200,
            "FunctionError": None,
            "ExecutedVersion": "7",
            "Payload": application_payload(200, accepted_body()),
        },
        {
            "StatusCode": 200,
            "ExecutedVersion": "$LATEST",
            "Payload": application_payload(200, accepted_body()),
        },
    ],
)
def test_outer_transport_failures_remain_uncertain(
    response: object,
) -> None:
    client = LambdaClient()
    client.response = response  # type: ignore[assignment]
    assert_uncertain(client)


def test_outer_transport_tolerates_documented_harmless_metadata() -> None:
    response = {
        "StatusCode": 200,
        "ExecutedVersion": "7",
        "Payload": application_payload(200, accepted_body()),
        "ResponseMetadata": {"RequestId": "synthetic-request"},
    }

    assert invoke_with(LambdaClient(response=response))["broker_effect"][
        "status"
    ] == "DISPATCH_ACCEPTED"


def test_alias_repoint_to_another_numeric_version_fails_closed() -> None:
    response = {
        "StatusCode": 200,
        "ExecutedVersion": "8",
        "Payload": application_payload(200, accepted_body()),
    }

    assert_uncertain(LambdaClient(response=response))


def test_executed_version_mismatch_does_not_read_payload() -> None:
    payload = FailingStream()
    client = LambdaClient(
        response={
            "StatusCode": 200,
            "ExecutedVersion": "8",
            "Payload": payload,
        }
    )

    assert_uncertain(client)
    assert payload.read_calls == 0


@pytest.mark.parametrize(
    ("schema_name", "runtime_keys"),
    (
        (
            "platform-authority-lambda-audit-repair-phase-b-"
            "proof-receipt.v1.schema.json",
            PROOF_RECEIPT_KEYS,
        ),
        (
            "platform-authority-lambda-audit-repair-phase-b-"
            "broker-effect-receipt.v1.schema.json",
            EFFECT_RECEIPT_KEYS,
        ),
        (
            "platform-authority-lambda-audit-repair-phase-b-"
            "closure-pending-receipt.v1.schema.json",
            CLOSURE_RECEIPT_KEYS,
        ),
    ),
)
def test_runtime_receipt_keys_remain_in_exact_schema_parity(
    schema_name: str,
    runtime_keys: frozenset[str],
) -> None:
    schema = json.loads(
        (ROOT / "schemas" / schema_name).read_text(encoding="utf-8")
    )

    assert runtime_keys == frozenset(schema["required"])
    assert runtime_keys == frozenset(schema["properties"])


def test_diagnostics_never_expose_secrets_or_raw_payload() -> None:
    secrets = (
        "synthetic-one-shot-code",
        "v" * 64,
        "state-0123456789-abcdef-XYZ",
        "arn:aws:synthetic:region:000000000000:resource/secret",
        "gug221-b-" + ("f" * 48),
        "synthetic-stack-id",
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


@pytest.mark.parametrize(
    "function_version",
    (
        "",
        "$LATEST",
        "0",
        "01",
        " 7",
        "7 ",
        "+7",
        "-7",
        "7.0",
        7,
        7.0,
        True,
        None,
        [],
        {},
        "9" * 1025,
    ),
)
def test_invoker_rejects_noncanonical_expected_version_before_lambda(
    function_version: object,
) -> None:
    current = evidence()
    current["broker_alias_function_version"] = function_version
    current["receipt_digest"] = broker_topology_signature_digest(current)
    client = LambdaClient()

    with pytest.raises(
        PhaseBInvokerError,
        match="^BROKER_TOPOLOGY_EVIDENCE_INVALID$",
    ):
        invoke_phase_b_broker(
            client=client,
            authorization_code="synthetic-one-shot-code",
            code_verifier="v" * 64,
            oauth_state="state-0123456789-abcdef-XYZ",
            broker_topology_evidence=current,
            execution_id=EXECUTION_ID,
            broker_topology_sha256=str(current["broker_topology_sha256"]),
            now=NOW,
        )

    assert client.calls == []


@pytest.mark.parametrize("case", ("missing", "schema", "expanded"))
def test_invoker_rejects_missing_or_wrong_version_contract_before_lambda(
    case: str,
) -> None:
    current = evidence()
    if case == "missing":
        current.pop("broker_alias_function_version")
    elif case == "schema":
        current["schema_version"] = "3"
    else:
        current["version_authority"] = "caller"
    current["receipt_digest"] = broker_topology_signature_digest(current)
    client = LambdaClient()

    with pytest.raises(
        PhaseBInvokerError,
        match="^BROKER_TOPOLOGY_EVIDENCE_INVALID$",
    ):
        invoke_phase_b_broker(
            client=client,
            authorization_code="synthetic-one-shot-code",
            code_verifier="v" * 64,
            oauth_state="state-0123456789-abcdef-XYZ",
            broker_topology_evidence=current,
            execution_id=EXECUTION_ID,
            broker_topology_sha256=str(current["broker_topology_sha256"]),
            now=NOW,
        )

    assert client.calls == []


@pytest.mark.parametrize("duplicate", (False, True))
def test_invoker_rejects_sequence_conversion_before_lambda(
    duplicate: bool,
) -> None:
    current = evidence()
    sequence: object = list(current.items())
    if duplicate:
        assert isinstance(sequence, list)
        sequence.append(("broker_alias_function_version", "8"))
    client = LambdaClient()

    with pytest.raises(
        PhaseBInvokerError,
        match="^BROKER_TOPOLOGY_EVIDENCE_INVALID$",
    ):
        invoke_phase_b_broker(
            client=client,
            authorization_code="synthetic-one-shot-code",
            code_verifier="v" * 64,
            oauth_state="state-0123456789-abcdef-XYZ",
            broker_topology_evidence=sequence,  # type: ignore[arg-type]
            execution_id=EXECUTION_ID,
            broker_topology_sha256=str(current["broker_topology_sha256"]),
            now=NOW,
        )

    assert client.calls == []


def test_invoker_sanitizes_mapping_snapshot_failure_before_lambda() -> None:
    current = evidence()

    class ExplodingMapping(Mapping[str, Any]):
        def __getitem__(self, key: str) -> Any:
            del key
            raise RuntimeError("synthetic-sensitive-provider-value")

        def __iter__(self) -> Iterator[str]:
            raise RuntimeError("synthetic-sensitive-provider-value")

        def __len__(self) -> int:
            return len(current)

    client = LambdaClient()
    with pytest.raises(PhaseBInvokerError) as caught:
        invoke_phase_b_broker(
            client=client,
            authorization_code="synthetic-one-shot-code",
            code_verifier="v" * 64,
            oauth_state="state-0123456789-abcdef-XYZ",
            broker_topology_evidence=ExplodingMapping(),
            execution_id=EXECUTION_ID,
            broker_topology_sha256=str(current["broker_topology_sha256"]),
            now=NOW,
        )

    assert str(caught.value) == "BROKER_TOPOLOGY_EVIDENCE_INVALID"
    assert "synthetic-sensitive-provider-value" not in str(caught.value)
    assert client.calls == []


def test_invoker_rejects_v1_topology_evidence_before_lambda() -> None:
    current = json.loads(
        (
            ROOT
            / "fixtures/valid/"
            "platform-authority-lambda-audit-repair-phase-b-"
            "broker-topology-evidence-v1-synthetic.json"
        ).read_text(encoding="utf-8")
    )
    client = LambdaClient()

    with pytest.raises(
        PhaseBInvokerError,
        match="^BROKER_TOPOLOGY_EVIDENCE_INVALID$",
    ):
        invoke_phase_b_broker(
            client=client,
            authorization_code="synthetic-one-shot-code",
            code_verifier="v" * 64,
            oauth_state="state-0123456789-abcdef-XYZ",
            broker_topology_evidence=current,
            execution_id=EXECUTION_ID,
            broker_topology_sha256=str(current["broker_topology_sha256"]),
            now=NOW,
        )

    assert client.calls == []


def test_invoker_snapshots_expected_version_before_dispatch() -> None:
    current = evidence()

    class MutatingClient(LambdaClient):
        def invoke(self, **kwargs: Any) -> dict[str, Any]:
            self.calls.append(kwargs)
            current["broker_alias_function_version"] = "8"
            current["receipt_digest"] = broker_topology_signature_digest(current)
            return {
                "StatusCode": 200,
                "ExecutedVersion": "8",
                "Payload": application_payload(200, accepted_body()),
            }

    client = MutatingClient()
    with pytest.raises(
        PhaseBInvokerError,
        match="^PHASE_B_INVOKE_UNCERTAIN$",
    ):
        invoke_phase_b_broker(
            client=client,
            authorization_code="synthetic-one-shot-code",
            code_verifier="v" * 64,
            oauth_state="state-0123456789-abcdef-XYZ",
            broker_topology_evidence=current,
            execution_id=EXECUTION_ID,
            broker_topology_sha256=str(current["broker_topology_sha256"]),
            now=NOW,
        )

    assert len(client.calls) == 1


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
