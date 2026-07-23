from __future__ import annotations

import base64
from dataclasses import replace
from datetime import UTC, datetime, timedelta
import json
from pathlib import Path
import sys
from typing import Any, Mapping

from jsonschema import Draft202012Validator
import pytest
import yaml


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from tooling.platform_authority_lambda_audit_repair_phase_b_pep import (  # noqa: E402
    BROKER_ROLE_NAME,
    FUNCTION_ALIAS,
    FUNCTION_NAME,
    OneShotExecutionLedger,
    PhaseBBrokerEffectReceipt,
    PhaseBClosurePendingReceipt,
    PhaseBExecutionBroker,
    PhaseBIdentityBinding,
    PhaseBIdentityProofVerifier,
    PhaseBPep,
    PhaseBPepError,
    BROKER_TOPOLOGY_SIGNATURE_ALGORITHM,
    broker_topology_signature_digest,
    calculate_broker_topology_sha256,
    canonical_digest,
    validate_broker_topology_evidence,
)
from tooling import (  # noqa: E402
    platform_authority_lambda_audit_repair_phase_b_runtime as phase_b_runtime,
)
from tooling import (  # noqa: E402
    platform_authority_lambda_audit_repair_phase_b_topology as topology_collector,
)


NOW = datetime(2030, 1, 1, 0, 5, tzinfo=UTC)
STACK_ARN = (
    "arn:aws:cloudformation:us-east-1:042360977644:stack/"
    "scanalyze-platform-authority-lambda-audit-repair-pep/"
    "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
)
CHANGE_SET_ARN = (
    "arn:aws:cloudformation:us-east-1:042360977644:changeSet/"
    "gug221-lambda-audit-repair-pep-create/"
    "11111111-2222-4333-8444-555555555555"
)
CLIENT_TOKEN = "gug221-b-" + ("a" * 48)
POLICY_DIGESTS = {
    "invoker_policy_sha256": "a" * 64,
    "broker_policy_sha256": "b" * 64,
    "proof_policy_sha256": "c" * 64,
    "application_actor_policy_sha256": "d" * 64,
}
PROVIDER_EVIDENCE_DIGEST = "sha256:" + ("e" * 64)
TOPOLOGY_SIGNING_KEY_ARN = (
    "arn:aws:kms:us-east-1:042360977644:key/"
    "12345678-1234-4234-8234-123456789abc"
)
TOPOLOGY_SIGNATURE = base64.b64encode(b"x" * 64).decode("ascii")
OAUTH_STATE = "state-0123456789-abcdef-XYZ"
PKCE_VERIFIER = "synthetic-pkce-verifier-" + ("a" * 43)


def _execution_request_digest() -> str:
    return canonical_digest(
        {
            "ChangeSetName": CHANGE_SET_ARN,
            "StackName": STACK_ARN,
            "ClientRequestToken": CLIENT_TOKEN,
        }
    )


def _execution_id() -> str:
    digest = canonical_digest(
        {
            "phase": "B_PEP_EXECUTION",
            "execution_request_digest": _execution_request_digest(),
            "not_before": "2030-01-01T00:00:00Z",
            "not_after": "2030-01-01T00:15:00Z",
        }
    ).removeprefix("sha256:")
    return "gug221-phase-b-" + digest


def _topology_inputs() -> dict[str, str]:
    return {
        "authority_account_id": "042360977644",
        "management_account_id": "839393571433",
        "region": "us-east-1",
        "identity_center_application_arn": (
            "arn:aws:sso::839393571433:application/"
            "ssoins-1234567890abcdef/apl-1234567890abcdef"
        ),
        "identity_center_instance_arn": (
            "arn:aws:sso:::instance/ssoins-1234567890abcdef"
        ),
        "identity_store_arn": (
            "arn:aws:identitystore::839393571433:"
            "identitystore/d-1234567890"
        ),
        "operator_user_id_digest": canonical_digest(
            {
                "identity_store_user_id": (
                    "11111111-2222-4333-8444-555555555555"
                )
            }
        ),
        "invoker_role_arn": (
            "arn:aws:iam::042360977644:role/aws-reserved/"
            "sso.amazonaws.com/AWSReservedSSO_"
            "ScanalyzeGug221PhaseBInvoker_0123456789abcdef"
        ),
        "broker_execution_role_arn": (
            "arn:aws:iam::042360977644:role/"
            "ScanalyzeGug221PhaseBBrokerExecution"
        ),
        "proof_role_arn": (
            "arn:aws:iam::042360977644:role/ScanalyzeGug221PhaseBProof"
        ),
        "ledger_table_arn": (
            "arn:aws:dynamodb:us-east-1:042360977644:table/"
            "scanalyze-platform-authority-gug221-phase-b-execution-ledger"
        ),
        "broker_alias_arn": (
            "arn:aws:lambda:us-east-1:042360977644:function:"
            f"{FUNCTION_NAME}:{FUNCTION_ALIAS}"
        ),
        "broker_artifact_bucket": "scanalyze-synthetic-artifacts",
        "broker_artifact_key": "gug221/broker.zip",
        "broker_artifact_version": "version-1",
        "broker_artifact_code_sha256": "A" * 43 + "=",
        "broker_code_signing_config_arn": (
            "arn:aws:lambda:us-east-1:042360977644:"
            "code-signing-config:csc-1234567890abcdef0"
        ),
        **POLICY_DIGESTS,
        "topology_signing_key_arn": TOPOLOGY_SIGNING_KEY_ARN,
        "topology_signature_algorithm": BROKER_TOPOLOGY_SIGNATURE_ALGORITHM,
    }


def binding(
    provider_evidence_digest: str = PROVIDER_EVIDENCE_DIGEST,
) -> PhaseBIdentityBinding:
    topology = calculate_broker_topology_sha256(_topology_inputs())
    return PhaseBIdentityBinding(
        authority_account_id="042360977644",
        management_account_id="839393571433",
        region="us-east-1",
        identity_center_application_arn=(
            "arn:aws:sso::839393571433:application/"
            "ssoins-1234567890abcdef/apl-1234567890abcdef"
        ),
        identity_center_instance_arn=(
            "arn:aws:sso:::instance/ssoins-1234567890abcdef"
        ),
        identity_store_arn=(
            "arn:aws:identitystore::839393571433:"
            "identitystore/d-1234567890"
        ),
        redirect_uri="http://127.0.0.1:43119/callback",
        operator_user_id="11111111-2222-4333-8444-555555555555",
        invoker_role_arn=(
            "arn:aws:iam::042360977644:role/aws-reserved/"
            "sso.amazonaws.com/AWSReservedSSO_"
            "ScanalyzeGug221PhaseBInvoker_0123456789abcdef"
        ),
        broker_execution_role_arn=(
            "arn:aws:iam::042360977644:role/"
            "ScanalyzeGug221PhaseBBrokerExecution"
        ),
        proof_role_arn=(
            "arn:aws:iam::042360977644:role/ScanalyzeGug221PhaseBProof"
        ),
        ledger_table_arn=(
            "arn:aws:dynamodb:us-east-1:042360977644:table/"
            "scanalyze-platform-authority-gug221-phase-b-execution-ledger"
        ),
        stack_arn=STACK_ARN,
        change_set_arn=CHANGE_SET_ARN,
        client_request_token=CLIENT_TOKEN,
        phase_b_intent_digest="sha256:" + ("1" * 64),
        change_set_receipt_digest="sha256:" + ("2" * 64),
        template_digest="sha256:" + ("3" * 64),
        parameters_digest="sha256:" + ("4" * 64),
        resource_inventory_digest="sha256:" + ("5" * 64),
        ledger_controls_digest="sha256:" + ("6" * 64),
        oauth_state_digest=canonical_digest({"oauth_state": OAUTH_STATE}),
        **POLICY_DIGESTS,
        broker_artifact_bucket="scanalyze-synthetic-artifacts",
        broker_artifact_key="gug221/broker.zip",
        broker_artifact_version="version-1",
        broker_artifact_code_sha256="A" * 43 + "=",
        broker_code_signing_config_arn=(
            "arn:aws:lambda:us-east-1:042360977644:"
            "code-signing-config:csc-1234567890abcdef0"
        ),
        broker_topology_provider_evidence_digest=provider_evidence_digest,
        broker_topology_signing_key_arn=TOPOLOGY_SIGNING_KEY_ARN,
        broker_topology_signature_algorithm=(
            BROKER_TOPOLOGY_SIGNATURE_ALGORITHM
        ),
        expected_broker_topology_sha256=topology,
        configured_execution_id=_execution_id(),
        execution_not_before=NOW - timedelta(minutes=5),
        execution_not_after=NOW + timedelta(minutes=10),
    )


class Oidc:
    def create_token_with_iam(self, **kwargs: Any) -> dict[str, Any]:
        self.request = kwargs
        return {
            "accessToken": "access-token",
            "idToken": "identity-token",
            "tokenType": "Bearer",
            "expiresIn": 900,
            "scope": ["openid", "sts:identity_context"],
            "awsAdditionalDetails": {"identityContext": "opaque-context"},
        }


class Sts:
    def assume_role(self, **kwargs: Any) -> dict[str, Any]:
        self.request = kwargs
        return {
            "AssumedRoleUser": {
                "Arn": (
                    "arn:aws:sts::042360977644:assumed-role/"
                    "ScanalyzeGug221PhaseBProof/"
                    "gug221-phase-b-0123456789abcdef"
                )
            },
            "Credentials": {
                "AccessKeyId": "synthetic",
                "SecretAccessKey": "synthetic",
                "SessionToken": "synthetic",
                "Expiration": NOW + timedelta(minutes=10),
            },
        }


def proof_for(bound: PhaseBIdentityBinding):
    oidc = Oidc()
    sts = Sts()
    moments = iter([NOW, NOW])
    proof = PhaseBIdentityProofVerifier(
        oidc_client=oidc,
        sts_client=sts,
        clock=lambda: next(moments),
    ).verify(
        event={
            "schema_version": "1",
            "record_type": (
                "platform_authority_lambda_audit_repair_phase_b_proof_request"
            ),
            "authorization_code": "synthetic-code",
            "code_verifier": PKCE_VERIFIER,
            "oauth_state": OAUTH_STATE,
            "broker_topology_evidence": {
                "receipt_digest": bound.broker_topology_provider_evidence_digest,
                "broker_topology_sha256": bound.broker_topology_sha256,
            },
        },
        binding=bound,
        now=NOW,
    )
    return proof, oidc, sts


class Ledger:
    def __init__(self, *, claim_error: bool = False) -> None:
        self.claim_error = claim_error
        self.claimed: OneShotExecutionLedger | None = None
        self.closed: dict[str, Any] | None = None

    def assert_open(self, *, binding: PhaseBIdentityBinding) -> None:
        del binding

    def claim_once(self, *, ledger: OneShotExecutionLedger) -> None:
        if self.claim_error:
            raise RuntimeError("ambiguous")
        self.claimed = ledger

    def close_once(self, **kwargs: Any) -> None:
        self.closed = kwargs


class Effect:
    def __init__(self, *, error: bool = False) -> None:
        self.error = error
        self.calls: list[PhaseBIdentityBinding] = []

    def assert_exact_target(self, *, binding: PhaseBIdentityBinding) -> None:
        self.preflight_binding = binding

    def execute_exact(self, *, binding: PhaseBIdentityBinding) -> None:
        self.calls.append(binding)
        if self.error:
            raise RuntimeError("ambiguous")


def _schema(name: str) -> dict[str, Any]:
    return json.loads((ROOT / "schemas" / name).read_text(encoding="utf-8"))


def test_exact_execution_id_is_calculated_not_pattern_trusted() -> None:
    current = binding()
    assert current.execution_id == _execution_id()
    with pytest.raises(PhaseBPepError, match="EXECUTION_ID_BINDING_INVALID"):
        replace(
            current,
            configured_execution_id="gug221-phase-b-" + ("f" * 64),
        )


def test_static_topology_excludes_fresh_provider_receipt_but_policy_drift_fails() -> None:
    current = binding()
    with pytest.raises(PhaseBPepError, match="BROKER_TOPOLOGY_DIGEST_MISMATCH"):
        replace(current, invoker_policy_sha256="9" * 64)
    other_receipt = replace(
        current,
        broker_topology_provider_evidence_digest="sha256:" + ("9" * 64),
    )
    assert other_receipt.broker_topology_sha256 == current.broker_topology_sha256
    assert other_receipt.binding_digest == current.binding_digest
    with pytest.raises(PhaseBPepError, match="PROVIDER_TOPOLOGY_EVIDENCE_INVALID"):
        replace(
            current,
            broker_topology_provider_evidence_digest="sha256:" + ("0" * 64),
        )


def _topology_evidence(
    *,
    collected_at: str = "2030-01-01T00:05:00Z",
    policy_digests: dict[str, str] | None = None,
) -> dict[str, Any]:
    evidence: dict[str, Any] = {
        "schema_version": "1",
        "record_type": (
            "platform_authority_lambda_audit_repair_phase_b_"
            "broker_topology_evidence"
        ),
        "environment": "non-production",
        "production": False,
        "status": "PROVIDER_TOPOLOGY_READBACK_VERIFIED",
        "authority_account_id": "042360977644",
        "management_account_id": "839393571433",
        "region": "us-east-1",
        "provider_readback": True,
        "identity_center_application_verified": True,
        "single_operator_assignment_verified": True,
        "broker_alias_verified": True,
        "broker_role_verified": True,
        "proof_role_verified": True,
        "ledger_resource_policy_verified": True,
        "direct_qualified_invoke_only": True,
        "function_url_absent": True,
        "synchronous_client_context_required": True,
        "asynchronous_effect_blocked": True,
        "pending_operations_absent": True,
        **(POLICY_DIGESTS if policy_digests is None else policy_digests),
        "broker_topology_sha256": calculate_broker_topology_sha256(
            _topology_inputs()
        ),
        "topology_state_digest": "sha256:" + ("8" * 64),
        "collected_at": collected_at,
        "signing_key_arn": TOPOLOGY_SIGNING_KEY_ARN,
        "signature_algorithm": BROKER_TOPOLOGY_SIGNATURE_ALGORITHM,
        "signature": TOPOLOGY_SIGNATURE,
    }
    evidence["receipt_digest"] = broker_topology_signature_digest(evidence)
    return evidence


def test_external_topology_evidence_requires_provider_readback_and_hash() -> None:
    evidence = _topology_evidence()
    assert (
        validate_broker_topology_evidence(evidence, now=NOW)
        == evidence["receipt_digest"]
    )
    with pytest.raises(PhaseBPepError):
        validate_broker_topology_evidence(
            {**evidence, "provider_readback": False},
            now=NOW,
        )
    with pytest.raises(PhaseBPepError):
        validate_broker_topology_evidence(
            {**evidence, "broker_role_verified": False},
            now=NOW,
        )


@pytest.mark.parametrize(
    ("collected_at", "reason"),
    [
        ("2030-01-01T00:05:01Z", "BROKER_TOPOLOGY_EVIDENCE_FROM_FUTURE"),
        ("2029-12-31T23:59:59Z", "BROKER_TOPOLOGY_EVIDENCE_STALE"),
    ],
)
def test_topology_evidence_rejects_future_and_stale_receipts(
    collected_at: str,
    reason: str,
) -> None:
    with pytest.raises(PhaseBPepError, match=reason):
        validate_broker_topology_evidence(
            _topology_evidence(collected_at=collected_at),
            now=NOW,
        )


class TopologyAuthenticator:
    def __init__(self, *, fail: bool = False) -> None:
        self.fail = fail
        self.calls: list[tuple[Mapping[str, Any], str]] = []

    def verify(
        self,
        *,
        evidence: Mapping[str, Any],
        receipt_digest: str,
    ) -> None:
        self.calls.append((evidence, receipt_digest))
        if self.fail:
            raise RuntimeError("untrusted")


def _bound_evidence() -> tuple[PhaseBIdentityBinding, dict[str, Any]]:
    evidence = _topology_evidence()
    return binding(str(evidence["receipt_digest"])), evidence


def test_runtime_binds_fresh_authenticated_provider_evidence() -> None:
    current, evidence = _bound_evidence()
    authenticator = TopologyAuthenticator()
    result, receipt_digest = phase_b_runtime._topology_evidence_from_invocation(
        event={
            "schema_version": "1",
            "record_type": (
                "platform_authority_lambda_audit_repair_phase_b_proof_request"
            ),
            "authorization_code": "synthetic-code",
            "code_verifier": PKCE_VERIFIER,
            "oauth_state": OAUTH_STATE,
            "broker_topology_evidence": evidence,
        },
        binding=current,
        now=NOW,
        authenticator=authenticator,
    )
    assert result == evidence
    assert receipt_digest == evidence["receipt_digest"]
    assert authenticator.calls == [(evidence, evidence["receipt_digest"])]


def test_kms_authenticator_verifies_exact_digest_key_and_algorithm() -> None:
    evidence = _topology_evidence()

    class Kms:
        def __init__(self) -> None:
            self.request: dict[str, Any] | None = None

        def verify(self, **kwargs: Any) -> dict[str, Any]:
            self.request = kwargs
            return {
                "SignatureValid": True,
                "KeyId": TOPOLOGY_SIGNING_KEY_ARN,
                "SigningAlgorithm": BROKER_TOPOLOGY_SIGNATURE_ALGORITHM,
                "ResponseMetadata": {"HTTPStatusCode": 200},
            }

    kms = Kms()
    phase_b_runtime.KmsBrokerTopologyEvidenceAuthenticator(
        client=kms,
        key_arn=TOPOLOGY_SIGNING_KEY_ARN,
        signing_algorithm=BROKER_TOPOLOGY_SIGNATURE_ALGORITHM,
    ).verify(
        evidence=evidence,
        receipt_digest=str(evidence["receipt_digest"]),
    )
    assert kms.request == {
        "KeyId": TOPOLOGY_SIGNING_KEY_ARN,
        "Message": bytes.fromhex(
            str(evidence["receipt_digest"]).removeprefix("sha256:")
        ),
        "MessageType": "DIGEST",
        "Signature": b"x" * 64,
        "SigningAlgorithm": BROKER_TOPOLOGY_SIGNATURE_ALGORITHM,
    }


@pytest.mark.parametrize(
    ("mutation", "reason"),
    (
        (
            {"signing_key_arn": (
                "arn:aws:kms:us-east-1:042360977644:key/"
                "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
            )},
            "BROKER_TOPOLOGY_SIGNATURE_BINDING_MISMATCH",
        ),
        (
            {"signature_algorithm": "RSASSA_PSS_SHA_256"},
            "BROKER_TOPOLOGY_SIGNATURE_BINDING_MISMATCH",
        ),
    ),
)
def test_kms_authenticator_rejects_foreign_signature_binding(
    mutation: dict[str, str],
    reason: str,
) -> None:
    evidence = {**_topology_evidence(), **mutation}
    with pytest.raises(PhaseBPepError, match=reason):
        phase_b_runtime.KmsBrokerTopologyEvidenceAuthenticator(
            client=object(),
            key_arn=TOPOLOGY_SIGNING_KEY_ARN,
            signing_algorithm=BROKER_TOPOLOGY_SIGNATURE_ALGORITHM,
        ).verify(
            evidence=evidence,
            receipt_digest=str(evidence["receipt_digest"]),
        )


def test_runtime_rejects_missing_forged_foreign_or_unbound_payload_evidence() -> None:
    current, evidence = _bound_evidence()
    authenticator = TopologyAuthenticator()
    base = {
        "schema_version": "1",
        "record_type": (
            "platform_authority_lambda_audit_repair_phase_b_proof_request"
        ),
        "authorization_code": "synthetic-code",
        "code_verifier": PKCE_VERIFIER,
        "oauth_state": OAUTH_STATE,
    }
    with pytest.raises(PhaseBPepError, match="REQUEST_AUTHORITY_FORBIDDEN"):
        phase_b_runtime._topology_evidence_from_invocation(
            event=base,
            binding=current,
            now=NOW,
            authenticator=authenticator,
        )
    forged = dict(evidence)
    forged["receipt_digest"] = "sha256:" + ("f" * 64)
    with pytest.raises(
        PhaseBPepError,
        match="BROKER_TOPOLOGY_EVIDENCE_DIGEST_MISMATCH",
    ):
        phase_b_runtime._topology_evidence_from_invocation(
            event={**base, "broker_topology_evidence": forged},
            binding=current,
            now=NOW,
            authenticator=authenticator,
        )
    foreign = _topology_evidence(
        policy_digests={**POLICY_DIGESTS, "broker_policy_sha256": "9" * 64}
    )
    foreign_binding = binding(str(foreign["receipt_digest"]))
    with pytest.raises(
        PhaseBPepError,
        match="BROKER_TOPOLOGY_POLICY_DIGEST_MISMATCH",
    ):
        phase_b_runtime._topology_evidence_from_invocation(
            event={**base, "broker_topology_evidence": foreign},
            binding=replace(
                foreign_binding,
                broker_policy_sha256=POLICY_DIGESTS["broker_policy_sha256"],
                expected_broker_topology_sha256=calculate_broker_topology_sha256(
                    _topology_inputs()
                ),
            ),
            now=NOW,
            authenticator=authenticator,
        )


def test_runtime_rejects_invalid_kms_signature_before_effect_clients(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observed = datetime.now(tz=UTC).replace(microsecond=0)
    evidence = _topology_evidence(
        collected_at=observed.isoformat().replace("+00:00", "Z")
    )
    current = binding(None)
    calls: list[str] = []
    monkeypatch.setattr(
        phase_b_runtime,
        "binding_from_environment",
        lambda: current,
    )
    class InvalidKms:
        def verify(self, **kwargs: Any) -> dict[str, Any]:
            calls.append("kms:" + str(sorted(kwargs)))
            return {
                "SignatureValid": False,
                "KeyId": TOPOLOGY_SIGNING_KEY_ARN,
                "SigningAlgorithm": BROKER_TOPOLOGY_SIGNATURE_ALGORITHM,
                "ResponseMetadata": {"HTTPStatusCode": 200},
            }

    monkeypatch.setattr(
        phase_b_runtime,
        "create_kms_verifier_client",
        lambda **_: InvalidKms(),
    )
    mutable_client_calls: list[str] = []
    monkeypatch.setattr(
        phase_b_runtime.BotoClients,
        "create",
        lambda **kwargs: mutable_client_calls.append(str(kwargs)) or None,
    )
    context = type(
        "Context",
        (),
        {
            "invoked_function_arn": current.broker_alias_arn,
            "client_context": type(
                "ClientContext",
                (),
                {
                    "custom": {
                        "transport": "REQUEST_RESPONSE",
                        "execution_id": current.execution_id,
                        "broker_topology_sha256": (
                            current.broker_topology_sha256
                        ),
                    }
                },
            )(),
        },
    )()
    response = phase_b_runtime.handler(
        {
            "schema_version": "1",
            "record_type": (
                "platform_authority_lambda_audit_repair_phase_b_proof_request"
            ),
            "authorization_code": "synthetic-code",
            "code_verifier": PKCE_VERIFIER,
            "oauth_state": OAUTH_STATE,
            "broker_topology_evidence": evidence,
        },
        context,
    )
    body = json.loads(response["body"])
    assert body["reason_code"] == "BROKER_TOPOLOGY_AUTHENTICATION_FAILED"
    assert calls and calls[0].startswith("kms:")
    assert mutable_client_calls == []


def test_runtime_rejects_expanded_payload_before_kms_or_effect_clients(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observed = datetime.now(tz=UTC).replace(microsecond=0)
    evidence = _topology_evidence(
        collected_at=observed.isoformat().replace("+00:00", "Z")
    )
    current = binding(None)
    kms_calls: list[str] = []
    effect_calls: list[str] = []
    monkeypatch.setattr(
        phase_b_runtime,
        "binding_from_environment",
        lambda: current,
    )
    monkeypatch.setattr(
        phase_b_runtime,
        "create_kms_verifier_client",
        lambda **kwargs: kms_calls.append(str(kwargs)),
    )
    monkeypatch.setattr(
        phase_b_runtime.BotoClients,
        "create",
        lambda **kwargs: effect_calls.append(str(kwargs)),
    )
    response = phase_b_runtime.handler(
        {
            "schema_version": "1",
            "record_type": (
                "platform_authority_lambda_audit_repair_phase_b_proof_request"
            ),
            "authorization_code": "synthetic-code",
            "code_verifier": PKCE_VERIFIER,
            "oauth_state": OAUTH_STATE,
            "broker_topology_evidence": evidence,
            "request_authority": "foreign",
        },
        _lambda_context(
            current,
            {
                "transport": "REQUEST_RESPONSE",
                "execution_id": current.execution_id,
                "broker_topology_sha256": current.broker_topology_sha256,
            },
        ),
    )
    assert json.loads(response["body"])["reason_code"] == (
        "REQUEST_AUTHORITY_FORBIDDEN"
    )
    assert kms_calls == []
    assert effect_calls == []


def _lambda_context(
    current: PhaseBIdentityBinding,
    custom: object,
) -> object:
    return type(
        "Context",
        (),
        {
            "invoked_function_arn": current.broker_alias_arn,
            "client_context": type(
                "ClientContext",
                (),
                {"custom": custom},
            )(),
        },
    )()


def test_exact_client_context_proves_request_response_transport() -> None:
    current = binding()
    phase_b_runtime._validate_synchronous_client_context(
        _lambda_context(
            current,
            {
                "transport": "REQUEST_RESPONSE",
                "execution_id": current.execution_id,
                "broker_topology_sha256": current.broker_topology_sha256,
            },
        ),
        binding=current,
    )


@pytest.mark.parametrize(
    "custom",
    [
        None,
        {},
        {
            "transport": "EVENT",
            "execution_id": "gug221-phase-b-" + ("0" * 64),
            "broker_topology_sha256": "sha256:" + ("0" * 64),
        },
        {
            "transport": "REQUEST_RESPONSE",
            "execution_id": "gug221-phase-b-" + ("0" * 64),
            "broker_topology_sha256": "sha256:" + ("0" * 64),
        },
        {
            "transport": "REQUEST_RESPONSE",
            "execution_id": "gug221-phase-b-" + ("0" * 64),
            "broker_topology_sha256": "sha256:" + ("0" * 64),
            "principal": "foreign",
        },
    ],
)
def test_async_missing_foreign_or_expanded_client_context_fails_closed(
    custom: object,
) -> None:
    current = binding()
    with pytest.raises(PhaseBPepError, match="SYNCHRONOUS_TRANSPORT_UNPROVEN"):
        phase_b_runtime._validate_synchronous_client_context(
            _lambda_context(current, custom),
            binding=current,
        )


def test_transport_failure_precedes_topology_and_aws_client_access(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    current = binding()
    evidence_calls: list[str] = []
    client_calls: list[str] = []
    monkeypatch.setattr(
        phase_b_runtime,
        "binding_from_environment",
        lambda: current,
    )
    monkeypatch.setattr(
        phase_b_runtime,
        "_validated_topology_evidence_from_invocation",
        lambda **kwargs: evidence_calls.append(str(kwargs)),
    )
    monkeypatch.setattr(
        phase_b_runtime.BotoClients,
        "create",
        lambda **kwargs: client_calls.append(str(kwargs)),
    )
    response = phase_b_runtime.handler(
        {},
        _lambda_context(current, None),
    )
    assert json.loads(response["body"])["reason_code"] == (
        "SYNCHRONOUS_TRANSPORT_UNPROVEN"
    )
    assert evidence_calls == []
    assert client_calls == []


_COLLECTOR_POLICIES = {
    "invoker": {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "InvokeOnlyExactQualifiedPhaseBBroker",
                "Effect": "Allow",
                "Action": "lambda:InvokeFunction",
                "Resource": (
                    "arn:aws:lambda:us-east-1:042360977644:function:"
                    f"{FUNCTION_NAME}:{FUNCTION_ALIAS}"
                ),
            }
        ],
    },
    "broker": {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "SyntheticReviewedBrokerPolicy",
                "Effect": "Allow",
                "Action": "kms:Verify",
                "Resource": TOPOLOGY_SIGNING_KEY_ARN,
            }
        ],
    },
    "proof": {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "DenyEveryProofSessionAction",
                "Effect": "Deny",
                "Action": "*",
                "Resource": "*",
            }
        ],
    },
    "application": {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowOnlyExactPhaseBBrokerApplicationActor",
                "Effect": "Allow",
                "Principal": {
                    "AWS": (
                        "arn:aws:iam::042360977644:role/"
                        f"{BROKER_ROLE_NAME}"
                    )
                },
                "Action": "sso-oauth:CreateTokenWithIAM",
                "Resource": "*",
            }
        ],
    },
}


def _collector_binding() -> PhaseBIdentityBinding:
    digests = {
        "invoker_policy_sha256": canonical_digest(
            _COLLECTOR_POLICIES["invoker"]
        ).removeprefix("sha256:"),
        "broker_policy_sha256": canonical_digest(
            _COLLECTOR_POLICIES["broker"]
        ).removeprefix("sha256:"),
        "proof_policy_sha256": canonical_digest(
            _COLLECTOR_POLICIES["proof"]
        ).removeprefix("sha256:"),
        "application_actor_policy_sha256": canonical_digest(
            _COLLECTOR_POLICIES["application"]
        ).removeprefix("sha256:"),
    }
    topology_inputs = {**_topology_inputs(), **digests}
    return replace(
        binding(),
        **digests,
        expected_broker_topology_sha256=calculate_broker_topology_sha256(
            topology_inputs
        ),
    )


class _ProviderNotFound(RuntimeError):
    response = {"Error": {"Code": "ResourceNotFoundException"}}


class _TopologySsoAdmin:
    def __init__(self, current: PhaseBIdentityBinding) -> None:
        self.current = current
        self.calls: list[tuple[str, dict[str, Any]]] = []

    def _call(self, name: str, kwargs: dict[str, Any]) -> None:
        self.calls.append((name, kwargs))

    def describe_application(self, **kwargs: Any) -> dict[str, Any]:
        self._call("describe_application", kwargs)
        return {
            "ApplicationArn": self.current.identity_center_application_arn,
            "InstanceArn": self.current.identity_center_instance_arn,
            "ApplicationAccount": self.current.management_account_id,
            "Name": "ScanalyzeGug221PhaseB",
            "Status": "ENABLED",
        }

    def get_application_assignment_configuration(
        self, **kwargs: Any
    ) -> dict[str, Any]:
        self._call("get_application_assignment_configuration", kwargs)
        return {"AssignmentRequired": True}

    def list_application_assignments(
        self, **kwargs: Any
    ) -> dict[str, Any]:
        self._call("list_application_assignments", kwargs)
        return {
            "ApplicationAssignments": [
                {
                    "ApplicationArn": (
                        self.current.identity_center_application_arn
                    ),
                    "PrincipalId": self.current.operator_user_id,
                    "PrincipalType": "USER",
                }
            ]
        }

    def list_application_authentication_methods(
        self, **kwargs: Any
    ) -> dict[str, Any]:
        self._call("list_application_authentication_methods", kwargs)
        return {
            "AuthenticationMethods": [
                {"AuthenticationMethodType": "IAM"}
            ]
        }

    def get_application_authentication_method(
        self, **kwargs: Any
    ) -> dict[str, Any]:
        self._call("get_application_authentication_method", kwargs)
        return {
            "AuthenticationMethod": {
                "Iam": {
                    "ActorPolicy": _COLLECTOR_POLICIES["application"]
                }
            }
        }

    def list_application_grants(self, **kwargs: Any) -> dict[str, Any]:
        self._call("list_application_grants", kwargs)
        return {"Grants": [{"GrantType": "authorization_code"}]}

    def get_application_grant(self, **kwargs: Any) -> dict[str, Any]:
        self._call("get_application_grant", kwargs)
        return {
            "Grant": {
                "AuthorizationCode": {
                    "RedirectUris": [self.current.redirect_uri]
                }
            }
        }

    def list_application_access_scopes(
        self, **kwargs: Any
    ) -> dict[str, Any]:
        self._call("list_application_access_scopes", kwargs)
        return {
            "Scopes": [
                {"Scope": "openid", "AuthorizedTargets": []},
                {
                    "Scope": "sts:identity_context",
                    "AuthorizedTargets": [self.current.proof_role_arn],
                },
            ]
        }

    def get_application_access_scope(
        self, **kwargs: Any
    ) -> dict[str, Any]:
        self._call("get_application_access_scope", kwargs)
        scope = kwargs["Scope"]
        return {
            "Scope": scope,
            "AuthorizedTargets": (
                [self.current.proof_role_arn]
                if scope == "sts:identity_context"
                else []
            ),
        }


class _TopologyIam:
    def __init__(self, current: PhaseBIdentityBinding) -> None:
        self.current = current
        self.calls: list[tuple[str, dict[str, Any]]] = []
        invoker_name = current.invoker_role_arn.rsplit("/", 1)[-1]
        broker_name = current.broker_execution_role_arn.rsplit("/", 1)[-1]
        proof_name = current.proof_role_arn.rsplit("/", 1)[-1]
        self.roles = {
            invoker_name: {
                "arn": current.invoker_role_arn,
                "trust": {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Principal": {
                                "Federated": (
                                    "arn:aws:iam::042360977644:"
                                    "saml-provider/AWSSSO_"
                                    "ssoins123_DO_NOT_DELETE"
                                )
                            },
                            "Action": [
                                "sts:AssumeRoleWithSAML",
                                "sts:TagSession",
                            ],
                            "Condition": {
                                "StringEquals": {
                                    "SAML:aud": (
                                        "https://signin.aws.amazon.com/saml"
                                    )
                                }
                            },
                        }
                    ],
                },
                "policy_name": "AwsSsoInlinePolicy",
                "policy": _COLLECTOR_POLICIES["invoker"],
                "tags": [],
            },
            broker_name: {
                "arn": current.broker_execution_role_arn,
                "trust": topology_collector._expected_broker_trust(current),
                "policy_name": topology_collector.BROKER_POLICY_NAME,
                "policy": _COLLECTOR_POLICIES["broker"],
                "tags": [
                    {"Key": "work_package", "Value": "GUG-221"}
                ],
            },
            proof_name: {
                "arn": current.proof_role_arn,
                "trust": topology_collector._expected_proof_trust(current),
                "policy_name": topology_collector.PROOF_POLICY_NAME,
                "policy": _COLLECTOR_POLICIES["proof"],
                "tags": [
                    {"Key": "work_package", "Value": "GUG-221"}
                ],
            },
        }
        self.attached: dict[str, list[Mapping[str, Any]]] = {
            name: [] for name in self.roles
        }

    def _record(
        self, name: str, kwargs: dict[str, Any]
    ) -> Mapping[str, Any]:
        self.calls.append((name, kwargs))
        return self.roles[str(kwargs["RoleName"])]

    def get_role(self, **kwargs: Any) -> dict[str, Any]:
        role = self._record("get_role", kwargs)
        return {
            "Role": {
                "RoleName": kwargs["RoleName"],
                "Arn": role["arn"],
                "MaxSessionDuration": 3600,
                "AssumeRolePolicyDocument": role["trust"],
            }
        }

    def list_role_policies(self, **kwargs: Any) -> dict[str, Any]:
        role = self._record("list_role_policies", kwargs)
        return {
            "PolicyNames": [role["policy_name"]],
            "IsTruncated": False,
        }

    def get_role_policy(self, **kwargs: Any) -> dict[str, Any]:
        role = self._record("get_role_policy", kwargs)
        return {
            "RoleName": kwargs["RoleName"],
            "PolicyName": kwargs["PolicyName"],
            "PolicyDocument": role["policy"],
        }

    def list_attached_role_policies(
        self, **kwargs: Any
    ) -> dict[str, Any]:
        self._record("list_attached_role_policies", kwargs)
        return {
            "AttachedPolicies": self.attached[str(kwargs["RoleName"])],
            "IsTruncated": False,
        }

    def list_role_tags(self, **kwargs: Any) -> dict[str, Any]:
        role = self._record("list_role_tags", kwargs)
        return {"Tags": role["tags"], "IsTruncated": False}


class _TopologyLambda:
    def __init__(self, current: PhaseBIdentityBinding) -> None:
        self.current = current
        self.calls: list[tuple[str, dict[str, Any]]] = []

    def _call(self, name: str, kwargs: dict[str, Any]) -> None:
        self.calls.append((name, kwargs))

    def get_alias(self, **kwargs: Any) -> dict[str, Any]:
        self._call("get_alias", kwargs)
        return {
            "AliasArn": self.current.broker_alias_arn,
            "Name": FUNCTION_ALIAS,
            "FunctionVersion": "7",
            "RoutingConfig": {},
        }

    def get_function_configuration(
        self, **kwargs: Any
    ) -> dict[str, Any]:
        self._call("get_function_configuration", kwargs)
        return {
            "FunctionName": FUNCTION_NAME,
            "FunctionArn": (
                "arn:aws:lambda:us-east-1:042360977644:function:"
                f"{FUNCTION_NAME}:7"
            ),
            "Runtime": "python3.12",
            "Role": self.current.broker_execution_role_arn,
            "Handler": (
                "tooling.platform_authority_lambda_audit_repair_"
                "phase_b_runtime.handler"
            ),
            "CodeSha256": self.current.broker_artifact_code_sha256,
            "Version": "7",
            "State": "Active",
            "LastUpdateStatus": "Successful",
            "PackageType": "Zip",
            "Architectures": ["x86_64"],
            "MemorySize": 256,
            "Timeout": 60,
            "Environment": {
                "Variables": dict(
                    self.current.broker_environment_variables
                )
            },
        }

    def get_function_code_signing_config(
        self, **kwargs: Any
    ) -> dict[str, Any]:
        self._call("get_function_code_signing_config", kwargs)
        return {
            "FunctionName": FUNCTION_NAME,
            "CodeSigningConfigArn": (
                self.current.broker_code_signing_config_arn
            ),
        }

    def get_function_concurrency(self, **kwargs: Any) -> dict[str, Any]:
        self._call("get_function_concurrency", kwargs)
        return {"ReservedConcurrentExecutions": 1}

    def get_policy(self, **kwargs: Any) -> dict[str, Any]:
        self._call("get_policy", kwargs)
        if kwargs.get("Qualifier") == FUNCTION_ALIAS:
            return {
                "Policy": json.dumps(
                    {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Sid": "ExactInvoker",
                                "Effect": "Allow",
                                "Principal": {
                                    "AWS": self.current.invoker_role_arn
                                },
                                "Action": "lambda:InvokeFunction",
                                "Resource": self.current.broker_alias_arn,
                            }
                        ],
                    }
                )
            }
        raise _ProviderNotFound()

    def get_function_url_config(self, **kwargs: Any) -> dict[str, Any]:
        self._call("get_function_url_config", kwargs)
        raise _ProviderNotFound()

    def get_function_event_invoke_config(
        self, **kwargs: Any
    ) -> dict[str, Any]:
        self._call("get_function_event_invoke_config", kwargs)
        if kwargs.get("Qualifier") == FUNCTION_ALIAS:
            return {
                "FunctionArn": self.current.broker_alias_arn,
                "MaximumRetryAttempts": 0,
                "MaximumEventAgeInSeconds": 60,
                "DestinationConfig": {},
                "ResponseMetadata": {"HTTPStatusCode": 200},
            }
        raise _ProviderNotFound()

    def list_event_source_mappings(
        self, **kwargs: Any
    ) -> dict[str, Any]:
        self._call("list_event_source_mappings", kwargs)
        return {"EventSourceMappings": []}


class _TopologyDynamoDb:
    def __init__(self, current: PhaseBIdentityBinding) -> None:
        self.current = current
        self.calls: list[tuple[str, dict[str, Any]]] = []
        self.time_to_live_description: Mapping[str, Any] = {
            "TimeToLiveStatus": "DISABLED"
        }

    def _call(self, name: str, kwargs: dict[str, Any]) -> None:
        self.calls.append((name, kwargs))

    def describe_table(self, **kwargs: Any) -> dict[str, Any]:
        self._call("describe_table", kwargs)
        return {
            "Table": {
                "TableName": (
                    "scanalyze-platform-authority-gug221-"
                    "phase-b-execution-ledger"
                ),
                "TableArn": self.current.ledger_table_arn,
                "TableStatus": "ACTIVE",
                "BillingModeSummary": {
                    "BillingMode": "PAY_PER_REQUEST"
                },
                "DeletionProtectionEnabled": True,
                "KeySchema": [
                    {
                        "AttributeName": "execution_id",
                        "KeyType": "HASH",
                    }
                ],
                "AttributeDefinitions": [
                    {
                        "AttributeName": "execution_id",
                        "AttributeType": "S",
                    }
                ],
                "SSEDescription": {
                    "Status": "ENABLED",
                    "SSEType": "KMS",
                    "KMSMasterKeyArn": TOPOLOGY_SIGNING_KEY_ARN,
                },
            }
        }

    def describe_continuous_backups(
        self, **kwargs: Any
    ) -> dict[str, Any]:
        self._call("describe_continuous_backups", kwargs)
        return {
            "ContinuousBackupsDescription": {
                "ContinuousBackupsStatus": "ENABLED",
                "PointInTimeRecoveryDescription": {
                    "PointInTimeRecoveryStatus": "ENABLED"
                },
            }
        }

    def describe_time_to_live(self, **kwargs: Any) -> dict[str, Any]:
        self._call("describe_time_to_live", kwargs)
        return {
            "TimeToLiveDescription": dict(
                self.time_to_live_description
            )
        }

    def get_resource_policy(self, **kwargs: Any) -> dict[str, Any]:
        self._call("get_resource_policy", kwargs)
        return {
            "Policy": json.dumps(
                topology_collector._expected_ledger_resource_policy(
                    self.current
                )
            )
        }


class _TopologyKms:
    def __init__(self, current: PhaseBIdentityBinding) -> None:
        self.current = current
        self.calls: list[tuple[str, dict[str, Any]]] = []
        self.key_policy: Mapping[str, Any] = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "EnableAuthorityAccount",
                    "Effect": "Allow",
                    "Principal": {
                        "AWS": (
                            "arn:aws:iam::042360977644:root"
                        )
                    },
                    "Action": "kms:*",
                    "Resource": "*",
                }
            ],
        }

    def describe_key(self, **kwargs: Any) -> dict[str, Any]:
        self.calls.append(("describe_key", kwargs))
        return {
            "KeyMetadata": {
                "Arn": self.current.broker_topology_signing_key_arn,
                "AWSAccountId": self.current.authority_account_id,
                "Enabled": True,
                "KeyState": "Enabled",
                "KeyUsage": "SIGN_VERIFY",
                "KeyManager": "CUSTOMER",
                "KeySpec": "ECC_NIST_P256",
                "SigningAlgorithms": ["ECDSA_SHA_256"],
                "Origin": "AWS_KMS",
                "MultiRegion": False,
            }
        }

    def get_key_policy(self, **kwargs: Any) -> dict[str, Any]:
        self.calls.append(("get_key_policy", kwargs))
        return {"Policy": json.dumps(self.key_policy)}

    def list_grants(self, **kwargs: Any) -> dict[str, Any]:
        self.calls.append(("list_grants", kwargs))
        return {"Grants": [], "Truncated": False}


def _topology_clients(
    current: PhaseBIdentityBinding,
) -> tuple[
    topology_collector.PhaseBTopologyReadOnlyClients,
    tuple[Any, ...],
]:
    services = (
        _TopologySsoAdmin(current),
        _TopologyIam(current),
        _TopologyLambda(current),
        _TopologyDynamoDb(current),
        _TopologyKms(current),
    )
    return (
        topology_collector.PhaseBTopologyReadOnlyClients(*services),
        services,
    )


def test_read_only_collector_builds_unsigned_provider_evidence() -> None:
    current = _collector_binding()
    clients, services = _topology_clients(current)
    unsigned = topology_collector.collect_unsigned_broker_topology_evidence(
        binding=current,
        clients=clients,
        now=NOW,
    )
    assert "signature" not in unsigned
    assert unsigned["provider_readback"] is True
    assert unsigned["status"] == "PROVIDER_TOPOLOGY_READBACK_VERIFIED"
    assert unsigned["receipt_digest"] == (
        broker_topology_signature_digest(unsigned)
    )
    signed = topology_collector.attach_broker_topology_signature(
        unsigned_evidence=unsigned,
        signature=TOPOLOGY_SIGNATURE,
    )
    assert (
        validate_broker_topology_evidence(signed, now=NOW)
        == unsigned["receipt_digest"]
    )
    observed_operations = {
        operation
        for service in services
        for operation, _ in service.calls
    }
    assert observed_operations == {
        "describe_application",
        "get_application_assignment_configuration",
        "list_application_assignments",
        "list_application_authentication_methods",
        "get_application_authentication_method",
        "list_application_grants",
        "get_application_grant",
        "list_application_access_scopes",
        "get_application_access_scope",
        "get_role",
        "list_role_policies",
        "get_role_policy",
        "list_attached_role_policies",
        "list_role_tags",
        "get_alias",
        "get_function_configuration",
        "get_function_code_signing_config",
        "get_function_concurrency",
        "get_policy",
        "get_function_url_config",
        "get_function_event_invoke_config",
        "list_event_source_mappings",
        "describe_table",
        "describe_continuous_backups",
        "describe_time_to_live",
        "get_resource_policy",
        "describe_key",
        "get_key_policy",
        "list_grants",
    }
    assert not any(
        operation.startswith(
            (
                "create",
                "delete",
                "execute",
                "put",
                "set",
                "sign",
                "tag",
                "untag",
                "update",
            )
        )
        for operation in observed_operations
    )


def test_read_only_collector_rejects_role_policy_expansion() -> None:
    current = _collector_binding()
    clients, services = _topology_clients(current)
    iam = services[1]
    assert isinstance(iam, _TopologyIam)
    broker_name = current.broker_execution_role_arn.rsplit("/", 1)[-1]
    iam.attached[broker_name] = [
        {
            "PolicyName": "AdministratorAccess",
            "PolicyArn": (
                "arn:aws:iam::aws:policy/AdministratorAccess"
            ),
        }
    ]
    with pytest.raises(
        PhaseBPepError,
        match="BROKER_TOPOLOGY_ROLE_POLICY_MISMATCH",
    ):
        topology_collector.collect_unsigned_broker_topology_evidence(
            binding=current,
            clients=clients,
            now=NOW,
        )


@pytest.mark.parametrize(
    "time_to_live_description",
    [
        {"TimeToLiveStatus": "ENABLED", "AttributeName": "expires_at"},
        {"TimeToLiveStatus": "ENABLING", "AttributeName": "expires_at"},
        {"TimeToLiveStatus": "DISABLING", "AttributeName": "expires_at"},
        {"TimeToLiveStatus": "DISABLED", "AttributeName": "expires_at"},
        {},
    ],
)
def test_read_only_collector_rejects_ledger_ttl_drift(
    time_to_live_description: Mapping[str, Any],
) -> None:
    current = _collector_binding()
    clients, services = _topology_clients(current)
    dynamodb = services[3]
    assert isinstance(dynamodb, _TopologyDynamoDb)
    dynamodb.time_to_live_description = time_to_live_description
    with pytest.raises(
        PhaseBPepError,
        match="BROKER_TOPOLOGY_LEDGER_MISMATCH",
    ):
        topology_collector.collect_unsigned_broker_topology_evidence(
            binding=current,
            clients=clients,
            now=NOW,
        )


@pytest.mark.parametrize(
    "drift",
    [
        {"MaximumRetryAttempts": 1},
        {"MaximumEventAgeInSeconds": 120},
        {"DestinationConfig": {"OnFailure": {"Destination": "foreign"}}},
        {"ResponseMetadata": {"HTTPStatusCode": 500}},
    ],
)
def test_read_only_collector_rejects_alias_async_configuration_drift(
    drift: Mapping[str, Any],
) -> None:
    current = _collector_binding()
    clients, services = _topology_clients(current)
    lambda_client = services[2]
    assert isinstance(lambda_client, _TopologyLambda)

    def drifted(**kwargs: Any) -> dict[str, Any]:
        lambda_client._call("get_function_event_invoke_config", kwargs)
        if kwargs.get("Qualifier") == FUNCTION_ALIAS:
            return {
                "FunctionArn": current.broker_alias_arn,
                "MaximumRetryAttempts": 0,
                "MaximumEventAgeInSeconds": 60,
                "DestinationConfig": {},
                "ResponseMetadata": {"HTTPStatusCode": 200},
                **drift,
            }
        raise _ProviderNotFound()

    lambda_client.get_function_event_invoke_config = drifted  # type: ignore[method-assign]
    with pytest.raises(
        PhaseBPepError,
        match="BROKER_TOPOLOGY_LAMBDA_CONFIGURATION_MISMATCH",
    ):
        topology_collector.collect_unsigned_broker_topology_evidence(
            binding=current,
            clients=clients,
            now=NOW,
        )


def _install_lambda_environment_drift(
    lambda_client: _TopologyLambda,
    mutate: Any,
) -> None:
    original = lambda_client.get_function_configuration

    def drifted(**kwargs: Any) -> dict[str, Any]:
        response = original(**kwargs)
        mutate(response)
        return response

    lambda_client.get_function_configuration = drifted  # type: ignore[method-assign]


def test_read_only_collector_binds_exact_lambda_environment_digest() -> None:
    current = _collector_binding()
    clients, services = _topology_clients(current)
    lambda_client = services[2]
    assert isinstance(lambda_client, _TopologyLambda)
    lambda_state = topology_collector._collect_lambda(
        binding=current,
        client=lambda_client,
    )
    assert lambda_state["environment_variables_sha256"] == (
        current.broker_environment_variables_sha256
    )


def test_signed_topology_state_digest_binds_lambda_environment_projection() -> None:
    current = _collector_binding()
    baseline_clients, _ = _topology_clients(current)
    baseline = topology_collector.collect_unsigned_broker_topology_evidence(
        binding=current,
        clients=baseline_clients,
        now=NOW,
    )
    changed = replace(
        current,
        phase_b_intent_digest="sha256:" + ("9" * 64),
    )
    changed_clients, _ = _topology_clients(changed)
    changed_receipt = (
        topology_collector.collect_unsigned_broker_topology_evidence(
            binding=changed,
            clients=changed_clients,
            now=NOW,
        )
    )
    assert changed.broker_topology_sha256 == current.broker_topology_sha256
    assert changed.broker_environment_variables_sha256 != (
        current.broker_environment_variables_sha256
    )
    assert changed_receipt["topology_state_digest"] != (
        baseline["topology_state_digest"]
    )
    assert changed_receipt["receipt_digest"] != baseline["receipt_digest"]


@pytest.mark.parametrize(
    "missing_key",
    ["__environment__", *_collector_binding().broker_environment_variables],
)
def test_read_only_collector_rejects_lambda_environment_omission(
    missing_key: str,
) -> None:
    current = _collector_binding()
    clients, services = _topology_clients(current)
    lambda_client = services[2]
    assert isinstance(lambda_client, _TopologyLambda)

    def omit(response: dict[str, Any]) -> None:
        if missing_key == "__environment__":
            response.pop("Environment")
        else:
            response["Environment"]["Variables"].pop(missing_key)

    _install_lambda_environment_drift(lambda_client, omit)
    with pytest.raises(
        PhaseBPepError,
        match="BROKER_TOPOLOGY_LAMBDA_ENVIRONMENT_MISMATCH",
    ):
        topology_collector.collect_unsigned_broker_topology_evidence(
            binding=current,
            clients=clients,
            now=NOW,
        )


def test_read_only_collector_rejects_lambda_environment_expansion() -> None:
    current = _collector_binding()
    clients, services = _topology_clients(current)
    lambda_client = services[2]
    assert isinstance(lambda_client, _TopologyLambda)

    def expand(response: dict[str, Any]) -> None:
        response["Environment"]["Variables"]["FOREIGN_AUTHORITY"] = "true"

    _install_lambda_environment_drift(lambda_client, expand)
    with pytest.raises(
        PhaseBPepError,
        match="BROKER_TOPOLOGY_LAMBDA_ENVIRONMENT_MISMATCH",
    ):
        topology_collector.collect_unsigned_broker_topology_evidence(
            binding=current,
            clients=clients,
            now=NOW,
        )


@pytest.mark.parametrize(
    "changed_key",
    list(_collector_binding().broker_environment_variables),
)
def test_read_only_collector_rejects_lambda_environment_drift(
    changed_key: str,
) -> None:
    current = _collector_binding()
    clients, services = _topology_clients(current)
    lambda_client = services[2]
    assert isinstance(lambda_client, _TopologyLambda)

    def alter(response: dict[str, Any]) -> None:
        response["Environment"]["Variables"][changed_key] = (
            "synthetic-drift"
        )

    _install_lambda_environment_drift(lambda_client, alter)
    with pytest.raises(
        PhaseBPepError,
        match="BROKER_TOPOLOGY_LAMBDA_ENVIRONMENT_MISMATCH",
    ):
        topology_collector.collect_unsigned_broker_topology_evidence(
            binding=current,
            clients=clients,
            now=NOW,
        )


def test_read_only_collector_rejects_replayed_provider_page() -> None:
    current = _collector_binding()
    clients, services = _topology_clients(current)
    sso = services[0]
    assert isinstance(sso, _TopologySsoAdmin)

    def repeated(**kwargs: Any) -> dict[str, Any]:
        sso._call("list_application_assignments", kwargs)
        return {
            "ApplicationAssignments": [],
            "NextToken": "replayed-token",
        }

    sso.list_application_assignments = repeated  # type: ignore[method-assign]
    with pytest.raises(
        PhaseBPepError,
        match="BROKER_TOPOLOGY_PROVIDER_PAGINATION_INVALID",
    ):
        topology_collector.collect_unsigned_broker_topology_evidence(
            binding=current,
            clients=clients,
            now=NOW,
        )


def test_read_only_collector_rejects_broker_as_topology_signer() -> None:
    current = _collector_binding()
    clients, services = _topology_clients(current)
    kms = services[4]
    assert isinstance(kms, _TopologyKms)
    kms.key_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {
                    "AWS": current.broker_execution_role_arn
                },
                "Action": "kms:Sign",
                "Resource": "*",
            }
        ],
    }
    with pytest.raises(
        PhaseBPepError,
        match="BROKER_TOPOLOGY_SIGNER_SEPARATION_MISMATCH",
    ):
        topology_collector.collect_unsigned_broker_topology_evidence(
            binding=current,
            clients=clients,
            now=NOW,
        )


def test_unsigned_or_malformed_topology_signature_never_becomes_evidence() -> None:
    current = _collector_binding()
    clients, _ = _topology_clients(current)
    unsigned = topology_collector.collect_unsigned_broker_topology_evidence(
        binding=current,
        clients=clients,
        now=NOW,
    )
    with pytest.raises(
        PhaseBPepError,
        match="BROKER_TOPOLOGY_EVIDENCE_INVALID",
    ):
        validate_broker_topology_evidence(unsigned, now=NOW)
    with pytest.raises(
        PhaseBPepError,
        match="BROKER_TOPOLOGY_EVIDENCE_INVALID",
    ):
        topology_collector.attach_broker_topology_signature(
            unsigned_evidence=unsigned,
            signature=base64.b64encode(b"x" * 8).decode("ascii"),
        )


def test_proof_uses_exactly_one_context_and_never_exposes_credentials() -> None:
    current = binding()
    proof, oidc, sts = proof_for(current)
    assert oidc.request["grantType"] == "authorization_code"
    assert len(sts.request["ProvidedContexts"]) == 1
    assert sts.request["ProvidedContexts"][0]["ProviderArn"].endswith(
        "/IdentityCenter"
    )
    serialized = json.dumps(proof.to_dict(), sort_keys=True)
    for secret in (
        "access-token",
        "identity-token",
        "opaque-context",
        "SecretAccessKey",
        "SessionToken",
    ):
        assert secret not in serialized
    assert proof.broker_topology_sha256 == current.broker_topology_sha256
    assert proof.broker_policy_sha256 == current.broker_policy_sha256


def test_pep_binds_authenticated_invocation_evidence_before_preflight() -> None:
    current = binding(None)
    evidence = _topology_evidence()
    evidence_digest = str(evidence["receipt_digest"])
    ledger = Ledger()
    effect = Effect()
    event = {
        "schema_version": "1",
        "record_type": (
            "platform_authority_lambda_audit_repair_phase_b_proof_request"
        ),
        "authorization_code": "synthetic-code",
        "code_verifier": PKCE_VERIFIER,
        "oauth_state": OAUTH_STATE,
        "broker_topology_evidence": evidence,
    }
    result = PhaseBPep(
        proof_verifier=PhaseBIdentityProofVerifier(
            oidc_client=Oidc(),
            sts_client=Sts(),
            clock=lambda: NOW,
        ),
        broker=PhaseBExecutionBroker(
            ledger_store=ledger,
            execution_client=effect,
            clock=lambda: NOW,
        ),
    ).execute(
        event=event,
        binding=current,
        broker_topology_provider_evidence_digest=evidence_digest,
        now=NOW,
    )
    assert current.broker_topology_provider_evidence_digest is None
    assert result["identity_proof"][
        "broker_topology_provider_evidence_digest"
    ] == evidence_digest
    assert effect.calls[0].broker_topology_provider_evidence_digest == (
        evidence_digest
    )
    assert event == {}


def test_pkce_and_oauth_state_are_exact_and_one_shot() -> None:
    current = binding()
    verifier = PhaseBIdentityProofVerifier(
        oidc_client=Oidc(),
        sts_client=Sts(),
        clock=lambda: NOW,
    )
    base = {
        "schema_version": "1",
        "record_type": (
            "platform_authority_lambda_audit_repair_phase_b_proof_request"
        ),
        "authorization_code": "synthetic-code",
        "code_verifier": PKCE_VERIFIER,
        "oauth_state": OAUTH_STATE,
        "broker_topology_evidence": {
            "receipt_digest": current.broker_topology_provider_evidence_digest,
            "broker_topology_sha256": current.broker_topology_sha256,
        },
    }
    def request(**overrides: str) -> dict[str, Any]:
        return {
            **base,
            "broker_topology_evidence": dict(
                base["broker_topology_evidence"]
            ),
            **overrides,
        }

    with pytest.raises(PhaseBPepError, match="AUTHORIZATION_CODE_MALFORMED"):
        verifier.verify(
            event=request(oauth_state="state-foreign-0123456789"),
            binding=current,
            now=NOW,
        )
    with pytest.raises(PhaseBPepError, match="AUTHORIZATION_CODE_MALFORMED"):
        verifier.verify(
            event=request(code_verifier="a" * 43),
            binding=current,
            now=NOW,
        )


def test_effect_interface_cannot_receive_proof_credentials_and_is_one_shot() -> None:
    current = binding()
    proof, _, _ = proof_for(current)
    ledger = Ledger()
    effect = Effect()
    receipt = PhaseBExecutionBroker(
        ledger_store=ledger,
        execution_client=effect,
        clock=lambda: NOW,
    ).dispatch(binding=current, proof=proof, now=NOW)
    assert isinstance(receipt, PhaseBBrokerEffectReceipt)
    assert effect.calls == [current]
    public = receipt.to_dict()
    assert public["proof_credentials_used_for_effect"] is False
    assert public["attempts"] == 1
    assert public["retry_permitted"] is False
    assert public["provider_revocation_pending"] is True
    assert public["authority_revoked"] is False
    assert ledger.closed is not None
    assert set(ledger.closed) == {
        "claimed_ledger_digest",
        "terminal_ledger",
        "closure_pending",
    }


def test_ambiguous_claim_never_dispatches_or_retries() -> None:
    current = binding()
    proof, _, _ = proof_for(current)
    ledger = Ledger(claim_error=True)
    effect = Effect()
    receipt = PhaseBExecutionBroker(
        ledger_store=ledger,
        execution_client=effect,
        clock=lambda: NOW,
    ).dispatch(binding=current, proof=proof, now=NOW)
    assert receipt.to_dict()["status"] == "UNCERTAIN_RECONCILE_ONLY"
    assert receipt.to_dict()["execution_ambiguous"] is True
    assert effect.calls == []


def test_pending_closure_cannot_claim_revocation() -> None:
    current = binding()
    proof, _, _ = proof_for(current)
    claimed = OneShotExecutionLedger.claim(
        binding=current,
        proof=proof,
        now=NOW,
    )
    terminal = claimed.terminal(status="DISPATCH_ACCEPTED", now=NOW)
    closure = PhaseBClosurePendingReceipt.from_terminal_ledger(
        terminal,
        now=NOW,
    ).to_dict()
    assert closure["status"] == "PROVIDER_REVOCATION_PENDING"
    assert closure["authority_revoked"] is False
    assert closure["provider_revocation_verified"] is False
    assert "revoked_at" not in closure
    assert closure["issued_at"] == "2030-01-01T00:05:00Z"


def test_generated_contracts_match_strict_schemas() -> None:
    current = binding()
    proof, _, _ = proof_for(current)
    claimed = OneShotExecutionLedger.claim(
        binding=current,
        proof=proof,
        now=NOW,
    )
    terminal = claimed.terminal(status="DISPATCH_ACCEPTED", now=NOW)
    closure = PhaseBClosurePendingReceipt.from_terminal_ledger(
        terminal,
        now=NOW,
    )
    effect = PhaseBBrokerEffectReceipt(
        ledger=terminal,
        closure_pending=closure,
        broker_execution_role_arn=current.broker_execution_role_arn,
    )
    for name, value in (
        (
            "platform-authority-lambda-audit-repair-phase-b-"
            "identity-binding.v1.schema.json",
            current.to_dict(),
        ),
        (
            "platform-authority-lambda-audit-repair-phase-b-"
            "proof-receipt.v1.schema.json",
            proof.to_dict(),
        ),
        (
            "platform-authority-lambda-audit-repair-phase-b-"
            "one-shot-execution-ledger.v1.schema.json",
            terminal.to_dict(),
        ),
        (
            "platform-authority-lambda-audit-repair-phase-b-"
            "closure-pending-receipt.v1.schema.json",
            closure.to_dict(),
        ),
        (
            "platform-authority-lambda-audit-repair-phase-b-"
            "broker-effect-receipt.v1.schema.json",
            effect.to_dict(),
        ),
    ):
        Draft202012Validator(_schema(name)).validate(value)


def _load_template() -> dict[str, Any]:
    class Loader(yaml.SafeLoader):
        pass

    def intrinsic(
        loader: yaml.SafeLoader,
        tag_suffix: str,
        node: yaml.Node,
    ) -> object:
        if isinstance(node, yaml.ScalarNode):
            value: object = loader.construct_scalar(node)
        elif isinstance(node, yaml.SequenceNode):
            value = loader.construct_sequence(node)
        else:
            value = loader.construct_mapping(node)
        return {tag_suffix: value}

    Loader.add_multi_constructor("!", intrinsic)
    return yaml.load(
        (
            ROOT
            / "bootstrap"
            / "cfn-platform-authority-lambda-audit-repair-phase-b-broker-pep.yaml"
        ).read_text(encoding="utf-8"),
        Loader=Loader,
    )


def test_cloudformation_broker_topology_has_no_ledger_role_cycle() -> None:
    template = _load_template()
    resources = template["Resources"]
    table = resources["PhaseBExecutionLedger"]
    role = resources["PhaseBBrokerExecutionRole"]
    role_json = json.dumps(role, sort_keys=True)
    assert "PhaseBExecutionLedger" not in role_json
    assert "scanalyze-platform-authority-gug221-phase-b-execution-ledger" in (
        role_json
    )
    assert "PhaseBBrokerExecutionRole" in json.dumps(
        table["Properties"]["ResourcePolicy"],
        sort_keys=True,
    )
    assert "AWS::DynamoDB::ResourcePolicy" not in {
        item["Type"] for item in resources.values()
    }


def test_template_is_direct_qualified_broker_only() -> None:
    template = _load_template()
    resources = template["Resources"]
    assert len(resources) == 9
    assert all(
        item["Type"] != "AWS::Lambda::Url" for item in resources.values()
    )
    event_configs = {
        name: item
        for name, item in resources.items()
        if item["Type"] == "AWS::Lambda::EventInvokeConfig"
    }
    assert set(event_configs) == {"PhaseBBrokerEventInvokeConfig"}
    event_config = event_configs["PhaseBBrokerEventInvokeConfig"]
    assert event_config["DependsOn"] == ["PhaseBBrokerExecuteAlias"]
    assert event_config["Properties"] == {
        "FunctionName": {"Ref": "PhaseBBrokerFunction"},
        "Qualifier": "broker-v1",
        "MaximumRetryAttempts": 0,
        "MaximumEventAgeInSeconds": 60,
    }
    assert "DestinationConfig" not in event_config["Properties"]
    function = resources["PhaseBBrokerFunction"]["Properties"]
    assert function["FunctionName"] == FUNCTION_NAME
    assert function["ReservedConcurrentExecutions"] == 1
    alias = resources["PhaseBBrokerExecuteAlias"]["Properties"]
    assert alias["Name"] == FUNCTION_ALIAS
    permission = resources["PhaseBBrokerInvokePermission"]["Properties"]
    assert permission["Action"] == "lambda:InvokeFunction"
    assert "broker-v1" in json.dumps(permission)
    environment = function["Environment"]["Variables"]
    assert environment["CONFIGURED_EXECUTION_ID"] == {"Ref": "ExactExecutionId"}
    assert set(environment) == set(binding().broker_environment_variables)
    assert "BROKER_TOPOLOGY_EVIDENCE_JSON" not in environment
    assert "BROKER_TOPOLOGY_PROVIDER_EVIDENCE_DIGEST" not in environment
    for key in (
        "INVOKER_POLICY_SHA256",
        "BROKER_POLICY_SHA256",
        "PROOF_POLICY_SHA256",
        "APPLICATION_ACTOR_POLICY_SHA256",
        "BROKER_TOPOLOGY_SIGNING_KEY_ARN",
        "BROKER_TOPOLOGY_SIGNATURE_ALGORITHM",
        "EXPECTED_BROKER_TOPOLOGY_SHA256",
    ):
        assert key in environment
    parameters = template["Parameters"]
    assert "BrokerTopologyEvidenceJson" not in parameters
    assert "BrokerTopologyProviderEvidenceDigest" not in parameters
    assert template["Outputs"]["SynchronousClientContextRequired"]["Value"] == (
        "true"
    )
    assert template["Outputs"]["AsynchronousEffectBlocked"]["Value"] == "true"
    assert template["Outputs"]["ProviderTopologyAuthenticationStatus"][
        "Value"
    ] == "KMS_VERIFY_REQUIRED"


_TEMPLATE_VALUES = {
    "AWS::Partition": "aws",
    "AWS::Region": "us-east-1",
    "AuthorityAccountId": "042360977644",
    "IdentityCenterApplicationArn": (
        "arn:aws:sso::839393571433:application/"
        "ssoins-1234567890abcdef/apl-1234567890abcdef"
    ),
    "ExecutionNotBefore": "2030-01-01T00:00:00Z",
    "ExecutionNotAfter": "2030-01-01T00:15:00Z",
    "ExactExecutionId": "gug221-phase-b-" + ("a" * 64),
    "RepairArtifactBucket": "repair-artifacts",
    "RepairArtifactKey": "repair.zip",
    "ReconcileArtifactBucket": "reconcile-artifacts",
    "ReconcileArtifactKey": "reconcile.zip",
    "BrokerTopologySigningKeyArn": TOPOLOGY_SIGNING_KEY_ARN,
}
_POLICY_VALUES = {
    "aws_partition": _TEMPLATE_VALUES["AWS::Partition"],
    "region": _TEMPLATE_VALUES["AWS::Region"],
    "authority_account_id": _TEMPLATE_VALUES["AuthorityAccountId"],
    "identity_center_application_arn": _TEMPLATE_VALUES[
        "IdentityCenterApplicationArn"
    ],
    "execution_not_before": _TEMPLATE_VALUES["ExecutionNotBefore"],
    "execution_not_after": _TEMPLATE_VALUES["ExecutionNotAfter"],
    "execution_id": _TEMPLATE_VALUES["ExactExecutionId"],
    "repair_artifact_bucket": _TEMPLATE_VALUES["RepairArtifactBucket"],
    "repair_artifact_key": _TEMPLATE_VALUES["RepairArtifactKey"],
    "reconcile_artifact_bucket": _TEMPLATE_VALUES[
        "ReconcileArtifactBucket"
    ],
    "reconcile_artifact_key": _TEMPLATE_VALUES["ReconcileArtifactKey"],
    "topology_signing_key_arn": _TEMPLATE_VALUES[
        "BrokerTopologySigningKeyArn"
    ],
}


def _replace_placeholders(value: str, replacements: Mapping[str, str]) -> str:
    result = value
    for key, replacement in replacements.items():
        result = result.replace("${" + key + "}", replacement)
    assert "${" not in result
    return result


def _render_template_value(value: Any) -> Any:
    if isinstance(value, list):
        return [_render_template_value(item) for item in value]
    if isinstance(value, dict):
        if set(value) == {"Ref"}:
            return _TEMPLATE_VALUES[str(value["Ref"])]
        if set(value) == {"Sub"}:
            return _replace_placeholders(
                str(value["Sub"]),
                _TEMPLATE_VALUES,
            )
        return {
            key: _render_template_value(item)
            for key, item in value.items()
        }
    return value


def _render_policy_value(value: Any) -> Any:
    if isinstance(value, list):
        return [_render_policy_value(item) for item in value]
    if isinstance(value, dict):
        return {key: _render_policy_value(item) for key, item in value.items()}
    if isinstance(value, str):
        return _replace_placeholders(value, _POLICY_VALUES)
    return value


def test_template_broker_policy_exactly_matches_canonical_artifact() -> None:
    template = _load_template()
    role = template["Resources"]["PhaseBBrokerExecutionRole"]["Properties"]
    policies = role["Policies"]
    assert [item["PolicyName"] for item in policies] == [
        "Gug221PhaseBBrokerExecution"
    ]
    effective = _render_template_value(policies[0]["PolicyDocument"])
    canonical = json.loads(
        (
            ROOT
            / "policies/iam/"
            "platform-authority-lambda-audit-repair-phase-b-"
            "broker-execution-role.json"
        ).read_text(encoding="utf-8")
    )
    assert effective == _render_policy_value(canonical)


def test_ledger_resource_policy_denies_foreign_writers_keys_and_operations() -> None:
    template = _load_template()
    table = template["Resources"]["PhaseBExecutionLedger"]["Properties"]
    statements = {
        item["Sid"]: item
        for item in table["ResourcePolicy"]["PolicyDocument"]["Statement"]
    }
    exact_broker = {"GetAtt": "PhaseBBrokerExecutionRole.Arn"}
    foreign = statements["DenyLedgerMutationsOutsideExactBroker"]
    assert foreign["Effect"] == "Deny"
    assert foreign["Principal"] == "*"
    assert set(foreign["Action"]) == {
        "dynamodb:PutItem",
        "dynamodb:UpdateItem",
    }
    assert foreign["Condition"]["ArnNotEquals"]["aws:PrincipalArn"] == (
        exact_broker
    )
    wrong_key = statements["DenyAnyForeignLedgerKey"]
    assert wrong_key["Condition"]["ForAnyValue:StringNotEquals"][
        "dynamodb:LeadingKeys"
    ] == [{"Ref": "ExactExecutionId"}]
    unsupported = set(statements["DenyUnsupportedLedgerOperations"]["Action"])
    for action in (
        "dynamodb:DeleteItem",
        "dynamodb:BatchGetItem",
        "dynamodb:BatchWriteItem",
        "dynamodb:ConditionCheckItem",
        "dynamodb:PartiQLSelect",
        "dynamodb:Query",
    ):
        assert action in unsupported
    assert not unsupported.intersection(
        {
            "dynamodb:BatchExecuteStatement",
            "dynamodb:ExecuteStatement",
            "dynamodb:ExecuteTransaction",
            "dynamodb:TransactGetItems",
            "dynamodb:TransactWriteItems",
        }
    )
    transactional = statements["DenyTransactionalLedgerItemOperations"]
    assert transactional["Effect"] == "Deny"
    assert transactional["Principal"] == "*"
    assert set(transactional["Action"]) == {
        "dynamodb:ConditionCheckItem",
        "dynamodb:DeleteItem",
        "dynamodb:GetItem",
        "dynamodb:PutItem",
        "dynamodb:UpdateItem",
    }
    assert transactional["Condition"]["ForAnyValue:StringEquals"][
        "dynamodb:EnclosingOperation"
    ] == ["TransactGetItems", "TransactWriteItems"]
    protected_control_plane = {
        "dynamodb:CreateBackup",
        "dynamodb:DeleteResourcePolicy",
        "dynamodb:DeleteTable",
        "dynamodb:DisableKinesisStreamingDestination",
        "dynamodb:EnableKinesisStreamingDestination",
        "dynamodb:ExportTableToPointInTime",
        "dynamodb:PutResourcePolicy",
        "dynamodb:RestoreTableToPointInTime",
        "dynamodb:TagResource",
        "dynamodb:UntagResource",
        "dynamodb:UpdateContinuousBackups",
        "dynamodb:UpdateContributorInsights",
        "dynamodb:UpdateKinesisStreamingDestination",
        "dynamodb:UpdateTable",
        "dynamodb:UpdateTableReplicaAutoScaling",
        "dynamodb:UpdateTimeToLive",
    }
    control_plane = statements["DenyLedgerControlPlaneMutation"]
    assert control_plane["Effect"] == "Deny"
    assert control_plane["Principal"] == "*"
    assert set(control_plane["Action"]) == protected_control_plane
    expected_policy = topology_collector._expected_ledger_resource_policy(
        _collector_binding()
    )
    expected_statements = {
        item["Sid"]: item for item in expected_policy["Statement"]
    }
    assert (
        set(expected_statements["DenyLedgerControlPlaneMutation"]["Action"])
        == protected_control_plane
    )
    allowed = statements["AllowOnlyExactBrokerLedgerItem"]
    assert allowed["Principal"]["AWS"] == exact_broker
    assert allowed["Condition"]["ForAllValues:StringEquals"][
        "dynamodb:LeadingKeys"
    ] == [{"Ref": "ExactExecutionId"}]
    assert allowed["Condition"]["Null"][
        "dynamodb:EnclosingOperation"
    ] == "true"
    for statement in statements.values():
        if statement["Sid"] != "DenyInsecureLedgerTransport":
            assert statement["Resource"] != "*"


def test_policy_artifacts_keep_proof_and_invoker_least_privileged() -> None:
    invoker = json.loads(
        (
            ROOT
            / "policies/iam/"
            "platform-authority-lambda-audit-repair-phase-b-invoker-role.json"
        ).read_text(encoding="utf-8")
    )
    proof = json.loads(
        (
            ROOT
            / "policies/iam/"
            "platform-authority-lambda-audit-repair-phase-b-proof-role.json"
        ).read_text(encoding="utf-8")
    )
    actor = json.loads(
        (
            ROOT
            / "policies/iam/"
            "platform-authority-lambda-audit-repair-phase-b-"
            "application-actor-policy.json"
        ).read_text(encoding="utf-8")
    )
    broker = json.loads(
        (
            ROOT
            / "policies/iam/"
            "platform-authority-lambda-audit-repair-phase-b-broker-execution-role.json"
        ).read_text(encoding="utf-8")
    )
    allowed = [s for s in invoker["Statement"] if s["Effect"] == "Allow"]
    assert allowed == [
        {
            "Sid": "InvokeOnlyExactQualifiedPhaseBBroker",
            "Effect": "Allow",
            "Action": "lambda:InvokeFunction",
            "Resource": (
                "arn:${aws_partition}:lambda:${region}:${authority_account_id}:"
                f"function:{FUNCTION_NAME}:{FUNCTION_ALIAS}"
            ),
        }
    ]
    assert proof["Statement"] == [
        {
            "Sid": "DenyEveryProofSessionAction",
            "Effect": "Deny",
            "Action": "*",
            "Resource": "*",
        }
    ]
    assert actor["Statement"][0]["Principal"] == {
        "AWS": "${broker_execution_role_arn}"
    }
    serialized = json.dumps(invoker)
    assert "InvokeFunctionUrl" in serialized
    assert "InvokeAsync" in serialized
    assert "cloudformation:*" in serialized
    execute = [
        statement
        for statement in broker["Statement"]
        if statement.get("Action") == "cloudformation:ExecuteChangeSet"
    ]
    assert len(execute) == 1
    assert execute[0]["Condition"]["StringEquals"] == {
        "aws:RequestedRegion": "${region}",
        "cloudformation:ChangeSetName": (
            "gug221-lambda-audit-repair-pep-create"
        ),
    }
    assert "DateGreaterThanEquals" in execute[0]["Condition"]
    assert "DateLessThan" in execute[0]["Condition"]
    assert "lambda:InvokeFunctionUrl" not in json.dumps(broker)
    broker_statements = {
        statement["Sid"]: statement for statement in broker["Statement"]
    }
    direct_ledger = broker_statements["UseOnlyExactOneShotLedgerItem"]
    assert direct_ledger["Condition"]["Null"] == {
        "dynamodb:EnclosingOperation": "true",
        "dynamodb:LeadingKeys": "false",
    }
    transaction_deny = broker_statements[
        "DenyTransactionalLedgerItemOperations"
    ]
    assert set(transaction_deny["Action"]) == {
        "dynamodb:ConditionCheckItem",
        "dynamodb:DeleteItem",
        "dynamodb:GetItem",
        "dynamodb:PutItem",
        "dynamodb:UpdateItem",
    }
    assert transaction_deny["Condition"]["ForAnyValue:StringEquals"][
        "dynamodb:EnclosingOperation"
    ] == ["TransactGetItems", "TransactWriteItems"]
    broker_json = json.dumps(broker)
    for api_name in (
        "dynamodb:BatchExecuteStatement",
        "dynamodb:ExecuteStatement",
        "dynamodb:ExecuteTransaction",
        "dynamodb:TransactGetItems",
        "dynamodb:TransactWriteItems",
    ):
        assert api_name not in broker_json
