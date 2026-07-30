"""GUG-217 identity-context-compatible retirement PEP tests."""
from __future__ import annotations

import copy
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
import yaml

from tooling.platform_authority_identity_context_pep import (
    ALLOWED_ALIASES,
    COMPATIBLE_PROOF_ONLY_TRANSPORT,
    IDENTITY_CENTER_CONTEXT_PROVIDER_ARN,
    PROOF_REQUIRED_ACTION,
    IdentityContextPep,
    IdentityContextPepBinding,
    IdentityContextProofVerifier,
    ProofBoundaryError,
    proof_compatibility_decision,
)
from tooling import platform_authority_identity_context_pep_runtime as runtime
from tooling.validate_policy import validate_policy


REPO_ROOT = Path(__file__).resolve().parents[2]
TEMPLATE = REPO_ROOT / "bootstrap/cfn-platform-authority-change-set-retirement-ledger.yaml"
ACTOR_POLICY = (
    REPO_ROOT
    / "policies/iam/platform-authority-identity-context-pep-application-actor-policy.json"
)
CLASSIFIER_POLICY = (
    REPO_ROOT / "policies/iam/platform-authority-identity-context-pep-classifier-role.json"
)
APPROVER_POLICY = (
    REPO_ROOT / "policies/iam/platform-authority-identity-context-pep-approver-role.json"
)
BINDING_FIXTURE = (
    REPO_ROOT
    / "fixtures/valid/platform-authority-identity-context-pep-binding-v1-synthetic.json"
)
COMPATIBILITY_FIXTURE = (
    REPO_ROOT
    / "fixtures/valid/platform-authority-identity-context-pep-compatibility-receipt-v1-synthetic.json"
)

NOW = datetime(2030, 1, 1, tzinfo=UTC)
AUTHORITY_ACCOUNT = "111122223333"
MANAGEMENT_ACCOUNT = "999900001111"
REGION = "us-east-1"
INSTANCE_ID = "ssoins-1234567890abcdef"
APPLICATION_ID = "apl-1234567890abcdef"
CLASSIFIER_USER = "00000000-0000-4000-8000-000000000011"
APPROVER_USER = "00000000-0000-4000-8000-000000000022"
APPLICATION_ARN = (
    f"arn:aws:sso::{MANAGEMENT_ACCOUNT}:application/{INSTANCE_ID}/{APPLICATION_ID}"
)
IDENTITY_STORE_ARN = (
    f"arn:aws:identitystore::{MANAGEMENT_ACCOUNT}:identitystore/d-1234567890"
)
BROKER_ROLE_ARN = (
    f"arn:aws:iam::{AUTHORITY_ACCOUNT}:role/ScanalyzeGug215BrokerExecution"
)
CLASSIFIER_PROOF_ROLE_ARN = (
    f"arn:aws:iam::{AUTHORITY_ACCOUNT}:role/ScanalyzeGug217ClassifierProof"
)
APPROVER_PROOF_ROLE_ARN = (
    f"arn:aws:iam::{AUTHORITY_ACCOUNT}:role/ScanalyzeGug217ApproverProof"
)


def _binding(**overrides: Any) -> IdentityContextPepBinding:
    values = {
        "authority_account_id": AUTHORITY_ACCOUNT,
        "region": REGION,
        "identity_center_application_arn": APPLICATION_ARN,
        "identity_center_instance_arn": f"arn:aws:sso:::instance/{INSTANCE_ID}",
        "identity_store_arn": IDENTITY_STORE_ARN,
        "redirect_uri": "http://127.0.0.1:43119/callback",
        "broker_execution_role_arn": BROKER_ROLE_ARN,
        "classifier_user_id": CLASSIFIER_USER,
        "approver_user_id": APPROVER_USER,
        "classifier_proof_role_arn": CLASSIFIER_PROOF_ROLE_ARN,
        "approver_proof_role_arn": APPROVER_PROOF_ROLE_ARN,
        "proof_duration_seconds": 900,
        "max_token_lifetime_seconds": 900,
    }
    values.update(overrides)
    return IdentityContextPepBinding(**values)


def _verifier(
    oidc: FakeOidc,
    sts: FakeSts,
    *,
    clock: Any = None,
) -> IdentityContextProofVerifier:
    return IdentityContextProofVerifier(
        oidc_client=oidc,
        sts_client=sts,
        clock=clock or (lambda: NOW),
    )


def _event(**body_overrides: Any) -> dict[str, Any]:
    body = {
        "schema_version": "1",
        "record_type": "platform_authority_identity_context_pep_request",
        "authorization_code": "synthetic-one-time-authorization-code",
        "code_verifier": "v" * 64,
    }
    body.update(body_overrides)
    return {
        "version": "2.0",
        "routeKey": "$default",
        "rawPath": "/",
        "rawQueryString": "",
        "headers": {"content-type": "application/json"},
        "requestContext": {"http": {"method": "POST"}},
        "body": json.dumps(body),
        "isBase64Encoded": False,
    }


class FakeOidc:
    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []
        self.returned: dict[str, Any] | None = None
        self.response: dict[str, Any] = {
            "accessToken": "synthetic-access-token-secret",
            "awsAdditionalDetails": {
                "identityContext": "synthetic-opaque-context-assertion-secret"
            },
            "expiresIn": 900,
            "scope": ["sts:identity_context"],
            "tokenType": "Bearer",
        }
        self.error: Exception | None = None

    def create_token_with_iam(self, **kwargs: Any) -> dict[str, Any]:
        self.calls.append(kwargs)
        if self.error is not None:
            raise self.error
        self.returned = copy.deepcopy(self.response)
        return self.returned


class FakeSts:
    def __init__(self, role_name: str = "ScanalyzeGug217ClassifierProof") -> None:
        self.calls: list[dict[str, Any]] = []
        self.returned: dict[str, Any] | None = None
        self.response: dict[str, Any] = {
            "Credentials": {
                "AccessKeyId": "ASIA" + "A" * 16,
                "SecretAccessKey": "synthetic-secret-access-key-value",
                "SessionToken": "synthetic-session-token-value",
                "Expiration": NOW + timedelta(minutes=15),
            },
            "AssumedRoleUser": {
                "Arn": (
                    f"arn:aws:sts::{AUTHORITY_ACCOUNT}:assumed-role/"
                    f"{role_name}/gug217-0123456789abcdef"
                )
            },
        }
        self.error: Exception | None = None

    def assume_role(self, **kwargs: Any) -> dict[str, Any]:
        self.calls.append(kwargs)
        if self.error is not None:
            raise self.error
        self.returned = copy.deepcopy(self.response)
        return self.returned


class FakeBroker:
    def __init__(self) -> None:
        self.preflight_calls: list[str] = []
        self.calls: list[dict[str, Any]] = []

    def preflight(self, *, alias: str) -> None:
        self.preflight_calls.append(alias)

    def handle(
        self,
        *,
        alias: str,
        event: object,
        identity_proof_sha256: str,
    ) -> dict[str, Any]:
        self.calls.append(
            {
                "alias": alias,
                "event": event,
                "identity_proof_sha256": identity_proof_sha256,
            }
        )
        return {"status": "CLASSIFIED", "ledger_digest": "sha256:" + "a" * 64}


def test_v12_supports_only_the_zero_authority_sts_proof_step() -> None:
    decision = proof_compatibility_decision()
    assert decision.status == COMPATIBLE_PROOF_ONLY_TRANSPORT
    assert decision.required_action == PROOF_REQUIRED_ACTION == "sts:SetContext"
    assert decision.policy_version == "v12"
    assert decision.policy_digest == (
        "sha256:588e10587ff62c683615a9612b1f42ded9fccd03bd94810dc6760dad50665655"
    )
    assert decision.live_effect_authorized is False
    assert decision.to_receipt(observed_at=NOW) == json.loads(
        COMPATIBILITY_FIXTURE.read_text(encoding="utf-8")
    )


@pytest.mark.parametrize(
    "overrides,reason",
    [
        ({"approver_user_id": CLASSIFIER_USER}, "INDEPENDENT_OPERATOR_REQUIRED"),
        ({"redirect_uri": "https://example.invalid/callback"}, "REDIRECT_URI_INVALID"),
        ({"proof_duration_seconds": 901}, "PROOF_DURATION_INVALID"),
        (
            {"classifier_proof_role_arn": APPROVER_PROOF_ROLE_ARN},
            "PROOF_ROLE_BINDING_INVALID",
        ),
    ],
)
def test_binding_fails_closed(overrides: dict[str, Any], reason: str) -> None:
    with pytest.raises(ProofBoundaryError, match=reason):
        _binding(**overrides)


def test_typed_binding_matches_the_versioned_internal_contract() -> None:
    assert _binding().to_dict() == json.loads(
        BINDING_FIXTURE.read_text(encoding="utf-8")
    )


def test_classifier_proof_is_exact_one_shot_and_credentials_are_never_consumed() -> None:
    oidc, sts = FakeOidc(), FakeSts()
    event = _event()
    verifier = _verifier(oidc, sts)

    receipt = verifier.verify(
        alias="classify",
        event=event,
        binding=_binding(),
        now=NOW,
    )

    assert receipt.status == "IDENTITY_CONTEXT_PROOF_VERIFIED"
    assert receipt.role_kind == "classifier"
    assert receipt.broker_alias == "classify"
    assert receipt.credentials_consumed is False
    assert receipt.live_retirement_authorized is False
    assert oidc.calls == [
        {
            "clientId": APPLICATION_ARN,
            "grantType": "authorization_code",
            "code": "synthetic-one-time-authorization-code",
            "codeVerifier": "v" * 64,
            "redirectUri": "http://127.0.0.1:43119/callback",
            "scope": ["sts:identity_context"],
        }
    ]
    assert sts.calls[0]["RoleArn"] == CLASSIFIER_PROOF_ROLE_ARN
    assert sts.calls[0]["ProvidedContexts"] == [
        {
            "ProviderArn": IDENTITY_CENTER_CONTEXT_PROVIDER_ARN,
            "ContextAssertion": "synthetic-opaque-context-assertion-secret",
        }
    ]
    assert oidc.returned == {}
    assert sts.returned == {}
    assert event["body"] == ""
    assert "authorization_code" not in repr(receipt)
    assert "identityContext" not in repr(receipt)


def test_sts_expiration_uses_the_fresh_assume_role_window() -> None:
    oidc, sts = FakeOidc(), FakeSts()
    sts.response["Credentials"]["Expiration"] = NOW + timedelta(seconds=902)
    observed = iter((NOW + timedelta(seconds=2), NOW + timedelta(seconds=3)))

    receipt = _verifier(oidc, sts, clock=lambda: next(observed)).verify(
        alias="classify",
        event=_event(),
        binding=_binding(),
        now=NOW,
    )

    assert receipt.status == "IDENTITY_CONTEXT_PROOF_VERIFIED"
    assert receipt.proof_expires_at == "2030-01-01T00:15:02Z"


def test_sts_expiration_cannot_exceed_duration_plus_clock_skew() -> None:
    oidc, sts = FakeOidc(), FakeSts()
    sts.response["Credentials"]["Expiration"] = NOW + timedelta(seconds=933)
    observed = iter((NOW + timedelta(seconds=2), NOW + timedelta(seconds=3)))

    with pytest.raises(ProofBoundaryError, match="STS_EXPIRATION_INVALID"):
        _verifier(oidc, sts, clock=lambda: next(observed)).verify(
            alias="classify",
            event=_event(),
            binding=_binding(),
            now=NOW,
        )


@pytest.mark.parametrize("alias", ["retire", "reconcile"])
def test_approver_aliases_use_only_the_approver_proof_role(alias: str) -> None:
    oidc, sts = FakeOidc(), FakeSts("ScanalyzeGug217ApproverProof")
    receipt = _verifier(oidc, sts).verify(
        alias=alias,
        event=_event(),
        binding=_binding(),
        now=NOW,
    )
    assert receipt.role_kind == "independent_approver"
    assert sts.calls[0]["RoleArn"] == APPROVER_PROOF_ROLE_ARN


@pytest.mark.parametrize(
    "body_override",
    [
        {"user_id": APPROVER_USER},
        {"target": "foreign-change-set"},
        {"action": "retire"},
        {"aws_profile": "synthetic-approver"},
        {"authorization_code": ""},
        {"expires_at": "2030-01-01T00:10:00Z"},
    ],
)
def test_payload_cannot_establish_authority_or_escape_one_shot_bounds(
    body_override: dict[str, Any],
) -> None:
    oidc, sts = FakeOidc(), FakeSts()
    with pytest.raises(ProofBoundaryError):
        _verifier(oidc, sts).verify(
            alias="classify",
            event=_event(**body_override),
            binding=_binding(),
            now=NOW,
        )
    assert oidc.calls == []
    assert sts.calls == []


@pytest.mark.parametrize(
    "event_override",
    [
        {"rawPath": "/retire"},
        {"rawQueryString": "action=retire"},
        {"isBase64Encoded": True},
        {"requestContext": {"http": {"method": "GET"}}},
    ],
)
def test_function_url_transport_is_post_only_and_has_no_routing_input(
    event_override: dict[str, Any],
) -> None:
    event = _event()
    event.update(event_override)
    oidc, sts = FakeOidc(), FakeSts()
    with pytest.raises(ProofBoundaryError):
        _verifier(oidc, sts).verify(
            alias="classify", event=event, binding=_binding(), now=NOW
        )
    assert oidc.calls == []
    assert sts.calls == []


def test_oidc_or_sts_uncertainty_never_reaches_the_retirement_broker() -> None:
    for boundary in ("oidc", "sts"):
        oidc, sts, broker = FakeOidc(), FakeSts(), FakeBroker()
        if boundary == "oidc":
            oidc.error = RuntimeError("synthetic secret response")
        else:
            sts.error = RuntimeError("synthetic secret response")
        pep = IdentityContextPep(
            verifier=_verifier(oidc, sts),
            broker=broker,
        )
        with pytest.raises(ProofBoundaryError, match="_UNCERTAIN"):
            pep.execute(alias="classify", event=_event(), binding=_binding(), now=NOW)
        assert broker.calls == []


def test_verified_proof_enters_existing_broker_with_an_empty_authority_payload() -> None:
    broker = FakeBroker()
    pep = IdentityContextPep(
        verifier=_verifier(FakeOidc(), FakeSts()),
        broker=broker,
    )
    result = pep.execute(alias="classify", event=_event(), binding=_binding(), now=NOW)
    assert broker.calls == [
        {
            "alias": "classify",
            "event": {},
            "identity_proof_sha256": result["identity_proof"]["receipt_digest"],
        }
    ]
    assert broker.preflight_calls == ["classify"]
    assert result["status"] == "CLASSIFIED"
    assert result["identity_proof"]["status"] == "IDENTITY_CONTEXT_PROOF_VERIFIED"
    assert result["identity_proof"]["live_retirement_authorized"] is False


def test_boundary_preflight_failure_stops_before_oauth_or_sts() -> None:
    class DeniedBroker(FakeBroker):
        def preflight(self, *, alias: str) -> None:
            del alias
            raise ProofBoundaryError("EFFECTIVE_BOUNDARY_CHANGED")

    oidc, sts = FakeOidc(), FakeSts()
    pep = IdentityContextPep(
        verifier=_verifier(oidc, sts),
        broker=DeniedBroker(),
    )
    with pytest.raises(ProofBoundaryError, match="EFFECTIVE_BOUNDARY_CHANGED"):
        pep.execute(alias="classify", event=_event(), binding=_binding(), now=NOW)
    assert oidc.calls == []
    assert sts.calls == []


def test_new_policies_keep_humans_and_proof_sessions_out_of_effects() -> None:
    actor = json.loads(ACTOR_POLICY.read_text(encoding="utf-8"))
    assert actor["Statement"] == [
        {
            "Sid": "AllowExactBrokerToCreateToken",
            "Effect": "Allow",
            "Principal": {"AWS": "${broker_execution_role_arn}"},
            "Action": "sso-oauth:CreateTokenWithIAM",
            "Resource": "*",
        }
    ]
    for path, expected_role in (
        (CLASSIFIER_POLICY, "ScanalyzeGug215ClassifierInvoker"),
        (APPROVER_POLICY, "ScanalyzeGug215ApproverInvoker"),
    ):
        policy = json.loads(path.read_text(encoding="utf-8"))
        allow = [s for s in policy["Statement"] if s["Effect"] == "Allow"]
        assert allow == [
            {
                "Sid": "AssumeExactSynchronousInvoker",
                "Effect": "Allow",
                "Action": "sts:AssumeRole",
                "Resource": (
                    "arn:${aws_partition}:iam::${authority_account_id}:role/"
                    + expected_role
                ),
            }
        ]
        deny_actions = {
            action
            for statement in policy["Statement"]
            if statement["Effect"] == "Deny"
            for action in statement["Action"]
        }
        assert {
            "cloudformation:DeleteChangeSet",
            "dynamodb:PutItem",
            "lambda:InvokeAsync",
            "lambda:InvokeFunction",
            "lambda:InvokeFunctionUrl",
            "sso-oauth:CreateTokenWithIAM",
            "sts:SetContext",
        } <= deny_actions


def test_policy_validator_accepts_only_deny_all_not_allow_all() -> None:
    deny_all = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Deny", "Action": "*", "Resource": "*"},
        ],
    }
    allow_all = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Action": "*", "Resource": "*"},
        ],
    }
    assert validate_policy(deny_all, "deny-all.json") == []
    assert any(
        "too broad" in error
        for error in validate_policy(allow_all, "allow-all.json")
    )


def test_template_uses_synchronous_function_urls_and_zero_authority_proof_roles() -> None:
    source = TEMPLATE.read_text(encoding="utf-8")
    assert "AWS::Lambda::Url" in source
    assert source.count("InvokeMode: BUFFERED") == 3
    assert source.count("FunctionUrlAuthType: AWS_IAM") >= 3
    assert "ScanalyzeGug217ClassifierProof" in source
    assert "ScanalyzeGug217ApproverProof" in source
    assert "Gug217ZeroAuthorityProof" in source
    assert "Action: '*'" in source
    assert "Effect: Deny" in source
    assert "sts:RequestContext/identitystore:UserId" in source
    assert "sso-oauth:CreateTokenWithIAM" in source
    assert "opensearch" not in source.lower()
    assert "athena" not in source.lower()


def test_cloudformation_function_url_resources_are_parseable_and_closed() -> None:
    class CloudFormationLoader(yaml.SafeLoader):
        pass

    def construct_intrinsic(
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

    CloudFormationLoader.add_multi_constructor("!", construct_intrinsic)
    template = yaml.load(
        TEMPLATE.read_text(encoding="utf-8"), Loader=CloudFormationLoader
    )
    resources = template["Resources"]
    urls = [
        resource
        for resource in resources.values()
        if resource.get("Type") == "AWS::Lambda::Url"
    ]
    assert len(urls) == 3
    for url in urls:
        assert set(url["Properties"]) == {
            "AuthType",
            "InvokeMode",
            "Qualifier",
            "TargetFunctionArn",
        }
        assert url["Properties"]["AuthType"] == "AWS_IAM"
        assert url["Properties"]["InvokeMode"] == "BUFFERED"
        assert url["Properties"]["Qualifier"] in ALLOWED_ALIASES
    permissions = [
        resource
        for resource in resources.values()
        if resource.get("Type") == "AWS::Lambda::Permission"
    ]
    assert len(permissions) == 6
    assert {permission["Properties"]["Action"] for permission in permissions} == {
        "lambda:InvokeFunction",
        "lambda:InvokeFunctionUrl",
    }
    assert all("Qualifier" not in permission["Properties"] for permission in permissions)


def _runtime_config() -> SimpleNamespace:
    return SimpleNamespace(
        authority_account_id=AUTHORITY_ACCOUNT,
        region=REGION,
        identity_center_application_arn=APPLICATION_ARN,
        identity_center_instance_arn=f"arn:aws:sso:::instance/{INSTANCE_ID}",
        identity_store_arn=IDENTITY_STORE_ARN,
        execution_role_arn=BROKER_ROLE_ARN,
        classifier_identity_store_user_id=CLASSIFIER_USER,
        approver_identity_store_user_id=APPROVER_USER,
        classifier_proof_role_arn=CLASSIFIER_PROOF_ROLE_ARN,
        approver_proof_role_arn=APPROVER_PROOF_ROLE_ARN,
    )


def test_runtime_handler_uses_the_exact_alias_and_returns_only_sanitized_evidence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class FixedDatetime(datetime):
        @classmethod
        def now(cls, tz: object = None) -> datetime:
            del tz
            return NOW

    oidc, sts, broker = FakeOidc(), FakeSts(), FakeBroker()
    monkeypatch.setenv(
        "IDENTITY_CENTER_REDIRECT_URI", "http://127.0.0.1:43119/callback"
    )
    monkeypatch.setattr(
        runtime.BrokerConfig, "from_environment", staticmethod(_runtime_config)
    )
    monkeypatch.setattr(
        runtime.BotoClients,
        "create",
        lambda region: SimpleNamespace(sso_oidc=oidc, sts=sts),
    )
    monkeypatch.setattr(
        runtime,
        "RetirementBroker",
        lambda *, config, clients: broker,
    )
    monkeypatch.setattr(runtime, "datetime", FixedDatetime)

    response = runtime.handler(
        _event(),
        SimpleNamespace(
            invoked_function_arn=(
                f"arn:aws:lambda:{REGION}:{AUTHORITY_ACCOUNT}:function:"
                "scanalyze-platform-authority-gug215-retirement:classify"
            )
        ),
    )

    assert response["statusCode"] == 200
    assert response["headers"]["cache-control"] == "no-store"
    assert response["isBase64Encoded"] is False
    body = json.loads(response["body"])
    assert body["status"] == "CLASSIFIED"
    assert body["identity_proof"]["status"] == "IDENTITY_CONTEXT_PROOF_VERIFIED"
    serialized = json.dumps(response, sort_keys=True)
    for secret in (
        "synthetic-one-time-authorization-code",
        "synthetic-access-token-secret",
        "synthetic-opaque-context-assertion-secret",
        "synthetic-secret-access-key-value",
        "synthetic-session-token-value",
        CLASSIFIER_USER,
        APPROVER_USER,
    ):
        assert secret not in serialized


def test_runtime_handler_sanitizes_proof_and_internal_failures(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        runtime.BrokerConfig, "from_environment", staticmethod(_runtime_config)
    )
    monkeypatch.setenv(
        "IDENTITY_CENTER_REDIRECT_URI", "http://127.0.0.1:43119/callback"
    )
    for error, expected_status, expected_reason in (
        (
            ProofBoundaryError("OIDC_EXCHANGE_UNCERTAIN"),
            403,
            "OIDC_EXCHANGE_UNCERTAIN",
        ),
        (RuntimeError("synthetic secret failure"), 500, "IDENTITY_CONTEXT_PEP_INTERNAL_ERROR"),
    ):
        monkeypatch.setattr(
            runtime.BotoClients,
            "create",
            lambda region, error=error: (_ for _ in ()).throw(error),
        )
        response = runtime.handler({}, SimpleNamespace(invoked_function_arn="secret"))
        assert response["statusCode"] == expected_status
        assert json.loads(response["body"]) == {
            "status": "DENY",
            "reason_code": expected_reason,
        }
        assert "synthetic secret" not in json.dumps(response)
