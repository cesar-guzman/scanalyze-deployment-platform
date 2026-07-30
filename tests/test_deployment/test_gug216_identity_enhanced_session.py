"""GUG-216 one-shot identity-enhanced session adapter tests."""
from __future__ import annotations

import copy
import importlib.util
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

import tooling.platform_authority_identity_enhanced_session as identity_session_module
from tooling.platform_authority_identity_context_compatibility import (
    AWS_IDENTITY_CONTEXT_POLICY_ARN,
    BLOCKED_ACTION_UNSUPPORTED,
    BROKER_REQUIRED_ACTION,
    CompatibilityDecision,
    canonical_digest,
    evaluate_identity_context_policy,
    load_bundled_policy_snapshot,
)
from tooling.platform_authority_identity_enhanced_session import (
    AUTHORIZATION_CODE_GRANT,
    IDENTITY_CENTER_CONTEXT_PROVIDER_ARN,
    REQUIRED_SCOPES,
    AuthorizationCodeGrant,
    IdentityEnhancedBinding,
    IdentityEnhancedSessionAdapter,
    SessionBoundaryError,
)


REPO_ROOT = Path(__file__).resolve().parents[2]
RETIREMENT_SCRIPT = (
    REPO_ROOT / "scripts/deployment/platform-authority-change-set-retirement.py"
)
ACTOR_POLICY = (
    REPO_ROOT
    / "policies/iam/platform-authority-identity-enhanced-application-actor-policy.json"
)
CLASSIFIER_POLICY = (
    REPO_ROOT
    / "policies/iam/platform-authority-change-set-retirement-classifier-role.json"
)
APPROVER_POLICY = (
    REPO_ROOT / "policies/iam/platform-authority-change-set-retirement-role.json"
)
NOW = datetime(2030, 1, 1, tzinfo=UTC)
ACCOUNT = "111122223333"
MANAGEMENT_ACCOUNT = "999900001111"
REGION = "us-east-1"
INSTANCE_ID = "ssoins-1234567890abcdef"
APPLICATION_ID = "apl-1234567890abcdef"
APPLICATION_ARN = (
    f"arn:aws:sso::{MANAGEMENT_ACCOUNT}:application/{INSTANCE_ID}/{APPLICATION_ID}"
)
IDENTITY_STORE_ARN = (
    f"arn:aws:identitystore::{MANAGEMENT_ACCOUNT}:identitystore/d-1234567890"
)
CLASSIFIER_USER = "00000000-0000-4000-8000-000000000011"
APPROVER_USER = "00000000-0000-4000-8000-000000000022"
CLASSIFIER_SOURCE_ROLE = (
    f"arn:aws:iam::{ACCOUNT}:role/aws-reserved/sso.amazonaws.com/"
    "AWSReservedSSO_ScanalyzeAuthorityRetireClass_0123456789abcdef"
)
APPROVER_SOURCE_ROLE = (
    f"arn:aws:iam::{ACCOUNT}:role/aws-reserved/sso.amazonaws.com/"
    "AWSReservedSSO_ScanalyzeAuthorityRetireApprove_fedcba9876543210"
)
CLASSIFIER_TARGET_ROLE = (
    f"arn:aws:iam::{ACCOUNT}:role/ScanalyzeGug215ClassifierInvoker"
)
APPROVER_TARGET_ROLE = (
    f"arn:aws:iam::{ACCOUNT}:role/ScanalyzeGug215ApproverInvoker"
)


def _compatible() -> CompatibilityDecision:
    document = copy.deepcopy(load_bundled_policy_snapshot())
    document["Statement"][0]["NotAction"].append(BROKER_REQUIRED_ACTION)
    return evaluate_identity_context_policy(
        document,
        policy_arn=AWS_IDENTITY_CONTEXT_POLICY_ARN,
        default_version_id="v13",
        required_action=BROKER_REQUIRED_ACTION,
        reviewed_digest=canonical_digest(document),
    )


@pytest.fixture
def compatible_managed_policy(monkeypatch: pytest.MonkeyPatch) -> None:
    """Model a future reviewed managed-policy version through the real evaluator."""

    monkeypatch.setattr(
        identity_session_module,
        "bundled_compatibility_decision",
        _compatible,
    )


def _binding(**overrides: Any) -> IdentityEnhancedBinding:
    values = {
        "authority_account_id": ACCOUNT,
        "region": REGION,
        "identity_center_application_arn": APPLICATION_ARN,
        "identity_center_instance_arn": f"arn:aws:sso:::instance/{INSTANCE_ID}",
        "identity_store_arn": IDENTITY_STORE_ARN,
        "role_kind": "classifier",
        "expected_user_id": CLASSIFIER_USER,
        "peer_user_id": APPROVER_USER,
        "source_role_arn": CLASSIFIER_SOURCE_ROLE,
        "target_role_arn": CLASSIFIER_TARGET_ROLE,
        "broker_alias": "classify",
        "required_action": BROKER_REQUIRED_ACTION,
        "role_duration_seconds": 900,
        "max_token_lifetime_seconds": 3600,
    }
    values.update(overrides)
    return IdentityEnhancedBinding(**values)


def _grant(**overrides: Any) -> AuthorizationCodeGrant:
    values = {
        "code": "synthetic-code-value",
        "code_verifier": "v" * 64,
        "redirect_uri": "http://127.0.0.1:43119/callback",
        "issued_at": NOW,
        "expires_at": NOW + timedelta(minutes=2),
    }
    values.update(overrides)
    return AuthorizationCodeGrant(**values)


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
            "scope": list(REQUIRED_SCOPES),
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
    def __init__(self) -> None:
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
                    f"arn:aws:sts::{ACCOUNT}:assumed-role/"
                    "ScanalyzeGug215ClassifierInvoker/gug216-0123456789abcdef"
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


class FakeConsumer:
    def __init__(self) -> None:
        self.calls = 0
        self.seen_keys: set[str] = set()
        self.reference: dict[str, Any] | None = None

    def consume(self, *, credentials: dict[str, Any], binding: IdentityEnhancedBinding) -> None:
        self.calls += 1
        self.seen_keys = set(credentials)
        self.reference = credentials
        assert binding.broker_alias == "classify"


def _load_retirement_script() -> ModuleType:
    spec = importlib.util.spec_from_file_location("gug215_retirement_cli", RETIREMENT_SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_current_managed_policy_blocks_before_oidc_sts_or_consumer() -> None:
    oidc, sts, consumer = FakeOidc(), FakeSts(), FakeConsumer()
    adapter = IdentityEnhancedSessionAdapter(oidc_client=oidc, sts_client=sts)
    with pytest.raises(SessionBoundaryError, match=BLOCKED_ACTION_UNSUPPORTED):
        adapter.establish_for_capability(
            binding=_binding(),
            grant=_grant(),
            consumer=consumer,
            now=NOW,
        )
    assert oidc.calls == []
    assert sts.calls == []
    assert consumer.calls == 0


def test_reviewed_synthetic_compatible_flow_is_exact_and_one_shot(
    compatible_managed_policy: None,
) -> None:
    oidc, sts, consumer = FakeOidc(), FakeSts(), FakeConsumer()
    adapter = IdentityEnhancedSessionAdapter(oidc_client=oidc, sts_client=sts)
    grant = _grant()
    receipt = adapter.establish_for_capability(
        binding=_binding(),
        grant=grant,
        consumer=consumer,
        now=NOW,
    )
    assert len(oidc.calls) == 1
    assert oidc.calls[0] == {
        "clientId": APPLICATION_ARN,
        "grantType": AUTHORIZATION_CODE_GRANT,
        "code": "synthetic-code-value",
        "codeVerifier": "v" * 64,
        "redirectUri": "http://127.0.0.1:43119/callback",
        "scope": list(REQUIRED_SCOPES),
    }
    assert len(sts.calls) == 1
    assert sts.calls[0]["RoleArn"] == CLASSIFIER_TARGET_ROLE
    assert sts.calls[0]["DurationSeconds"] == 900
    assert set(sts.calls[0]) == {
        "RoleArn",
        "RoleSessionName",
        "DurationSeconds",
        "ProvidedContexts",
    }
    assert sts.calls[0]["ProvidedContexts"] == [
        {
            "ProviderArn": IDENTITY_CENTER_CONTEXT_PROVIDER_ARN,
            "ContextAssertion": "synthetic-opaque-context-assertion-secret",
        }
    ]
    assert consumer.calls == 1
    assert consumer.seen_keys == {
        "AccessKeyId",
        "SecretAccessKey",
        "SessionToken",
        "Expiration",
    }
    assert consumer.reference == {}
    assert oidc.returned == {}
    assert sts.returned == {}
    assert grant.code == ""
    assert grant.code_verifier == ""
    public = json.dumps(receipt.to_dict(), sort_keys=True)
    assert receipt.status == "IDENTITY_ENHANCED_SESSION_CONSUMED"
    assert receipt.role_kind == "classifier"
    assert receipt.broker_alias == "classify"
    for secret in (
        "synthetic-code-value",
        "synthetic-access-token-secret",
        "synthetic-opaque-context-assertion-secret",
        "synthetic-secret-access-key-value",
        "synthetic-session-token-value",
        CLASSIFIER_USER,
    ):
        assert secret not in public
        assert secret not in repr(receipt)
    with pytest.raises(SessionBoundaryError, match="AUTHORIZATION_CODE_REPLAY"):
        adapter.establish_for_capability(
            binding=_binding(),
            grant=grant,
            consumer=consumer,
            now=NOW,
        )


def test_same_user_cannot_fill_classifier_and_approver_bindings() -> None:
    with pytest.raises(SessionBoundaryError, match="INDEPENDENT_OPERATOR_REQUIRED"):
        _binding(peer_user_id=CLASSIFIER_USER.upper())


@pytest.mark.parametrize(
    "overrides",
    (
        {"role_kind": "approver"},
        {"broker_alias": "retire"},
        {"target_role_arn": APPROVER_TARGET_ROLE},
        {"source_role_arn": APPROVER_SOURCE_ROLE},
        {"required_action": "cloudformation:DeleteChangeSet"},
        {"region": "us_east_1"},
    ),
)
def test_role_capability_or_topology_mismatch_fails_closed(overrides: dict[str, Any]) -> None:
    with pytest.raises(SessionBoundaryError):
        _binding(**overrides)


@pytest.mark.parametrize(
    ("mutation", "code"),
    (
        (lambda r: r.update({"scope": []}), "OIDC_SCOPE_MISMATCH"),
        (
            lambda r: r.update({"scope": ["sts:identity_context", "aws"]}),
            "OIDC_SCOPE_MISMATCH",
        ),
        (lambda r: r.update({"tokenType": "DPoP"}), "OIDC_TOKEN_TYPE_MISMATCH"),
        (
            lambda r: r.update({"expiresIn": 7200}),
            "OIDC_TOKEN_LIFETIME_INVALID",
        ),
        (
            lambda r: r.update({"refreshToken": "forbidden-refresh-secret"}),
            "OIDC_REFRESH_TOKEN_FORBIDDEN",
        ),
        (
            lambda r: r.update({"awsAdditionalDetails": {}}),
            "IDENTITY_CONTEXT_MISSING",
        ),
        (
            lambda r: r.update(
                {"awsAdditionalDetails": {"identityContext": "x" * 4097}}
            ),
            "IDENTITY_CONTEXT_MALFORMED",
        ),
    ),
)
def test_oidc_response_failures_are_sanitized_and_stop_before_sts(
    mutation,
    code: str,
    compatible_managed_policy: None,
) -> None:
    oidc, sts, consumer = FakeOidc(), FakeSts(), FakeConsumer()
    mutation(oidc.response)
    adapter = IdentityEnhancedSessionAdapter(oidc_client=oidc, sts_client=sts)
    with pytest.raises(SessionBoundaryError, match=code):
        adapter.establish_for_capability(
            binding=_binding(),
            grant=_grant(),
            consumer=consumer,
            now=NOW,
        )
    assert len(oidc.calls) == 1
    assert sts.calls == []
    assert consumer.calls == 0
    assert oidc.returned == {}


def test_expired_or_naive_authorization_code_fails_before_oidc(
    compatible_managed_policy: None,
) -> None:
    for grant in (
        _grant(expires_at=NOW - timedelta(seconds=1)),
        _grant(issued_at=datetime(2030, 1, 1), expires_at=datetime(2030, 1, 1, 0, 1)),
    ):
        oidc, sts, consumer = FakeOidc(), FakeSts(), FakeConsumer()
        adapter = IdentityEnhancedSessionAdapter(oidc_client=oidc, sts_client=sts)
        with pytest.raises(SessionBoundaryError):
            adapter.establish_for_capability(
                binding=_binding(),
                grant=grant,
                consumer=consumer,
                now=NOW,
            )
        assert oidc.calls == []
        assert sts.calls == []


def test_ambiguous_oidc_or_sts_response_is_not_retried_and_is_sanitized(
    compatible_managed_policy: None,
) -> None:
    for failing_client in ("oidc", "sts"):
        oidc, sts, consumer = FakeOidc(), FakeSts(), FakeConsumer()
        secret = "secret-that-must-not-escape"
        if failing_client == "oidc":
            oidc.error = RuntimeError(secret)
        else:
            sts.error = RuntimeError(secret)
        adapter = IdentityEnhancedSessionAdapter(oidc_client=oidc, sts_client=sts)
        with pytest.raises(SessionBoundaryError) as captured:
            adapter.establish_for_capability(
                binding=_binding(),
                grant=_grant(),
                consumer=consumer,
                now=NOW,
            )
        assert secret not in str(captured.value)
        assert len(oidc.calls) == 1
        assert len(sts.calls) == (0 if failing_client == "oidc" else 1)
        assert consumer.calls == 0
        if failing_client == "oidc":
            assert oidc.returned is None
        else:
            assert oidc.returned == {}
        assert sts.returned is None


def test_wrong_sts_role_or_expiration_never_reaches_consumer(
    compatible_managed_policy: None,
) -> None:
    cases = (
        {
            "AssumedRoleUser": {
                "Arn": f"arn:aws:sts::{ACCOUNT}:assumed-role/Foreign/gug216-0123456789abcdef"
            }
        },
        {
            "Credentials": {
                "AccessKeyId": "ASIA" + "A" * 16,
                "SecretAccessKey": "secret",
                "SessionToken": "token",
                "Expiration": NOW + timedelta(hours=2),
            }
        },
    )
    for override in cases:
        oidc, sts, consumer = FakeOidc(), FakeSts(), FakeConsumer()
        sts.response.update(override)
        adapter = IdentityEnhancedSessionAdapter(oidc_client=oidc, sts_client=sts)
        with pytest.raises(SessionBoundaryError):
            adapter.establish_for_capability(
                binding=_binding(),
                grant=_grant(),
                consumer=consumer,
                now=NOW,
            )
        assert consumer.calls == 0
        assert sts.returned == {}


def test_application_actor_policy_and_source_policies_are_least_privilege() -> None:
    actor = json.loads(ACTOR_POLICY.read_text(encoding="utf-8"))
    assert actor["Statement"] == [
        {
            "Sid": "AllowExactRetirementSourceRolesToCreateToken",
            "Effect": "Allow",
            "Principal": {
                "AWS": [
                    "${classifier_permission_set_role_arn}",
                    "${approver_permission_set_role_arn}",
                ]
            },
            "Action": "sso-oauth:CreateTokenWithIAM",
            "Resource": "*",
        }
    ]
    for path in (CLASSIFIER_POLICY, APPROVER_POLICY):
        policy = json.loads(path.read_text(encoding="utf-8"))
        allows = [s for s in policy["Statement"] if s["Effect"] == "Allow"]
        actions = {
            action
            for statement in allows
            for action in (
                statement["Action"]
                if isinstance(statement["Action"], list)
                else [statement["Action"]]
            )
        }
        assert actions == {
            "sso-oauth:CreateTokenWithIAM",
            "sts:AssumeRole",
            "sts:SetContext",
        }
        token_allow = next(
            statement
            for statement in allows
            if statement["Action"] == "sso-oauth:CreateTokenWithIAM"
        )
        assert token_allow["Resource"].endswith(
            "application/${identity_center_instance_id}/${identity_center_application_id}"
        )
        direct_effect_deny = next(
            statement
            for statement in policy["Statement"]
            if statement["Sid"] == "DenyDirectRetirementEffects"
        )
        assert {
            "lambda:InvokeAsync",
            "lambda:InvokeFunction",
        } <= set(direct_effect_deny["Action"])


def test_gug215_cli_rejects_ordinary_profile_before_any_broker_invocation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _load_retirement_script()
    monkeypatch.setenv("AWS_PROFILE", "synthetic-readonly")
    args = module._parser().parse_args(
        [
            "broker-classify",
            "--authority-account-id",
            ACCOUNT,
            "--region",
            REGION,
            "--allow-broker-classification",
        ]
    )
    with pytest.raises(Exception, match=BLOCKED_ACTION_UNSUPPORTED):
        args.handler(args)
