"""Offline JWT runtime -> broker -> real proof verifier integration.

Only provider ports are synthetic. JWT signature/replay acceptance belongs to
AWS Identity Center; the fake SDK's success is never live identity evidence.
No AWS client, credential lookup, signature verifier stub or network is used.
"""
from __future__ import annotations

import base64
import copy
from dataclasses import FrozenInstanceError, replace
from datetime import timedelta
import itertools
import json
import re

import pytest

from tests.test_deployment import test_gug274_bootstrap_artifact_trust_root as fixtures
from tooling.platform_authority_bootstrap import BootstrapAuthorizationError
from tooling.platform_authority_bootstrap_artifact_authority import (
    BootstrapArtifactAuthorityBroker,
    BootstrapArtifactAuthorityError,
    BootstrapArtifactAuthorityRuntimeConfig,
    validate_authority_ledger,
)
from tooling.platform_authority_bootstrap_identity_proof import (
    BootstrapIdentityProofVerifier,
    validate_identity_proof_receipt,
)
from tooling.platform_authority_bootstrap_jwt_grant import (
    JWT_BEARER_GRANT,
    JwtBearerBinding,
    operation_binding_digest,
)


NOW = fixtures.NOW
EPOCH = int(NOW.timestamp())
JWT_ENVIRONMENT = {
    "GUG274_JWT_TRUSTED_TOKEN_ISSUER_ARN": (
        "arn:aws:sso::111122223333:trustedTokenIssuer/"
        "ssoins-1234567890abcdef/tti-11111111-2222-3333-4444-555555555555"
    ),
    "GUG274_JWT_ISSUER_URL": "https://synthetic-issuer.example.test/identity",
    "GUG274_JWT_AUDIENCE": "synthetic:gug274-authority",
}
OPERATIONS = ("plan", "approval", "apply")


def runtime_environment():
    return fixtures._runtime_environment() | {
        "GUG274_IDENTITY_GRANT_VERSION": "2",
    } | JWT_ENVIRONMENT


def jwt_envelope(nonce, *, changes=None, header=None):
    claims = {
        "iss": JWT_ENVIRONMENT["GUG274_JWT_ISSUER_URL"],
        "aud": JWT_ENVIRONMENT["GUG274_JWT_AUDIENCE"],
        "sub": "synthetic-person", "jti": "synthetic-one-shot-" + nonce,
        "nonce": nonce, "iat": EPOCH, "exp": EPOCH + 900, "auth_time": EPOCH,
    } | (changes or {})

    def segment(value):
        return base64.urlsafe_b64encode(json.dumps(value, separators=(",", ":")).encode()).decode().rstrip("=")

    # Syntactically valid bytes, deliberately not a cryptographic signature.
    assertion = ".".join((
        segment(header or {"alg": "RS256", "kid": "synthetic-key", "typ": "JWT"}),
        segment(claims),
        base64.urlsafe_b64encode(b"synthetic-signature-not-identity-proof").decode().rstrip("="),
    ))
    return {
        "schema_version": "2", "record_type": "platform_authority_bootstrap_identity_grant",
        "grant_type": JWT_BEARER_GRANT, "assertion": assertion,
    }


def legacy_envelope():
    return {
        "schema_version": "1", "record_type": "platform_authority_bootstrap_identity_grant",
        "authorization_code": "synthetic-one-shot-code", "code_verifier": "v" * 43,
    }


class FakeSDK:
    """Provider boundary, including simulated AWS signature/replay denials."""

    def __init__(self, events):
        self.events = events
        self.now = NOW
        self.oidc_calls = []
        self.sts_calls = []
        self.oidc_responses = []
        self.sts_responses = []
        self.seen_assertions = set()
        self.oidc_error = None
        self.sts_error = False
        self.transform_oidc = lambda response: response
        self.transform_sts = lambda response: response
        self.after_oidc = lambda: None

    def create_token_with_iam(self, **kwargs):
        self.events.append("oidc:exchange")
        self.oidc_calls.append(copy.deepcopy(kwargs))
        if self.oidc_error is not None:
            raise RuntimeError("synthetic-provider-private-detail:" + self.oidc_error)
        if kwargs["grantType"] == JWT_BEARER_GRANT:
            assertion = kwargs["assertion"]
            if assertion in self.seen_assertions:
                raise RuntimeError("synthetic-provider-private-detail:replayed-jti")
            self.seen_assertions.add(assertion)
        response = self.transform_oidc({
            "accessToken": "synthetic-opaque-access-token", "tokenType": "Bearer",
            "expiresIn": 900, "scope": ["sts:identity_context"],
            "awsAdditionalDetails": {"identityContext": "synthetic-opaque-identity-context"},
        })
        self.oidc_responses.append(response)
        self.after_oidc()
        return response

    def assume_role(self, **kwargs):
        self.events.append("sts:proof")
        self.sts_calls.append(copy.deepcopy(kwargs))
        if self.sts_error:
            raise RuntimeError("synthetic-provider-private-detail:sts-denied")
        role = kwargs["RoleArn"].rsplit("/", 1)[1]
        response = self.transform_sts({
            "AssumedRoleUser": {"Arn": (
                f"arn:aws:sts::111122223333:assumed-role/{role}/{kwargs['RoleSessionName']}"
            )},
            "Credentials": {
                "AccessKeyId": "synthetic-access-key", "SecretAccessKey": "synthetic-secret-key",
                "SessionToken": "synthetic-session-token", "Expiration": self.now + timedelta(seconds=900),
            },
        })
        self.sts_responses.append(response)
        return response


class Harness:
    def __init__(self):
        self.config = BootstrapArtifactAuthorityRuntimeConfig.from_environment(runtime_environment())
        self.events = []
        self.sdk = FakeSDK(self.events)
        self.store = fixtures.FakeStore(self.events)
        self.effects = fixtures.FakeEffectsFactory(self.events)
        self.verifier = BootstrapIdentityProofVerifier(
            oidc_client=self.sdk, sts_client=self.sdk, clock=lambda: self.sdk.now,
        )
        self.broker = BootstrapArtifactAuthorityBroker(
            binding=self.config.binding, identity_binding=self.config.identity_binding,
            identity_verifier=self.verifier, store=self.store, now=lambda: self.sdk.now,
            effects_factory=self.effects,
        )
        self.plan = fixtures._plan()
        self.approval = fixtures._approval(self.plan)

    def nonce(self, operation):
        return operation_binding_digest(
            operation, self.plan["plan_artifact_digest"],
            self.approval["approval_artifact_digest"] if operation != "plan" else None,
        )

    def invoke(self, operation, grant):
        if operation == "plan":
            return self.broker.anchor_plan(self.plan, grant)
        if operation == "approval":
            return self.broker.approve_plan(self.plan, self.approval, grant)
        return self.broker.claim_and_execute(self.plan, self.approval, grant)

    def prepare(self, operation):
        for earlier in OPERATIONS[:OPERATIONS.index(operation)]:
            self.invoke(earlier, jwt_envelope(self.nonce(earlier)))
        self.events.clear()
        self.sdk.oidc_calls.clear()
        self.sdk.sts_calls.clear()
        self.sdk.oidc_responses.clear()
        self.sdk.sts_responses.clear()


@pytest.mark.parametrize("operation", OPERATIONS)
def test_real_broker_derives_nonce_exchanges_exact_jwt_and_proves_before_effects(operation, capsys):
    h = Harness()
    h.prepare(operation)
    grant = jwt_envelope(h.nonce(operation))
    assertion = grant["assertion"]
    result = h.invoke(operation, grant)
    assert grant == {}
    assert h.sdk.oidc_calls == [{
        "clientId": h.config.identity_binding.identity_center_application_arn,
        "grantType": JWT_BEARER_GRANT, "assertion": assertion, "scope": ["sts:identity_context"],
    }]
    sts_request, = h.sdk.sts_calls
    assert set(sts_request) == {"RoleArn", "RoleSessionName", "DurationSeconds", "ProvidedContexts"}
    assert sts_request["RoleArn"] == getattr(h.config.identity_binding, operation + "_proof_role_arn")
    assert re.fullmatch(r"gug274-" + operation + r"-[a-f0-9]{12}", sts_request["RoleSessionName"])
    assert sts_request["DurationSeconds"] == 900
    assert sts_request["ProvidedContexts"] == [{
        "ProviderArn": "arn:aws:iam::aws:contextProvider/IdentityCenter",
        "ContextAssertion": "synthetic-opaque-identity-context",
    }]
    assert h.sdk.oidc_responses == [{}] and h.sdk.sts_responses == [{}]
    expected_events = {
        "plan": ["oidc:exchange", "sts:proof", "store:create"],
        "approval": ["oidc:exchange", "sts:proof", "store:get", "store:cas"],
        "apply": ["oidc:exchange", "sts:proof", "store:get", "store:cas", "effects:construct", "effects:execute"],
    }
    assert h.events == expected_events[operation]
    record = validate_authority_ledger(record=h.store.record, binding=h.config.binding)
    proof = record[operation + "_identity_proof"]
    validate_identity_proof_receipt(proof, operation=operation, now=NOW)
    assert proof["identity_binding_digest"] == h.config.identity_binding.binding_digest
    assert proof["credentials_consumed"] is False and proof["live_effect_authorized"] is False
    persisted = json.dumps([record, result])
    for raw in (assertion, "synthetic-opaque-access-token", "synthetic-opaque-identity-context",
                "synthetic-access-key", "synthetic-secret-key", "synthetic-session-token",
                fixtures.PLAN_USER_ID, fixtures.SECOND_PARTY_USER_ID):
        assert raw not in persisted
    assert capsys.readouterr() == ("", "")


@pytest.mark.parametrize("operation", OPERATIONS)
@pytest.mark.parametrize("defect", ["wrong_operation", "wrong_plan", "wrong_approval", "claim_issuer", "claim_audience"])
def test_grant_cannot_choose_operation_artifact_or_runtime_binding(operation, defect):
    h = Harness()
    h.prepare(operation)
    nonce = h.nonce(operation)
    changes = {}
    if defect == "wrong_operation":
        nonce = h.nonce("approval" if operation == "plan" else "plan")
    elif defect == "wrong_plan":
        nonce = operation_binding_digest(operation, "sha256:" + "e" * 64,
            h.approval["approval_artifact_digest"] if operation != "plan" else None)
    elif defect == "wrong_approval":
        nonce = operation_binding_digest("approval" if operation == "plan" else operation,
            h.plan["plan_artifact_digest"], "sha256:" + "f" * 64)
    else:
        changes["iss" if defect == "claim_issuer" else "aud"] = "synthetic-foreign-binding"
    before = copy.deepcopy(h.store.record)
    grant = jwt_envelope(nonce, changes=changes)
    with pytest.raises(BootstrapAuthorizationError):
        h.invoke(operation, grant)
    assert grant == {} and h.events == [] and h.store.record == before
    assert h.effects.calls == 0


@pytest.mark.parametrize("operation", OPERATIONS)
@pytest.mark.parametrize("provider_error", ["invalid-signature", "provider-error", "replayed-jti"])
def test_aws_exchange_denials_prevent_sts_ledger_cas_and_effects(operation, provider_error, capsys):
    h = Harness()
    h.prepare(operation)
    grant = jwt_envelope(h.nonce(operation))
    assertion = grant["assertion"]
    if provider_error == "replayed-jti":
        h.sdk.seen_assertions.add(assertion)
    else:
        h.sdk.oidc_error = provider_error
    before = copy.deepcopy(h.store.record)
    with pytest.raises(BootstrapAuthorizationError) as caught:
        h.invoke(operation, grant)
    assert "synthetic-provider-private-detail" not in str(caught.value)
    assert assertion not in str(caught.value)
    assert h.events == ["oidc:exchange"] and not h.sdk.sts_calls
    assert grant == {} and h.store.record == before and h.effects.calls == 0
    assert capsys.readouterr() == ("", "")


@pytest.mark.parametrize("defect", ["refresh", "ttl", "missing_context", "wrong_scope", "missing_token"])
@pytest.mark.parametrize("operation", OPERATIONS)
def test_unusable_identity_center_response_never_reaches_sts_or_ledger(operation, defect):
    h = Harness()
    h.prepare(operation)
    before = copy.deepcopy(h.store.record)

    def tamper(response):
        if defect == "refresh":
            response["refreshToken"] = "synthetic-forbidden-refresh"
        elif defect == "ttl":
            response["expiresIn"] = 901
        elif defect == "missing_context":
            response["awsAdditionalDetails"] = {}
        elif defect == "wrong_scope":
            response["scope"] = ["sts:identity_context", "openid"]
        else:
            del response["accessToken"]
        return response

    h.sdk.transform_oidc = tamper
    with pytest.raises(BootstrapAuthorizationError):
        h.invoke(operation, jwt_envelope(h.nonce(operation)))
    assert h.events == ["oidc:exchange"] and not h.sdk.sts_calls
    assert h.sdk.oidc_responses == [{}]
    assert h.store.record == before and h.effects.calls == 0


@pytest.mark.parametrize("operation", OPERATIONS)
@pytest.mark.parametrize("defect", ["error", "wrong_role", "wrong_account", "expired"])
def test_sts_denial_or_malformed_proof_prevents_all_ledger_and_effect_access(operation, defect):
    h = Harness()
    h.prepare(operation)
    before = copy.deepcopy(h.store.record)
    h.sdk.sts_error = defect == "error"

    def tamper(response):
        if defect == "wrong_role":
            response["AssumedRoleUser"]["Arn"] = response["AssumedRoleUser"]["Arn"].replace("IdentityProof", "ForeignProof")
        elif defect == "wrong_account":
            response["AssumedRoleUser"]["Arn"] = response["AssumedRoleUser"]["Arn"].replace("111122223333", "444455556666")
        elif defect == "expired":
            response["Credentials"]["Expiration"] = NOW
        return response

    h.sdk.transform_sts = tamper
    with pytest.raises(BootstrapAuthorizationError) as caught:
        h.invoke(operation, jwt_envelope(h.nonce(operation)))
    assert "synthetic-provider-private-detail" not in str(caught.value)
    assert h.events == ["oidc:exchange", "sts:proof"]
    assert all(response == {} for response in h.sdk.sts_responses)
    assert h.store.record == before and h.effects.calls == 0


@pytest.mark.parametrize("stage,defect", [
    ("before_exchange", "expired"), ("before_exchange", "auth_age"),
    ("before_exchange", "future_issue"), ("before_exchange", "ttl"),
    ("during_exchange", "expired"), ("during_exchange", "auth_age"),
])
def test_assertion_time_bounds_are_checked_on_both_sides_of_provider_call(stage, defect):
    h = Harness()
    changes = {
        "expired": {"iat": EPOCH - 1, "auth_time": EPOCH - 1, "exp": EPOCH + 1},
        "auth_age": {"auth_time": EPOCH - 300},
        "future_issue": {"iat": EPOCH + 1, "exp": EPOCH + 900},
        "ttl": {"exp": EPOCH + 901},
    }[defect]
    delta = 1 if defect == "auth_age" else 2
    if stage == "before_exchange" and defect in ("expired", "auth_age"):
        h.sdk.now += timedelta(seconds=delta)
    elif stage == "during_exchange":
        h.sdk.after_oidc = lambda: setattr(h.sdk, "now", NOW + timedelta(seconds=delta))
    with pytest.raises(BootstrapAuthorizationError):
        h.invoke("plan", jwt_envelope(h.nonce("plan"), changes=changes))
    assert h.events == (["oidc:exchange"] if stage == "during_exchange" else [])
    assert not h.sdk.sts_calls and h.store.record is None and h.effects.calls == 0
    assert all(response == {} for response in h.sdk.oidc_responses)


@pytest.mark.parametrize("operation,stage,expiring", [
    ("plan", "oidc", "plan"),
    ("approval", "sts", "approval"),
    ("apply", "store_get", "plan"),
    ("apply", "store_get", "approval"),
])
def test_provider_delay_cannot_anchor_or_claim_expired_artifacts(
    operation, stage, expiring, monkeypatch,
):
    h = Harness()
    if expiring == "plan":
        # Rebuild through the real contract: the Plan is valid at entry and
        # expires one second later. Approval cannot outlive its parent Plan.
        h.plan = fixtures._plan(now=NOW - timedelta(minutes=55) + timedelta(seconds=1))
    h.approval = fixtures.build_bootstrap_approval_v2(
        plan=h.plan, binding=h.config.binding,
        approver_id="reviewer-2002", approver_arn=fixtures.APPROVER_ARN,
        approved_at=NOW - timedelta(seconds=1), expires_at=NOW + timedelta(seconds=1),
        approval_nonce="2" * 64,
    )
    h.prepare(operation)
    before = copy.deepcopy(h.store.record)

    def advance():
        h.sdk.now = NOW + timedelta(seconds=2)

    if stage == "oidc":
        h.sdk.after_oidc = advance
    elif stage == "sts":
        def slow_sts(response):
            advance()
            return response
        h.sdk.transform_sts = slow_sts
    else:
        get_record = h.store.get

        def slow_get(record_id):
            record = get_record(record_id)
            advance()
            return record

        monkeypatch.setattr(h.store, "get", slow_get)

    with pytest.raises(BootstrapArtifactAuthorityError, match="expired|fresh"):
        h.invoke(operation, jwt_envelope(h.nonce(operation)))
    expected = ["oidc:exchange", "sts:proof"]
    if operation != "plan":
        expected.append("store:get")
    assert h.events == expected
    assert h.store.record == before and h.effects.calls == 0
    assert h.sdk.oidc_responses == [{}] and h.sdk.sts_responses == [{}]


@pytest.mark.parametrize("operation,stage", [("plan", "sts"), ("apply", "store_get")])
def test_transition_rejects_backward_clock_after_successful_identity_proof(operation, stage, monkeypatch):
    h = Harness()
    h.prepare(operation)
    before = copy.deepcopy(h.store.record)

    def regress():
        h.sdk.now = NOW - timedelta(seconds=1)

    if stage == "sts":
        def slow_sts(response):
            regress()
            return response
        h.sdk.transform_sts = slow_sts
    else:
        get_record = h.store.get

        def slow_get(record_id):
            record = get_record(record_id)
            regress()
            return record

        monkeypatch.setattr(h.store, "get", slow_get)

    with pytest.raises(BootstrapArtifactAuthorityError, match="transition clock is invalid"):
        h.invoke(operation, jwt_envelope(h.nonce(operation)))
    expected = ["oidc:exchange", "sts:proof"] + (["store:get"] if stage == "store_get" else [])
    assert h.events == expected
    assert h.store.record == before and h.effects.calls == 0


@pytest.mark.parametrize("mode,grant_kind,nonce_enabled", [
    ("2", "legacy", True), ("1", "jwt", False), ("1", "legacy", True), ("2", "jwt", False),
])
def test_real_verifier_has_no_cross_version_or_missing_nonce_fallback(mode, grant_kind, nonce_enabled):
    h = Harness()
    binding = h.config.identity_binding
    if mode == "1":
        binding = replace(binding, jwt_bearer=None)
    grant = legacy_envelope() if grant_kind == "legacy" else jwt_envelope(h.nonce("plan"))
    with pytest.raises(BootstrapAuthorizationError):
        h.verifier.verify(operation="plan", identity_grant=grant, binding=binding, now=NOW,
            operation_binding_digest=h.nonce("plan") if nonce_enabled else None)
    assert h.events == [] and h.store.record is None


def test_consumed_mapping_replay_fails_before_another_provider_exchange():
    h = Harness()
    grant = jwt_envelope(h.nonce("plan"))
    h.invoke("plan", grant)
    before = copy.deepcopy(h.store.record)
    h.events.clear()
    with pytest.raises(BootstrapAuthorizationError):
        h.invoke("plan", grant)
    assert grant == {} and h.events == [] and h.store.record == before


def test_serialized_grant_replay_still_requires_provider_acceptance_each_time():
    h = Harness()
    grant = json.dumps(jwt_envelope(h.nonce("plan")))
    h.invoke("plan", grant)
    before = copy.deepcopy(h.store.record)
    h.events.clear()
    with pytest.raises(BootstrapAuthorizationError):
        h.invoke("plan", grant)
    assert h.events == ["oidc:exchange"] and h.store.record == before
    assert len(h.sdk.sts_calls) == 1 and h.effects.calls == 0


@pytest.mark.parametrize("operation,changed_artifact", [
    ("plan", "plan"), ("approval", "plan"), ("apply", "plan"),
    ("approval", "approval"), ("apply", "approval"),
])
def test_valid_rebuilt_artifact_cannot_reuse_previous_operation_assertion(operation, changed_artifact):
    h = Harness()
    h.prepare(operation)
    grant = jwt_envelope(h.nonce(operation))
    before = copy.deepcopy(h.store.record)
    if changed_artifact == "plan":
        h.plan = fixtures._plan(nonce="4" * 64)
        h.approval = fixtures._approval(h.plan)
    else:
        h.approval = fixtures._approval(h.plan, now=NOW + timedelta(seconds=1))
    with pytest.raises(BootstrapAuthorizationError):
        h.invoke(operation, grant)
    assert h.events == [] and h.store.record == before and h.effects.calls == 0


@pytest.mark.parametrize("present", itertools.product((False, True), repeat=3))
def test_real_runtime_v2_requires_every_public_jwt_field(present):
    environment = fixtures._runtime_environment() | {"GUG274_IDENTITY_GRANT_VERSION": "2"}
    environment |= {name: value for (name, value), include in zip(JWT_ENVIRONMENT.items(), present) if include}
    if all(present):
        config = BootstrapArtifactAuthorityRuntimeConfig.from_environment(environment)
        assert isinstance(config.identity_binding.jwt_bearer, JwtBearerBinding)
        assert config.identity_binding.jwt_bearer.max_assertion_lifetime_seconds == 900
        assert config.identity_binding.jwt_bearer.max_auth_age_seconds == 300
    else:
        with pytest.raises(BootstrapArtifactAuthorityError):
            BootstrapArtifactAuthorityRuntimeConfig.from_environment(environment)


@pytest.mark.parametrize("explicit_mode", [False, True])
@pytest.mark.parametrize("field", JWT_ENVIRONMENT)
def test_legacy_mode_rejects_leftover_jwt_configuration(explicit_mode, field):
    environment = fixtures._runtime_environment() | {field: JWT_ENVIRONMENT[field]}
    if explicit_mode:
        environment["GUG274_IDENTITY_GRANT_VERSION"] = "1"
    with pytest.raises(BootstrapArtifactAuthorityError):
        BootstrapArtifactAuthorityRuntimeConfig.from_environment(environment)


@pytest.mark.parametrize("version", ["", "3", "02", None, 2])
def test_present_invalid_runtime_mode_never_defaults_to_legacy(version):
    environment = fixtures._runtime_environment() | {"GUG274_IDENTITY_GRANT_VERSION": version}
    with pytest.raises(BootstrapArtifactAuthorityError):
        BootstrapArtifactAuthorityRuntimeConfig.from_environment(environment)


def test_legacy_runtime_accepts_empty_public_fields_and_preserves_binding_digest():
    old = BootstrapArtifactAuthorityRuntimeConfig.from_environment(fixtures._runtime_environment())
    explicit = BootstrapArtifactAuthorityRuntimeConfig.from_environment(fixtures._runtime_environment() | {
        "GUG274_IDENTITY_GRANT_VERSION": "1", **{name: "" for name in JWT_ENVIRONMENT},
    })
    assert old == explicit and old.identity_binding.jwt_bearer is None


@pytest.mark.parametrize("field", JWT_ENVIRONMENT)
def test_runtime_binding_snapshots_public_metadata_and_digest_changes_with_authority(field):
    environment = runtime_environment()
    original = BootstrapArtifactAuthorityRuntimeConfig.from_environment(environment)
    digest = original.identity_binding.binding_digest
    environment[field] = (environment[field][:-1] + "6" if field.endswith("ARN")
                          else environment[field] + "-other")
    changed = BootstrapArtifactAuthorityRuntimeConfig.from_environment(environment)
    assert changed.identity_binding.binding_digest != digest
    assert original.identity_binding.binding_digest == digest
    with pytest.raises(FrozenInstanceError):
        original.identity_binding.jwt_bearer.audience = "caller-selected"


def _single_owner_runtime_environment():
    """Closed César-scope env; not an installation or live UserId."""
    environment = runtime_environment()
    environment.update(
        {
            "GUG274_AUTHORITY_ACCOUNT_ID": "042360977644",
            "GUG274_DESTINATION_ACCOUNT_IDS": "905418363887",
            "GUG274_IDENTITY_CENTER_APPLICATION_ARN": (
                "arn:aws:sso::042360977644:application/"
                "ssoins-1234567890abcdef/apl-1234567890abcdef"
            ),
            "GUG274_IDENTITY_CENTER_INSTANCE_ARN": (
                "arn:aws:sso:::instance/ssoins-1234567890abcdef"
            ),
            "GUG274_IDENTITY_STORE_ARN": (
                "arn:aws:identitystore::042360977644:identitystore/d-90667f73ff"
            ),
            "GUG274_JWT_TRUSTED_TOKEN_ISSUER_ARN": (
                "arn:aws:sso::042360977644:trustedTokenIssuer/"
                "ssoins-1234567890abcdef/tti-11111111-2222-3333-4444-555555555555"
            ),
            "GUG274_SECOND_PARTY_IDENTITY_STORE_USER_ID": "",
            "GUG274_OPERATOR_POLICY_MODE": "single_owner_v1",
            "GUG274_SINGLE_OWNER_AUTHORIZED_AT": "2026-09-16T00:00:00Z",
            "GUG274_SINGLE_OWNER_EXPIRES_AT": "2026-09-16T12:00:00Z",
        }
    )
    return environment


def test_single_owner_runtime_from_environment_binds_owner_policy_and_empty_peer():
    from tooling.platform_authority_bootstrap import SingleOwnerPolicy

    config = BootstrapArtifactAuthorityRuntimeConfig.from_environment(
        _single_owner_runtime_environment()
    )
    assert isinstance(config.binding.single_owner, SingleOwnerPolicy)
    assert config.identity_binding.single_owner is config.binding.single_owner
    assert config.identity_binding.second_party_user_id == ""
    assert config.identity_binding.jwt_bearer is not None
    role_kind, user_id, peer, *_ = config.identity_binding.proof_target("approval")
    assert role_kind == "single_owner_review"
    assert user_id == config.identity_binding.plan_user_id
    assert peer is None


@pytest.mark.parametrize(
    "changes",
    [
        {"GUG274_OPERATOR_POLICY_MODE": "independent"},
        {"GUG274_SECOND_PARTY_IDENTITY_STORE_USER_ID": fixtures.SECOND_PARTY_USER_ID},
        {"GUG274_IDENTITY_GRANT_VERSION": "1", **{name: "" for name in JWT_ENVIRONMENT}},
        {"GUG274_SINGLE_OWNER_AUTHORIZED_AT": ""},
        {"GUG274_SINGLE_OWNER_EXPIRES_AT": ""},
        {"GUG274_AUTHORITY_ACCOUNT_ID": "111122223333"},
    ],
)
def test_single_owner_runtime_rejects_incomplete_or_out_of_scope_bindings(changes):
    environment = _single_owner_runtime_environment()
    environment.update(changes)
    with pytest.raises(BootstrapArtifactAuthorityError):
        BootstrapArtifactAuthorityRuntimeConfig.from_environment(environment)


def test_independent_runtime_rejects_single_owner_window_without_mode():
    environment = runtime_environment() | {
        "GUG274_SINGLE_OWNER_AUTHORIZED_AT": "2026-09-16T00:00:00Z",
        "GUG274_SINGLE_OWNER_EXPIRES_AT": "2026-09-16T12:00:00Z",
    }
    with pytest.raises(BootstrapArtifactAuthorityError):
        BootstrapArtifactAuthorityRuntimeConfig.from_environment(environment)
