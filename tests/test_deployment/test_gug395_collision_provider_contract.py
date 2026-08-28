from __future__ import annotations

import copy
from datetime import UTC, datetime, timedelta
import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Mapping

import pytest

from tooling import platform_authority_gug376_live_provider as provider
from tooling import platform_authority_gug395_preplan_collision_probe as contract


NOW = datetime(2026, 8, 28, 1, 5, tzinfo=UTC)
AUTHORITY_ACCOUNT = "042360977644"
IDENTITY_ACCOUNT = "839393571433"
AUTHORITY_PROFILE = "042360977644_AWSReadOnlyAccess"
IDENTITY_PROFILE = "839393571433_AWSReadOnlyAccess"


def _digest(label: str) -> str:
    return provider.canonical_digest({"label": label})


def _stamp(value: datetime) -> str:
    return value.astimezone(UTC).replace(microsecond=0).isoformat().replace(
        "+00:00", "Z"
    )


def _tag_pairs(tag_contract: Mapping[str, str]) -> list[dict[str, str]]:
    return sorted(
        (
            {
                "key_digest": provider.canonical_digest(key),
                "value_digest": provider.canonical_digest(value),
            }
            for key, value in tag_contract.items()
        ),
        key=lambda item: (item["key_digest"], item["value_digest"]),
    )


class _BuilderBudget:
    def __init__(self) -> None:
        self.budget_digest = _digest("collision-budget")

    def reserve_provider_call(self, operation: str, *, is_page: bool) -> None:
        raise AssertionError(f"unexpected provider call: {operation}/{is_page}")

    def record_session_bootstrap(self, operation: str) -> None:
        raise AssertionError(f"unexpected session bootstrap: {operation}")

    def record_credential_vend(self, operation: str) -> None:
        raise AssertionError(f"unexpected credential vend: {operation}")

    def record_response(self, byte_count: int) -> None:
        raise AssertionError(f"unexpected response: {byte_count}")

    def summary(self) -> dict[str, Any]:
        return {
            "budget_digest": self.budget_digest,
            "provider_calls": 0,
            "session_bootstrap_attempts": 0,
            "credential_vending_calls": 0,
            "network_calls": 0,
            "page_calls": 0,
            "projected_response_bytes": 0,
        }

    def evidence_events(self) -> list[dict[str, Any]]:
        return []


def _builder_arguments(sdk_runtime_root: Path) -> dict[str, Any]:
    return {
        "sdk_runtime_root": str(sdk_runtime_root),
        "authority_profile": AUTHORITY_PROFILE,
        "identity_center_profile": IDENTITY_PROFILE,
        "authority_expected_account_id": AUTHORITY_ACCOUNT,
        "authority_expected_principal_digest": _digest(
            "authority-principal"
        ),
        "authority_expected_sso_role_name_digest": _digest(
            "authority-role"
        ),
        "identity_expected_account_id": IDENTITY_ACCOUNT,
        "identity_expected_principal_digest": _digest("identity-principal"),
        "identity_expected_sso_role_name_digest": _digest("identity-role"),
        "authority_verification_digest": _digest("authority-verification"),
        "identity_authority_verification_digest": _digest(
            "identity-verification"
        ),
    }


def test_collision_builder_binds_every_capability_field_and_exact_attestation(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    capability = object()
    captured: dict[str, Any] = {}
    budget = _BuilderBudget()

    class CapabilityGate:
        def __call__(self) -> None:
            return None

        def authorize_session(self, **_: Any) -> None:
            return None

    def assert_bindings(value: object, **bindings: Any) -> CapabilityGate:
        assert value is capability
        captured.update(bindings)
        return CapabilityGate()

    monkeypatch.setattr(
        contract,
        "assert_collision_probe_provider_capability_bindings",
        assert_bindings,
    )
    monkeypatch.setattr(provider, "_ambient_gate", lambda _: None)
    monkeypatch.setattr(
        provider,
        "_load_sdk",
        lambda _: provider._LoadedSdk(
            session_factory=lambda **_: None,
            config_factory=lambda **_: None,
            guard=lambda: None,
        ),
    )
    arguments = _builder_arguments(tmp_path.resolve())

    factory = provider.build_collision_probe_provider_factory(
        **arguments,
        collision_budget=budget,
        execution_capability=capability,
    )

    assert captured == {**arguments, "budget_digest": budget.budget_digest}
    assert factory.mode == "ATTESTED_PREPLAN_COLLISION_PROBE"
    assert factory.collision_probe_provider is True
    assert provider.is_attested_collision_probe_provider(factory, capability)
    assert not provider.is_attested_collision_probe_provider(factory, object())
    assert not provider.is_attested_live_provider(factory, capability)
    assert not provider.is_attested_discovery_provider(factory, capability)
    assert not provider.is_attested_collision_probe_provider(
        SimpleNamespace(
            mode="ATTESTED_PREPLAN_COLLISION_PROBE",
            collision_probe_provider=True,
        ),
        capability,
    )


class _SsoEmitter:
    def __init__(self) -> None:
        self.handler: Any = None

    def register(self, _: str, handler: Any, *, unique_id: str) -> None:
        assert unique_id
        assert self.handler is None
        self.handler = handler

    def unregister(self, _: str, *, unique_id: str) -> None:
        assert unique_id
        assert self.handler is not None
        self.handler = None


class _SsoCoreSession:
    def __init__(self, emitter: _SsoEmitter) -> None:
        self.full_config = {
            "profiles": {
                AUTHORITY_PROFILE: {
                    "sso_session": "scanalyze-read-only",
                    "sso_account_id": AUTHORITY_ACCOUNT,
                    "sso_role_name": "ScanalyzeReadOnly",
                    "region": provider.REGION,
                }
            },
            "sso_sessions": {
                "scanalyze-read-only": {
                    "sso_start_url": "https://example.invalid/start",
                    "sso_region": provider.REGION,
                }
            },
        }
        self._emitter = emitter
        self._variables: dict[str, Any] = {}

    def set_config_variable(self, name: str, value: Any) -> None:
        self._variables[name] = value

    def get_config_variable(self, name: str) -> Any:
        return self._variables.get(name)

    def get_component(self, name: str) -> _SsoEmitter:
        assert name == "event_emitter"
        return self._emitter


class _SsoCredentials:
    method = "sso"

    def __init__(self) -> None:
        self._expiry_time = NOW + timedelta(minutes=30)

    def get_frozen_credentials(self) -> SimpleNamespace:
        return SimpleNamespace(
            access_key="test-access",
            secret_key="test-secret",
            token="test-session",
        )


class _SsoSession:
    def __init__(self, *, emit_vend: bool, order: list[str]) -> None:
        self.region_name = provider.REGION
        self.emitter = _SsoEmitter()
        self._session = _SsoCoreSession(self.emitter)
        self.emit_vend = emit_vend
        self.order = order

    def get_credentials(self) -> _SsoCredentials:
        self.order.append("get_credentials")
        if self.emit_vend:
            assert callable(self.emitter.handler)
            self.emitter.handler(
                event_name="before-call.sso.GetRoleCredentials",
                context={
                    "client_config": SimpleNamespace(
                        retries={
                            "mode": "standard",
                            "total_max_attempts": 1,
                        }
                    )
                },
            )
        return _SsoCredentials()


@pytest.mark.parametrize("emit_vend", [False, True])
def test_collision_session_bootstrap_counts_attempt_before_optional_vend(
    emit_vend: bool,
) -> None:
    order: list[str] = []
    session = _SsoSession(emit_vend=emit_vend, order=order)

    provider._validate_direct_sso_profile(
        session,
        profile_name=AUTHORITY_PROFILE,
        account_id=AUTHORITY_ACCOUNT,
        sso_role_name_digest=provider.canonical_digest("ScanalyzeReadOnly"),
        region=provider.REGION,
        opened_at=NOW,
        required_end=NOW + timedelta(minutes=10),
        observe_credential_bootstrap=True,
        credential_vend_recorder=lambda operation: order.append(
            f"vend:{operation}"
        ),
        session_bootstrap_recorder=lambda operation: order.append(
            f"bootstrap:{operation}"
        ),
    )

    assert order == [
        "bootstrap:sso:GetRoleCredentials",
        "get_credentials",
        *(["vend:sso:GetRoleCredentials"] if emit_vend else []),
    ]
    assert session.emitter.handler is None


def test_collision_session_bootstrap_counts_failed_get_attempt() -> None:
    order: list[str] = []
    session = _SsoSession(emit_vend=False, order=order)

    def fail_get_credentials() -> _SsoCredentials:
        order.append("get_credentials")
        raise RuntimeError("private-bootstrap-failure")

    session.get_credentials = fail_get_credentials  # type: ignore[method-assign]
    with pytest.raises(
        provider.LiveProviderError,
        match="^DIRECT_SSO_CREDENTIALS_REQUIRED$",
    ):
        provider._validate_direct_sso_profile(
            session,
            profile_name=AUTHORITY_PROFILE,
            account_id=AUTHORITY_ACCOUNT,
            sso_role_name_digest=provider.canonical_digest(
                "ScanalyzeReadOnly"
            ),
            region=provider.REGION,
            opened_at=NOW,
            required_end=NOW + timedelta(minutes=10),
            observe_credential_bootstrap=True,
            credential_vend_recorder=lambda operation: order.append(
                f"vend:{operation}"
            ),
            session_bootstrap_recorder=lambda operation: order.append(
                f"bootstrap:{operation}"
            ),
        )

    assert order == [
        "bootstrap:sso:GetRoleCredentials",
        "get_credentials",
    ]
    assert session.emitter.handler is None


class _TrackingBudget:
    def __init__(self) -> None:
        self.provider_calls: list[tuple[str, bool]] = []
        self.response_bytes: list[int] = []

    def reserve_provider_call(self, operation: str, *, is_page: bool) -> None:
        self.provider_calls.append((operation, is_page))

    def record_response(self, byte_count: int) -> None:
        assert type(byte_count) is int and byte_count > 0
        self.response_bytes.append(byte_count)

    def evidence_events(self) -> list[dict[str, Any]]:
        assert len(self.provider_calls) == len(self.response_bytes)
        return [
            {
                "operation": operation,
                "is_page": is_page,
                "response_bytes": response_bytes,
            }
            for (operation, is_page), response_bytes in zip(
                self.provider_calls, self.response_bytes, strict=True
            )
        ]


def test_partial_provider_summary_never_overclaims_an_aws_call() -> None:
    owner = object.__new__(provider.LiveProviderFactory)
    owner._provider_attestation = provider._COLLISION_PROBE_PROVIDER_ATTESTATION
    owner._concrete = True
    owner._ledger = contract.CollisionCallLedger()
    owner._ledger.authorize(
        domain="authority",
        session_digest=_digest("partial-session"),
        operation="sts:GetCallerIdentity",
        retries=0,
        started_at=_stamp(NOW),
    )

    summary = owner.collision_partial_transcript_summary()

    assert summary["provider_calls"] == 1
    assert summary["aws_calls"] is None
    assert summary["live_provider_evidence"] is False


class _HeadBucketError(RuntimeError):
    def __init__(self, status: int, code: str | None = None) -> None:
        self.response = {
            "Error": {"Code": code or str(status)},
            "ResponseMetadata": {
                "HTTPStatusCode": status,
                "HTTPHeaders": (
                    {"x-amz-bucket-region": "us-west-2"}
                    if status in {301, 403}
                    else {}
                ),
            },
        }
        super().__init__(f"private-{status}-detail-must-not-escape")


class _HeadBucketClient:
    def __init__(self, status: int) -> None:
        self.status = status
        self.requests: list[dict[str, Any]] = []
        self.meta = SimpleNamespace(events=_S3Events())

    def head_bucket(self, **request: Any) -> Mapping[str, Any]:
        self.requests.append(request)
        if 200 <= self.status <= 299:
            return {"ResponseMetadata": {"HTTPStatusCode": self.status}}
        if self.status in {301, 400, 403, 404}:
            raise _HeadBucketError(self.status)
        raise _HeadBucketError(self.status, "InternalError")


class _S3Events:
    def __init__(self) -> None:
        self.first_handler: Any = None
        self.registrations = 0

    def register_first(
        self, event_name: str, handler: Any, *, unique_id: str
    ) -> None:
        assert event_name == "needs-retry.s3"
        assert unique_id
        self.first_handler = handler
        self.registrations += 1

    def emit_redirect_response(self) -> None:
        assert callable(self.first_handler)
        self.first_handler(
            response=(
                SimpleNamespace(status_code=301),
                {
                    "Error": {"Code": "301"},
                    "ResponseMetadata": {
                        "HTTPStatusCode": 301,
                        "HTTPHeaders": {
                            "x-amz-bucket-region": "us-west-2"
                        },
                    },
                },
            ),
            operation=SimpleNamespace(name="HeadBucket"),
        )


class _HeadSdkSession:
    def __init__(self, client: _HeadBucketClient) -> None:
        self.client_value = client

    def client(self, service: str, *, config: Any, verify: bool) -> Any:
        assert service == "s3"
        assert config == {"retries": 0}
        assert verify is True
        return self.client_value


def _head_bucket_session(status: int) -> tuple[
    provider._StsSession,
    contract.CollisionCallLedger,
    _TrackingBudget,
    provider.LiveProviderFactory,
    _HeadBucketClient,
]:
    budget = _TrackingBudget()
    owner = object.__new__(provider.LiveProviderFactory)
    owner._operation_allowlist = provider.COLLISION_PROBE_OPERATION_ALLOWLIST
    owner._collision_budget = budget
    owner._discovery_budget = None
    owner._events = []
    owner._concrete = False
    owner._config = SimpleNamespace(validity_gate=lambda: None)
    owner._clock = lambda: NOW

    ledger = contract.CollisionCallLedger()
    session_digest = _digest(f"head-bucket-session-{status}")
    sts_ticket = ledger.authorize(
        domain="authority",
        session_digest=session_digest,
        operation="sts:GetCallerIdentity",
        retries=0,
        started_at=_stamp(NOW - timedelta(seconds=2)),
    )
    ledger.complete(
        sts_ticket,
        completed_at=_stamp(NOW - timedelta(seconds=1)),
    )
    client = _HeadBucketClient(status)
    session = provider._StsSession(
        owner=owner,
        domain="authority",
        sdk_session=_HeadSdkSession(client),
        sdk_config={"retries": 0},
        sts_client=object(),
        ledger=ledger,
        session_digest=session_digest,
        account_id=AUTHORITY_ACCOUNT,
        principal_digest=_digest("authority-principal"),
        authority_verification_digest=_digest("authority-verification"),
        policy={},
        policy_digest=_digest("authority-policy"),
        start=NOW - timedelta(minutes=1),
        end=NOW + timedelta(minutes=10),
        opened_at=NOW - timedelta(seconds=3),
        credential_expires_at=NOW + timedelta(minutes=20),
        policy_actions=provider.COLLISION_PROBE_OPERATION_ALLOWLIST[
            "authority"
        ],
        region=provider.REGION,
        capture_index=1,
        stage="collision_probe",
    )
    session._identity_validated = True
    return session, ledger, budget, owner, client


def test_concrete_collision_s3_client_installs_first_priority_redirect_guard(
) -> None:
    session, _, _, owner, client = _head_bucket_session(301)
    owner._concrete = True

    assert session._client("s3") is client
    assert session._client("s3") is client
    assert client.meta.events.registrations == 1

    with pytest.raises(
        provider._S3RegionRedirectBlocked,
        match="^COLLISION_S3_REGION_REDIRECT_BLOCKED$",
    ) as blocked:
        client.meta.events.emit_redirect_response()
    assert blocked.value.region_header_digest == provider.canonical_digest(
        "us-west-2"
    )


def test_concrete_collision_s3_guard_fails_before_provider_request() -> None:
    session, _, _, owner, client = _head_bucket_session(200)
    owner._concrete = True
    client.meta = SimpleNamespace(events=object())

    with pytest.raises(
        provider.LiveProviderError,
        match="^COLLISION_S3_REDIRECT_GUARD_REQUIRED$",
    ):
        session._client("s3")
    assert client.requests == []


@pytest.mark.parametrize(
    ("status", "collision", "absent"),
    [
        (200, True, False),
        (204, True, False),
        (301, True, False),
    ],
)
def test_head_bucket_classifies_global_name_without_false_absence(
    status: int, collision: bool, absent: bool
) -> None:
    session, ledger, budget, owner, client = _head_bucket_session(status)

    result = session._head_bucket("scanalyze-gug395-candidate")

    assert result == {
        "status_code": status,
        "collision": collision,
        "absent": absent,
        **(
            {
                "bucket_region_header_digest": provider.canonical_digest(
                    "us-west-2"
                )
            }
            if status == 301
            else {}
        ),
    }
    assert client.requests == [{"Bucket": "scanalyze-gug395-candidate"}]
    assert ledger.finalize()[0] == 2
    assert len(ledger.evidence_events()) == 2
    assert budget.provider_calls == [("s3:HeadBucket", False)]
    assert len(budget.evidence_events()) == 1
    assert owner._events[-1]["outcome"] == "SUCCESS"


@pytest.mark.parametrize("status", [400, 403, 404])
def test_head_bucket_generic_failure_is_uncertain_and_fully_accounted(
    status: int,
) -> None:
    session, ledger, budget, owner, client = _head_bucket_session(status)

    with pytest.raises(
        provider.LiveProviderError,
        match="^COLLISION_HEAD_BUCKET_AMBIGUOUS$",
    ):
        session._head_bucket("scanalyze-gug395-candidate")

    assert client.requests == [{"Bucket": "scanalyze-gug395-candidate"}]
    assert ledger._pending == {}
    assert ledger._events[-1]["outcome"] == "ERROR"
    assert budget.provider_calls == [("s3:HeadBucket", False)]
    assert owner._events[-1]["outcome"] == "ERROR"
    assert f"private-{status}-detail" not in contract.canonical_json(
        ledger._events + owner._events + budget.evidence_events()
    )


def test_identity_policy_uses_primary_region_only_for_supported_actions() -> None:
    policy_path = (
        Path(__file__).resolve().parents[2]
        / "policies"
        / "iam"
        / "platform-authority-gug395-preplan-collision-identity-read-only.json"
    )
    policy = json.loads(policy_path.read_text(encoding="utf-8"))
    supported = {
        "sso:DescribeApplication",
        "sso:DescribePermissionSet",
        "sso:ListPermissionSets",
    }
    unsupported = {
        "sso:ListApplications",
        "sso:ListInstances",
        "sso:ListTagsForResource",
    }
    primary_region_actions: set[str] = set()
    non_primary_region_actions: set[str] = set()

    for statement in policy["Statement"]:
        if statement.get("Effect") != "Allow":
            continue
        actions = statement["Action"]
        action_set = {actions} if isinstance(actions, str) else set(actions)
        sso_actions = {action for action in action_set if action.startswith("sso:")}
        if not sso_actions:
            continue
        string_equals = statement["Condition"]["StringEquals"]
        assert string_equals["aws:RequestedRegion"] == provider.REGION
        if "sso:PrimaryRegion" in string_equals:
            assert string_equals["sso:PrimaryRegion"] == provider.REGION
            primary_region_actions.update(sso_actions)
        else:
            non_primary_region_actions.update(sso_actions)

    assert primary_region_actions == supported
    assert non_primary_region_actions == unsupported


def test_identity_policy_scopes_indirect_kms_dependency_without_adapter_dispatch(
) -> None:
    policy_path = (
        Path(__file__).resolve().parents[2]
        / "policies"
        / "iam"
        / "platform-authority-gug395-preplan-collision-identity-read-only.json"
    )
    policy = json.loads(policy_path.read_text(encoding="utf-8"))
    decrypt = [
        statement
        for statement in policy["Statement"]
        if statement.get("Effect") == "Allow"
        and statement.get("Action") == "kms:Decrypt"
    ]

    assert decrypt == [
        {
            "Sid": "DecryptCollisionMetadataThroughIdentityCenter",
            "Effect": "Allow",
            "Action": "kms:Decrypt",
            "Resource": "${identity_center_kms_key_arn}",
            "Condition": {
                "StringEquals": {
                    "aws:RequestedRegion": provider.REGION,
                    "kms:CallerAccount": "${management_account_id}",
                    "kms:ViaService": "sso.us-east-1.amazonaws.com",
                },
                "StringLike": {
                    "kms:EncryptionContext:aws:sso:instance-arn": (
                        "${identity_center_instance_arn}"
                    )
                },
                "DateGreaterThanEquals": {
                    "aws:CurrentTime": "${inventory_not_before}"
                },
                "DateLessThan": {
                    "aws:CurrentTime": "${inventory_not_after}"
                },
            },
        }
    ]
    deny = next(
        statement
        for statement in policy["Statement"]
        if statement.get("Sid") == "DenyEveryUnreviewedAction"
    )
    assert "kms:Decrypt" in deny["NotAction"]
    assert "kms:Decrypt" not in set().union(
        *provider.COLLISION_PROBE_OPERATION_ALLOWLIST.values()
    )


def test_head_bucket_unexpected_error_is_closed_and_fully_accounted() -> None:
    session, ledger, budget, owner, _ = _head_bucket_session(500)

    with pytest.raises(provider.LiveProviderError, match="^PROVIDER_READ_FAILED$"):
        session._head_bucket("scanalyze-gug395-candidate")

    assert ledger._pending == {}
    assert ledger._events[-1]["outcome"] == "ERROR"
    with pytest.raises(
        contract.CollisionProbeError,
        match="^COLLISION_UNCERTAIN_RECONCILE_ONLY$",
    ):
        ledger.finalize()
    assert budget.provider_calls == [("s3:HeadBucket", False)]
    assert len(budget.evidence_events()) == 1
    assert owner._events[-1]["outcome"] == "ERROR"
    assert "private-500-detail" not in contract.canonical_json(
        ledger._events + owner._events + budget.evidence_events()
    )


class _ScriptedCollisionSession:
    def __init__(
        self,
        *,
        pages: Mapping[str, Any] | None = None,
        values: Mapping[str, Any] | None = None,
        head: Mapping[str, Any] | None = None,
        account_id: str = IDENTITY_ACCOUNT,
    ) -> None:
        self._account_id = account_id
        self.pages = dict(pages or {})
        self.values = dict(values or {})
        self.head = copy.deepcopy(head)
        self.calls: list[tuple[str, str, dict[str, Any]]] = []

    def _paginate(self, **kwargs: Any) -> list[Any]:
        operation = kwargs["operation"]
        self.calls.append(("paginate", operation, copy.deepcopy(kwargs)))
        value = self.pages[operation]
        if callable(value):
            value = value(kwargs)
        return copy.deepcopy(value)

    def _invoke(self, **kwargs: Any) -> Mapping[str, Any]:
        operation = kwargs["operation"]
        self.calls.append(("invoke", operation, copy.deepcopy(kwargs)))
        value = self.values[operation]
        if callable(value):
            value = value(kwargs)
        return copy.deepcopy(value)

    def _head_bucket(self, bucket_name: str) -> Mapping[str, Any]:
        self.calls.append(("head", "s3:HeadBucket", {"Bucket": bucket_name}))
        if self.head is None:
            raise AssertionError("unexpected HeadBucket call")
        return copy.deepcopy(self.head)


def test_authority_selectors_detect_tag_collision_without_exact_name() -> None:
    tags = _tag_pairs(contract.AUTHORITY_TAG_CONTRACT)
    key_arn = f"arn:aws:kms:us-east-1:{AUTHORITY_ACCOUNT}:key/tagged-key"
    profile_arn = (
        f"arn:aws:signer:us-east-1:{AUTHORITY_ACCOUNT}:"
        "signing-profiles/unrelated"
    )
    config_arn = (
        f"arn:aws:lambda:us-east-1:{AUTHORITY_ACCOUNT}:"
        "code-signing-config:csc-unrelated"
    )

    def signing_profiles(kwargs: Mapping[str, Any]) -> list[dict[str, str]]:
        assert kwargs["request"] == {
            "includeCanceled": True,
            "statuses": ["Active", "Canceled", "Revoked"],
        }
        return [
            {
                "profileName": "unrelated",
                "profileVersion": "1",
                "profileVersionArn": profile_arn,
                "arn": profile_arn,
            }
        ]

    session = _ScriptedCollisionSession(
        pages={
            "s3:ListAllMyBuckets": [{"Name": "unrelated-bucket"}],
            "kms:ListKeys": [{"KeyId": "tagged-key", "KeyArn": key_arn}],
            "kms:ListAliases": [],
            "kms:ListResourceTags": tags,
            "signer:ListSigningProfiles": signing_profiles,
            "lambda:ListCodeSigningConfigs": [
                {
                    "CodeSigningConfigId": "csc-unrelated",
                    "CodeSigningConfigArn": config_arn,
                }
            ],
        },
        values={
            "s3:GetBucketTagging": {"TagSet": tags},
            "kms:DescribeKey": {
                "KeyMetadata": {
                    "KeyId": "tagged-key",
                    "Arn": key_arn,
                    "KeyManager": "CUSTOMER",
                }
            },
            "signer:GetSigningProfile": {
                "profileName": "unrelated",
                "profileVersion": "1",
                "profileVersionArn": profile_arn,
                "arn": profile_arn,
            },
            "signer:ListTagsForResource": {"Tags": {"tag_pairs": tags}},
            "lambda:GetCodeSigningConfig": {
                "CodeSigningConfig": {
                    "CodeSigningConfigId": "csc-unrelated",
                    "CodeSigningConfigArn": config_arn,
                }
            },
            "lambda:ListTags": {"Tags": {"tag_pairs": tags}},
        },
        head={
            "status_code": "synthetic_not_executed",
            "collision": False,
            "absent": False,
        },
    )
    reader = provider._CollisionAuthorityReader(session)

    bucket = reader.artifact_bucket(
        "scanalyze-gug395-candidate",
        max_owned_buckets=1,
        tag_contract=contract.AUTHORITY_TAG_CONTRACT,
    )
    kms = reader.kms_alias(
        "alias/scanalyze-gug395-candidate",
        max_kms_keys=1,
        tag_contract=contract.AUTHORITY_TAG_CONTRACT,
    )
    signer = reader.signing_profile(
        "scanalyze_gug395_candidate",
        max_signing_profiles=1,
        tag_contract=contract.AUTHORITY_TAG_CONTRACT,
    )
    signing_config = reader.code_signing_configs(
        contract.AUTHORITY_TAG_CONTRACT,
        max_code_signing_configs=1,
    )

    assert bucket["owned_matches"] == []
    assert bucket["tag_matches"]
    assert bucket["collision"] is True
    assert kms["alias_matches"] == []
    assert kms["collision"] is True
    assert signer["name_matches"] == []
    assert signer["collision"] is True
    assert signing_config["collision"] is True


def test_signer_inventory_includes_revoked_exact_name_collisions() -> None:
    profile_name = "scanalyze_gug395_candidate"
    profile_arn = (
        f"arn:aws:signer:us-east-1:{AUTHORITY_ACCOUNT}:"
        f"signing-profiles/{profile_name}"
    )

    def signing_profiles(kwargs: Mapping[str, Any]) -> list[dict[str, str]]:
        assert kwargs["request"] == {
            "includeCanceled": True,
            "statuses": ["Active", "Canceled", "Revoked"],
        }
        return [
            {
                "profileName": profile_name,
                "profileVersion": "1",
                "profileVersionArn": profile_arn,
                "arn": profile_arn,
                "status": "Revoked",
            }
        ]

    session = _ScriptedCollisionSession(
        pages={"signer:ListSigningProfiles": signing_profiles},
        values={
            "signer:GetSigningProfile": {
                "profileName": profile_name,
                "profileVersion": "1",
                "profileVersionArn": profile_arn,
                "arn": profile_arn,
                "status": "Revoked",
            },
            "signer:ListTagsForResource": {"Tags": {"tag_pairs": []}},
        },
    )

    result = provider._CollisionAuthorityReader(session).signing_profile(
        profile_name,
        max_signing_profiles=1,
        tag_contract=contract.AUTHORITY_TAG_CONTRACT,
    )

    assert result["name_matches"][0]["status"] == "Revoked"
    assert result["collision"] is True


def test_kms_aws_managed_key_is_bound_but_never_tagged() -> None:
    key_arn = f"arn:aws:kms:us-east-1:{AUTHORITY_ACCOUNT}:key/aws-key"
    session = _ScriptedCollisionSession(
        pages={
            "kms:ListKeys": [{"KeyId": "aws-key", "KeyArn": key_arn}],
            "kms:ListAliases": [],
        },
        values={
            "kms:DescribeKey": {
                "KeyMetadata": {
                    "KeyId": "aws-key",
                    "Arn": key_arn,
                    "KeyManager": "AWS",
                }
            }
        },
    )

    facts = provider._CollisionAuthorityReader(session).kms_alias(
        "alias/candidate",
        max_kms_keys=1,
        tag_contract=contract.AUTHORITY_TAG_CONTRACT,
    )

    assert facts["key_details"][0]["tags"] == []
    assert facts["key_details"][0]["tag_contract_matches"] is False
    assert "kms:ListResourceTags" not in [
        operation for _, operation, _ in session.calls
    ]


@pytest.mark.parametrize(
    ("detail_key_id", "detail_key_arn"),
    [
        ("different", "expected"),
        ("expected", "different"),
    ],
)
def test_kms_summary_and_description_must_bind_exactly(
    detail_key_id: str, detail_key_arn: str
) -> None:
    expected_arn = (
        f"arn:aws:kms:us-east-1:{AUTHORITY_ACCOUNT}:key/expected"
    )
    supplied_arn = (
        expected_arn
        if detail_key_arn == "expected"
        else f"arn:aws:kms:us-east-1:{AUTHORITY_ACCOUNT}:key/different"
    )
    session = _ScriptedCollisionSession(
        pages={
            "kms:ListKeys": [
                {"KeyId": "expected", "KeyArn": expected_arn}
            ],
            "kms:ListAliases": [],
        },
        values={
            "kms:DescribeKey": {
                "KeyMetadata": {
                    "KeyId": detail_key_id,
                    "Arn": supplied_arn,
                    "KeyManager": "CUSTOMER",
                }
            }
        },
    )

    with pytest.raises(
        provider.LiveProviderError,
        match="^COLLISION_PROBE_RESPONSE_CONFLICT$",
    ):
        provider._CollisionAuthorityReader(session).kms_alias(
            "alias/candidate", max_kms_keys=1
        )
    assert "kms:ListResourceTags" not in [
        operation for _, operation, _ in session.calls
    ]


@pytest.mark.parametrize("selector", ["signer", "code_signing_config"])
def test_signing_summary_and_description_conflicts_fail_closed(
    selector: str,
) -> None:
    profile_arn = (
        f"arn:aws:signer:us-east-1:{AUTHORITY_ACCOUNT}:"
        "signing-profiles/candidate/2"
    )
    config_arn = (
        f"arn:aws:lambda:us-east-1:{AUTHORITY_ACCOUNT}:"
        "code-signing-config:csc-candidate"
    )
    session = _ScriptedCollisionSession(
        pages={
            "signer:ListSigningProfiles": [
                {
                    "profileName": "candidate",
                    "profileVersion": "2",
                    "profileVersionArn": profile_arn,
                    "arn": profile_arn,
                }
            ],
            "lambda:ListCodeSigningConfigs": [
                {
                    "CodeSigningConfigId": "csc-candidate",
                    "CodeSigningConfigArn": config_arn,
                }
            ],
        },
        values={
            "signer:GetSigningProfile": {
                "profileName": "candidate",
                "profileVersion": "3",
                "profileVersionArn": profile_arn,
                "arn": profile_arn,
            },
            "lambda:GetCodeSigningConfig": {
                "CodeSigningConfig": {
                    "CodeSigningConfigId": "csc-different",
                    "CodeSigningConfigArn": config_arn,
                }
            },
        },
    )
    reader = provider._CollisionAuthorityReader(session)

    with pytest.raises(
        provider.LiveProviderError,
        match="^COLLISION_PROBE_RESPONSE_CONFLICT$",
    ):
        if selector == "signer":
            reader.signing_profile("candidate", max_signing_profiles=1)
        else:
            reader.code_signing_configs(
                contract.AUTHORITY_TAG_CONTRACT,
                max_code_signing_configs=1,
            )


def test_identity_selectors_detect_tag_collision_without_exact_name() -> None:
    tags = _tag_pairs(contract.IDENTITY_TAG_CONTRACT)
    instance_arn = "arn:aws:sso:::instance/ssoins-1234567890abcdef"
    application_arn = (
        f"arn:aws:sso::{IDENTITY_ACCOUNT}:application/"
        "ssoins-1234567890abcdef/apl-1234567890abcdef"
    )
    classifier_arn = (
        "arn:aws:sso:::permissionSet/"
        "ssoins-1234567890abcdef/ps-1111111111111111"
    )
    approver_arn = (
        "arn:aws:sso:::permissionSet/"
        "ssoins-1234567890abcdef/ps-2222222222222222"
    )

    def describe_permission_set(kwargs: Mapping[str, Any]) -> Mapping[str, Any]:
        arn = kwargs["request"]["PermissionSetArn"]
        name = "UnrelatedOne" if arn == classifier_arn else "UnrelatedTwo"
        return {"PermissionSet": {"PermissionSetArn": arn, "Name": name}}

    session = _ScriptedCollisionSession(
        pages={
            "sso:ListInstances": [
                {
                    "InstanceArn": instance_arn,
                    "OwnerAccountId": IDENTITY_ACCOUNT,
                    "Status": "ACTIVE",
                }
            ],
            "sso:ListApplications": [
                {
                    "ApplicationArn": application_arn,
                    "ApplicationAccount": IDENTITY_ACCOUNT,
                    "InstanceArn": instance_arn,
                    "Name": "UnrelatedApplication",
                }
            ],
            "sso:ListPermissionSets": [classifier_arn, approver_arn],
            "sso:ListTagsForResource": tags,
        },
        values={
            "sso:DescribeApplication": {
                "ApplicationArn": application_arn,
                "ApplicationAccount": IDENTITY_ACCOUNT,
                "InstanceArn": instance_arn,
                "NameDigest": provider.canonical_digest(
                    "UnrelatedApplication"
                ),
            },
            "sso:DescribePermissionSet": describe_permission_set,
        },
    )

    facts = provider._CollisionIdentityReader(session)._read_explicit_facts(
        instance_arn=instance_arn,
        application_name="ScanalyzeAuthorityRetirement",
        classifier_permission_set_name="ScanalyzeAuthorityRetireClass",
        approver_permission_set_name="ScanalyzeAuthorityRetireApprove",
        tag_contract=contract.IDENTITY_TAG_CONTRACT,
        max_applications=1,
        max_permission_sets=2,
    )

    assert facts["application_matches"][0]["name_matches"] is False
    assert facts["application_matches"][0]["tag_contract_matches"] is True
    assert facts["application_collision"] is True
    assert facts["classifier_permission_set_collision"] is True
    assert facts["approver_permission_set_collision"] is True


@pytest.mark.parametrize(
    "conflict",
    [
        "instance_owner",
        "summary_account",
        "summary_instance",
        "description_account",
        "description_name",
    ],
)
def test_identity_instance_and_application_bindings_fail_closed(
    conflict: str,
) -> None:
    instance_arn = "arn:aws:sso:::instance/ssoins-1234567890abcdef"
    other_instance = "arn:aws:sso:::instance/ssoins-fedcba0987654321"
    application_arn = (
        f"arn:aws:sso::{IDENTITY_ACCOUNT}:application/"
        "ssoins-1234567890abcdef/apl-1234567890abcdef"
    )
    instance = {
        "InstanceArn": instance_arn,
        "OwnerAccountId": IDENTITY_ACCOUNT,
        "Status": "ACTIVE",
    }
    summary = {
        "ApplicationArn": application_arn,
        "ApplicationAccount": IDENTITY_ACCOUNT,
        "InstanceArn": instance_arn,
        "Name": "ApplicationName",
    }
    description = {
        "ApplicationArn": application_arn,
        "ApplicationAccount": IDENTITY_ACCOUNT,
        "InstanceArn": instance_arn,
        "NameDigest": provider.canonical_digest("ApplicationName"),
    }
    if conflict == "instance_owner":
        instance["OwnerAccountId"] = AUTHORITY_ACCOUNT
    elif conflict == "summary_account":
        summary["ApplicationAccount"] = AUTHORITY_ACCOUNT
    elif conflict == "summary_instance":
        summary["InstanceArn"] = other_instance
    elif conflict == "description_account":
        description["ApplicationAccount"] = AUTHORITY_ACCOUNT
    else:
        description["NameDigest"] = provider.canonical_digest("Different")
    session = _ScriptedCollisionSession(
        pages={
            "sso:ListInstances": [instance],
            "sso:ListApplications": [summary],
            "sso:ListPermissionSets": [],
        },
        values={"sso:DescribeApplication": description},
    )

    with pytest.raises(
        provider.LiveProviderError,
        match=(
            "^COLLISION_(?:IDENTITY_OWNER_MISMATCH|"
            "PROBE_RESPONSE_CONFLICT)$"
        ),
    ):
        provider._CollisionIdentityReader(session)._read_explicit_facts(
            instance_arn=instance_arn,
            application_name="ApplicationName",
            classifier_permission_set_name="Classifier",
            approver_permission_set_name="Approver",
            tag_contract=contract.IDENTITY_TAG_CONTRACT,
            max_applications=1,
            max_permission_sets=1,
        )


@pytest.mark.parametrize(
    ("selector", "expected_operation"),
    [
        ("bucket", "s3:ListAllMyBuckets"),
        ("kms", "kms:ListKeys"),
        ("signer", "signer:ListSigningProfiles"),
        ("code_signing_config", "lambda:ListCodeSigningConfigs"),
    ],
)
def test_authority_caps_stop_before_any_detail_call(
    selector: str, expected_operation: str
) -> None:
    responses = {
        "s3:ListAllMyBuckets": [{"Name": "one"}, {"Name": "two"}],
        "kms:ListKeys": [{"KeyId": "one"}, {"KeyId": "two"}],
        "signer:ListSigningProfiles": [
            {"profileName": "one"},
            {"profileName": "two"},
        ],
        "lambda:ListCodeSigningConfigs": [
            {"CodeSigningConfigArn": "arn:one"},
            {"CodeSigningConfigArn": "arn:two"},
        ],
    }
    session = _ScriptedCollisionSession(pages=responses)
    reader = provider._CollisionAuthorityReader(session)

    with pytest.raises(
        provider.LiveProviderError,
        match="^COLLISION_RESOURCE_CAP_EXCEEDED$",
    ):
        if selector == "bucket":
            reader.artifact_bucket("candidate", max_owned_buckets=1)
        elif selector == "kms":
            reader.kms_alias("alias/candidate", max_kms_keys=1)
        elif selector == "signer":
            reader.signing_profile("candidate", max_signing_profiles=1)
        else:
            reader.code_signing_configs(
                contract.AUTHORITY_TAG_CONTRACT,
                max_code_signing_configs=1,
            )

    assert [(kind, operation) for kind, operation, _ in session.calls] == [
        ("paginate", expected_operation)
    ]


@pytest.mark.parametrize("over_cap_resource", ["applications", "permission_sets"])
def test_identity_caps_stop_before_corresponding_detail_calls(
    over_cap_resource: str,
) -> None:
    instance_arn = "arn:aws:sso:::instance/ssoins-1234567890abcdef"
    pages: dict[str, Any] = {
        "sso:ListInstances": [
            {
                "InstanceArn": instance_arn,
                "OwnerAccountId": IDENTITY_ACCOUNT,
                "Status": "ACTIVE",
            }
        ],
        "sso:ListApplications": [],
        "sso:ListPermissionSets": [],
    }
    if over_cap_resource == "applications":
        pages["sso:ListApplications"] = [
            {"ApplicationArn": "arn:application:one"},
            {"ApplicationArn": "arn:application:two"},
        ]
    else:
        pages["sso:ListPermissionSets"] = [
            "arn:permission-set:one",
            "arn:permission-set:two",
        ]
    session = _ScriptedCollisionSession(pages=pages)

    with pytest.raises(
        provider.LiveProviderError,
        match="^COLLISION_RESOURCE_CAP_EXCEEDED$",
    ):
        provider._CollisionIdentityReader(session)._read_explicit_facts(
            instance_arn=instance_arn,
            application_name="ScanalyzeAuthorityRetirement",
            classifier_permission_set_name="ScanalyzeAuthorityRetireClass",
            approver_permission_set_name="ScanalyzeAuthorityRetireApprove",
            tag_contract=contract.IDENTITY_TAG_CONTRACT,
            max_applications=1,
            max_permission_sets=1,
        )

    operations = [operation for _, operation, _ in session.calls]
    if over_cap_resource == "applications":
        assert operations == ["sso:ListInstances", "sso:ListApplications"]
    else:
        assert operations == [
            "sso:ListInstances",
            "sso:ListApplications",
            "sso:ListPermissionSets",
        ]
    assert all(kind == "paginate" for kind, _, _ in session.calls)
