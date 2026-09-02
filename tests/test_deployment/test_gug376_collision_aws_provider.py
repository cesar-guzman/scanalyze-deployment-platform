from __future__ import annotations

from collections import defaultdict
from datetime import UTC, datetime, timedelta
import gc
from itertools import count
from typing import Any
import weakref

import pytest

from tooling import platform_authority_gug376_collision_aws_provider as subject
from tooling import platform_authority_gug376_collision_policy as policy_contract
from tooling import platform_authority_gug376_collision_transcript_contract as transcript
from tooling.platform_authority_gug376_collision_catalog import (
    materialize_route_collision_catalog,
)
from tooling.platform_authority_gug365_upstream_inventory import canonical_digest


AUTHORITY = "042360977644"
MANAGEMENT = "839393571433"
INSTANCE_ARN = "arn:aws:sso:::instance/ssoins-1234567890abcdef"
PERMISSION_SET_ARN = (
    "arn:aws:sso:::permissionSet/"
    "ssoins-1234567890abcdef/ps-1234567890abcdef"
)
IDENTITY_CENTER_KMS_KEY_ARN = (
    "arn:aws:kms:us-east-1:839393571433:key/"
    "12345678-abcd-1234-abcd-1234567890ab"
)
PRIVATE_KMS_BINDING_DIGEST = canonical_digest(
    {
        "source": "GUG393_PRIVATE_MATERIALIZATION",
        "key_arn": IDENTITY_CENTER_KMS_KEY_ARN,
    }
)


def _stamp(value: datetime) -> str:
    return value.isoformat().replace("+00:00", "Z")


def _catalog() -> dict[str, Any]:
    now = datetime(2026, 9, 1, 1, tzinfo=UTC)
    return materialize_route_collision_catalog(
        source_commit_sha="a" * 40,
        source_tree_sha="b" * 40,
        bootstrap_intent_digest="sha256:" + "c" * 64,
        not_before=_stamp(now - timedelta(minutes=1)),
        expires_at=_stamp(now + timedelta(minutes=10)),
        artifact_bucket_name=(
            "scanalyze-g376-art-aaaaaaaaaaaa-"
            "042360977644-us-east-1-an"
        ),
    )


def _candidate_resources() -> dict[str, dict[str, list[str]]]:
    return {
        "authority": {
            "cloudformation_stack": [
                "arn:aws:cloudformation:us-east-1:042360977644:stack/"
                "scanalyze-platform-authority-gug376-artifact-foundation/"
                "12345678-abcd-1234-abcd-1234567890ab"
            ],
            "kms_key": [
                "arn:aws:kms:us-east-1:042360977644:key/"
                "12345678-abcd-1234-abcd-1234567890ab"
            ],
            "lambda_code_signing_config": [
                "arn:aws:lambda:us-east-1:042360977644:"
                "code-signing-config:csc-0123456789abcdef0"
            ],
        },
        "management": {
            "cloudformation_stack": [
                "arn:aws:cloudformation:us-east-1:839393571433:stack/"
                "scanalyze-platform-authority-gug376-artifact-bootstrap-bridge/"
                "12345678-abcd-1234-abcd-1234567890ab"
            ],
            "identity_center_kms_key": [
                "arn:aws:kms:us-east-1:839393571433:key/"
                "12345678-abcd-1234-abcd-1234567890ab"
            ],
            "sso_application": [
                "arn:aws:sso::839393571433:application/"
                "ssoins-1234567890abcdef/apl-1234567890abcdef"
            ],
            "sso_instance": [INSTANCE_ARN],
            "sso_permission_set": [PERMISSION_SET_ARN],
        },
    }


def _policy(
    catalog: dict[str, Any], *, inventory_only: bool = False
) -> dict[str, Any]:
    del inventory_only
    return policy_contract.materialize_route_collision_policy_set(catalog)


def _principal(domain: str) -> str:
    account = AUTHORITY if domain == "authority" else MANAGEMENT
    return (
        f"arn:aws:sts::{account}:assumed-role/"
        f"AWSReservedSSO_Gug376ReadOnly_{domain}/operator"
    )


def _role(domain: str) -> str:
    return f"AWSReservedSSO_Gug376ReadOnly_{domain}"


def _expected_identities(policy: dict[str, Any]) -> dict[str, Any]:
    identities = {}
    for domain, account in (("authority", AUTHORITY), ("management", MANAGEMENT)):
        identities[domain] = {
            "account_id": account,
            "source": "DIRECT_SSO",
            "chain_depth": 0,
            "principal_digest": canonical_digest(_principal(domain)),
            "sso_role_name_digest": canonical_digest(_role(domain)),
            "policy_digest": policy["policy_set_digest"],
            "authority_verification_digest": canonical_digest(
                {"authority": domain}
            ),
        }
    return identities


def _request(catalog: dict[str, Any], policy: dict[str, Any]) -> dict[str, Any]:
    value = {
        "catalog": catalog,
        "catalog_digest": catalog["catalog_digest"],
        "collision_policy_set_digest": policy["policy_set_digest"],
        "collision_policy_digests": policy["policy_digests"],
        "collision_policy_stage": policy["stage"],
        "collision_provider_implementation_digest": (
            transcript.COLLISION_PROVIDER_IMPLEMENTATION_DIGEST
        ),
        "expected_identities": _expected_identities(policy),
        "expected_dispositions": {
            target["target_id"]: "ABSENT_AT_SNAPSHOT"
            for target in catalog["targets"]
        },
    }
    value["request_digest"] = canonical_digest(value)
    return value


class FakeAwsError(Exception):
    def __init__(self, code: str) -> None:
        self.response = {"Error": {"Code": code}}


class FakeClient:
    def __init__(self, sdk: "FakeSdkSession", service: str) -> None:
        self.sdk = sdk
        self.service = service

    def _call(self, method: str, kwargs: dict[str, Any]) -> dict[str, Any]:
        self.sdk.calls.append((self.service, method, kwargs))
        scripted = self.sdk.scripts.get((self.service, method))
        if scripted:
            value = scripted.pop(0)
            if isinstance(value, Exception):
                raise value
            return value
        if method == "get_caller_identity":
            return {
                "Account": self.sdk.account,
                "Arn": _principal(self.sdk.domain),
                "UserId": f"user-{self.sdk.domain}",
            }
        if method in {"describe_stacks", "describe_stack_resource"}:
            raise FakeAwsError("ValidationError")
        if method == "describe_table":
            raise FakeAwsError("ResourceNotFoundException")
        if method == "get_role":
            raise FakeAwsError("NoSuchEntity")
        if method in {"get_alias", "get_function", "get_code_signing_config"}:
            raise FakeAwsError("ResourceNotFoundException")
        if method == "get_signing_profile":
            raise FakeAwsError("ResourceNotFoundException")
        empty = {
            "list_stacks": {"StackSummaries": []},
            "list_aliases": {"Aliases": [], "Truncated": False},
            "describe_log_groups": {"logGroups": []},
            "list_buckets": {"Buckets": []},
            "list_applications": {"Applications": []},
            "list_instances": {
                "Instances": [
                    {
                        "InstanceArn": INSTANCE_ARN,
                        "OwnerAccountId": MANAGEMENT,
                    }
                ]
            },
            "list_permission_sets": {"PermissionSets": []},
        }
        if method in empty:
            return empty[method]
        raise AssertionError((self.service, method, kwargs))

    def __getattr__(self, method: str) -> Any:
        return lambda **kwargs: self._call(method, kwargs)


class FakeSdkSession:
    def __init__(self, domain: str) -> None:
        self.domain = domain
        self.account = AUTHORITY if domain == "authority" else MANAGEMENT
        self.calls: list[tuple[str, str, dict[str, Any]]] = []
        self.scripts: dict[tuple[str, str], list[Any]] = defaultdict(list)

    def client(self, service: str, *, region_name: str) -> FakeClient:
        assert region_name == subject.REGION
        return FakeClient(self, service)


class Harness:
    def __init__(
        self,
        policy: dict[str, Any],
        *,
        max_pages: int = transcript.MAX_PAGES,
        account_overrides: dict[str, str] | None = None,
        reuse_sdk_session: bool = False,
        session_setup: Any | None = None,
        discovery_capability: object | None = None,
        kms_binding_source: str = "GUG393_PRIVATE_MATERIALIZATION",
        kms_binding_digest: str = PRIVATE_KMS_BINDING_DIGEST,
        kms_mode: str = "CUSTOMER_MANAGED_KEY",
        kms_key_arn: str | None = IDENTITY_CENTER_KMS_KEY_ARN,
        before_call: Any | None = None,
        session_registry: object | None = None,
        shared_sdk_session: FakeSdkSession | None = None,
        permission_set_name_by_arn: dict[str, str] | None = None,
    ) -> None:
        self.policy = policy
        account_overrides = account_overrides or {}
        self.sessions: dict[tuple[int, str], FakeSdkSession] = {}
        shared_session: FakeSdkSession | None = shared_sdk_session
        ticks = count()

        def opener(**context: Any) -> subject.OpenedReadOnlySession:
            domain = context["domain"]
            capture = context["capture_index"]
            nonlocal shared_session
            session = shared_session if reuse_sdk_session else None
            if session is None:
                session = FakeSdkSession(domain)
                if reuse_sdk_session:
                    shared_session = session
            session.domain = domain
            session.account = AUTHORITY if domain == "authority" else MANAGEMENT
            session.account = account_overrides.get(domain, session.account)
            self.sessions[(capture, domain)] = session
            if session_setup is not None:
                session_setup(capture, domain, session)
            return subject.OpenedReadOnlySession(
                sdk_session=session,
                principal_arn=_principal(domain),
                sso_role_name=_role(domain),
                policy_digest=policy["policy_set_digest"],
                authority_verification_digest=canonical_digest(
                    {"authority": domain}
                ),
                session_nonce_digest=canonical_digest(
                    {"capture": capture, "domain": domain}
                ),
                identity_center_instance_arn=(
                    INSTANCE_ARN if domain == "management" else None
                ),
                permission_set_name_by_arn={
                    PERMISSION_SET_ARN: "ScanalyzeGug376ArtifactBootstrap"
                } if permission_set_name_by_arn is None else permission_set_name_by_arn,
                identity_center_kms_mode=(
                    kms_mode
                    if domain == "management"
                    else None
                ),
                identity_center_kms_key_arn=(
                    kms_key_arn
                    if domain == "management"
                    else None
                ),
                identity_center_kms_binding_source=(
                    kms_binding_source
                    if domain == "management"
                    else None
                ),
                identity_center_kms_private_binding_digest=(
                    kms_binding_digest
                    if domain == "management"
                    else None
                ),
            )

        def clock() -> datetime:
            return datetime(2026, 9, 1, 1, tzinfo=UTC) + timedelta(
                seconds=next(ticks)
            )

        self.factory = subject.build_attested_provider_factory(
            session_opener=opener,
            clock=clock,
            policy_set=policy,
            discovery_capability=discovery_capability,
            before_call=before_call,
            session_registry=session_registry,
            max_pages=max_pages,
        )


def _open(harness: Harness, request: dict[str, Any], capture: int = 1) -> Any:
    return harness.factory.open_snapshot(
        request=request,
        capture_index=capture,
        purpose={
            1: "independent-snapshot-1",
            2: "independent-snapshot-2",
            3: "pre-effect-snapshot",
        }[capture],
    )


def _domain_targets(request: dict[str, Any], domain: str) -> list[dict[str, Any]]:
    return [
        target for target in request["catalog"]["targets"]
        if target["domain"] == domain
    ]


def _discover_candidate_policy(
    harness: Harness,
    catalog: dict[str, Any],
) -> tuple[object, dict[str, Any]]:
    capability = harness.factory.discover_route_collision_candidates(
        catalog=catalog,
        expected_identities=_expected_identities(harness.policy),
        expected_identity_center_kms_binding_digest=(
            PRIVATE_KMS_BINDING_DIGEST
        ),
    )
    policy = policy_contract.materialize_route_collision_policy_set(
        catalog,
        discovery_capability=capability,
    )
    return capability, policy


def test_discovery_capability_requires_two_independent_scans_and_is_one_shot(
) -> None:
    catalog = _catalog()
    inventory = _policy(catalog)
    harness = Harness(inventory)
    capability, candidate_policy = _discover_candidate_policy(
        harness,
        catalog,
    )

    assert set(harness.sessions) == {
        (1, "authority"),
        (1, "management"),
        (2, "authority"),
        (2, "management"),
    }
    assert len({id(session) for session in harness.sessions.values()}) == 4
    assert candidate_policy["stage"] == "inventory-and-candidate-detail"
    attestation = subject.discovery_capability_attestation(capability)
    assert attestation["scan_count"] == 2
    assert set(attestation) == {
        "record_type",
        "schema_version",
        "catalog_digest",
        "inventory_policy_set_digest",
        "provenance_digest",
        "capability_digest",
        "selector_attestation_digest",
        "scan_count",
        "read_only",
        "aws_mutations",
    }
    candidate_factory = Harness(
        candidate_policy,
        discovery_capability=capability,
    ).factory
    assert candidate_factory.provider_attestation()[
        "discovery_provenance_digest"
    ] == candidate_policy["discovery_provenance_digest"]
    with pytest.raises(subject.CollisionAwsProviderError) as reused_policy:
        policy_contract.materialize_route_collision_policy_set(
            catalog,
            discovery_capability=capability,
        )
    assert reused_policy.value.code == "COLLISION_DISCOVERY_LIFECYCLE_INVALID"
    with pytest.raises(subject.CollisionAwsProviderError) as rebound:
        Harness(candidate_policy, discovery_capability=capability)
    assert rebound.value.code == "COLLISION_PROVIDER_DISCOVERY_BINDING_INVALID"


def test_discovery_models_aws_owned_identity_center_kms_without_inventing_arn(
) -> None:
    catalog = _catalog()
    inventory = _policy(catalog)
    harness = Harness(
        inventory,
        kms_mode="AWS_OWNED_KMS_KEY",
        kms_key_arn=None,
    )

    _capability, candidate_policy = _discover_candidate_policy(
        harness,
        catalog,
    )

    assert candidate_policy["candidate_resources"]["management"][
        "identity_center_kms_key"
    ] == []
    items = candidate_policy["discovery_evidence"]["domains"]["management"][
        "identity_center_kms_key"
    ]["pages"][0]["items"]
    assert items == [
        {
            "BindingName": "identity_center_kms_key_arn",
            "Mode": "AWS_OWNED_KMS_KEY",
            "PrivateBindingDigest": PRIVATE_KMS_BINDING_DIGEST,
        }
    ]


def test_exact_instance_inventory_resolves_permission_set_names_in_transcript(
) -> None:
    catalog = _catalog()
    inventory = policy_contract.materialize_route_collision_policy_set(
        catalog,
        identity_center_instance_arn=INSTANCE_ARN,
    )

    def setup(_capture: int, domain: str, session: FakeSdkSession) -> None:
        if domain != "management":
            return
        session.scripts[("sso-admin", "list_permission_sets")] = [
            {"PermissionSets": [PERMISSION_SET_ARN]}
        ]
        session.scripts[("sso-admin", "describe_permission_set")] = [
            {
                "PermissionSet": {
                    "PermissionSetArn": PERMISSION_SET_ARN,
                    "Name": "ScanalyzeGug376ArtifactBootstrap",
                }
            }
        ]

    harness = Harness(
        inventory,
        session_setup=setup,
        permission_set_name_by_arn={},
    )
    capability = harness.factory.discover_route_collision_candidates(
        catalog=catalog,
        expected_identities=_expected_identities(inventory),
        expected_identity_center_kms_binding_digest=(
            PRIVATE_KMS_BINDING_DIGEST
        ),
    )
    candidate = policy_contract.materialize_route_collision_policy_set(
        catalog,
        discovery_capability=capability,
        identity_center_instance_arn=INSTANCE_ARN,
    )

    for capture in (1, 2):
        calls = harness.sessions[(capture, "management")].calls
        assert (
            "sso-admin",
            "describe_permission_set",
            {
                "InstanceArn": INSTANCE_ARN,
                "PermissionSetArn": PERMISSION_SET_ARN,
            },
        ) in calls
    assert candidate["candidate_resources"]["management"][
        "sso_permission_set"
    ] == [PERMISSION_SET_ARN]
    candidate_factory = Harness(
        candidate,
        discovery_capability=capability,
        permission_set_name_by_arn={
            PERMISSION_SET_ARN: "ScanalyzeGug376ArtifactBootstrap"
        },
    ).factory
    assert candidate_factory.provider_attestation()[
        "policy_stage"
    ] == "inventory-and-candidate-detail"


def test_exact_instance_inventory_rejects_stale_injected_name_index() -> None:
    catalog = _catalog()
    inventory = policy_contract.materialize_route_collision_policy_set(
        catalog,
        identity_center_instance_arn=INSTANCE_ARN,
    )
    harness = Harness(inventory)

    with pytest.raises(subject.CollisionAwsProviderError) as raised:
        harness.factory.discover_route_collision_candidates(
            catalog=catalog,
            expected_identities=_expected_identities(inventory),
            expected_identity_center_kms_binding_digest=(
                PRIVATE_KMS_BINDING_DIGEST
            ),
        )

    assert raised.value.code == "COLLISION_PROVIDER_SELECTOR_BINDING_INVALID"


def test_candidate_factory_rejects_json_duck_type_and_missing_capability() -> None:
    catalog = _catalog()
    inventory = _policy(catalog)
    with pytest.raises(subject.CollisionAwsProviderError) as duck:
        policy_contract.materialize_route_collision_policy_set(
            catalog,
            discovery_capability={"self_sealed": True},
        )
    assert duck.value.code == "COLLISION_DISCOVERY_CAPABILITY_NOT_ATTESTED"

    harness = Harness(inventory)
    capability, candidate_policy = _discover_candidate_policy(harness, catalog)
    with pytest.raises(subject.CollisionAwsProviderError) as missing:
        Harness(candidate_policy)
    assert missing.value.code == "COLLISION_PROVIDER_DISCOVERY_BINDING_INVALID"
    Harness(candidate_policy, discovery_capability=capability)


def test_discovery_rejects_independent_result_mismatch() -> None:
    catalog = _catalog()
    inventory = _policy(catalog)
    alias_name = next(
        target["name"]
        for target in catalog["targets"]
        if target["service"] == "kms"
    )

    def setup(capture: int, domain: str, session: FakeSdkSession) -> None:
        if domain == "authority" and capture == 2:
            session.scripts[("kms", "list_aliases")] = [
                {
                    "Aliases": [
                        {
                            "AliasName": alias_name,
                            "TargetKeyId": (
                                "12345678-abcd-1234-abcd-1234567890ab"
                            ),
                        }
                    ],
                    "Truncated": False,
                }
            ]

    harness = Harness(inventory, session_setup=setup)
    with pytest.raises(subject.CollisionAwsProviderError) as mismatch:
        harness.factory.discover_route_collision_candidates(
            catalog=catalog,
            expected_identities=_expected_identities(inventory),
            expected_identity_center_kms_binding_digest=(
                PRIVATE_KMS_BINDING_DIGEST
            ),
        )
    assert mismatch.value.code == (
        "COLLISION_DISCOVERY_INDEPENDENT_RESULT_MISMATCH"
    )


def test_discovery_binds_complete_cursor_chains_without_leaking_tokens() -> None:
    catalog = _catalog()
    inventory = _policy(catalog)

    def setup(_capture: int, domain: str, session: FakeSdkSession) -> None:
        if domain == "authority":
            session.scripts[("kms", "list_aliases")] = [
                {
                    "Aliases": [{"AliasName": "alias/unrelated-a"}],
                    "Truncated": True,
                    "NextMarker": "private-page-token",
                },
                {
                    "Aliases": [{"AliasName": "alias/unrelated-b"}],
                    "Truncated": False,
                },
            ]

    harness = Harness(inventory, session_setup=setup)
    capability, _candidate_policy = _discover_candidate_policy(
        harness,
        catalog,
    )
    attestation = subject.discovery_capability_attestation(capability)
    assert "private-page-token" not in repr(attestation)
    for capture in (1, 2):
        calls = [
            call
            for call in harness.sessions[(capture, "authority")].calls
            if call[:2] == ("kms", "list_aliases")
        ]
        assert len(calls) == 2


def test_discovery_binds_account_regional_s3_owner_sweeps_without_head_bucket(
) -> None:
    catalog = _catalog()
    inventory = _policy(catalog)
    harness = Harness(inventory)
    capability, _candidate_policy = _discover_candidate_policy(
        harness,
        catalog,
    )

    bucket_name = str(catalog["artifact_bucket_name"])
    expected_request = {
        "BucketRegion": "us-east-1",
        "Prefix": bucket_name,
        "MaxBuckets": 100,
    }
    for capture in (1, 2):
        calls = harness.sessions[(capture, "authority")].calls
        assert ("s3", "list_buckets", expected_request) in calls
        assert all(
            method != "head_bucket"
            for _service, method, _request in calls
        )
    attestation = subject.discovery_capability_attestation(capability)
    assert bucket_name not in repr(attestation)


def test_discovery_rejects_inconsistent_account_regional_bucket_result() -> None:
    catalog = _catalog()
    inventory = _policy(catalog)

    def setup(capture: int, domain: str, session: FakeSdkSession) -> None:
        if capture == 2 and domain == "authority":
            session.scripts[("s3", "list_buckets")] = [
                {
                    "Buckets": [
                        {
                            "Name": catalog["artifact_bucket_name"],
                            "BucketRegion": "us-east-1",
                        }
                    ]
                }
            ]

    harness = Harness(inventory, session_setup=setup)
    with pytest.raises(subject.CollisionAwsProviderError) as mismatch:
        harness.factory.discover_route_collision_candidates(
            catalog=catalog,
            expected_identities=_expected_identities(inventory),
            expected_identity_center_kms_binding_digest=(
                PRIVATE_KMS_BINDING_DIGEST
            ),
        )
    assert mismatch.value.code == (
        "COLLISION_DISCOVERY_INDEPENDENT_RESULT_MISMATCH"
    )


@pytest.mark.parametrize("capture", [1, 2])
@pytest.mark.parametrize("bucket_region", [None, "eu-west-1"])
def test_discovery_rejects_exact_bucket_without_expected_region(
    capture: int,
    bucket_region: str | None,
) -> None:
    catalog = _catalog()
    inventory = _policy(catalog)

    def setup(
        current_capture: int,
        domain: str,
        session: FakeSdkSession,
    ) -> None:
        if current_capture != capture or domain != "authority":
            return
        bucket = {"Name": catalog["artifact_bucket_name"]}
        if bucket_region is not None:
            bucket["BucketRegion"] = bucket_region
        session.scripts[("s3", "list_buckets")] = [
            {"Buckets": [bucket]}
        ]

    harness = Harness(inventory, session_setup=setup)
    with pytest.raises(subject.CollisionAwsProviderError) as malformed:
        harness.factory.discover_route_collision_candidates(
            catalog=catalog,
            expected_identities=_expected_identities(inventory),
            expected_identity_center_kms_binding_digest=(
                PRIVATE_KMS_BINDING_DIGEST
            ),
        )
    assert malformed.value.code == "COLLISION_PROVIDER_RESPONSE_INVALID"


def test_discovery_rejects_wrong_private_kms_provenance_and_session_reuse() -> None:
    catalog = _catalog()
    inventory = _policy(catalog)
    bad = Harness(
        inventory,
        kms_binding_source="ARBITRARY_JSON",
    )
    with pytest.raises(subject.CollisionAwsProviderError) as binding:
        bad.factory.discover_route_collision_candidates(
            catalog=catalog,
            expected_identities=_expected_identities(inventory),
            expected_identity_center_kms_binding_digest=(
                PRIVATE_KMS_BINDING_DIGEST
            ),
        )
    assert binding.value.code == "COLLISION_DISCOVERY_KMS_BINDING_INVALID"

    reused = Harness(inventory, reuse_sdk_session=True)
    with pytest.raises(subject.CollisionAwsProviderError) as sessions:
        reused.factory.discover_route_collision_candidates(
            catalog=catalog,
            expected_identities=_expected_identities(inventory),
            expected_identity_center_kms_binding_digest=(
                PRIVATE_KMS_BINDING_DIGEST
            ),
        )
    assert sessions.value.code == "COLLISION_PROVIDER_SESSION_NOT_INDEPENDENT"


def test_before_call_expiry_between_pages_prevents_the_next_aws_call() -> None:
    catalog = _catalog()
    policy = _policy(catalog)
    request = _request(catalog, policy)
    calls = 0

    def before_call() -> None:
        nonlocal calls
        calls += 1
        if calls >= 6:
            raise RuntimeError("expired")

    harness = Harness(policy, before_call=before_call)
    snapshot = _open(harness, request)
    snapshot.read_identity(domain="authority")
    session = harness.sessions[(1, "authority")]
    session.scripts[("kms", "list_aliases")] = [
        {
            "Aliases": [{"AliasName": "alias/unrelated"}],
            "Truncated": True,
            "NextMarker": "next-page",
        },
        {"Aliases": [], "Truncated": False},
    ]
    target = next(
        item
        for item in catalog["targets"]
        if item["target_id"] == "authority.kms.artifact-alias"
    )

    with pytest.raises(subject.CollisionAwsProviderError) as raised:
        snapshot._inventory("authority", target)

    assert raised.value.code == "COLLISION_PROVIDER_BUDGET_EXPIRED"
    assert [
        call for call in session.calls if call[:2] == ("kms", "list_aliases")
    ] == [
        (
            "kms",
            "list_aliases",
            {"Limit": 100},
        )
    ]


def test_shared_registry_rejects_discovery_to_snapshot_session_reuse() -> None:
    catalog = _catalog()
    policy = _policy(catalog)
    request = _request(catalog, policy)
    registry = subject.build_session_uniqueness_registry()
    reused_sdk = FakeSdkSession("authority")
    first = Harness(
        policy,
        reuse_sdk_session=True,
        session_registry=registry,
        shared_sdk_session=reused_sdk,
    )
    _open(first, request).read_identity(domain="authority")
    retained_session = weakref.ref(reused_sdk)
    del first, reused_sdk
    gc.collect()
    assert retained_session() is not None
    second = Harness(
        policy,
        reuse_sdk_session=True,
        session_registry=registry,
        shared_sdk_session=retained_session(),
    )

    with pytest.raises(subject.CollisionAwsProviderError) as raised:
        _open(second, request).read_identity(domain="authority")

    assert raised.value.code == "COLLISION_PROVIDER_SESSION_NOT_INDEPENDENT"
    assert subject.session_uniqueness_registry_summary(registry)[
        "sdk_session_count"
    ] == 1


def test_factory_is_private_attested_and_policy_digest_bound() -> None:
    catalog = _catalog()
    policy = _policy(catalog)
    harness = Harness(policy)
    asserted = subject.assert_attested_provider_factory(harness.factory)
    assert asserted is harness.factory
    attestation = harness.factory.provider_attestation()
    assert attestation["policy_set_digest"] == policy["policy_set_digest"]
    assert attestation["policy_digests"] == policy["policy_digests"]
    assert attestation["provider_implementation_digest"] == (
        transcript.COLLISION_PROVIDER_IMPLEMENTATION_DIGEST
    )
    assert attestation["read_only"] is True
    assert attestation["aws_mutations"] == 0
    with pytest.raises(subject.CollisionAwsProviderError) as raised:
        subject.assert_attested_provider_factory(object())
    assert raised.value.code == "COLLISION_PROVIDER_FACTORY_NOT_ATTESTED"
    with pytest.raises(subject.CollisionAwsProviderError) as immutable:
        harness.factory._max_pages = 1
    assert immutable.value.code == "COLLISION_PROVIDER_FACTORY_IMMUTABLE"


def test_factory_rejects_request_bound_to_another_policy_set() -> None:
    catalog = _catalog()
    policy = _policy(catalog)
    request = _request(catalog, policy)
    request["collision_policy_set_digest"] = "sha256:" + "9" * 64
    request["request_digest"] = canonical_digest(
        {
            key: value
            for key, value in request.items()
            if key != "request_digest"
        }
    )

    with pytest.raises(subject.CollisionAwsProviderError) as raised:
        _open(Harness(policy), request)

    assert raised.value.code == "COLLISION_PROVIDER_POLICY_SET_INVALID"


def test_identity_binds_selector_account_region_and_session_provenance() -> None:
    catalog = _catalog()
    policy = _policy(catalog)
    request = _request(catalog, policy)
    harness = Harness(policy)
    provider = _open(harness, request)
    identity = provider.read_identity(domain="authority")
    assert identity["account_id"] == AUTHORITY
    assert identity["region"] == "us-east-1"
    assert identity["principal_digest"] == canonical_digest(
        _principal("authority")
    )
    assert identity["policy_digest"] == policy["policy_set_digest"]
    assert harness.sessions[(1, "authority")].calls == [
        ("sts", "get_caller_identity", {})
    ]


def test_identity_rejects_account_contradiction_without_leaking_response() -> None:
    catalog = _catalog()
    policy = _policy(catalog)
    request = _request(catalog, policy)
    harness = Harness(policy, account_overrides={"authority": MANAGEMENT})
    provider = _open(harness, request)
    with pytest.raises(subject.CollisionAwsProviderError) as raised:
        provider.read_identity(domain="authority")
    assert raised.value.code == "COLLISION_PROVIDER_IDENTITY_CONTRADICTION"
    assert MANAGEMENT not in str(raised.value)


def test_all_catalog_descriptors_are_canonical_read_only_operations() -> None:
    catalog = _catalog()
    policy = _policy(catalog)
    request = _request(catalog, policy)
    harness = Harness(policy)
    provider = _open(harness, request)
    provider.read_identity(domain="authority")
    provider.read_identity(domain="management")
    operations = []
    for target in catalog["targets"]:
        envelope = provider._session(target["domain"])
        plan = subject._operation_plan(target, envelope)
        operations.append(plan.operation)
        assert plan.operation in transcript.READ_ONLY_OPERATION_ALLOWLIST
        assert canonical_digest(target).startswith("sha256:")
    assert len(operations) == subject.TARGET_COUNT
    assert {target["domain"] for target in catalog["targets"]} == {
        "authority", "management"
    }


def test_complete_pagination_uses_digest_only_cursor_chain_and_all_pages() -> None:
    catalog = _catalog()
    policy = _policy(catalog)
    request = _request(catalog, policy)
    harness = Harness(policy)
    provider = _open(harness, request)
    provider.read_identity(domain="authority")
    session = harness.sessions[(1, "authority")]
    session.scripts[("kms", "list_aliases")] = [
        {
            "Aliases": [{"AliasName": "alias/unrelated-a", "TargetKeyId": "key-a"}],
            "Truncated": True,
            "NextMarker": "opaque-page-2",
        },
        {
            "Aliases": [{"AliasName": "alias/unrelated-b", "TargetKeyId": "key-b"}],
            "Truncated": False,
        },
    ]
    target = next(
        item for item in _domain_targets(request, "authority")
        if item["service"] == "kms"
    )
    observations = provider.read_target_observations(
        domain="authority",
        targets=[target],
        expected_dispositions={target["target_id"]: "ABSENT_AT_SNAPSHOT"},
    )
    assert observations[target["target_id"]]["disposition"] == "ABSENT_AT_SNAPSHOT"
    calls = [call for call in provider._calls if call.operation == "kms:ListAliases"]
    assert len(calls) == 2
    assert calls[0].output_cursor_digest is not None
    assert canonical_digest(
        {"AliasName": "alias/unrelated-a", "TargetKeyId": "key-a"}
    ) in calls[0].page_item_digests
    assert calls[1].input_cursor_digest == calls[0].output_cursor_digest
    assert calls[1].output_cursor_digest is None
    assert "opaque-page-2" not in canonical_json_safe(calls)


def canonical_json_safe(value: object) -> str:
    return repr(
        [
            {
                "input": item.input_cursor_digest,
                "output": item.output_cursor_digest,
                "items": item.page_item_digests,
            }
            for item in value
        ]
    )


@pytest.mark.parametrize(
    ("pages", "max_pages", "code"),
    [
        (
            [
                {"Aliases": [], "Truncated": True, "NextMarker": "same"},
                {"Aliases": [], "Truncated": True, "NextMarker": "same"},
            ],
            3,
            "COLLISION_PROVIDER_CURSOR_LOOP",
        ),
        (
            [{"Aliases": [], "Truncated": True, "NextMarker": "more"}],
            1,
            "COLLISION_PROVIDER_PAGE_CAP_EXCEEDED",
        ),
    ],
)
def test_pagination_fails_closed_on_loop_or_truncation(
    pages: list[dict[str, Any]], max_pages: int, code: str
) -> None:
    catalog = _catalog()
    policy = _policy(catalog)
    request = _request(catalog, policy)
    harness = Harness(policy, max_pages=max_pages)
    provider = _open(harness, request)
    provider.read_identity(domain="authority")
    harness.sessions[(1, "authority")].scripts[("kms", "list_aliases")] = pages
    target = next(
        item for item in _domain_targets(request, "authority")
        if item["service"] == "kms"
    )
    with pytest.raises(subject.CollisionAwsProviderError) as raised:
        provider.read_target_observations(
            domain="authority",
            targets=[target],
            expected_dispositions={target["target_id"]: "ABSENT_AT_SNAPSHOT"},
        )
    assert raised.value.code == code


def test_absent_expected_but_exact_resource_present_is_contradiction() -> None:
    catalog = _catalog()
    policy = _policy(catalog)
    request = _request(catalog, policy)
    harness = Harness(policy)
    provider = _open(harness, request)
    provider.read_identity(domain="authority")
    target = next(
        item for item in _domain_targets(request, "authority")
        if item["service"] == "dynamodb"
    )
    harness.sessions[(1, "authority")].scripts[("dynamodb", "describe_table")] = [
        {
            "Table": {
                "TableName": target["name"],
                "TableArn": (
                    f"arn:aws:dynamodb:us-east-1:{AUTHORITY}:"
                    f"table/{target['name']}"
                ),
            }
        }
    ]
    with pytest.raises(subject.CollisionAwsProviderError) as raised:
        provider.read_target_observations(
            domain="authority",
            targets=[target],
            expected_dispositions={target["target_id"]: "ABSENT_AT_SNAPSHOT"},
        )
    assert raised.value.code == "COLLISION_PROVIDER_DISPOSITION_CONTRADICTION"


def test_present_resource_requires_exact_ownership_tags() -> None:
    catalog = _catalog()
    policy = _policy(catalog)
    request = _request(catalog, policy)
    harness = Harness(policy)
    provider = _open(harness, request)
    provider.read_identity(domain="authority")
    target = next(
        item for item in _domain_targets(request, "authority")
        if item["service"] == "dynamodb"
    )
    session = harness.sessions[(1, "authority")]
    arn = f"arn:aws:dynamodb:us-east-1:{AUTHORITY}:table/{target['name']}"
    session.scripts[("dynamodb", "describe_table")] = [
        {"Table": {"TableName": target["name"], "TableArn": arn}}
    ]
    session.scripts[("dynamodb", "list_tags_of_resource")] = [
        {"Tags": [{"Key": "service", "Value": "foreign"}]}
    ]
    with pytest.raises(subject.CollisionAwsProviderError) as raised:
        provider.read_target_observations(
            domain="authority",
            targets=[target],
            expected_dispositions={target["target_id"]: "PRESENT_OWNED"},
        )
    assert raised.value.code == "COLLISION_PROVIDER_OWNERSHIP_NOT_PROVEN"


def test_inventory_only_policy_can_prove_named_sso_target_absent() -> None:
    catalog = _catalog()
    policy = _policy(catalog, inventory_only=True)
    request = _request(catalog, policy)
    harness = Harness(policy)
    provider = _open(harness, request)
    provider.read_identity(domain="management")
    target = next(
        item for item in _domain_targets(request, "management")
        if item["service"] == "sso" and item["scope"] == "application"
    )
    observations = provider.read_target_observations(
        domain="management",
        targets=[target],
        expected_dispositions={target["target_id"]: "ABSENT_AT_SNAPSHOT"},
    )
    assert observations[target["target_id"]]["disposition"] == (
        "ABSENT_AT_SNAPSHOT"
    )


def test_current_policy_and_transcript_csc_contract_is_callable() -> None:
    catalog = _catalog()
    policy = _policy(catalog)
    request = _request(catalog, policy)
    harness = Harness(policy)
    provider = _open(harness, request)
    provider.read_identity(domain="authority")
    target = next(
        item for item in _domain_targets(request, "authority")
        if item["scope"] == "code_signing_config"
    )
    assert "cloudformation:DescribeStackResource" in {
        action
        for stage in policy["allowed_actions"]["authority"].values()
        for action in stage
    }
    observations = provider.read_target_observations(
        domain="authority",
        targets=[target],
        expected_dispositions={target["target_id"]: "ABSENT_AT_SNAPSHOT"},
    )
    assert observations[target["target_id"]]["disposition"] == (
        "ABSENT_AT_SNAPSHOT"
    )


def test_reused_sdk_session_is_rejected_across_domains() -> None:
    catalog = _catalog()
    policy = _policy(catalog)
    request = _request(catalog, policy)
    harness = Harness(policy, reuse_sdk_session=True)
    provider = _open(harness, request)
    provider.read_identity(domain="authority")
    with pytest.raises(subject.CollisionAwsProviderError) as raised:
        provider.read_identity(domain="management")
    assert raised.value.code == "COLLISION_PROVIDER_SESSION_NOT_INDEPENDENT"
