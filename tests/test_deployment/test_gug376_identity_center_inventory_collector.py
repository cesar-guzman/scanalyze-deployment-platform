from __future__ import annotations
import copy, json, os, stat, subprocess, sys
from datetime import UTC, datetime, timedelta; from pathlib import Path; import pytest
from tooling.platform_authority_gug365_upstream_inventory import canonical_digest
from tooling.platform_authority_gug376_identity_center_inventory_collector import AuthorityAccessDenied, CollectorError, NAMES, POLICY, _exact, _pages, _render, _valid_kms_binding, _valid_live_exact_shape, capture, capture_live, capture_live_discovery, certify, certify_live, plan_binding, read_private_json, render_live_policy, render_policy, validate_public_receipt
START = datetime(2026, 8, 24, 16, 0, tzinfo=UTC); MGMT, AUTH = "111111111111", "222222222222"
def _d(char: str) -> str: return "sha256:" + char * 64
PRIVATE = {"application_name": "ScanalyzeAuthority", "approved_user_id": "12345678-1234-1234-1234-123456789012", "approved_single_operator_user_arn": "arn:aws:identitystore:::user/d-1234567890/12345678-1234-1234-1234-123456789012", "authority_account_arn": f"arn:aws:sso:::account/{AUTH}", "identity_center_kms_key_arn": f"arn:aws:kms:us-east-1:{MGMT}:key/11111111-1111-1111-1111-111111111111", "identity_store_arn": "arn:aws:identitystore:::identitystore/d-1234567890", "identity_store_id": "d-1234567890"}
INSTANCE = "arn:aws:sso:::instance/ssoins-1234567890abcdef"
LIVE_PRIVATE = {
    **PRIVATE,
    "application_actor_policy_digest": canonical_digest(
        {"actor": "approved-user"}
    ),
    "application_provider_arn": "arn:aws:sso::aws:applicationProvider/custom",
    "application_redirect_uri": "http://127.0.0.1:18443/callback",
    "identity_center_instance_arn": INSTANCE,
    "identity_center_kms_mode": "CUSTOMER_MANAGED_KEY",
}
LIVE_PRIVATE["identity_center_kms_binding_digest"] = canonical_digest(
    {
        "binding_name": "identity_center_kms_key_arn",
        "identity_center_instance_arn": INSTANCE,
        "mode": LIVE_PRIVATE["identity_center_kms_mode"],
        "key_arn": LIVE_PRIVATE["identity_center_kms_key_arn"],
    }
)
APP = f"arn:aws:sso::{MGMT}:application/ssoins-1234567890abcdef/apl-1234567890abcdef"
TARGETS = {"management_account_id": MGMT, "authority_account_arn": PRIVATE["authority_account_arn"], "identity_center_instance_arn": INSTANCE, "identity_store_arn": PRIVATE["identity_store_arn"], "approved_single_operator_user_arn": PRIVATE["approved_single_operator_user_arn"], "identity_center_kms_key_arn": PRIVATE["identity_center_kms_key_arn"], "identity_center_application_arn": APP, "retire_approve_permission_set_arn": "arn:aws:sso:::permissionSet/ssoins-1234567890abcdef/ps-approve", "retire_class_permission_set_arn": "arn:aws:sso:::permissionSet/ssoins-1234567890abcdef/ps-class"}
LIVE_TARGETS = {**TARGETS, "identity_center_kms_mode": "CUSTOMER_MANAGED_KEY"}
DISCOVERY = {"instances": [{"identity_store_id": PRIVATE["identity_store_id"], "instance_arn": INSTANCE, "owner_account_id": MGMT, "status": "ACTIVE"}], "applications": [{"application_arn": APP, "name": PRIVATE["application_name"]}], "permission_sets": [{"name": NAMES[0], "permission_set_arn": TARGETS["retire_approve_permission_set_arn"]}, {"name": NAMES[1], "permission_set_arn": TARGETS["retire_class_permission_set_arn"]}]}
@pytest.fixture(autouse=True)
def _clean_aws(monkeypatch: pytest.MonkeyPatch) -> None:
    for key in tuple(os.environ):
        if key.startswith("AWS_") or key in {"BOTO_CONFIG", "REQUESTS_CA_BUNDLE", "SSL_CERT_FILE", "SSL_CERT_DIR"}: monkeypatch.delenv(key)
def _page(items): return {"items": items, "next_token": None, "truncated": False, "complete": True}
class Reader:
    def __init__(self, events: list[str] | None = None, mode: str = "ok", live: bool = False): self.events, self.mode, self.live = events if events is not None else [], mode, live
    def _observed_discovery(self):
        return {"instances": DISCOVERY["instances"] if self.mode != "absent" else [], "applications": [] if self.mode == "live_absent" else DISCOVERY["applications"], "permission_sets": [] if self.mode == "live_absent" else DISCOVERY["permission_sets"]}
    def attest_transition(self, discovery_digest):
        assert [
            event
            for event in self.events
            if event
            in {
                "list_instances",
                "describe_instance",
                "list_applications",
                "list_permission_sets",
            }
        ] == [
            "list_instances",
            "describe_instance",
            "list_applications",
            "list_permission_sets",
        ]
        self.events.append("attest_transition")
        assert self.live
        assert discovery_digest == canonical_digest({"discovery": self._observed_discovery(), "instance": self._instance_value()})
        return {"test_transition_attestation": discovery_digest}
    def list_instances(self, token):
        self.events.append("list_instances")
        if self.mode == "denied": raise AuthorityAccessDenied("private provider text")
        if self.mode == "timeout": raise TimeoutError("private provider text")
        values = [] if self.mode == "absent" else DISCOVERY["instances"] * (2 if self.mode == "multiple" else 1); return _page([dict(DISCOVERY["instances"][0], instance_arn="not-an-arn")] if self.mode == "malformed" else [dict(item, status="INACTIVE") for item in values] if self.mode == "inactive" else values)
    def list_applications(self, instance, name, token): self.events.append("list_applications"); assert instance == INSTANCE and name == PRIVATE["application_name"]; return _page([] if self.mode in {"missing", "live_absent"} else DISCOVERY["applications"])
    def list_permission_sets(self, instance, names, token): self.events.append("list_permission_sets"); assert instance == INSTANCE and names == NAMES; values = [] if self.mode == "live_absent" else copy.deepcopy(DISCOVERY["permission_sets"]); values and values.__setitem__(0, dict(values[0], name="Foreign" if self.mode == "wrong_name" else values[0]["name"])); len(values) > 1 and values.__setitem__(1, dict(values[1], name=values[0]["name"] if self.mode == "duplicate" else values[1]["name"])); return _page(values)
    def _instance_value(self):
        value = {"instance_arn": INSTANCE, "identity_store_id": PRIVATE["identity_store_id"], "owner_account_id": MGMT, "status": "ACTIVE"}
        if self.live:
            value["encryption"] = {"key_type": LIVE_PRIVATE["identity_center_kms_mode"], "kms_key_arn": LIVE_PRIVATE["identity_center_kms_key_arn"], "status": "ENABLED"}
        return value
    def describe_instance(self, arn): self.events.append("describe_instance"); assert arn == INSTANCE; return {"complete": True, "value": self._instance_value()}
    def read_application(self, arn): self.events.append("read_application"); value = {"application_arn": arn, "grants": ["authorization_code"], "scopes": ["openid"], "redirect_uris": [], "authentication_methods": [], "assignment_configuration": {}, "actor_policy": {}, "tags": []}; value.update({"redirect_url": "https://drift.invalid"} if self.mode == "additive" else {"redirect_uris": "malformed"} if self.mode == "malformed_exact" else {}); return {"complete": True, "value": value}
    def read_permission_set(self, instance, arn): self.events.append("read_permission_set"); return {"complete": True, "value": {"instance_arn": instance, "permission_set_arn": arn, "managed_policies": [], "customer_managed_policies": [], "inline_policy": None, "boundary": None, "tags": []}}
    def list_assignments(self, instance, arn, account, token): self.events.append("list_assignments"); return _page([{"account_arn": account, "permission_set_arn": arn, "principal_id": PRIVATE["approved_user_id"], "principal_type": "USER"}])
    def list_provisioning(self, instance, arn, token): self.events.append("list_provisioning"); return _page([{"permission_set_arn": arn, "status": "SUCCEEDED"}])
    def list_target_accounts(self, instance, arn, token): self.events.append("list_target_accounts"); return _page([{"account_arn": PRIVATE["authority_account_arn"], "permission_set_arn": arn}])
    def describe_approved_user(self, store, user): self.events.append("describe_approved_user"); assert (store, user) == (PRIVATE["identity_store_id"], PRIVATE["approved_user_id"]); return {"complete": True, "value": {"UserId": user, "UserName": "private", "Emails": [{"Value": "private@example.invalid"}]}}
def _plan() -> dict[str, object]:
    plan: dict[str, object] = {"private_targets": PRIVATE, "not_before": START, "not_after": START + timedelta(minutes=30), "expected_account_id": MGMT, "expected_principal_arn": f"arn:aws:sts::{MGMT}:assumed-role/ScanalyzeIdentityInventory/operator", "authority_verification_digest": _d("a"), "expected_discovery_policy_digest": _d("b"), "expected_exact_policy_digest": _d("c"), "expected_target_digest": canonical_digest(TARGETS), "expected_facts_digest": _d("d")}
    plan["expected_discovery_policy_digest"] = _render(plan, None)[1]; plan["expected_exact_policy_digest"] = _render(plan, TARGETS)[1]
    facts, _ = _exact(Reader(), plan, TARGETS, DISCOVERY); plan["expected_facts_digest"] = canonical_digest(facts); return plan
def _live_plan() -> dict[str, object]:
    plan = _plan()
    plan["private_targets"] = LIVE_PRIVATE
    plan["expected_discovery_policy_digest"] = _render(
        plan, None, live=True, live_discovery=True
    )[1]
    plan["expected_target_digest"] = canonical_digest(LIVE_TARGETS)
    plan["expected_exact_policy_digest"] = _render(
        plan, LIVE_TARGETS, live=True
    )[1]
    return plan
class Session:
    def __init__(self, factory, stage, digest): self.factory, self.stage, self.digest = factory, stage, digest
    def get_caller_identity(self):
        self.factory.events.append("sts:" + self.stage); value = {"source": "DIRECT_SSO", "chain_depth": 0, "account_id": MGMT, "region": "us-east-1", "principal_arn": _plan()["expected_principal_arn"], "session_id_digest": canonical_digest({"seed": self.factory.seed, "stage": self.stage}), "started_at": START, "expires_at": START + timedelta(minutes=45), "observed_at": START + timedelta(minutes=int(self.factory.seed)), "policy_digest": self.digest, "authority_verification_digest": _d("a")}; value.update(self.factory.identity); return value
    def open_discovery(self): self.factory.events.append("open_discovery"); return Reader(self.factory.events, self.factory.mode, self.factory.live)
    def open_exact(self): self.factory.events.append("open_exact"); return Reader(self.factory.events, self.factory.mode, self.factory.live)
class Factory:
    def __init__(self, seed="1", mode="ok", identity=None): self.seed, self.mode, self.identity, self.events, self.live = seed, mode, {} if identity is None else identity, [], False
    def open_sts(self, *, stage, policy, policy_digest, region): assert canonical_digest(policy) == policy_digest and region == "us-east-1"; self.live = self.live or any(item.get("Sid") == "ReadBoundIdentityCenterInstance" for item in policy["Statement"]); self.events.append("open_sts:" + stage); return Session(self, stage, policy_digest)
def _root(tmp_path: Path) -> Path: root = tmp_path / "private"; root.mkdir(mode=0o700, parents=True, exist_ok=True); root.chmod(0o700); return root
def _capture(tmp_path: Path, name: str, factory: Factory):
    root = _root(tmp_path); receipt = capture(_plan(), factory, private_root=root, artifact_name=name, now=START + timedelta(minutes=5)); return root, receipt, read_private_json(root, name)
def _discovery_only(value):
    value = copy.deepcopy(value); value.update({"classification": "DRIFT_BLOCKED_NO_REPAIR", "policies": {"discovery": value["policies"]["discovery"]}, "targets": {}, "facts": {"discovery": value["facts"]["discovery"]}, "identities": value["identities"][:1], "session_digests": value["session_digests"][:1], "surface_counts": {key: item if key in {"instances", "applications", "permission_sets"} else None for key, item in value["surface_counts"].items()}}); value["policy_binding_digest"] = canonical_digest({"discovery": canonical_digest(value["policies"]["discovery"])}); value["target_digest"] = canonical_digest(value["targets"]); value["facts_digest"] = canonical_digest(value["facts"]); value["snapshot_digest"] = canonical_digest({key: item for key, item in value.items() if key != "snapshot_digest"}); return value
def test_staged_policy_typed_capture_and_private_public_split(tmp_path: Path) -> None:
    plan = _plan(); discovery, _ = render_policy(plan); exact, _ = render_policy(plan, TARGETS)
    assert "${" not in json.dumps((discovery, exact)) and not any(item["Sid"].startswith("ReadExact") for item in discovery["Statement"]) and not any(item["Sid"].startswith("Discover") for item in exact["Statement"])
    factory = Factory(); root, receipt, private = _capture(tmp_path, "one.json", factory)
    assert factory.events[:3] == ["open_sts:discovery", "sts:discovery", "open_discovery"] and factory.events.index("open_sts:exact") > factory.events.index("list_permission_sets")
    assert private["classification"] == "EXACT_PRESENT_NO_TOUCH" and receipt["classification"] == "UNCERTAIN_RECONCILE_ONLY" and receipt["stable"] is False and receipt["aws_calls"] == receipt["aws_mutations"] == 0 and receipt["two_human_status"] == "NOT_PROVEN" and receipt["independent_approval_present"] is False
    public = json.dumps(receipt); assert MGMT not in public and "arn:aws:" not in public and PRIVATE["approved_user_id"] not in public and "private@example" not in public
    item = (root / "one.json").stat(); assert stat.S_IMODE(item.st_mode) == 0o600 and item.st_nlink == 1 and private["facts"]["operator"]["UserId"] == PRIVATE["approved_user_id"]


def test_live_discovery_supplement_is_narrow_and_does_not_change_v1() -> None:
    legacy_plan = _plan()
    legacy_policy, legacy_digest = render_policy(legacy_plan)
    assert all(item["Sid"] != "DiscoverPermissionSetNames" for item in legacy_policy["Statement"])

    live_plan = _live_plan()
    live_policy, live_digest = render_live_policy(live_plan)
    list_permission_sets = [
        item for item in live_policy["Statement"]
        if item["Sid"] == "DiscoverExactPermissionSets"
    ]
    list_applications = next(
        item
        for item in live_policy["Statement"]
        if item["Sid"] == "DiscoverExactIdentityCenterApplication"
    )
    supplement = [
        item for item in live_policy["Statement"]
        if item["Sid"] in {
            "DiscoverPermissionSetNames",
            "DecryptDiscoveryMetadataThroughIdentityCenter",
        }
    ]
    bound_instance = next(
        item
        for item in live_policy["Statement"]
        if item["Sid"] == "ReadBoundIdentityCenterInstance"
    )
    assert live_digest != legacy_digest
    assert list_permission_sets[0]["Resource"] == INSTANCE
    assert list_applications["Resource"] == "*"
    assert list_applications["Condition"]["StringEquals"] == {
        "aws:RequestedRegion": "us-east-1"
    }
    assert "sso:ApplicationAccount" not in json.dumps(list_applications)
    assert "sso:PrimaryRegion" not in json.dumps(list_applications)
    assert bound_instance["Action"] == "sso:DescribeInstance"
    assert bound_instance["Resource"] == INSTANCE
    assert next(
        item for item in legacy_policy["Statement"]
        if item["Sid"] == "DiscoverExactPermissionSets"
    )["Resource"] == "*"
    assert supplement == [
        {
            "Sid": "DiscoverPermissionSetNames",
            "Effect": "Allow",
            "Action": "sso:DescribePermissionSet",
            "Resource": [
                INSTANCE,
                "arn:aws:sso:::permissionSet/"
                "ssoins-1234567890abcdef/*",
            ],
            "Condition": {
                "StringEquals": {
                    "aws:RequestedRegion": "us-east-1",
                    "sso:PrimaryRegion": "us-east-1",
                },
                "DateGreaterThanEquals": {
                    "aws:CurrentTime": "2026-08-24T16:00:00Z",
                },
                "DateLessThan": {
                    "aws:CurrentTime": "2026-08-24T16:30:00Z",
                },
            },
        },
        {
            "Sid": "DecryptDiscoveryMetadataThroughIdentityCenter",
            "Effect": "Allow",
            "Action": "kms:Decrypt",
            "Resource": PRIVATE["identity_center_kms_key_arn"],
            "Condition": {
                "StringEquals": {
                    "aws:PrincipalAccount": MGMT,
                    "aws:RequestedRegion": "us-east-1",
                    "kms:EncryptionContext:aws:sso:instance-arn": INSTANCE,
                    "kms:CallerAccount": MGMT,
                    "kms:ViaService": "sso.us-east-1.amazonaws.com",
                },
                "DateGreaterThanEquals": {
                    "aws:CurrentTime": "2026-08-24T16:00:00Z",
                },
                "DateLessThan": {
                    "aws:CurrentTime": "2026-08-24T16:30:00Z",
                },
            },
        },
    ]


def test_customer_managed_exact_policy_uses_only_bound_kms_contexts() -> None:
    policy, _ = _render(_live_plan(), LIVE_TARGETS, live=True)
    decrypts = [
        item
        for item in policy["Statement"]
        if item.get("Effect") == "Allow"
        and item.get("Action") == "kms:Decrypt"
    ]
    assert {item["Sid"] for item in decrypts} == {
        "DecryptOnlyThroughExactIdentityCenterInstance",
        "DecryptOnlyThroughExactIdentityStore",
    }
    expected_contexts = {
        "DecryptOnlyThroughExactIdentityCenterInstance": {
            "kms:EncryptionContext:aws:sso:instance-arn": INSTANCE,
            "kms:ViaService": "sso.us-east-1.amazonaws.com",
        },
        "DecryptOnlyThroughExactIdentityStore": {
            "kms:EncryptionContext:aws:identitystore:identitystore-arn": (
                PRIVATE["identity_store_arn"]
            ),
            "kms:ViaService": "identitystore.us-east-1.amazonaws.com",
        },
    }
    for statement in decrypts:
        assert statement["Resource"] == PRIVATE["identity_center_kms_key_arn"]
        expected = expected_contexts[statement["Sid"]]
        assert statement["Condition"]["StringEquals"] == {
            "aws:PrincipalAccount": MGMT,
            "aws:RequestedRegion": "us-east-1",
            "kms:CallerAccount": MGMT,
            **expected,
        }
        assert statement["Condition"]["DateGreaterThanEquals"] == {
            "aws:CurrentTime": "2026-08-24T16:00:00Z"
        }
        assert statement["Condition"]["DateLessThan"] == {
            "aws:CurrentTime": "2026-08-24T16:30:00Z"
        }


def test_aws_owned_kms_omits_decrypt_and_accepts_null_exact_readback() -> None:
    plan = _live_plan()
    private = {
        **LIVE_PRIVATE,
        "identity_center_kms_mode": "AWS_OWNED_KMS_KEY",
        "identity_center_kms_key_arn": None,
    }
    private["identity_center_kms_binding_digest"] = canonical_digest(
        {
            "binding_name": "identity_center_kms_key_arn",
            "identity_center_instance_arn": INSTANCE,
            "mode": "AWS_OWNED_KMS_KEY",
            "key_arn": None,
        }
    )
    plan["private_targets"] = private
    targets = {
        **TARGETS,
        "identity_center_kms_mode": "AWS_OWNED_KMS_KEY",
        "identity_center_kms_key_arn": None,
    }
    plan["expected_target_digest"] = canonical_digest(targets)
    discovery_policy, _ = _render(plan, None, live=True, live_discovery=True)
    exact_policy, _ = _render(plan, targets, live=True)
    rendered = json.dumps([discovery_policy, exact_policy])
    assert "kms:" not in rendered
    assert PRIVATE["identity_center_kms_key_arn"] not in rendered

    documented = json.loads(
        (
            Path(__file__).parents[2]
            / "docs/operations/platform-authority-gug392-identity-center-exact-plan-input.example.json"
        ).read_text(encoding="utf-8")
    )["expected_state"]
    documented_targets = documented["targets"]
    documented_facts = documented["facts"]
    documented_targets["identity_center_kms_mode"] = "AWS_OWNED_KMS_KEY"
    documented_targets["identity_center_kms_key_arn"] = None
    documented_facts["instance"]["encryption"] = {
        "key_type": "AWS_OWNED_KMS_KEY",
        "kms_key_arn": None,
        "status": "ENABLED",
    }
    assert _valid_live_exact_shape(documented_facts, documented_targets)


@pytest.mark.parametrize(
    "key_id",
    [
        "11111111-1111-1111-1111-111111111111",
        "mrk-0123456789abcdef0123456789abcdef",
    ],
)
def test_customer_managed_uuid_and_mrk_bindings_have_equal_validation(
    key_id: str,
) -> None:
    assert _valid_kms_binding(
        {
            "identity_center_kms_mode": "CUSTOMER_MANAGED_KEY",
            "identity_center_kms_key_arn": (
                f"arn:aws:kms:us-east-1:{MGMT}:key/{key_id}"
            ),
        },
        account=MGMT,
        live=True,
    )


@pytest.mark.parametrize(
    "mode,key_arn",
    [
        ("AWS_OWNED_KMS_KEY", PRIVATE["identity_center_kms_key_arn"]),
        ("CUSTOMER_MANAGED_KEY", None),
        (
            "CUSTOMER_MANAGED_KEY",
            "arn:aws:kms:us-east-1:999999999999:key/11111111-1111-1111-1111-111111111111",
        ),
        (
            "CUSTOMER_MANAGED_KEY",
            f"arn:aws:kms:us-east-1:{MGMT}:key/not-a-real-key-id",
        ),
    ],
)
def test_kms_mode_and_key_pair_fail_closed(mode: str, key_arn: object) -> None:
    plan = _live_plan()
    private = {
        **LIVE_PRIVATE,
        "identity_center_kms_mode": mode,
        "identity_center_kms_key_arn": key_arn,
    }
    private["identity_center_kms_binding_digest"] = canonical_digest(
        {
            "binding_name": "identity_center_kms_key_arn",
            "identity_center_instance_arn": INSTANCE,
            "mode": mode,
            "key_arn": key_arn,
        }
    )
    plan["private_targets"] = private
    with pytest.raises(CollectorError, match="IDENTITY_CENTER_PRIVATE_TARGET_INVALID"):
        _render(plan, None, live=True, live_discovery=True)


def test_capture_live_uses_post_sts_validation_clock(tmp_path: Path) -> None:
    plan = _live_plan()
    initial_now = START + timedelta(minutes=5)
    observed_at = initial_now + timedelta(seconds=1)
    factory = Factory(mode="absent", identity={"observed_at": observed_at})
    clock_events: list[str] = []

    def validation_clock() -> datetime:
        assert factory.events == ["open_sts:discovery", "sts:discovery"]
        clock_events.append("validation_clock")
        return observed_at + timedelta(seconds=1)

    root = _root(tmp_path)
    receipt = capture_live(
        plan,
        factory,
        private_root=root,
        artifact_name="live.json",
        now=initial_now,
        validation_clock=validation_clock,
    )

    assert clock_events == ["validation_clock"]
    assert factory.events[:3] == [
        "open_sts:discovery",
        "sts:discovery",
        "open_discovery",
    ]
    assert receipt["read_only"] is True
    assert receipt["aws_calls"] == receipt["aws_mutations"] == 0
    assert read_private_json(root, "live.json")["classification"] == (
        "DRIFT_BLOCKED_NO_REPAIR"
    )


def test_live_transition_describes_instance_before_dependent_lists(
    tmp_path: Path,
) -> None:
    plan = _live_plan()
    factory = Factory(mode="live_absent")
    capture_live_discovery(
        plan,
        factory,
        private_root=_root(tmp_path),
        artifact_name="ordered.json",
        now=START + timedelta(minutes=5),
        validation_clock=lambda: START + timedelta(minutes=5, seconds=1),
        exact_plan_materializer=lambda *_args: plan,
    )
    discovery_events = [
        event
        for event in factory.events
        if event
        in {
            "list_instances",
            "describe_instance",
            "list_applications",
            "list_permission_sets",
            "attest_transition",
        }
    ]
    assert discovery_events == [
        "list_instances",
        "describe_instance",
        "list_applications",
        "list_permission_sets",
        "attest_transition",
    ]


def test_live_private_v2_allows_same_second_but_v1_remains_strict(
    tmp_path: Path,
) -> None:
    plan = _live_plan()
    observed = START + timedelta(minutes=5, seconds=1)
    root = _root(tmp_path)
    for name, seed in (("first.json", "3"), ("second.json", "4")):
        capture_live(
            plan,
            Factory(seed=seed, mode="live_absent", identity={"observed_at": observed}),
            private_root=root,
            artifact_name=name,
            now=observed - timedelta(seconds=1),
            validation_clock=lambda: observed + timedelta(seconds=1),
        )
    first = read_private_json(root, "first.json")
    second = read_private_json(root, "second.json")
    expected = plan_binding(plan)[1]
    assert first["record_type"].endswith("private.v2")
    live_receipt = certify_live(
        first, second, expected_plan_binding_digest=expected
    )
    assert live_receipt["stable"] is True
    assert live_receipt["classification"] == "ABSENT_READY"

    legacy_plan = _plan()
    legacy_root = tmp_path / "legacy"
    legacy_root.mkdir(mode=0o700)
    legacy_root.chmod(0o700)
    for name, seed in (("first.json", "3"), ("second.json", "4")):
        capture(
            legacy_plan,
            Factory(seed=seed, mode="absent", identity={"observed_at": observed}),
            private_root=legacy_root,
            artifact_name=name,
            now=observed,
        )
    legacy = [
        read_private_json(legacy_root, name)
        for name in ("first.json", "second.json")
    ]
    expected = plan_binding(legacy_plan)[1]
    with pytest.raises(CollectorError, match="SESSIONS_NOT_INDEPENDENT"):
        certify(*legacy, expected_plan_binding_digest=expected)
@pytest.mark.parametrize("mode,expected", [("absent", "ABSENT_READY"), ("missing", "DRIFT_BLOCKED_NO_REPAIR"), ("multiple", "DRIFT_BLOCKED_NO_REPAIR"), ("wrong_name", "DRIFT_BLOCKED_NO_REPAIR"), ("duplicate", "DRIFT_BLOCKED_NO_REPAIR"), ("inactive", "DRIFT_BLOCKED_NO_REPAIR"), ("malformed", "UNCERTAIN_RECONCILE_ONLY"), ("malformed_exact", "UNCERTAIN_RECONCILE_ONLY"), ("denied", "NOT_AUTHORIZED"), ("timeout", "UNCERTAIN_RECONCILE_ONLY")])
def test_absence_drift_and_provider_failures_never_expand_authority(tmp_path: Path, mode: str, expected: str) -> None:
    factory = Factory(mode=mode); _, receipt, private = _capture(tmp_path / mode, "one.json", factory)
    assert private["classification"] == expected and receipt["classification"] == ("NOT_AUTHORIZED" if expected == "NOT_AUTHORIZED" else "UNCERTAIN_RECONCILE_ONLY") and (("open_sts:exact" in factory.events) == (mode == "malformed_exact"))
@pytest.mark.parametrize("kind", ["repeat", "conflict", "incomplete", "limit"])
def test_pagination_is_complete_bounded_and_cycle_safe(kind: str) -> None:
    calls = 0
    def read(token):
        nonlocal calls; calls += 1
        if kind == "repeat": return {"items": [], "next_token": "same", "truncated": True, "complete": False}
        if kind == "conflict": return {"items": [], "next_token": None, "truncated": True, "complete": True}
        if kind == "incomplete": return {"items": [], "next_token": None, "truncated": False, "complete": False}
        return {"items": [], "next_token": str(calls), "truncated": True, "complete": False}
    with pytest.raises(CollectorError): _pages(read)
    assert calls == {"repeat": 2, "conflict": 1, "incomplete": 1, "limit": 50}[kind]
def test_pagination_consumes_every_page() -> None:
    def read(token): return {"items": [{"page": 1 if token is None else 2}], "next_token": ("second" if token is None else None), "truncated": token is None, "complete": token is not None}
    assert _pages(read) == [{"page": 1}, {"page": 2}]
@pytest.mark.parametrize("field,value", [("account_id", "000000000000"), ("region", "us-west-2"), ("source", "ASSUME_ROLE"), ("chain_depth", 1), ("expires_at", START + timedelta(minutes=20)), ("policy_digest", _d("0"))])
def test_wrong_or_stale_session_stops_before_reader(tmp_path: Path, field: str, value: object) -> None:
    factory, root = Factory(identity={field: value}), _root(tmp_path)
    with pytest.raises(CollectorError, match="DIRECT_SESSION_BINDING_INVALID"): capture(_plan(), factory, private_root=root, artifact_name="x.json", now=START + timedelta(minutes=5))
    assert factory.events == ["open_sts:discovery", "sts:discovery"]
def test_local_gates_stop_before_clients(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    plan, factory, root = _plan(), Factory(), _root(tmp_path); monkeypatch.setenv("AWS_ENDPOINT_URL_SSO", "https://unreviewed.invalid")
    with pytest.raises(CollectorError, match="AMBIENT_AWS_OVERRIDE_FORBIDDEN"): capture(plan, factory, private_root=root, artifact_name="x.json", now=START + timedelta(minutes=5))
    assert factory.events == []
    monkeypatch.delenv("AWS_ENDPOINT_URL_SSO"); plan["expected_discovery_policy_digest"] = _d("0")
    with pytest.raises(CollectorError, match="POLICY_DIGEST_NOT_VERIFIED"): capture(plan, factory, private_root=root, artifact_name="x.json", now=START + timedelta(minutes=5))
    assert factory.events == []
    plan, factory = _plan(), Factory(); plan["expected_account_id"] = int(MGMT); pytest.raises(CollectorError, capture, plan, factory, private_root=root, artifact_name="x.json", now=START + timedelta(minutes=5)); assert factory.events == []; monkeypatch.setattr(Session, "get_caller_identity", lambda self: None); factory = Factory(); pytest.raises(CollectorError, capture, _plan(), factory, private_root=root, artifact_name="x.json", now=START + timedelta(minutes=5)); assert factory.events == ["open_sts:discovery"]
def test_two_independent_stable_snapshots_certify_and_drift_reconciles(tmp_path: Path) -> None:
    root, _, first = _capture(tmp_path, "a.json", Factory("3")); _, _, second = _capture(tmp_path, "b.json", Factory("4"))
    expected = plan_binding(_plan())[1]; receipt = certify(first, second, expected_plan_binding_digest=expected); assert receipt["stable"] is True and receipt["snapshot_count"] == 2 and receipt["classification"] == "EXACT_PRESENT_NO_TOUCH"
    with pytest.raises(CollectorError, match="PRIVATE_SNAPSHOT_INVALID"): certify(_discovery_only(first), _discovery_only(second), expected_plan_binding_digest=expected)
    _, _, inactive_first = _capture(tmp_path / "inactive", "a.json", Factory("3", "inactive")); _, _, inactive_second = _capture(tmp_path / "inactive", "b.json", Factory("4", "inactive")); assert certify(inactive_first, inactive_second, expected_plan_binding_digest=expected)["classification"] == "DRIFT_BLOCKED_NO_REPAIR"; _, _, absent_first = _capture(tmp_path / "absent", "a.json", Factory("3", "absent")); _, _, absent_second = _capture(tmp_path / "absent", "b.json", Factory("4", "absent")); pytest.raises(CollectorError, certify, _discovery_only(absent_first), _discovery_only(absent_second), expected_plan_binding_digest=expected)
    malformed = copy.deepcopy(second); malformed["facts"]["assignments"][NAMES[0]] = [123]; malformed["facts_digest"] = canonical_digest(malformed["facts"]); malformed["classification"] = "DRIFT_BLOCKED_NO_REPAIR"; malformed["snapshot_digest"] = canonical_digest({key: value for key, value in malformed.items() if key != "snapshot_digest"}); pytest.raises(CollectorError, certify, first, malformed, expected_plan_binding_digest=expected); inactive = copy.deepcopy(second); inactive["facts"]["discovery"]["instances"][0]["status"] = "DELETED"; inactive["facts_digest"] = canonical_digest(inactive["facts"]); inactive["classification"] = "DRIFT_BLOCKED_NO_REPAIR"; inactive["snapshot_digest"] = canonical_digest({key: value for key, value in inactive.items() if key != "snapshot_digest"}); pytest.raises(CollectorError, certify, first, inactive, expected_plan_binding_digest=expected)
    _, _, drift = _capture(tmp_path, "c.json", Factory("5", mode="additive")); uncertain = certify(first, drift, expected_plan_binding_digest=expected); assert uncertain["classification"] == "UNCERTAIN_RECONCILE_ONLY" and uncertain["stable"] is False
    with pytest.raises(CollectorError, match="SESSIONS_NOT_INDEPENDENT"): certify(first, first, expected_plan_binding_digest=expected)
    script = Path(__file__).parents[2] / "scripts/deployment/platform-authority-gug376-identity-center-inventory.py"
    result = subprocess.run([sys.executable, "-I", "-S", script, "certify", "--private-root", str(root), "--first", "a.json", "--second", "b.json", "--expected-plan-binding-digest", expected], text=True, capture_output=True, check=False)
    assert result.returncode == 0 and MGMT not in result.stdout and "arn:aws:" not in result.stdout and "Traceback" not in result.stderr
def test_public_validator_rejects_every_extra_sensitive_channel(tmp_path: Path) -> None:
    _, receipt, _ = _capture(tmp_path, "one.json", Factory()); validate_public_receipt(receipt); forged = dict(receipt, classification="EXACT_PRESENT_NO_TOUCH", stable=False); forged["receipt_digest"] = canonical_digest({key: value for key, value in forged.items() if key != "receipt_digest"}); pytest.raises(CollectorError, validate_public_receipt, forged)
    for key in ("account", "profile", "session", "arn", "IdentityStoreId", "UserId", "name", "email", "url", "policy", "assignments", "principal", "request_id", "next_token", "private_path", "provider_payload", "snapshot_count", "aws_calls", "aws_mutations"):
        leaked = dict(receipt, **{key: False if key in {"snapshot_count", "aws_calls", "aws_mutations"} else "sensitive"}); leaked["receipt_digest"] = canonical_digest({field: value for field, value in leaked.items() if field != "receipt_digest"})
        with pytest.raises(CollectorError, match="PUBLIC_RECEIPT_INVALID"): validate_public_receipt(leaked)
