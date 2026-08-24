from __future__ import annotations
import copy, json, os, stat, subprocess, sys
from datetime import UTC, datetime, timedelta; from pathlib import Path; import pytest
from tooling.platform_authority_gug365_upstream_inventory import canonical_digest
from tooling.platform_authority_gug376_identity_center_inventory_collector import AuthorityAccessDenied, CollectorError, NAMES, POLICY, _exact, _pages, _render, capture, certify, plan_binding, read_private_json, render_policy, validate_public_receipt
START = datetime(2026, 8, 24, 16, 0, tzinfo=UTC); MGMT, AUTH = "111111111111", "222222222222"
def _d(char: str) -> str: return "sha256:" + char * 64
PRIVATE = {"application_name": "ScanalyzeAuthority", "approved_user_id": "12345678-1234-1234-1234-123456789012", "approved_single_operator_user_arn": "arn:aws:identitystore:::user/d-1234567890/12345678-1234-1234-1234-123456789012", "authority_account_arn": f"arn:aws:sso:::account/{AUTH}", "identity_center_kms_key_arn": f"arn:aws:kms:us-east-1:{MGMT}:key/11111111-1111-1111-1111-111111111111", "identity_store_arn": "arn:aws:identitystore:::identitystore/d-1234567890", "identity_store_id": "d-1234567890"}
INSTANCE = "arn:aws:sso:::instance/ssoins-1234567890abcdef"; APP = f"arn:aws:sso::{MGMT}:application/ssoins-1234567890abcdef/apl-1234567890abcdef"
TARGETS = {"management_account_id": MGMT, "authority_account_arn": PRIVATE["authority_account_arn"], "identity_center_instance_arn": INSTANCE, "identity_store_arn": PRIVATE["identity_store_arn"], "approved_single_operator_user_arn": PRIVATE["approved_single_operator_user_arn"], "identity_center_kms_key_arn": PRIVATE["identity_center_kms_key_arn"], "identity_center_application_arn": APP, "retire_approve_permission_set_arn": "arn:aws:sso:::permissionSet/ssoins-1234567890abcdef/ps-approve", "retire_class_permission_set_arn": "arn:aws:sso:::permissionSet/ssoins-1234567890abcdef/ps-class"}
DISCOVERY = {"instances": [{"identity_store_id": PRIVATE["identity_store_id"], "instance_arn": INSTANCE, "owner_account_id": MGMT, "status": "ACTIVE"}], "applications": [{"application_arn": APP, "name": PRIVATE["application_name"]}], "permission_sets": [{"name": NAMES[0], "permission_set_arn": TARGETS["retire_approve_permission_set_arn"]}, {"name": NAMES[1], "permission_set_arn": TARGETS["retire_class_permission_set_arn"]}]}
@pytest.fixture(autouse=True)
def _clean_aws(monkeypatch: pytest.MonkeyPatch) -> None:
    for key in tuple(os.environ):
        if key.startswith("AWS_") or key in {"BOTO_CONFIG", "REQUESTS_CA_BUNDLE", "SSL_CERT_FILE", "SSL_CERT_DIR"}: monkeypatch.delenv(key)
def _page(items): return {"items": items, "next_token": None, "truncated": False, "complete": True}
class Reader:
    def __init__(self, events: list[str] | None = None, mode: str = "ok"): self.events, self.mode = events if events is not None else [], mode
    def list_instances(self, token):
        self.events.append("list_instances")
        if self.mode == "denied": raise AuthorityAccessDenied("private provider text")
        if self.mode == "timeout": raise TimeoutError("private provider text")
        values = [] if self.mode == "absent" else DISCOVERY["instances"] * (2 if self.mode == "multiple" else 1); return _page([dict(DISCOVERY["instances"][0], instance_arn="not-an-arn")] if self.mode == "malformed" else [dict(item, status="INACTIVE") for item in values] if self.mode == "inactive" else values)
    def list_applications(self, instance, name, token): self.events.append("list_applications"); assert instance == INSTANCE and name == PRIVATE["application_name"]; return _page([] if self.mode == "missing" else DISCOVERY["applications"])
    def list_permission_sets(self, instance, names, token): self.events.append("list_permission_sets"); assert instance == INSTANCE and names == NAMES; values = copy.deepcopy(DISCOVERY["permission_sets"]); values[0]["name"] = "Foreign" if self.mode == "wrong_name" else values[0]["name"]; values[1]["name"] = values[0]["name"] if self.mode == "duplicate" else values[1]["name"]; return _page(values)
    def describe_instance(self, arn): self.events.append("describe_instance"); return {"complete": True, "value": {"instance_arn": arn, "identity_store_id": PRIVATE["identity_store_id"], "owner_account_id": MGMT, "status": "ACTIVE"}}
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
class Session:
    def __init__(self, factory, stage, digest): self.factory, self.stage, self.digest = factory, stage, digest
    def get_caller_identity(self):
        self.factory.events.append("sts:" + self.stage); value = {"source": "DIRECT_SSO", "chain_depth": 0, "account_id": MGMT, "region": "us-east-1", "principal_arn": _plan()["expected_principal_arn"], "session_id_digest": canonical_digest({"seed": self.factory.seed, "stage": self.stage}), "started_at": START, "expires_at": START + timedelta(minutes=45), "observed_at": START + timedelta(minutes=int(self.factory.seed)), "policy_digest": self.digest, "authority_verification_digest": _d("a")}; value.update(self.factory.identity); return value
    def open_discovery(self): self.factory.events.append("open_discovery"); return Reader(self.factory.events, self.factory.mode)
    def open_exact(self): self.factory.events.append("open_exact"); return Reader(self.factory.events, self.factory.mode)
class Factory:
    def __init__(self, seed="1", mode="ok", identity=None): self.seed, self.mode, self.identity, self.events = seed, mode, {} if identity is None else identity, []
    def open_sts(self, *, stage, policy, policy_digest, region): assert canonical_digest(policy) == policy_digest and region == "us-east-1"; self.events.append("open_sts:" + stage); return Session(self, stage, policy_digest)
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
