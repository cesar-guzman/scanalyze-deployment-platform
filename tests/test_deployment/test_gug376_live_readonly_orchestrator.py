from __future__ import annotations

import copy
import json
import os
import socket
import stat
import subprocess
from collections import Counter
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Mapping

import pytest
from jsonschema import Draft202012Validator

import tooling.platform_authority_gug376_live_readonly_orchestrator as live
from tooling.platform_authority_gug365_upstream_inventory import canonical_digest, canonical_json
from tooling.platform_authority_gug376_authority_inventory_collector import POLICY as AUTH_POLICY, render_policy as render_authority_policy
from tooling.platform_authority_gug376_identity_center_inventory_collector import POLICY as IDENTITY_POLICY, plan_binding, render_policy as render_identity_policy

ROOT = Path(__file__).parents[2]
START = datetime(2026, 8, 25, 16, 0, tzinfo=UTC)
NOW, END = START + timedelta(minutes=10), START + timedelta(minutes=30)
AUTH_ACCOUNT, IDENTITY_ACCOUNT = "111122223333", "444455556666"
SOURCE_SHA, TREE_SHA = "1" * 40, "2" * 40
VALID = ROOT / "fixtures/valid/platform-authority-gug376-live-readonly-handoff-v1-synthetic.json"
INVALID = ROOT / "fixtures/invalid/platform-authority-gug376-live-readonly-handoff-v1-overclaim.json"


def _d(seed: str) -> str:
    return canonical_digest({"synthetic": seed})


def _authority_plan(start: datetime = START, end: datetime = END) -> dict[str, Any]:
    bucket = "arn:aws:s3:::synthetic-private-artifacts"
    targets = {
        "artifact_bucket_arn": bucket, "broker_signed_object_arn": bucket + "/broker-signed.zip",
        "broker_unsigned_object_arn": bucket + "/broker-unsigned.zip", "ledger_factory_signed_object_arn": bucket + "/factory-signed.zip",
        "ledger_factory_unsigned_object_arn": bucket + "/factory-unsigned.zip", "artifact_kms_key_arn": f"arn:aws:kms:us-east-1:{AUTH_ACCOUNT}:key/11111111-1111-1111-1111-111111111111",
        "signing_profile_arn": f"arn:aws:signer:us-east-1:{AUTH_ACCOUNT}:/signing-profiles/synthetic", "code_signing_config_arn": f"arn:aws:lambda:us-east-1:{AUTH_ACCOUNT}:code-signing-config:csc-0123456789abcdef0",
        "runtime_source_function_arn": f"arn:aws:lambda:us-east-1:{AUTH_ACCOUNT}:function:synthetic-source", "runtime_source_function_version_arn": f"arn:aws:lambda:us-east-1:{AUTH_ACCOUNT}:function:synthetic-source:7",
        "retire_approve_generated_role_arn": f"arn:aws:iam::{AUTH_ACCOUNT}:role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_Approve_0123456789abcdef",
        "retire_class_generated_role_arn": f"arn:aws:iam::{AUTH_ACCOUNT}:role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_Class_0123456789abcdef",
    }
    plan = {"targets": targets, "not_before": start, "not_after": end, "expected_policy_digest": _d("pending"), "expected_account_id": AUTH_ACCOUNT, "expected_principal_arn": f"arn:aws:sts::{AUTH_ACCOUNT}:assumed-role/SyntheticAuthority/operator", "authority_verification_digest": _d("authority-verification")}
    text = AUTH_POLICY.read_text()
    values = dict(targets, inventory_not_before=start.isoformat().replace("+00:00", "Z"), inventory_not_after=end.isoformat().replace("+00:00", "Z"))
    for key, value in values.items():
        text = text.replace("${" + key + "}", value)
    plan["expected_policy_digest"] = canonical_digest(json.loads(text)); render_authority_policy(plan)
    return plan


def _identity_plan(start: datetime = START, end: datetime = END) -> dict[str, Any]:
    store, user = "d-1234567890", "12345678-1234-1234-1234-123456789012"
    private = {"application_name": "SyntheticAuthority", "approved_user_id": user, "approved_single_operator_user_arn": f"arn:aws:identitystore:::user/{store}/{user}", "authority_account_arn": f"arn:aws:sso:::account/{AUTH_ACCOUNT}", "identity_center_kms_key_arn": f"arn:aws:kms:us-east-1:{IDENTITY_ACCOUNT}:key/22222222-2222-2222-2222-222222222222", "identity_store_arn": f"arn:aws:identitystore:::identitystore/{store}", "identity_store_id": store}
    plan = {"private_targets": private, "not_before": start, "not_after": end, "expected_account_id": IDENTITY_ACCOUNT, "expected_principal_arn": f"arn:aws:sts::{IDENTITY_ACCOUNT}:assumed-role/SyntheticIdentity/operator", "authority_verification_digest": _d("identity-verification"), "expected_discovery_policy_digest": _d("pending"), "expected_exact_policy_digest": _d("unused-exact"), "expected_target_digest": _d("absent-target"), "expected_facts_digest": _d("absent-facts")}
    policy = json.loads(IDENTITY_POLICY.read_text()); policy["Statement"] = [item for item in policy["Statement"] if item["Sid"].startswith(("Confirm", "Discover", "Deny"))]
    text = canonical_json(policy)
    for key, value in {"inventory_not_before": start.isoformat().replace("+00:00", "Z"), "inventory_not_after": end.isoformat().replace("+00:00", "Z"), "management_account_id": IDENTITY_ACCOUNT}.items():
        text = text.replace("${" + key + "}", value)
    plan["expected_discovery_policy_digest"] = canonical_digest(json.loads(text)); render_identity_policy(plan); plan_binding(plan)
    return plan


def _config(start: datetime = START, end: datetime = END) -> dict[str, Any]:
    authority, identity = _authority_plan(start, end), _identity_plan(start, end)
    profiles = {"authority": {"name": "synthetic-authority", "source": "DIRECT_SSO", "chain_depth": 0}, "identity_center": {"name": "synthetic-identity", "source": "DIRECT_SSO", "chain_depth": 0}}
    window = canonical_digest({"not_before": start.isoformat().replace("+00:00", "Z"), "not_after": end.isoformat().replace("+00:00", "Z"), "region": "us-east-1"})
    profile, run_id = canonical_digest(profiles), canonical_digest("synthetic-run-0001")
    _, authority_policy = render_authority_policy(authority); _, identity_binding = plan_binding(identity)
    runtime = canonical_digest({"policy_digest": authority_policy, "runtime_source_function_version_arn": authority["targets"]["runtime_source_function_version_arn"]})
    authority_binding = {"account_id": AUTH_ACCOUNT, "principal_arn": authority["expected_principal_arn"], "not_before": start.isoformat().replace("+00:00", "Z"), "not_after": end.isoformat().replace("+00:00", "Z"), "policy_digest": authority_policy, "authority_verification_digest": authority["authority_verification_digest"], "runtime_target_digest": runtime, "target_digest": canonical_digest(authority["targets"]), "region": "us-east-1"}
    authorization = {"record_type": "scanalyze.platform_authority.gug376_live_readonly_authorization.v1", "opt_in": live.OPT_IN, "source_commit_sha": SOURCE_SHA, "source_tree_sha": TREE_SHA, "window_digest": window, "policy_digest": live.POLICY_DIGEST, "profile_binding_digest": profile, "authority_plan_digest": canonical_digest(authority_binding), "identity_center_plan_digest": identity_binding, "run_id_digest": run_id, "read_only": True, "aws_mutations": 0, "deployment_authorized": False}
    authorization_digest = canonical_digest(authorization)
    attestation = {"record_type": "scanalyze.platform_authority.gug376_live_readonly_attestation.v1", "authorization_digest": authorization_digest, "source_commit_sha": SOURCE_SHA, "source_tree_sha": TREE_SHA, "window_digest": window, "policy_digest": live.POLICY_DIGEST, "profile_binding_digest": profile, "authority_account_digest": canonical_digest(AUTH_ACCOUNT), "authority_principal_digest": canonical_digest(authority["expected_principal_arn"]), "identity_center_account_digest": canonical_digest(IDENTITY_ACCOUNT), "identity_center_principal_digest": canonical_digest(identity["expected_principal_arn"]), "read_only": True, "aws_mutations": 0}
    attestation_digest = canonical_digest(attestation)
    trust = {"record_type": "scanalyze.platform_authority.gug376_live_readonly_trust_anchor.v1", "authorization_digest": authorization_digest, "attestation_digest": attestation_digest, "policy_digest": live.POLICY_DIGEST, "authority_verification_digest": authority["authority_verification_digest"], "identity_center_authority_verification_digest": identity["authority_verification_digest"], "read_only": True}
    return {"opt_in": live.OPT_IN, "source_commit_sha": SOURCE_SHA, "source_tree_sha": TREE_SHA, "run_id": "synthetic-run-0001", "profiles": profiles, "authority_plan": authority, "identity_center_plan": identity, "authorization": authorization, "authorization_digest": authorization_digest, "attestation": attestation, "attestation_digest": attestation_digest, "trust_anchor": trust, "trust_anchor_digest": canonical_digest(trust)}


AUTHORITY_OPERATIONS = {"s3": "s3:ListAllMyBuckets", "kms": "kms:ListKeys", "signer": "signer:ListSigningProfiles", "lambda_code_signing": "lambda:ListCodeSigningConfigs", "lambda_runtime": "lambda:ListVersionsByFunction", "iam_roles": "iam:ListRoles", "artifact_objects": "s3:ListBucketVersions"}


class FakeProvider:
    mode = "SYNTHETIC"

    def __init__(self, config: Mapping[str, Any], *, fault: str | None = None, identity: Mapping[str, Any] | None = None) -> None:
        self.config, self.fault, self.identity = config, fault, dict(identity or {})
        self.builds: list[tuple[str, int]] = []; self.attempts: list[tuple[str, int, str, str]] = []; self.completed = 0; self.reader_opens = 0

    def build_authority(self, *, profile: str, ledger: live.CallLedger, capture_index: int, retries: int) -> Any:
        assert profile == self.config["profiles"]["authority"]["name"] and retries == 0
        self.builds.append(("authority", capture_index)); return _SessionFactory(self, "authority", capture_index, ledger)

    def build_identity(self, *, profile: str, ledger: live.CallLedger, capture_index: int, retries: int) -> Any:
        assert profile == self.config["profiles"]["identity_center"]["name"] and retries == 0
        self.builds.append(("identity_center", capture_index)); return _SessionFactory(self, "identity_center", capture_index, ledger)


class _Actor:
    def __init__(self, owner: FakeProvider, domain: str, capture: int, stage: str, ledger: live.CallLedger, digest: str) -> None:
        self.owner, self.domain, self.capture, self.stage, self.ledger, self.digest = owner, domain, capture, stage, ledger, digest
        seed = {"domain": domain, "capture": capture, "stage": stage}
        if owner.fault == "cross_session" and domain == "identity_center": seed = {"domain": "authority", "capture": 1, "stage": "authority"}
        self.session = canonical_digest(seed)

    def call(self, operation: str, response: Any, *, token: Any = None) -> Any:
        requested, retries = operation, 0
        if operation != "sts:GetCallerIdentity" and self.owner.fault == "unapproved": requested = "iam:DeleteRole"
        if operation != "sts:GetCallerIdentity" and self.owner.fault == "retry": retries = 1
        self.owner.attempts.append((self.domain, self.capture, self.stage, requested))
        ticket = self.ledger.authorize(domain=self.domain, session_digest=self.session, operation=requested, retries=retries, request={"capture": self.capture, "stage": self.stage}, page_token=token)
        broken = self.domain == "authority" and self.capture == 1 and operation == AUTHORITY_OPERATIONS["s3"] and self.owner.fault in {"partial", "ambiguous"}
        if broken:
            self.ledger.complete(ticket, _d("provider-error"), outcome="ERROR"); self.owner.completed += 1
            if self.owner.fault == "partial": raise TimeoutError("synthetic-provider-error")
            return {"items": [], "next_cursor": None, "truncated": True}
        next_token = response.get("next_cursor", response.get("next_token")) if isinstance(response, Mapping) else None
        truncated = bool(response.get("truncated")) if isinstance(response, Mapping) else False
        self.ledger.complete(ticket, _d(f"{self.domain}-{self.capture}-{self.stage}-{operation}-{token}"), complete=next_token is None, truncated=truncated, next_token=next_token)
        self.owner.completed += 1; return response


class _SessionFactory:
    def __init__(self, owner: FakeProvider, domain: str, capture: int, ledger: live.CallLedger) -> None:
        self.owner, self.domain, self.capture, self.ledger = owner, domain, capture, ledger

    def open_sts(self, *, policy: Mapping[str, Any], policy_digest: str, region: str, stage: str = "authority") -> Any:
        assert canonical_digest(policy) == policy_digest and region == "us-east-1"
        return _Session(_Actor(self.owner, self.domain, self.capture, stage, self.ledger, policy_digest), self.owner.config["authority_plan" if self.domain == "authority" else "identity_center_plan"])


class _Session:
    def __init__(self, actor: _Actor, plan: Mapping[str, Any]) -> None: self.actor, self.plan = actor, plan
    def get_caller_identity(self) -> Mapping[str, Any]:
        value = {"source": "DIRECT_SSO", "chain_depth": 0, "account_id": self.plan["expected_account_id"], "region": "us-east-1", "principal_arn": self.plan["expected_principal_arn"], "session_id_digest": self.actor.session, "started_at": START, "expires_at": END + timedelta(minutes=5), "observed_at": START + timedelta(minutes=4 + self.actor.capture), "policy_digest": self.actor.digest, "authority_verification_digest": self.plan["authority_verification_digest"]}
        if self.actor.domain == "authority": value.update(self.actor.owner.identity)
        return self.actor.call("sts:GetCallerIdentity", value)
    def open_reader(self) -> Any: self.actor.owner.reader_opens += 1; return _AuthorityReader(self.actor, self.plan)
    def open_discovery(self) -> Any: self.actor.owner.reader_opens += 1; return _IdentityReader(self.actor)
    def open_exact(self) -> Any: self.actor.owner.reader_opens += 1; return _IdentityReader(self.actor)


class _AuthorityReader:
    def __init__(self, actor: _Actor, plan: Mapping[str, Any]) -> None: self.actor, self.plan = actor, plan
    def _page(self, name: str, cursor: Any) -> Mapping[str, Any]:
        items: list[dict[str, Any]] = []
        if name == "lambda_runtime": items = [{"function_arn": self.plan["targets"]["runtime_source_function_version_arn"], "version": "7", "runtime": "python3.12", "architectures": ["x86_64"], "update_runtime_on": "Manual", "runtime_version_arn": "arn:aws:lambda:us-east-1::runtime:" + "a" * 64}]
        if name == "s3" and self.actor.owner.fault == "drift" and self.actor.capture == 2: items = [{"synthetic": "changed"}]
        return self.actor.call(AUTHORITY_OPERATIONS[name], {"items": items, "next_cursor": None, "truncated": False}, token=cursor)
    def s3(self, token: Any) -> Any: return self._page("s3", token)
    def kms(self, token: Any) -> Any: return self._page("kms", token)
    def signer(self, token: Any) -> Any: return self._page("signer", token)
    def lambda_code_signing(self, token: Any) -> Any: return self._page("lambda_code_signing", token)
    def lambda_runtime(self, token: Any) -> Any: return self._page("lambda_runtime", token)
    def iam_roles(self, token: Any) -> Any: return self._page("iam_roles", token)
    def artifact_objects(self, token: Any) -> Any: return self._page("artifact_objects", token)


class _IdentityReader:
    def __init__(self, actor: _Actor) -> None: self.actor = actor
    def list_instances(self, token: Any) -> Any: return self.actor.call("sso:ListInstances", {"items": [], "next_token": None, "truncated": False, "complete": True}, token=token)


@pytest.fixture(autouse=True)
def _clean_ambient(monkeypatch: pytest.MonkeyPatch) -> None:
    for key in tuple(os.environ):
        if key.startswith("AWS_") or key in {"BOTO_CONFIG", "REQUESTS_CA_BUNDLE", "SSL_CERT_FILE", "SSL_CERT_DIR"}: monkeypatch.delenv(key)


def _root(tmp_path: Path, name: str = "private") -> Path:
    root = tmp_path / name; root.mkdir(mode=0o700, parents=True); root.chmod(0o700); return root


def _execute(tmp_path: Path, *, config: dict[str, Any] | None = None, factory: FakeProvider | None = None, now: datetime = NOW) -> tuple[dict[str, Any], dict[str, Any], Path, FakeProvider]:
    config, root = config or _config(), _root(tmp_path)
    factory = factory or FakeProvider(config)
    run, handoff = live.execute(config, factory, private_root=root, now=now, actual_source_commit_sha=SOURCE_SHA, actual_source_tree_sha=TREE_SHA)
    return run, handoff, root, factory


def test_happy_path_is_synthetic_sanitized_private_and_offline(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    forbidden = lambda *_args, **_kwargs: pytest.fail("network or subprocess attempted")
    monkeypatch.setattr(socket, "socket", forbidden); monkeypatch.setattr(subprocess, "run", forbidden); monkeypatch.setattr(subprocess, "Popen", forbidden)
    run, handoff, root, factory = _execute(tmp_path)
    assert (run["status"], run["classification"], run["provider_calls"], run["aws_calls"]) == ("LIVE_INVENTORY_NOT_PROVEN", "SYNTHETIC_VALIDATED", 20, 0)
    assert handoff["deployment_authorized"] is handoff["live_provider_evidence"] is False and handoff["aws_mutations"] == 0 and handoff["two_human_status"] == "NOT_PROVEN" and handoff["production_status"] == "NO-GO"
    assert len(factory.attempts) == factory.completed == 20 and factory.builds == [("authority", 1), ("authority", 2), ("identity_center", 1), ("identity_center", 2)]
    assert stat.S_IMODE(root.stat().st_mode) == 0o700 and all(stat.S_IMODE((root / name).stat().st_mode) == 0o600 for name in live.ARTIFACT_NAMES)
    public = json.dumps(handoff)
    for private in (AUTH_ACCOUNT, IDENTITY_ACCOUNT, "arn:aws:", "synthetic-authority", "synthetic-identity", str(root), "session_id"):
        assert private not in public


def test_injected_factory_cannot_self_assert_live_or_construct_a_provider(tmp_path: Path) -> None:
    config, root = _config(), _root(tmp_path)
    factory = FakeProvider(config); factory.mode = "LIVE"
    with pytest.raises(live.OrchestratorError, match="LIVE_PROVIDER_NOT_IMPLEMENTED"):
        live.execute(config, factory, private_root=root, now=NOW, actual_source_commit_sha=SOURCE_SHA, actual_source_tree_sha=TREE_SHA)
    assert factory.builds == [] and factory.attempts == [] and factory.completed == factory.reader_opens == 0
    assert not any((root / name).exists() for name in live.ARTIFACT_NAMES)
    with pytest.raises(live.OrchestratorError, match="LIVE_PROVIDER_NOT_IMPLEMENTED"):
        live.CallLedger("LIVE")


def test_consistent_looking_live_public_claim_is_still_rejected(tmp_path: Path) -> None:
    _, handoff, _, _ = _execute(tmp_path)
    forged = dict(handoff, status="LIVE_READ_ONLY_CAPTURED", classification="ABSENT_READY", live_provider_evidence=True, aws_calls=handoff["provider_calls"])
    forged["handoff_digest"] = canonical_digest({key: value for key, value in forged.items() if key != "handoff_digest"})
    with pytest.raises(live.OrchestratorError, match="PUBLIC_HANDOFF_INVALID"):
        live.validate_public_handoff(forged)


@pytest.mark.parametrize("case,code", [("opt_in", "EXPLICIT_OPT_IN_REQUIRED"), ("same", "PROFILE_BINDING_INVALID"), ("same_case", "PROFILE_BINDING_INVALID"), ("default", "PROFILE_BINDING_INVALID"), ("chained", "PROFILE_BINDING_INVALID"), ("expired", "WINDOW_INVALID"), ("future", "WINDOW_INVALID"), ("commit", "SOURCE_BINDING_INVALID"), ("tree", "SOURCE_BINDING_INVALID"), ("authorization", "AUTHORIZATION_BINDING_INVALID"), ("attestation", "ATTESTATION_BINDING_INVALID"), ("trust", "TRUST_ANCHOR_BINDING_INVALID"), ("policy", "SOURCE_BINDING_INVALID"), ("static", "AMBIENT_AWS_OVERRIDE_FORBIDDEN"), ("endpoint", "AMBIENT_AWS_OVERRIDE_FORBIDDEN")])
def test_local_preflight_gates_stop_before_provider(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, case: str, code: str) -> None:
    config, now, commit, tree = _config(), NOW, SOURCE_SHA, TREE_SHA
    if case == "opt_in": config["opt_in"] = "DISABLED"
    elif case == "same": config["profiles"]["identity_center"]["name"] = config["profiles"]["authority"]["name"]
    elif case == "same_case": config["profiles"]["identity_center"]["name"] = config["profiles"]["authority"]["name"].upper()
    elif case == "default": config["profiles"]["authority"]["name"] = "default"
    elif case == "chained": config["profiles"]["authority"]["chain_depth"] = 1
    elif case == "expired": now = END
    elif case == "future": now = START - timedelta(seconds=1)
    elif case == "commit": commit = "3" * 40
    elif case == "tree": tree = "4" * 40
    elif case == "authorization": config["authorization_digest"] = _d("drift")
    elif case == "attestation": config["attestation_digest"] = _d("drift")
    elif case == "trust": config["trust_anchor_digest"] = _d("drift")
    elif case == "policy": monkeypatch.setattr(live, "_CLOSED_POLICY", dict(live._CLOSED_POLICY, max_pages=49))
    elif case == "static": monkeypatch.setenv("AWS_ACCESS_KEY_ID", "synthetic-test-only")
    else: monkeypatch.setenv("AWS_ENDPOINT_URL", "https://synthetic.invalid")
    root, factory = _root(tmp_path), FakeProvider(config)
    with pytest.raises(live.OrchestratorError, match=code): live.execute(config, factory, private_root=root, now=now, actual_source_commit_sha=commit, actual_source_tree_sha=tree)
    assert factory.builds == [] and factory.attempts == []


@pytest.mark.parametrize("field,value", [("account_id", "000000000000"), ("region", "us-west-2"), ("principal_arn", "arn:aws:sts::000000000000:assumed-role/Wrong/operator"), ("source", "ASSUME_ROLE"), ("chain_depth", 1), ("expires_at", START + timedelta(minutes=5))])
def test_caller_binding_fails_after_sts_and_before_reader(tmp_path: Path, field: str, value: Any) -> None:
    config = _config(); factory = FakeProvider(config, identity={field: value})
    with pytest.raises(live.OrchestratorError, match="DIRECT_SESSION_BINDING_INVALID"): _execute(tmp_path, config=config, factory=factory)
    assert factory.reader_opens == 0 and [item[-1] for item in factory.attempts] == ["sts:GetCallerIdentity"] and factory.completed == 1


@pytest.mark.parametrize("fault,code", [("unapproved", "PROVIDER_OPERATION_NOT_ALLOWED"), ("retry", "PROVIDER_RETRIES_FORBIDDEN")])
def test_closed_operations_and_zero_retries_are_ledger_enforced(tmp_path: Path, fault: str, code: str) -> None:
    config = _config(); factory = FakeProvider(config, fault=fault)
    with pytest.raises(live.OrchestratorError, match=code): _execute(tmp_path, config=config, factory=factory)
    assert len(factory.attempts) == 8 and factory.attempts[0][-1] == "sts:GetCallerIdentity" and factory.completed == 1


def _ledger() -> tuple[live.CallLedger, str]:
    ledger, session = live.CallLedger("SYNTHETIC"), _d("ledger-session")
    ticket = ledger.authorize(domain="authority", session_digest=session, operation="sts:GetCallerIdentity", retries=0)
    ledger.complete(ticket, _d("sts")); return ledger, session


def test_ledger_rejects_truncated_repeated_and_over_limit_pagination() -> None:
    ledger, session = _ledger(); ticket = ledger.authorize(domain="authority", session_digest=session, operation="s3:ListAllMyBuckets", retries=0)
    with pytest.raises(live.OrchestratorError, match="PROVIDER_PAGE_INCOMPLETE"): ledger.complete(ticket, complete=True, truncated=True, next_token="next")
    ledger, session = _ledger(); ticket = ledger.authorize(domain="authority", session_digest=session, operation="s3:ListAllMyBuckets", retries=0); ledger.complete(ticket, complete=False, truncated=True, next_token="same")
    ticket = ledger.authorize(domain="authority", session_digest=session, operation="s3:ListAllMyBuckets", retries=0, page_token="same")
    with pytest.raises(live.OrchestratorError, match="PROVIDER_PAGE_TOKEN_REPEATED"): ledger.complete(ticket, complete=False, truncated=True, next_token="same")
    ledger, session, token = *_ledger(), None
    for index in range(50):
        ticket = ledger.authorize(domain="authority", session_digest=session, operation="s3:ListAllMyBuckets", retries=0, page_token=token); token = f"page-{index}"
        ledger.complete(ticket, complete=False, truncated=True, next_token=token)
    with pytest.raises(live.OrchestratorError, match="PROVIDER_PAGE_SEQUENCE_INVALID"): ledger.authorize(domain="authority", session_digest=session, operation="s3:ListAllMyBuckets", retries=0, page_token=token)


@pytest.mark.parametrize("fault", ["partial", "ambiguous", "drift"])
def test_partial_ambiguous_or_inconsistent_evidence_is_reconcile_only_without_retry(tmp_path: Path, fault: str) -> None:
    config = _config(); factory = FakeProvider(config, fault=fault)
    with pytest.raises(live.OrchestratorError, match="RECONCILIATION_READ_ONLY_REQUIRED"): _execute(tmp_path, config=config, factory=factory)
    assert all(count == 1 for count in Counter(factory.attempts).values())


def test_substituted_receipt_and_cross_domain_session_are_rejected(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    config = _config(); collision = FakeProvider(config, fault="cross_session")
    with pytest.raises(live.OrchestratorError, match="STS_FIRST_REQUIRED"): _execute(tmp_path / "session", config=config, factory=collision)
    original = live.certify_identity_center
    def substituted(*args: Any, **kwargs: Any) -> dict[str, Any]:
        receipt = original(*args, **kwargs); receipt["record_type"] = "scanalyze.platform_authority.gug376_authority_inventory_receipt.v1"
        receipt["receipt_digest"] = canonical_digest({key: value for key, value in receipt.items() if key != "receipt_digest"}); return receipt
    monkeypatch.setattr(live, "certify_identity_center", substituted)
    with pytest.raises(live.OrchestratorError, match="GUG385_RECEIPT_INVALID"): _execute(tmp_path / "receipt")


def test_public_contract_rejects_sensitive_fields_and_every_overclaim(tmp_path: Path) -> None:
    _, handoff, _, _ = _execute(tmp_path)
    for field in ("account_id", "arn", "profile", "UserId", "email", "path", "request_id", "token", "provider_payload"):
        forged = dict(handoff, **{field: "synthetic-private"}); forged["handoff_digest"] = canonical_digest({key: value for key, value in forged.items() if key != "handoff_digest"})
        with pytest.raises(live.OrchestratorError, match="PUBLIC_HANDOFF_INVALID"): live.validate_public_handoff(forged)
    for field, value in (("status", "DEPLOYED"), ("classification", "LIVE_COMPLETE"), ("live_provider_evidence", True), ("aws_calls", 1), ("aws_mutations", 1), ("reconciliation_only", True), ("deployment_authorized", True), ("two_human_status", "PROVEN"), ("independent_approval_present", True), ("production_status", "GO")):
        forged = dict(handoff, **{field: value}); forged["handoff_digest"] = canonical_digest({key: item for key, item in forged.items() if key != "handoff_digest"})
        with pytest.raises(live.OrchestratorError, match="PUBLIC_HANDOFF_INVALID"): live.validate_public_handoff(forged)


def test_schema_contracts_and_fixtures(tmp_path: Path) -> None:
    run, handoff, _, _ = _execute(tmp_path)
    run_schema = json.loads((ROOT / "schemas/platform-authority-gug376-live-readonly-run.v1.schema.json").read_text()); handoff_schema = json.loads((ROOT / "schemas/platform-authority-gug376-live-readonly-handoff.v1.schema.json").read_text())
    Draft202012Validator.check_schema(run_schema); Draft202012Validator.check_schema(handoff_schema)
    assert not list(Draft202012Validator(run_schema).iter_errors(run)) and not list(Draft202012Validator(handoff_schema).iter_errors(handoff))
    forged_live = {"status": "LIVE_READ_ONLY_CAPTURED", "classification": "ABSENT_READY", "live_provider_evidence": True, "aws_calls": handoff["provider_calls"]}
    assert list(Draft202012Validator(run_schema).iter_errors(dict(run, **forged_live)))
    assert list(Draft202012Validator(handoff_schema).iter_errors(dict(handoff, **forged_live)))
    valid, invalid = json.loads(VALID.read_text()), json.loads(INVALID.read_text())
    assert valid == handoff == live.validate_public_handoff(valid)
    assert list(Draft202012Validator(handoff_schema).iter_errors(invalid))
    with pytest.raises(live.OrchestratorError, match="PUBLIC_HANDOFF_INVALID"): live.validate_public_handoff(invalid)


def test_unsafe_private_roots_stop_before_provider(tmp_path: Path) -> None:
    roots: list[Path] = []
    bad = tmp_path / "bad-mode"; bad.mkdir(mode=0o700); bad.chmod(0o755); roots.append(bad)
    cloud = tmp_path / "CloudStorage"; cloud.mkdir(mode=0o700); cloud.chmod(0o700); roots.append(cloud)
    git = tmp_path / "git-root"; git.mkdir(mode=0o700); git.chmod(0o700); (git / ".git").mkdir(); roots.append(git)
    real = tmp_path / "real"; real.mkdir(mode=0o700); real.chmod(0o700); linked = tmp_path / "linked"; linked.symlink_to(real, target_is_directory=True); roots.append(linked)
    for root in roots:
        config, factory = _config(), FakeProvider(_config())
        with pytest.raises(live.OrchestratorError): live.execute(config, factory, private_root=root, now=NOW, actual_source_commit_sha=SOURCE_SHA, actual_source_tree_sha=TREE_SHA)
        assert factory.builds == []


def test_v1_collectors_remain_stopped_and_executor_imports_no_sdk_provider() -> None:
    for name in ("platform-authority-gug376-authority-inventory.py", "platform-authority-gug376-identity-center-inventory.py", "platform-authority-gug383-dual-domain-inventory-handoff.py"):
        assert "STOP_LIVE_ORCHESTRATOR_NOT_IMPLEMENTED" in (ROOT / "scripts/deployment" / name).read_text()
    source = (ROOT / "tooling/platform_authority_gug376_live_readonly_orchestrator.py").read_text()
    for forbidden in ("boto3", "botocore", "import socket", "import subprocess", "subprocess.run", "aws sts"):
        assert forbidden not in source
