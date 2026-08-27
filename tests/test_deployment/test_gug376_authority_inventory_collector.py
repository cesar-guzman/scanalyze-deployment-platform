from __future__ import annotations
import copy, json, os, stat, subprocess, sys
from datetime import UTC, datetime, timedelta; from hashlib import sha256
from pathlib import Path; import pytest
from tooling.platform_authority_gug365_upstream_inventory import canonical_digest
from tooling.platform_authority_gug376_authority_inventory_collector import AuthorityAccessDenied, CollectorError, MAX_PRIVATE_JSON_BYTES, POLICY, SURFACES, _collect, capture, capture_live, certify, certify_live, read_private_json, render_policy, write_private_json
START = datetime(2026, 8, 23, 20, 0, tzinfo=UTC)
D1, D2 = "sha256:" + "1" * 64, "sha256:" + "2" * 64
ACCOUNT = "042360977644"
@pytest.fixture(autouse=True)
def _clean_runtime_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    for key in tuple(os.environ):
        if key.startswith("AWS_") or key in {"BOTO_CONFIG", "REQUESTS_CA_BUNDLE", "SSL_CERT_FILE", "SSL_CERT_DIR"}: monkeypatch.delenv(key)
def _plan() -> dict[str, object]:
    bucket = "arn:aws:s3:::scanalyze-private-artifacts"
    targets = {"artifact_bucket_arn": bucket, "broker_signed_object_arn": bucket + "/broker-signed.zip", "broker_unsigned_object_arn": bucket + "/broker-unsigned.zip", "ledger_factory_signed_object_arn": bucket + "/factory-signed.zip", "ledger_factory_unsigned_object_arn": bucket + "/factory-unsigned.zip", "artifact_kms_key_arn": f"arn:aws:kms:us-east-1:{ACCOUNT}:key/11111111-1111-1111-1111-111111111111", "signing_profile_arn": f"arn:aws:signer:us-east-1:{ACCOUNT}:/signing-profiles/scanalyze", "code_signing_config_arn": f"arn:aws:lambda:us-east-1:{ACCOUNT}:code-signing-config:csc-0123456789abcdef0", "runtime_source_function_arn": f"arn:aws:lambda:us-east-1:{ACCOUNT}:function:runtime-source", "runtime_source_function_version_arn": f"arn:aws:lambda:us-east-1:{ACCOUNT}:function:runtime-source:7", "retire_approve_generated_role_arn": f"arn:aws:iam::{ACCOUNT}:role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_Approve_0123456789abcdef", "retire_class_generated_role_arn": f"arn:aws:iam::{ACCOUNT}:role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_Class_0123456789abcdef"}
    plan: dict[str, object] = {"targets": targets, "not_before": START, "not_after": START + timedelta(minutes=30), "expected_policy_digest": D1, "expected_account_id": ACCOUNT, "expected_principal_arn": f"arn:aws:sts::{ACCOUNT}:assumed-role/ScanalyzeInventory/operator", "authority_verification_digest": D2}
    text = POLICY.read_text()
    for key, value in dict(targets, inventory_not_before="2026-08-23T20:00:00Z", inventory_not_after="2026-08-23T20:30:00Z").items(): text = text.replace("${" + key + "}", value)
    rendered = json.loads(text); plan["expected_policy_digest"] = "sha256:" + sha256(json.dumps(rendered, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode()).hexdigest(); return plan
def _live_plan() -> dict[str, object]:
    plan = _plan()
    plan["expected_generated_role_trust_policy_digests"] = {
        "retire_approve": canonical_digest("synthetic-approve-trust"),
        "retire_class": canonical_digest("synthetic-class-trust"),
    }
    return plan
def _root(tmp_path: Path, name: str = "private") -> Path:
    root = tmp_path / name; root.mkdir(mode=0o700, parents=True); root.chmod(0o700); return root
class Reader:
    def __init__(self, events: list[str], *, present: bool = False, fault: str | None = None): self.events, self.present, self.fault = events, present, fault
    def page(self, name: str, cursor: object | None) -> dict[str, object]:
        self.events.append(name)
        if name == "s3" and self.fault == "denied": raise AuthorityAccessDenied("provider secret")
        if name == "s3" and self.fault == "timeout": raise TimeoutError("provider secret")
        if name == "s3" and self.fault == "repeat": return {"items": [], "next_cursor": "same", "truncated": True}
        if name == "s3" and self.fault == "truncation": return {"items": [], "next_cursor": None, "truncated": True}
        if name == "lambda_runtime":
            item = {"function_arn": _plan()["targets"]["runtime_source_function_version_arn"], "version": "7", "runtime": "python3.12", "architectures": ["x86_64"], "update_runtime_on": "Manual", "runtime_version_arn": "arn:aws:lambda:us-east-1::runtime:" + "a" * 64}
            if self.fault and self.fault.startswith("runtime:"): field = self.fault.split(":")[1]; item[field] = "8" if field == "version" else "bad"
            return {"items": [item], "next_cursor": None, "truncated": False}
        return {"items": ([{"private_name": "never-public"}] if self.present and name == "s3" else []), "next_cursor": None, "truncated": False}
    def s3(self, value): return self.page("s3", value)
    def kms(self, value): return self.page("kms", value)
    def signer(self, value): return self.page("signer", value)
    def lambda_code_signing(self, value): return self.page("lambda_code_signing", value)
    def lambda_runtime(self, value): return self.page("lambda_runtime", value)
    def iam_roles(self, value): return self.page("iam_roles", value)
    def artifact_objects(self, value): return self.page("artifact_objects", value)
class Factory:
    def __init__(self, plan, *, session=D1, observed=START + timedelta(minutes=5), identity=None, **reader): self.plan, self.events, self.session, self.observed, self.override, self.reader = plan, [], session, observed, identity or {}, reader
    def open_sts(self, **_): self.events.append("open_sts"); return self
    def get_caller_identity(self):
        self.events.append("sts"); plan = self.plan
        value = {"source": "DIRECT_SSO", "chain_depth": 0, "account_id": ACCOUNT, "region": "us-east-1", "principal_arn": plan["expected_principal_arn"], "session_id_digest": self.session, "started_at": START, "expires_at": START + timedelta(minutes=45), "observed_at": self.observed, "policy_digest": plan["expected_policy_digest"], "authority_verification_digest": D2}; value.update(self.override); return value
    def open_reader(self): self.events.append("open_reader"); return Reader(self.events, **self.reader)
def _capture(tmp_path: Path, name="one.json", **factory):
    plan, root = _plan(), _root(tmp_path)
    actor = Factory(plan, **factory); receipt = capture(plan, actor, private_root=root, artifact_name=name, now=actor.observed + timedelta(minutes=1))
    return plan, root, actor, receipt, read_private_json(root, name)
def test_policy_render_and_local_gates_precede_factory(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    plan = _plan(); policy, digest = render_policy(plan)
    assert digest == plan["expected_policy_digest"] and "${" not in json.dumps(policy)
    reordered = copy.deepcopy(plan); reordered["targets"] = dict(reversed(tuple(reordered["targets"].items()))); assert render_policy(reordered) == (policy, digest)
    for mutation in ("wildcard", "region", "service", "latest", "digest", "window"):
        bad = copy.deepcopy(plan)
        if mutation == "wildcard": bad["targets"]["artifact_bucket_arn"] += "/*"
        elif mutation == "region": bad["targets"]["artifact_kms_key_arn"] = bad["targets"]["artifact_kms_key_arn"].replace("us-east-1", "us-west-2")
        elif mutation == "service": bad["targets"]["artifact_kms_key_arn"] = bad["targets"]["signing_profile_arn"]
        elif mutation == "latest": bad["targets"]["runtime_source_function_version_arn"] = bad["targets"]["runtime_source_function_arn"] + ":$LATEST"
        elif mutation == "digest": bad["expected_policy_digest"] = D1
        else: bad["not_after"] = bad["not_before"]
        with pytest.raises(CollectorError): render_policy(bad)
    root, actor = _root(tmp_path), Factory(plan); monkeypatch.setenv("AWS_ENDPOINT_URL", "https://unreviewed.invalid")
    with pytest.raises(CollectorError, match="AMBIENT_AWS_OVERRIDE_FORBIDDEN"): capture(plan, actor, private_root=root, artifact_name="x.json", now=START + timedelta(minutes=6))
    assert actor.events == []
@pytest.mark.parametrize("field,value", [("account_id", "000000000000"), ("region", "us-west-2"), ("principal_arn", "arn:aws:sts::000000000000:assumed-role/x/y"), ("source", "ASSUME_ROLE"), ("chain_depth", 1), ("expires_at", START + timedelta(minutes=20)), ("policy_digest", D1), ("authority_verification_digest", D1)])
def test_identity_mismatch_stops_before_reader(tmp_path: Path, field: str, value: object) -> None:
    plan, root = _plan(), _root(tmp_path); actor = Factory(plan, identity={field: value})
    with pytest.raises(CollectorError, match="DIRECT_SESSION_BINDING_INVALID"): capture(plan, actor, private_root=root, artifact_name="x.json", now=START + timedelta(minutes=6))
    assert actor.events == ["open_sts", "sts"]
def test_capture_is_sts_first_private_atomic_and_publicly_sanitized(tmp_path: Path) -> None:
    plan, root, actor, receipt, private = _capture(tmp_path, present=True)
    assert actor.events[:3] == ["open_sts", "sts", "open_reader"] and actor.events[3:] == list(SURFACES)
    assert receipt["aws_mutations"] == 0 and receipt["two_human_status"] == "NOT_PROVEN" and receipt["independent_approval_present"] is False and receipt["production_status"] == "NO-GO" and receipt["external_certification_digest"] is None
    assert receipt["receipt_digest"] == canonical_digest({key: value for key, value in receipt.items() if key != "receipt_digest"})
    public = json.dumps(receipt); assert ACCOUNT not in public and "arn:aws:" not in public and "never-public" not in public
    item = (root / "one.json").stat(); assert stat.S_IMODE(item.st_mode) == 0o600 and item.st_nlink == 1 and private["identity"]["account_id"] == ACCOUNT
    with pytest.raises(CollectorError): write_private_json(root, "one.json", {"replacement": True})


def test_private_atomic_write_removes_partial_temporary_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = _root(tmp_path)
    real_write = os.write
    attempts = 0

    def partial_then_fail(descriptor: int, payload: bytes) -> int:
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            return real_write(descriptor, payload[:1])
        raise OSError("synthetic partial write")

    monkeypatch.setattr(os, "write", partial_then_fail)
    with pytest.raises(CollectorError, match="PRIVATE_OUTPUT_WRITE_FAILED"):
        write_private_json(root, "partial.json", {"value": "never-published"})
    assert list(root.iterdir()) == []


def test_private_atomic_write_rejects_oversize_before_creating_files(
    tmp_path: Path,
) -> None:
    root = _root(tmp_path)
    with pytest.raises(CollectorError, match="PRIVATE_OUTPUT_TOO_LARGE"):
        write_private_json(
            root,
            "oversize.json",
            {"payload": "x" * MAX_PRIVATE_JSON_BYTES},
        )
    assert list(root.iterdir()) == []


def test_private_atomic_write_preserves_a_preexisting_temporary_file(
    tmp_path: Path,
) -> None:
    root = _root(tmp_path)
    value = {"value": "new-writer"}
    temporary = root / f".collision.json.{canonical_digest(value)[7:23]}.tmp"
    temporary.write_text('{"value":"other-writer"}\n', encoding="utf-8")
    temporary.chmod(0o600)

    with pytest.raises(CollectorError, match="PRIVATE_OUTPUT_WRITE_FAILED"):
        write_private_json(root, "collision.json", value)

    assert temporary.read_text(encoding="utf-8") == '{"value":"other-writer"}\n'
    assert not (root / "collision.json").exists()


def test_private_atomic_write_preserves_published_target_after_post_link_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = _root(tmp_path)
    value = {"value": "published"}
    temporary_name = f".published.json.{canonical_digest(value)[7:23]}.tmp"
    real_unlink = os.unlink
    failed_once = False

    def fail_first_temporary_unlink(path, *args, **kwargs):
        nonlocal failed_once
        if path == temporary_name and not failed_once:
            failed_once = True
            raise OSError("synthetic post-link cleanup failure")
        return real_unlink(path, *args, **kwargs)

    monkeypatch.setattr(os, "unlink", fail_first_temporary_unlink)
    with pytest.raises(CollectorError, match="PRIVATE_OUTPUT_WRITE_FAILED"):
        write_private_json(root, "published.json", value)

    assert failed_once is True
    assert read_private_json(root, "published.json") == value
    assert not (root / temporary_name).exists()


def test_capture_live_uses_post_sts_validation_clock(
    tmp_path: Path,
) -> None:
    plan = _live_plan()
    initial_now = START + timedelta(minutes=5)
    observed_at = initial_now + timedelta(seconds=1)
    stale_actor = Factory(plan, observed=observed_at)

    with pytest.raises(CollectorError, match="DIRECT_SESSION_BINDING_INVALID"):
        capture(
            plan,
            stale_actor,
            private_root=_root(tmp_path, "legacy"),
            artifact_name="legacy.json",
            now=initial_now,
        )

    actor = Factory(plan, observed=observed_at)
    clock_events: list[str] = []

    def validation_clock() -> datetime:
        assert actor.events == ["open_sts", "sts"]
        clock_events.append("validation_clock")
        return observed_at + timedelta(seconds=1)

    receipt = capture_live(
        plan,
        actor,
        private_root=_root(tmp_path, "live"),
        artifact_name="live.json",
        now=initial_now,
        validation_clock=validation_clock,
    )

    assert clock_events == ["validation_clock"]
    assert actor.events[:3] == ["open_sts", "sts", "open_reader"]
    assert receipt["read_only"] is True
    assert receipt["aws_mutations"] == 0


def test_live_private_v2_allows_same_second_but_v1_remains_strict(
    tmp_path: Path,
) -> None:
    plan = _live_plan()
    observed = START + timedelta(minutes=5, seconds=1)
    root = _root(tmp_path)
    for name, session in (("first.json", D1), ("second.json", D2)):
        capture_live(
            plan,
            Factory(plan, session=session, observed=observed),
            private_root=root,
            artifact_name=name,
            now=observed - timedelta(seconds=1),
            validation_clock=lambda: observed + timedelta(seconds=1),
        )
    first = read_private_json(root, "first.json")
    second = read_private_json(root, "second.json")
    assert first["record_type"].endswith("private.v2")
    assert certify_live(
        first,
        second,
        expected_runtime_target_digest=first["runtime_target_digest"],
    )["stable"] is True

    legacy = []
    for snapshot in (first, second):
        value = copy.deepcopy(snapshot)
        value["record_type"] = (
            "scanalyze.platform_authority.gug376_authority_inventory_private.v1"
        )
        value["snapshot_digest"] = canonical_digest(
            {key: item for key, item in value.items() if key != "snapshot_digest"}
        )
        legacy.append(value)
    with pytest.raises(CollectorError, match="SESSIONS_NOT_INDEPENDENT"):
        certify(
            *legacy,
            expected_runtime_target_digest=first["runtime_target_digest"],
        )
@pytest.mark.parametrize("fault,expected", [("denied", "NOT_AUTHORIZED"), ("timeout", "UNCERTAIN_RECONCILE_ONLY"), ("repeat", "UNCERTAIN_RECONCILE_ONLY"), ("truncation", "UNCERTAIN_RECONCILE_ONLY")])
def test_pagination_and_provider_failures_are_never_absence(fault: str, expected: str) -> None:
    reader = Reader([], fault=fault); result = _collect("s3", reader.s3, "unused")
    assert result["complete"] is False and result["classification"] == expected and result["count"] is None
@pytest.mark.parametrize("field", ["function_arn", "version", "runtime", "architectures", "update_runtime_on", "runtime_version_arn"])
def test_runtime_source_is_exact_or_uncertain(field: str) -> None:
    reader = Reader([], fault="runtime:" + field); result = _collect("lambda_runtime", reader.lambda_runtime, _plan()["targets"]["runtime_source_function_version_arn"])
    assert result["classification"] == "UNCERTAIN_RECONCILE_ONLY"
def _pair(tmp_path: Path, *, present=False, fault=None):
    plan, root = _plan(), _root(tmp_path); a, b = Factory(plan, present=present, fault=fault), Factory(plan, session=D2, observed=START + timedelta(minutes=8), present=present, fault=fault)
    capture(plan, a, private_root=root, artifact_name="a.json", now=START + timedelta(minutes=6)); capture(plan, b, private_root=root, artifact_name="b.json", now=START + timedelta(minutes=9))
    return read_private_json(root, "a.json"), read_private_json(root, "b.json")
def _certify(first, second, **kwargs): return certify(first, second, expected_runtime_target_digest=first["runtime_target_digest"], **kwargs)
class Verifier:
    def verify(self, first, second):
        value = {"record_type": "scanalyze.platform_authority.gug376_external_inventory_certification.v1", "verifier_identity_digest": D1, "trust_anchor_digest": second["identity"]["authority_verification_digest"], "policy_digest": second["policy_digest"], "facts_digest": second["facts_digest"], "runtime_target_digest": second["runtime_target_digest"], "first_snapshot_digest": first["snapshot_digest"], "second_snapshot_digest": second["snapshot_digest"], "first_session_digest": first["identity"]["session_id_digest"], "second_session_digest": second["identity"]["session_id_digest"], "authority_verification_digest": second["identity"]["authority_verification_digest"]}
        value["certification_digest"] = canonical_digest(value); return value
def test_certification_covers_all_closed_classifications(tmp_path: Path) -> None:
    first, second = _pair(tmp_path / "absent"); assert _certify(first, second)["classification"] == "ABSENT_READY"
    present, same = _pair(tmp_path / "present", present=True); assert _certify(present, same)["classification"] == "PREEXISTING_NO_TOUCH"
    exact = _certify(present, same, expected_facts_digest=same["facts_digest"], external_verifier=Verifier()); assert exact["classification"] == "EXACT_PRESENT_NO_TOUCH" and exact["external_trust_anchor_digest"] == D2 and exact["external_certification_digest"] is not None
    assert _certify(present, same, expected_facts_digest=D1)["classification"] == "DRIFT_BLOCKED_NO_REPAIR"
    drift = copy.deepcopy(same); drift["surfaces"]["s3"]["items"] = [{"private_name": "changed"}]; drift["surfaces"]["s3"]["evidence_digest"] = canonical_digest(drift["surfaces"]["s3"]["items"])
    facts = {name: item["items"] for name, item in drift["surfaces"].items()}; drift["facts_digest"] = canonical_digest(facts); drift["snapshot_digest"] = canonical_digest({k: v for k, v in drift.items() if k != "snapshot_digest"})
    assert _certify(present, drift)["classification"] == "UNCERTAIN_RECONCILE_ONLY"
    denied = _pair(tmp_path / "denied", fault="denied"); assert _certify(*denied)["classification"] == "NOT_AUTHORIZED"
    with pytest.raises(CollectorError, match="SESSIONS_NOT_INDEPENDENT"): _certify(first, first)
    for mutation in ("foreign", "classification", "time", "runtime", "runtime_target"):
        bad = copy.deepcopy(same)
        if mutation == "foreign": bad["identity"]["account_id"] = "000000000000"; bad["identity"]["principal_arn"] = "arn:aws:sts::000000000000:assumed-role/ScanalyzeInventory/operator"
        elif mutation == "classification": bad["classification"] = "NOT_AUTHORIZED"
        elif mutation == "time": bad["identity"]["started_at"] = "2026-08-23T21:00:00Z"
        elif mutation == "runtime": bad["surfaces"]["lambda_runtime"]["items"][0].update(version="999", runtime="nodejs22.x", update_runtime_on="Auto"); bad["surfaces"]["lambda_runtime"]["evidence_digest"] = canonical_digest(bad["surfaces"]["lambda_runtime"]["items"]); bad["facts_digest"] = canonical_digest({name: item["items"] for name, item in bad["surfaces"].items()})
        else: other = f"arn:aws:lambda:us-east-1:{ACCOUNT}:function:other-source:99"; bad["surfaces"]["lambda_runtime"]["items"][0].update(function_arn=other, version="99"); bad["surfaces"]["lambda_runtime"]["evidence_digest"] = canonical_digest(bad["surfaces"]["lambda_runtime"]["items"]); bad["facts_digest"] = canonical_digest({name: item["items"] for name, item in bad["surfaces"].items()}); bad["runtime_target_digest"] = canonical_digest({"policy_digest": bad["policy_digest"], "runtime_source_function_version_arn": other})
        bad["snapshot_digest"] = canonical_digest({k: v for k, v in bad.items() if k != "snapshot_digest"})
        with pytest.raises(CollectorError): _certify(present, bad)
def test_custody_rejects_modes_links_sync_roots_and_cli_is_inert(tmp_path: Path) -> None:
    bad = _root(tmp_path, "bad"); bad.chmod(0o755)
    with pytest.raises(CollectorError): write_private_json(bad, "x.json", {"x": 1})
    cloud = _root(tmp_path, "CloudStorage");
    with pytest.raises(CollectorError, match="PRIVATE_ROOT_LOCATION_INVALID"): write_private_json(cloud, "x.json", {"x": 1})
    root = _root(tmp_path, "hardlinks"); write_private_json(root, "x.json", {"x": 1}); os.link(root / "x.json", root / "alias.json")
    with pytest.raises(CollectorError, match="PRIVATE_INPUT_CUSTODY_INVALID"): read_private_json(root, "x.json")
    script = Path(__file__).parents[2] / "scripts/deployment/platform-authority-gug376-authority-inventory.py"
    result = subprocess.run([sys.executable, "-I", "-S", script, "capture"], text=True, capture_output=True, check=False)
    assert result.returncode == 2 and "STOP_LIVE_ORCHESTRATOR_NOT_IMPLEMENTED" in result.stderr and "boto3" not in Path(__file__).parents[2].joinpath("tooling/platform_authority_gug376_authority_inventory_collector.py").read_text()
    cli_first, _ = _pair(tmp_path / "cli"); success = subprocess.run([sys.executable, "-I", "-S", script, "certify", "--private-root", str(tmp_path / "cli/private"), "--first", "a.json", "--second", "b.json", "--expected-runtime-target-digest", cli_first["runtime_target_digest"]], text=True, capture_output=True, check=False)
    assert success.returncode == 0 and ACCOUNT not in success.stdout and "arn:aws:" not in success.stdout and "Traceback" not in success.stderr
