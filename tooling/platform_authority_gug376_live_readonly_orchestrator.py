"""Guarded, provider-injected GUG-376 dual-domain read-only executor."""
from __future__ import annotations

from datetime import UTC, datetime, timedelta
from hashlib import sha256
import json, os, re
from pathlib import Path
from typing import Any, Mapping, Protocol

from tooling.platform_authority_gug365_upstream_inventory import canonical_digest, canonical_json
from tooling.platform_authority_gug376_authority_inventory_collector import (
    CollectorError, capture as capture_authority, certify as certify_authority,
    private_target_absent, read_private_json, render_policy as render_authority_policy,
)
from tooling.platform_authority_gug376_identity_center_inventory_collector import (
    LIVE_DISCOVERY_SUPPLEMENT_SHA256,
    capture as capture_identity_center, certify as certify_identity_center,
    plan_binding as identity_center_plan_binding, render_policy as render_identity_center_policy,
    render_live_policy as render_live_identity_center_policy,
)
from tooling.platform_authority_gug383_dual_domain_inventory_handoff import (
    HandoffError, validate_authority_receipt, validate_identity_center_receipt,
)

REGION = "us-east-1"
OPT_IN = "EXECUTE_GUG376_LIVE_READ_ONLY"
ARTIFACT_NAMES = (
    "gug376-authority-snapshot-1.json", "gug376-authority-snapshot-2.json",
    "gug376-identity-center-snapshot-1.json", "gug376-identity-center-snapshot-2.json",
)
EVIDENCE_MANIFEST_NAME = "gug376-live-evidence-manifest.json"
REPO_ROOT = Path(__file__).resolve().parents[1]
_POLICIES = {
    "authority": REPO_ROOT / "policies/iam/platform-authority-gug376-authority-inventory-read-only.json",
    "identity_center": REPO_ROOT / "policies/iam/platform-authority-gug376-identity-center-inventory-read-only.json",
}
_LIVE_DISCOVERY_SUPPLEMENT = REPO_ROOT / "policies/iam/platform-authority-gug392-identity-center-discovery-read-only.json"
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_SHA = re.compile(r"^[0-9a-f]{40}$")
_TOKEN = re.compile(r"^[A-Z][A-Z0-9_]{2,95}$")
_PROFILE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_MODES = {"SYNTHETIC"}
_LEDGER_MODES = {"SYNTHETIC", "ATTESTED_LIVE"}
_PARTIAL = {"NOT_AUTHORIZED", "UNCERTAIN_RECONCILE_ONLY"}
_AMBIENT = {"BOTO_CONFIG", "REQUESTS_CA_BUNDLE", "SSL_CERT_FILE", "SSL_CERT_DIR"}


class OrchestratorError(RuntimeError):
    """One public-safe, fail-closed executor error."""

    def __init__(self, code: str) -> None:
        self.code = code if _TOKEN.fullmatch(code) else "LIVE_READ_ONLY_EXECUTOR_BLOCKED"
        super().__init__(self.code)


def _fail(code: str) -> None:
    raise OrchestratorError(code)


def _closed_policy() -> dict[str, Any]:
    sources: dict[str, str] = {}; operations: dict[str, list[str]] = {}
    try:
        for domain, path in _POLICIES.items():
            raw = path.read_bytes(); document = json.loads(raw)
            actions: set[str] = set()
            for statement in document["Statement"]:
                if statement.get("Effect") != "Allow" or "Action" not in statement: continue
                supplied = statement["Action"] if isinstance(statement["Action"], list) else [statement["Action"]]
                actions.update(item for item in supplied if isinstance(item, str) and (item == "sts:GetCallerIdentity" or item.split(":", 1)[-1].startswith(("List", "Get", "Describe"))))
            if not actions or any("*" in item for item in actions): _fail("CLOSED_POLICY_INVALID")
            sources[domain] = "sha256:" + sha256(raw).hexdigest(); operations[domain] = sorted(actions)
    except OrchestratorError: raise
    except (OSError, KeyError, TypeError, json.JSONDecodeError) as exc:
        raise OrchestratorError("CLOSED_POLICY_INVALID") from exc
    return {"record_type": "scanalyze.platform_authority.gug376_live_readonly_policy.v1", "region": REGION, "max_pages": 50, "sources": sources, "operations": operations}


def live_closed_policy() -> dict[str, Any]:
    """Load the GUG-392 extension only for an explicitly live v2 caller."""

    result = _closed_policy()
    try:
        raw = _LIVE_DISCOVERY_SUPPLEMENT.read_bytes(); document = json.loads(raw)
        actions = {
            action
            for statement in document["Statement"]
            if statement.get("Effect") == "Allow"
            for action in (
                statement["Action"]
                if isinstance(statement.get("Action"), list)
                else [statement.get("Action")]
            )
            if isinstance(action, str)
        }
    except (OSError, KeyError, TypeError, json.JSONDecodeError) as exc:
        raise OrchestratorError("CLOSED_POLICY_INVALID") from exc
    if (
        sha256(raw).hexdigest() != LIVE_DISCOVERY_SUPPLEMENT_SHA256
        or actions != {"kms:Decrypt", "sso:DescribePermissionSet"}
    ):
        _fail("CLOSED_POLICY_INVALID")
    result["record_type"] = "scanalyze.platform_authority.gug376_live_readonly_policy.v2"
    result["sources"]["identity_center_discovery_supplement"] = "sha256:" + sha256(raw).hexdigest()
    result["dependencies"] = {"identity_center": ["kms:Decrypt"]}
    result["operations"]["identity_center"] = sorted(
        set(result["operations"]["identity_center"])
        | (actions - {"kms:Decrypt"})
    )
    return result


def live_policy_digest() -> str:
    """Return the attested v2 policy digest without coupling legacy imports."""

    return canonical_digest(live_closed_policy())


_CLOSED_POLICY = _closed_policy()
POLICY_DIGEST = canonical_digest(_CLOSED_POLICY)
ALLOWED_OPERATIONS = {key: frozenset(value) for key, value in _CLOSED_POLICY["operations"].items()}


class ProviderFactory(Protocol):
    mode: str
    def build_authority(self, *, profile: str, ledger: "CallLedger", capture_index: int, retries: int) -> Any: ...
    def build_identity(self, *, profile: str, ledger: "CallLedger", capture_index: int, retries: int) -> Any: ...


class CallLedger:
    """Closed operation ledger used by injected adapters around every provider call."""

    def __init__(self, mode: str) -> None:
        if mode == "LIVE": _fail("LIVE_PROVIDER_NOT_IMPLEMENTED")
        if mode not in _LEDGER_MODES: _fail("PROVIDER_MODE_INVALID")
        self.mode, self._ordinal = mode, 0
        self._pending: dict[str, dict[str, Any]] = {}; self._events: list[dict[str, Any]] = []
        self._sessions: dict[str, str] = {}; self._sts_complete: set[str] = set()
        self._streams: dict[str, dict[str, Any]] = {}; self._failure: str | None = None
        self._last_completed_at: datetime | None = None

    def _reject(self, code: str) -> None:
        self._failure = code; _fail(code)

    @property
    def provider_calls(self) -> int: return self._ordinal

    def session_digests(self, domain: str) -> list[str]:
        return [item for item, owner in self._sessions.items() if owner == domain]

    def authorize(self, *, domain: str, session_digest: str, operation: str, retries: int,
                  request: Any = None, page_token: Any = None, pagination_key: str | None = None,
                  started_at: str | None = None) -> str:
        if domain not in ALLOWED_OPERATIONS or _DIGEST.fullmatch(str(session_digest)) is None: self._reject("PROVIDER_SESSION_INVALID")
        if operation not in ALLOWED_OPERATIONS[domain]: self._reject("PROVIDER_OPERATION_NOT_ALLOWED")
        if type(retries) is not int or retries != 0: self._reject("PROVIDER_RETRIES_FORBIDDEN")
        owner = self._sessions.get(session_digest)
        if operation == "sts:GetCallerIdentity":
            if owner is not None: self._reject("STS_FIRST_REQUIRED")
            if page_token is not None or pagination_key is not None: self._reject("PROVIDER_PAGE_INVALID")
            self._sessions[session_digest] = domain
        elif owner != domain or session_digest not in self._sts_complete:
            self._reject("STS_FIRST_REQUIRED")
        request_digest = request if _DIGEST.fullmatch(str(request)) else canonical_digest({} if request is None else request)
        verb, stream_key, token_digest = operation.split(":", 1)[-1], None, None
        if page_token is not None: token_digest = canonical_digest(page_token)
        if verb.startswith("List"):
            if pagination_key is not None and _DIGEST.fullmatch(pagination_key) is None: self._reject("PROVIDER_PAGE_KEY_INVALID")
            if pagination_key is None and page_token is not None:
                matches = [key for key, stream in self._streams.items() if stream["domain"] == domain and stream["session"] == session_digest and stream["operation"] == operation and stream["expected"] == token_digest]
                if len(matches) != 1: self._reject("PROVIDER_PAGE_SEQUENCE_INVALID")
                stream_key = matches[0]
            else:
                stream_key = pagination_key or canonical_digest({"session": session_digest, "operation": operation, "ordinal": self._ordinal + 1})
            stream = self._streams.setdefault(stream_key, {"domain": domain, "session": session_digest, "operation": operation, "expected": None, "seen": set(), "pages": 0, "closed": False})
            if stream["closed"] or stream["expected"] != token_digest or stream["pages"] >= 50: self._reject("PROVIDER_PAGE_SEQUENCE_INVALID")
            stream["pages"] += 1
        elif page_token is not None or pagination_key is not None:
            self._reject("PROVIDER_PAGE_INVALID")
        self._ordinal += 1
        ticket = canonical_digest({"ordinal": self._ordinal, "domain": domain, "session": session_digest, "operation": operation, "request": request_digest})
        if self.mode == "ATTESTED_LIVE":
            if not isinstance(started_at, str) or not started_at.endswith("Z"):
                self._reject("PROVIDER_CALL_TIME_INVALID")
            try: parsed_started = datetime.fromisoformat(started_at[:-1] + "+00:00")
            except ValueError: self._reject("PROVIDER_CALL_TIME_INVALID")
            if parsed_started.astimezone(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z") != started_at:
                self._reject("PROVIDER_CALL_TIME_INVALID")
            if self._last_completed_at is not None and parsed_started < self._last_completed_at:
                self._reject("PROVIDER_CALL_TIME_INVALID")
        self._pending[ticket] = {"ordinal": self._ordinal, "domain": domain, "session_digest": session_digest, "operation": operation, "request_digest": request_digest, "page_token_digest": token_digest, "stream": stream_key, **({"started_at": started_at} if self.mode == "ATTESTED_LIVE" else {})}
        return ticket

    def complete(self, ticket: str, response: Any = None, *, complete: bool = True,
                 truncated: bool = False, next_token: Any = None, outcome: str = "SUCCESS",
                 completed_at: str | None = None) -> None:
        call = self._pending.pop(ticket, None)
        if call is None: self._reject("PROVIDER_CALL_TICKET_INVALID")
        if outcome not in {"SUCCESS", "ERROR"} or type(complete) is not bool or type(truncated) is not bool: self._reject("PROVIDER_CALL_RESULT_INVALID")
        next_digest = canonical_digest(next_token) if next_token is not None else None
        if outcome == "SUCCESS" and (truncated != (next_token is not None) or complete != (next_token is None)): self._reject("PROVIDER_PAGE_INCOMPLETE")
        if outcome == "ERROR": self._failure = "RECONCILIATION_READ_ONLY_REQUIRED"
        stream_key = call["stream"]
        if stream_key is not None and outcome == "SUCCESS":
            stream = self._streams[stream_key]
            if next_digest is not None:
                if next_digest in stream["seen"] or next_digest == call["page_token_digest"]: self._reject("PROVIDER_PAGE_TOKEN_REPEATED")
                stream["seen"].add(next_digest); stream["expected"] = next_digest
            else: stream["expected"], stream["closed"] = None, True
        elif call["operation"] == "sts:GetCallerIdentity" and outcome == "SUCCESS" and complete and next_token is None:
            self._sts_complete.add(call["session_digest"])
        response_digest = response if _DIGEST.fullmatch(str(response)) else canonical_digest({} if response is None else response)
        time_fields: dict[str, Any] = {}
        if self.mode == "ATTESTED_LIVE":
            if not isinstance(completed_at, str) or not completed_at.endswith("Z"):
                self._reject("PROVIDER_CALL_TIME_INVALID")
            try:
                started = datetime.fromisoformat(str(call["started_at"])[:-1] + "+00:00")
                completed = datetime.fromisoformat(completed_at[:-1] + "+00:00")
            except (KeyError, ValueError):
                self._reject("PROVIDER_CALL_TIME_INVALID")
            if completed < started or completed.astimezone(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z") != completed_at:
                self._reject("PROVIDER_CALL_TIME_INVALID")
            time_fields["completed_at"] = completed_at
            self._last_completed_at = completed
        persisted_call = {
            key: value for key, value in call.items() if key != "stream"
        }
        if self.mode == "ATTESTED_LIVE":
            persisted_call["pagination_stream_digest"] = stream_key
        self._events.append(
            persisted_call
            | time_fields
            | {
                "response_digest": response_digest,
                "outcome": outcome,
                "complete": complete,
                "truncated": truncated,
                "next_token_digest": next_digest,
            }
        )

    def raise_if_failed(self) -> None:
        if self._failure is not None: _fail(self._failure)

    def finalize(self) -> tuple[int, str]:
        self.raise_if_failed()
        if self._pending or not self._events or any(not item["closed"] for item in self._streams.values()) or set(self._sessions) != self._sts_complete:
            _fail("PROVIDER_TRANSCRIPT_INCOMPLETE")
        return self._ordinal, canonical_digest(self._events)

    def evidence_events(self) -> list[dict[str, Any]]:
        """Return the finalized digest-only transcript for private custody."""

        self.finalize()
        return json.loads(canonical_json(self._events))


_RUN_FIELDS = {"record_type", "status", "classification", "source_commit_sha", "source_tree_sha", "window_digest", "policy_digest", "authorization_digest", "attestation_digest", "trust_anchor_digest", "run_id_digest", "profile_binding_digest", "authority_receipt_digest", "identity_center_receipt_digest", "authority_snapshot_digests", "identity_center_snapshot_digests", "authority_session_digests", "identity_center_session_digests", "transcript_digest", "provider_calls", "aws_calls", "evidence_complete", "evidence_stable", "live_provider_evidence", "read_only", "aws_mutations", "reconciliation_only", "deployment_authorized", "two_human_status", "independent_approval_present", "production_status", "run_digest"}
_HANDOFF_FIELDS = {"record_type", "status", "classification", "source_commit_sha", "source_tree_sha", "run_digest", "window_digest", "policy_digest", "authorization_digest", "attestation_digest", "trust_anchor_digest", "authority_receipt_digest", "identity_center_receipt_digest", "transcript_digest", "provider_calls", "aws_calls", "evidence_complete", "evidence_stable", "live_provider_evidence", "read_only", "aws_mutations", "reconciliation_only", "deployment_authorized", "two_human_status", "independent_approval_present", "production_status", "handoff_digest"}


def _output(value: Mapping[str, Any], *, handoff: bool) -> dict[str, Any]:
    try: item = json.loads(canonical_json(value))
    except Exception as exc: raise OrchestratorError("PUBLIC_HANDOFF_INVALID" if handoff else "RUN_RECORD_INVALID") from exc
    fields, digest_key = (_HANDOFF_FIELDS, "handoff_digest") if handoff else (_RUN_FIELDS, "run_digest")
    code = "PUBLIC_HANDOFF_INVALID" if handoff else "RUN_RECORD_INVALID"
    digests = fields - {"record_type", "status", "classification", "source_commit_sha", "source_tree_sha", "provider_calls", "aws_calls", "evidence_complete", "evidence_stable", "live_provider_evidence", "read_only", "aws_mutations", "reconciliation_only", "deployment_authorized", "two_human_status", "independent_approval_present", "production_status", "authority_snapshot_digests", "identity_center_snapshot_digests", "authority_session_digests", "identity_center_session_digests"}
    record_type = "scanalyze.platform_authority.gug376_live_readonly_handoff.v1" if handoff else "scanalyze.platform_authority.gug376_live_readonly_run.v1"
    fixed = item.get("record_type") == record_type and item.get("read_only") is True and type(item.get("aws_mutations")) is int and item.get("aws_mutations") == 0 and item.get("reconciliation_only") is False and item.get("deployment_authorized") is False and item.get("two_human_status") == "NOT_PROVEN" and item.get("independent_approval_present") is False and item.get("production_status") == "NO-GO" and item.get("evidence_complete") is True and item.get("evidence_stable") is True
    mode_ok = (item.get("status"), item.get("classification"), item.get("live_provider_evidence"), item.get("aws_calls")) == ("LIVE_INVENTORY_NOT_PROVEN", "SYNTHETIC_VALIDATED", False, 0)
    valid = isinstance(item, dict) and set(item) == fields and fixed and mode_ok and item.get("policy_digest") == POLICY_DIGEST and isinstance(item.get("source_commit_sha"), str) and _SHA.fullmatch(item["source_commit_sha"]) and isinstance(item.get("source_tree_sha"), str) and _SHA.fullmatch(item["source_tree_sha"]) and type(item.get("provider_calls")) is int and item["provider_calls"] >= 1 and type(item.get("aws_calls")) is int and item["aws_calls"] >= 0 and all(_DIGEST.fullmatch(str(item.get(key))) for key in digests) and item.get(digest_key) == canonical_digest({key: raw for key, raw in item.items() if key != digest_key})
    if not handoff:
        arrays = [item.get(key) for key in ("authority_snapshot_digests", "identity_center_snapshot_digests", "authority_session_digests", "identity_center_session_digests")]
        valid = valid and all(isinstance(array, list) and all(_DIGEST.fullmatch(str(raw)) for raw in array) and len(array) == len(set(array)) for array in arrays) and all(len(array) == 2 for array in arrays[:3]) and 2 <= len(arrays[3]) <= 4 and not set(arrays[0]) & set(arrays[1]) and not set(arrays[2]) & set(arrays[3])
    if not valid: _fail(code)
    return item


def validate_run_record(value: Mapping[str, Any]) -> dict[str, Any]: return _output(value, handoff=False)
def validate_public_handoff(value: Mapping[str, Any]) -> dict[str, Any]: return _output(value, handoff=True)


def _stamp(value: object) -> tuple[datetime, str]:
    if not isinstance(value, datetime) or value.tzinfo is None: _fail("WINDOW_INVALID")
    parsed = value.astimezone(UTC).replace(microsecond=0)
    return parsed, parsed.isoformat().replace("+00:00", "Z")


def _preflight(config: Mapping[str, Any], *, private_root: Path, now: datetime,
               actual_source_commit_sha: str, actual_source_tree_sha: str,
               attested_live: bool = False) -> dict[str, Any]:
    fields = {"opt_in", "source_commit_sha", "source_tree_sha", "run_id", "profiles", "authority_plan", "identity_center_plan", "authorization", "authorization_digest", "attestation", "attestation_digest", "trust_anchor", "trust_anchor_digest"}
    supplied_fields = set(config) if isinstance(config, Mapping) else set()
    accepted_fields = {
        frozenset(fields | {"sdk_runtime_root"})
        if attested_live
        else frozenset(fields)
    }
    if not isinstance(config, Mapping) or frozenset(supplied_fields) not in accepted_fields or config.get("opt_in") != OPT_IN: _fail("EXPLICIT_OPT_IN_REQUIRED")
    if any(key.startswith("AWS_") or key in _AMBIENT for key in os.environ): _fail("AMBIENT_AWS_OVERRIDE_FORBIDDEN")
    live_policy = live_closed_policy() if attested_live else None
    expected_policy_digest = (
        canonical_digest(live_policy) if live_policy is not None else POLICY_DIGEST
    )
    if (
        _closed_policy() != _CLOSED_POLICY
        or not all(
            isinstance(value, str) and _SHA.fullmatch(value)
            for value in (actual_source_commit_sha, actual_source_tree_sha)
        )
        or config["source_commit_sha"] != actual_source_commit_sha
        or config["source_tree_sha"] != actual_source_tree_sha
    ):
        _fail("SOURCE_BINDING_INVALID")
    profiles = config["profiles"]
    if not isinstance(profiles, Mapping) or set(profiles) != {"authority", "identity_center"}: _fail("PROFILE_BINDING_INVALID")
    for profile in profiles.values():
        if not isinstance(profile, Mapping) or set(profile) != {"name", "source", "chain_depth"} or not isinstance(profile["name"], str) or _PROFILE.fullmatch(profile["name"]) is None or profile["name"].casefold() == "default" or profile["source"] != "DIRECT_SSO" or type(profile["chain_depth"]) is not int or profile["chain_depth"] != 0: _fail("PROFILE_BINDING_INVALID")
    if profiles["authority"]["name"].casefold() == profiles["identity_center"]["name"].casefold(): _fail("PROFILE_BINDING_INVALID")
    authority_plan, identity_plan = config["authority_plan"], config["identity_center_plan"]
    try:
        _, authority_policy_digest = render_authority_policy(authority_plan)
        _, identity_binding_digest = identity_center_plan_binding(identity_plan)
        (render_live_identity_center_policy if attested_live else render_identity_center_policy)(identity_plan)
    except CollectorError as exc: raise OrchestratorError(exc.code) from exc
    starts, ends = [], []
    for plan in (authority_plan, identity_plan):
        start, start_text = _stamp(plan.get("not_before")); end, end_text = _stamp(plan.get("not_after")); starts.append((start, start_text)); ends.append((end, end_text))
    current, _ = _stamp(now)
    if starts[0] != starts[1] or ends[0] != ends[1] or not starts[0][0] <= current < ends[0][0] or not starts[0][0] < ends[0][0] or ends[0][0] - starts[0][0] > timedelta(hours=1): _fail("WINDOW_INVALID")
    window_digest = canonical_digest({"not_before": starts[0][1], "not_after": ends[0][1], "region": REGION})
    profile_digest = canonical_digest(profiles); run_id = config["run_id"]
    if not isinstance(run_id, str) or not 8 <= len(run_id) <= 128: _fail("RUN_ID_INVALID")
    run_id_digest = canonical_digest(run_id)
    runtime_digest = canonical_digest({"policy_digest": authority_policy_digest, "runtime_source_function_version_arn": authority_plan["targets"]["runtime_source_function_version_arn"]})
    authority_binding = {"account_id": authority_plan["expected_account_id"], "principal_arn": authority_plan["expected_principal_arn"], "not_before": starts[0][1], "not_after": ends[0][1], "policy_digest": authority_policy_digest, "authority_verification_digest": authority_plan["authority_verification_digest"], "runtime_target_digest": runtime_digest, "target_digest": canonical_digest(authority_plan["targets"]), "region": REGION}
    authorization = {"record_type": "scanalyze.platform_authority.gug376_live_readonly_authorization.v1", "opt_in": OPT_IN, "source_commit_sha": actual_source_commit_sha, "source_tree_sha": actual_source_tree_sha, "window_digest": window_digest, "policy_digest": expected_policy_digest, "profile_binding_digest": profile_digest, "authority_plan_digest": canonical_digest(authority_binding), "identity_center_plan_digest": identity_binding_digest, "run_id_digest": run_id_digest, "read_only": True, "aws_mutations": 0, "deployment_authorized": False}
    if config["authorization"] != authorization or config["authorization_digest"] != canonical_digest(authorization): _fail("AUTHORIZATION_BINDING_INVALID")
    attestation = {"record_type": "scanalyze.platform_authority.gug376_live_readonly_attestation.v1", "authorization_digest": config["authorization_digest"], "source_commit_sha": actual_source_commit_sha, "source_tree_sha": actual_source_tree_sha, "window_digest": window_digest, "policy_digest": expected_policy_digest, "profile_binding_digest": profile_digest, "authority_account_digest": canonical_digest(authority_plan["expected_account_id"]), "authority_principal_digest": canonical_digest(authority_plan["expected_principal_arn"]), "identity_center_account_digest": canonical_digest(identity_plan["expected_account_id"]), "identity_center_principal_digest": canonical_digest(identity_plan["expected_principal_arn"]), "read_only": True, "aws_mutations": 0}
    if config["attestation"] != attestation or config["attestation_digest"] != canonical_digest(attestation): _fail("ATTESTATION_BINDING_INVALID")
    trust = {"record_type": "scanalyze.platform_authority.gug376_live_readonly_trust_anchor.v1", "authorization_digest": config["authorization_digest"], "attestation_digest": config["attestation_digest"], "policy_digest": expected_policy_digest, "authority_verification_digest": authority_plan["authority_verification_digest"], "identity_center_authority_verification_digest": identity_plan["authority_verification_digest"], "read_only": True}
    if config["trust_anchor"] != trust or config["trust_anchor_digest"] != canonical_digest(trust): _fail("TRUST_ANCHOR_BINDING_INVALID")
    try:
        for name in ARTIFACT_NAMES: private_target_absent(private_root, name)
    except CollectorError as exc:
        raise OrchestratorError(exc.code) from exc
    return {"profiles": profiles, "window_digest": window_digest, "profile_binding_digest": profile_digest, "run_id_digest": run_id_digest, "authority_runtime_digest": runtime_digest, "identity_binding_digest": identity_binding_digest}


def execute(config: Mapping[str, Any], provider_factory: ProviderFactory, *, private_root: Path,
            now: datetime, actual_source_commit_sha: str, actual_source_tree_sha: str) -> tuple[dict[str, Any], dict[str, Any]]:
    """Evaluate two offline synthetic snapshots; ``now`` is never a live clock."""
    mode = getattr(provider_factory, "mode", None)
    if mode == "LIVE": _fail("LIVE_PROVIDER_NOT_IMPLEMENTED")
    if mode not in _MODES: _fail("PROVIDER_MODE_INVALID")
    local = _preflight(config, private_root=private_root, now=now, actual_source_commit_sha=actual_source_commit_sha, actual_source_tree_sha=actual_source_tree_sha)
    ledger = CallLedger(mode)
    try:
        authority_private = []
        for index, name in enumerate(ARTIFACT_NAMES[:2], 1):
            factory = provider_factory.build_authority(profile=local["profiles"]["authority"]["name"], ledger=ledger, capture_index=index, retries=0)
            capture_authority(config["authority_plan"], factory, private_root=private_root, artifact_name=name, now=now)
            ledger.raise_if_failed(); snapshot = read_private_json(private_root, name)
            if any(surface.get("complete") is not True for surface in snapshot.get("surfaces", {}).values()): _fail("RECONCILIATION_READ_ONLY_REQUIRED")
            authority_private.append(snapshot)
        authority_receipt = certify_authority(*authority_private, expected_runtime_target_digest=local["authority_runtime_digest"])
        identity_private = []
        for index, name in enumerate(ARTIFACT_NAMES[2:], 1):
            factory = provider_factory.build_identity(profile=local["profiles"]["identity_center"]["name"], ledger=ledger, capture_index=index, retries=0)
            capture_identity_center(config["identity_center_plan"], factory, private_root=private_root, artifact_name=name, now=now)
            ledger.raise_if_failed(); snapshot = read_private_json(private_root, name)
            if snapshot.get("classification") in _PARTIAL: _fail("RECONCILIATION_READ_ONLY_REQUIRED")
            identity_private.append(snapshot)
        identity_receipt = certify_identity_center(*identity_private, expected_plan_binding_digest=local["identity_binding_digest"])
        authority_receipt = validate_authority_receipt(authority_receipt); identity_receipt = validate_identity_center_receipt(identity_receipt)
    except OrchestratorError: raise
    except (CollectorError, HandoffError) as exc: raise OrchestratorError(getattr(exc, "code", "PROVIDER_EXECUTION_FAILED")) from exc
    except Exception as exc: raise OrchestratorError("PROVIDER_EXECUTION_FAILED") from exc
    if authority_receipt["stable"] is not True or identity_receipt["stable"] is not True or authority_receipt["classification"] in _PARTIAL or identity_receipt["classification"] in _PARTIAL: _fail("RECONCILIATION_READ_ONLY_REQUIRED")
    authority_sessions = [item["identity"]["session_id_digest"] for item in authority_private]
    identity_sessions = [session for item in identity_private for session in item["session_digests"]]
    if authority_sessions != ledger.session_digests("authority") or identity_sessions != ledger.session_digests("identity_center") or set(authority_sessions) & set(identity_sessions) or set(authority_receipt["snapshot_digests"]) & set(identity_receipt["snapshot_digests"]): _fail("CROSS_DOMAIN_EVIDENCE_SUBSTITUTION")
    calls, transcript = ledger.finalize()
    record = {"record_type": "scanalyze.platform_authority.gug376_live_readonly_run.v1", "status": "LIVE_INVENTORY_NOT_PROVEN", "classification": "SYNTHETIC_VALIDATED", "source_commit_sha": actual_source_commit_sha, "source_tree_sha": actual_source_tree_sha, "window_digest": local["window_digest"], "policy_digest": POLICY_DIGEST, "authorization_digest": config["authorization_digest"], "attestation_digest": config["attestation_digest"], "trust_anchor_digest": config["trust_anchor_digest"], "run_id_digest": local["run_id_digest"], "profile_binding_digest": local["profile_binding_digest"], "authority_receipt_digest": authority_receipt["receipt_digest"], "identity_center_receipt_digest": identity_receipt["receipt_digest"], "authority_snapshot_digests": authority_receipt["snapshot_digests"], "identity_center_snapshot_digests": identity_receipt["snapshot_digests"], "authority_session_digests": authority_sessions, "identity_center_session_digests": identity_sessions, "transcript_digest": transcript, "provider_calls": calls, "aws_calls": 0, "evidence_complete": True, "evidence_stable": True, "live_provider_evidence": False, "read_only": True, "aws_mutations": 0, "reconciliation_only": False, "deployment_authorized": False, "two_human_status": "NOT_PROVEN", "independent_approval_present": False, "production_status": "NO-GO"}
    record["run_digest"] = canonical_digest(record); record = validate_run_record(record)
    projected = {key: record[key] for key in _HANDOFF_FIELDS - {"record_type", "handoff_digest"}}
    handoff = {"record_type": "scanalyze.platform_authority.gug376_live_readonly_handoff.v1", **projected}
    handoff["handoff_digest"] = canonical_digest(handoff)
    return record, validate_public_handoff(handoff)
