"""Attested GUG-392 executor for GUG-376 dual-domain read-only inventory.

The legacy GUG-387 synthetic executor and its v1 public contracts remain
unchanged.  This module is the only path that may project a concrete provider
transcript to the schema-closed v2 public records.
"""
from __future__ import annotations

from datetime import UTC, datetime
import json
from pathlib import Path
import re
from typing import Any, Mapping, Protocol

from tooling.platform_authority_gug365_upstream_inventory import (
    canonical_digest,
    canonical_json,
)
from tooling.platform_authority_gug376_authority_inventory_collector import (
    CollectorError,
    capture_live as capture_authority,
    certify_live as certify_authority,
    private_target_absent,
    read_private_json,
    validate_live_generated_identity_center_roles,
    write_private_json,
)
from tooling.platform_authority_gug376_identity_center_inventory_collector import (
    capture_live as capture_identity_center,
    certify_live as certify_identity_center,
)
from tooling.platform_authority_gug376_live_readonly_orchestrator import (
    ALLOWED_OPERATIONS,
    ARTIFACT_NAMES,
    CallLedger,
    EVIDENCE_MANIFEST_NAME,
    OrchestratorError,
    _HANDOFF_FIELDS,
    _PARTIAL,
    _RUN_FIELDS,
    _DIGEST,
    _SHA,
    _preflight,
    live_closed_policy,
    live_policy_digest,
)
from tooling.platform_authority_gug376_live_provider import (
    is_attested_live_provider,
)
from tooling.platform_authority_gug376_live_request_materializer import (
    CHECKPOINT_RECORD_TYPE,
    CONSUMPTION_CLAIM,
    REQUEST_RECORD_TYPE,
    LiveRequestMaterializationError,
    assert_live_request_execution_capability,
    execution_capability_validity_gate,
    private_root_binding_digest,
    render_permission_set_inline_policies,
    validate_materialized_live_request,
)
from tooling.platform_authority_gug383_dual_domain_inventory_handoff import (
    HandoffError,
    validate_authority_receipt,
    validate_identity_center_receipt,
)

_AUTHORITY_CLASSES = {
    "ABSENT_READY",
    "PREEXISTING_NO_TOUCH",
}
_IDENTITY_CLASSES = {
    "ABSENT_READY",
    "EXACT_PRESENT_NO_TOUCH",
    "DRIFT_BLOCKED_NO_REPAIR",
}
_V2_EXTRA_FIELDS = {
    "request_digest",
    "checkpoint_digest",
    "approval_reference_digest",
    "authority_classification",
    "identity_center_classification",
    "evidence_manifest_digest",
    "sealed_at",
}
_LIVE_RUN_FIELDS = _RUN_FIELDS | _V2_EXTRA_FIELDS
_LIVE_HANDOFF_FIELDS = _HANDOFF_FIELDS | _V2_EXTRA_FIELDS
LIVE_POLICY_DIGEST = live_policy_digest()
_STAMP = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$"
)
_PRIVATE_FILE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,126}\.json$")


class LiveExecutorError(OrchestratorError):
    """Public-safe fail-closed error for the attested live path."""


def _fail(code: str) -> None:
    raise LiveExecutorError(code)


class ConcreteProviderFactory(Protocol):
    """Narrow surface supplied by the concrete GUG-392 provider module."""

    mode: str
    concrete_provider: bool

    def build_authority(
        self,
        *,
        profile: str,
        ledger: CallLedger,
        capture_index: int,
        retries: int,
    ) -> Any: ...

    def build_identity(
        self,
        *,
        profile: str,
        ledger: CallLedger,
        capture_index: int,
        retries: int,
    ) -> Any: ...

    def transcript_summary(self) -> Mapping[str, Any]: ...

    def evaluation_time(self) -> datetime: ...


def _normalized(value: Mapping[str, Any], code: str) -> dict[str, Any]:
    try:
        result = json.loads(canonical_json(value))
    except Exception as exc:
        raise LiveExecutorError(code) from exc
    if not isinstance(result, dict):
        _fail(code)
    return result


def _validate_v2_output(value: Mapping[str, Any], *, handoff: bool) -> dict[str, Any]:
    code = "PUBLIC_HANDOFF_V2_INVALID" if handoff else "RUN_RECORD_V2_INVALID"
    item = _normalized(value, code)
    fields = _LIVE_HANDOFF_FIELDS if handoff else _LIVE_RUN_FIELDS
    digest_key = "handoff_digest" if handoff else "run_digest"
    record_type = (
        "scanalyze.platform_authority.gug376_live_readonly_handoff.v2"
        if handoff
        else "scanalyze.platform_authority.gug376_live_readonly_run.v2"
    )
    non_digest_fields = {
        "record_type",
        "status",
        "classification",
        "source_commit_sha",
        "source_tree_sha",
        "provider_calls",
        "aws_calls",
        "evidence_complete",
        "evidence_stable",
        "live_provider_evidence",
        "read_only",
        "aws_mutations",
        "reconciliation_only",
        "deployment_authorized",
        "two_human_status",
        "independent_approval_present",
        "production_status",
        "authority_classification",
        "identity_center_classification",
        "sealed_at",
        "authority_snapshot_digests",
        "identity_center_snapshot_digests",
        "authority_session_digests",
        "identity_center_session_digests",
    }
    digests = fields - non_digest_fields
    fixed = (
        item.get("record_type") == record_type
        and item.get("status") == "LIVE_READ_ONLY_CAPTURED"
        and item.get("classification") == "LIVE_DUAL_DOMAIN_CAPTURED"
        and item.get("authority_classification") in _AUTHORITY_CLASSES
        and item.get("identity_center_classification") in _IDENTITY_CLASSES
        and not (
            item.get("identity_center_classification")
            == "EXACT_PRESENT_NO_TOUCH"
            and item.get("authority_classification")
            != "PREEXISTING_NO_TOUCH"
        )
        and item.get("evidence_complete") is True
        and item.get("evidence_stable") is True
        and item.get("live_provider_evidence") is True
        and item.get("read_only") is True
        and type(item.get("aws_mutations")) is int
        and item.get("aws_mutations") == 0
        and item.get("reconciliation_only") is False
        and item.get("deployment_authorized") is False
        and item.get("two_human_status") == "NOT_PROVEN"
        and item.get("independent_approval_present") is False
        and item.get("production_status") == "NO-GO"
        and item.get("policy_digest") == LIVE_POLICY_DIGEST
        and _parse_stamp(item.get("sealed_at"), code) is not None
    )
    counts = (
        type(item.get("provider_calls")) is int
        and type(item.get("aws_calls")) is int
        and item["provider_calls"] == item["aws_calls"]
        and item["aws_calls"] >= 1
    )
    valid = (
        set(item) == fields
        and fixed
        and counts
        and isinstance(item.get("source_commit_sha"), str)
        and _SHA.fullmatch(item["source_commit_sha"]) is not None
        and isinstance(item.get("source_tree_sha"), str)
        and _SHA.fullmatch(item["source_tree_sha"]) is not None
        and all(_DIGEST.fullmatch(str(item.get(key))) for key in digests)
        and item.get(digest_key)
        == canonical_digest({key: raw for key, raw in item.items() if key != digest_key})
    )
    if not handoff:
        arrays = [
            item.get(key)
            for key in (
                "authority_snapshot_digests",
                "identity_center_snapshot_digests",
                "authority_session_digests",
                "identity_center_session_digests",
            )
        ]
        identity_session_count = (
            len(arrays[3]) if isinstance(arrays[3], list) else -1
        )
        identity_classification = item.get("identity_center_classification")
        identity_sessions_match_classification = (
            (
                identity_classification == "ABSENT_READY"
                and identity_session_count == 2
            )
            or (
                identity_classification == "EXACT_PRESENT_NO_TOUCH"
                and identity_session_count == 4
            )
            or (
                identity_classification == "DRIFT_BLOCKED_NO_REPAIR"
                and identity_session_count in {2, 4}
            )
        )
        valid = (
            valid
            and all(
                isinstance(array, list)
                and all(_DIGEST.fullmatch(str(raw)) for raw in array)
                and len(array) == len(set(array))
                for array in arrays
            )
            and all(len(array) == 2 for array in arrays[:3])
            and len(arrays[3]) in {2, 4}
            and identity_sessions_match_classification
            and item["provider_calls"] >= len(arrays[2]) + len(arrays[3])
            and not set(arrays[0]) & set(arrays[1])
            and not set(arrays[2]) & set(arrays[3])
        )
    if not valid:
        _fail(code)
    return item


def validate_live_run_record(value: Mapping[str, Any]) -> dict[str, Any]:
    return _validate_v2_output(value, handoff=False)


def validate_live_public_handoff(value: Mapping[str, Any]) -> dict[str, Any]:
    """Validate handoff shape only; use validate_live_bundle for causal proof."""

    return _validate_v2_output(value, handoff=True)


def validate_live_bundle(
    run_record: Mapping[str, Any], public_handoff: Mapping[str, Any]
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Validate the exact run-to-handoff projection as one public bundle."""

    run = validate_live_run_record(run_record)
    handoff = validate_live_public_handoff(public_handoff)
    expected = {
        "record_type": "scanalyze.platform_authority.gug376_live_readonly_handoff.v2",
        **{
            key: run[key]
            for key in _LIVE_HANDOFF_FIELDS - {"record_type", "handoff_digest"}
        },
    }
    expected["handoff_digest"] = canonical_digest(expected)
    if handoff != expected:
        _fail("LIVE_BUNDLE_V2_INVALID")
    return run, handoff


_PRIVATE_EVENT_FIELDS = {
    "ordinal",
    "domain",
    "session_digest",
    "operation",
    "request_digest",
    "pagination_stream_digest",
    "page_token_digest",
    "started_at",
    "response_digest",
    "outcome",
    "complete",
    "truncated",
    "next_token_digest",
    "completed_at",
}
_PRIVATE_RECEIPT_FIELDS = {
    "record_type",
    "domain",
    "status",
    "classification",
    "collector_receipt_digest",
    "snapshot_digests",
    "session_digests",
    "transcript_digest",
    "provider_calls",
    "aws_calls",
    "evidence_complete",
    "evidence_stable",
    "live_provider_evidence",
    "read_only",
    "aws_mutations",
    "receipt_digest",
}
_PRIVATE_EVIDENCE_FIELDS = {
    "record_type",
    "source_commit_sha",
    "source_tree_sha",
    "not_before",
    "not_after",
    "sealed_at",
    "window_digest",
    "request_file",
    "request_digest",
    "owner_checkpoint_file",
    "checkpoint_digest",
    "consumption_claim_file",
    "consumption_claim_digest",
    "approval_reference_digest",
    "authority_receipt",
    "identity_center_receipt",
    "authority_collector_receipt",
    "identity_center_collector_receipt",
    "transcript_events",
    "transcript_digest",
    "provider_calls",
    "aws_calls",
    "read_only",
    "aws_mutations",
    "repository_persisted",
    "evidence_manifest_digest",
}
_CONSUMPTION_CLAIM_FIELDS = {
    "record_type",
    "implementation_issue",
    "parent_issue",
    "source_commit_sha",
    "source_tree_sha",
    "request_digest",
    "checkpoint_digest",
    "approval_reference_digest",
    "host_digest",
    "private_root_digest",
    "claimed_at",
    "read_only",
    "aws_mutations",
    "deployment_authorized",
    "production_status",
    "claim_digest",
}


def _parse_stamp(value: Any, code: str) -> datetime:
    if not isinstance(value, str) or _STAMP.fullmatch(value) is None:
        _fail(code)
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise LiveExecutorError(code) from exc
    canonical = (
        parsed.astimezone(UTC)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )
    if canonical != value:
        _fail(code)
    return parsed.astimezone(UTC).replace(microsecond=0)


def _validate_private_transcript_causality(
    events: list[dict[str, Any]],
) -> None:
    """Replay STS-first and closed pagination invariants from sealed events."""

    max_pages = live_closed_policy().get("max_pages")
    if type(max_pages) is not int or max_pages < 1:
        _fail("PRIVATE_EVIDENCE_MANIFEST_INVALID")
    session_domains: dict[str, str] = {}
    sts_complete: set[str] = set()
    streams: dict[str, dict[str, Any]] = {}
    for event in events:
        domain = event["domain"]
        session_digest = event["session_digest"]
        operation = event["operation"]
        owner = session_domains.get(session_digest)
        if owner is None:
            if operation != "sts:GetCallerIdentity":
                _fail("PRIVATE_EVIDENCE_MANIFEST_INVALID")
            session_domains[session_digest] = domain
        elif owner != domain:
            _fail("PRIVATE_EVIDENCE_MANIFEST_INVALID")

        if operation == "sts:GetCallerIdentity":
            if (
                owner is not None
                or session_digest in sts_complete
                or event["pagination_stream_digest"] is not None
                or event["page_token_digest"] is not None
                or event["next_token_digest"] is not None
                or event["complete"] is not True
                or event["truncated"] is not False
            ):
                _fail("PRIVATE_EVIDENCE_MANIFEST_INVALID")
            sts_complete.add(session_digest)
            continue
        if session_digest not in sts_complete:
            _fail("PRIVATE_EVIDENCE_MANIFEST_INVALID")

        is_list = operation.split(":", 1)[-1].startswith("List")
        if not is_list:
            if (
                event["pagination_stream_digest"] is not None
                or event["page_token_digest"] is not None
                or event["next_token_digest"] is not None
                or event["complete"] is not True
                or event["truncated"] is not False
            ):
                _fail("PRIVATE_EVIDENCE_MANIFEST_INVALID")
            continue

        stream_digest = event["pagination_stream_digest"]
        if _DIGEST.fullmatch(str(stream_digest)) is None:
            _fail("PRIVATE_EVIDENCE_MANIFEST_INVALID")
        token = event["page_token_digest"]
        stream = streams.get(stream_digest)
        binding = (domain, session_digest, operation)
        if stream is None:
            if token is not None:
                _fail("PRIVATE_EVIDENCE_MANIFEST_INVALID")
            stream = {
                "binding": binding,
                "expected": None,
                "seen": set(),
                "pages": 0,
                "closed": False,
            }
            streams[stream_digest] = stream
        elif (
            stream["binding"] != binding
            or stream["closed"] is not False
            or stream["expected"] != token
        ):
            _fail("PRIVATE_EVIDENCE_MANIFEST_INVALID")
        stream["pages"] += 1
        if stream["pages"] > max_pages:
            _fail("PRIVATE_EVIDENCE_MANIFEST_INVALID")
        if event["truncated"]:
            next_token = event["next_token_digest"]
            if (
                next_token is None
                or next_token == token
                or next_token in stream["seen"]
            ):
                _fail("PRIVATE_EVIDENCE_MANIFEST_INVALID")
            stream["seen"].add(next_token)
            stream["expected"] = next_token
        else:
            stream["expected"] = None
            stream["closed"] = True
    if (
        set(session_domains) != sts_complete
        or any(stream["closed"] is False for stream in streams.values())
    ):
        _fail("PRIVATE_EVIDENCE_MANIFEST_INVALID")


def _live_domain_receipt(
    *,
    domain: str,
    collector_receipt: Mapping[str, Any],
    session_digests: list[str],
    events: list[dict[str, Any]],
) -> dict[str, Any]:
    body: dict[str, Any] = {
        "record_type": (
            "scanalyze.platform_authority.gug392_live_inventory_receipt.v1"
        ),
        "domain": domain,
        "status": "LIVE_READ_ONLY_CAPTURED",
        "classification": collector_receipt["classification"],
        "collector_receipt_digest": collector_receipt["receipt_digest"],
        "snapshot_digests": collector_receipt["snapshot_digests"],
        "session_digests": session_digests,
        "transcript_digest": canonical_digest(events),
        "provider_calls": len(events),
        "aws_calls": len(events),
        "evidence_complete": True,
        "evidence_stable": collector_receipt["stable"],
        "live_provider_evidence": True,
        "read_only": True,
        "aws_mutations": 0,
    }
    return {**body, "receipt_digest": canonical_digest(body)}


def _validate_private_domain_receipt(
    value: Mapping[str, Any],
    *,
    domain: str,
    collector_receipt: Mapping[str, Any],
    events: list[dict[str, Any]],
) -> dict[str, Any]:
    item = _normalized(value, "PRIVATE_EVIDENCE_MANIFEST_INVALID")
    expected_classes = (
        _AUTHORITY_CLASSES if domain == "authority" else _IDENTITY_CLASSES
    )
    session_digests = sorted(
        {event["session_digest"] for event in events}
    )
    if (
        set(item) != _PRIVATE_RECEIPT_FIELDS
        or item.get("record_type")
        != "scanalyze.platform_authority.gug392_live_inventory_receipt.v1"
        or item.get("domain") != domain
        or item.get("status") != "LIVE_READ_ONLY_CAPTURED"
        or item.get("classification") not in expected_classes
        or item.get("classification") != collector_receipt.get("classification")
        or item.get("collector_receipt_digest")
        != collector_receipt.get("receipt_digest")
        or item.get("snapshot_digests")
        != collector_receipt.get("snapshot_digests")
        or sorted(item.get("session_digests", [])) != session_digests
        or item.get("transcript_digest") != canonical_digest(events)
        or type(item.get("provider_calls")) is not int
        or item.get("provider_calls") != len(events)
        or item.get("aws_calls") != len(events)
        or item.get("evidence_complete") is not True
        or item.get("evidence_stable") is not True
        or item.get("live_provider_evidence") is not True
        or item.get("read_only") is not True
        or type(item.get("aws_mutations")) is not int
        or item.get("aws_mutations") != 0
        or item.get("receipt_digest")
        != canonical_digest(
            {key: raw for key, raw in item.items() if key != "receipt_digest"}
        )
    ):
        _fail("PRIVATE_EVIDENCE_MANIFEST_INVALID")
    return item


def _private_file(value: Any, code: str) -> str:
    if not isinstance(value, str) or _PRIVATE_FILE.fullmatch(value) is None:
        _fail(code)
    return value


def _locate_private_request_file(
    private_root: Path, *, request_digest: str
) -> str:
    """Locate the unique owner-only request while building the manifest."""

    try:
        names = sorted(path.name for path in private_root.iterdir())
    except OSError as exc:
        raise LiveExecutorError("PRIVATE_EVIDENCE_REQUEST_INVALID") from exc
    matches: list[str] = []
    reserved = set(ARTIFACT_NAMES) | {
        CONSUMPTION_CLAIM,
        EVIDENCE_MANIFEST_NAME,
    }
    for name in names:
        if name in reserved or _PRIVATE_FILE.fullmatch(name) is None:
            continue
        try:
            value = read_private_json(private_root, name)
        except CollectorError:
            continue
        if (
            value.get("record_type") == REQUEST_RECORD_TYPE
            and value.get("request_digest") == request_digest
        ):
            matches.append(name)
    if len(matches) != 1:
        _fail("PRIVATE_EVIDENCE_REQUEST_INVALID")
    return matches[0]


def _private_request_manifest_references(
    private_root: Path,
    *,
    request_digest: str,
    checkpoint_digest: str,
) -> dict[str, str]:
    """Resolve the three activation artefacts before sealing evidence."""

    request_file = _locate_private_request_file(
        private_root, request_digest=request_digest
    )
    try:
        request = read_private_json(private_root, request_file)
        claim = read_private_json(private_root, CONSUMPTION_CLAIM)
    except CollectorError as exc:
        raise LiveExecutorError("PRIVATE_EVIDENCE_REQUEST_INVALID") from exc
    checkpoint_file = _private_file(
        request.get("owner_checkpoint_file"),
        "PRIVATE_EVIDENCE_REQUEST_INVALID",
    )
    claim_digest = claim.get("claim_digest")
    if (
        request.get("request_file") != request_file
        or request.get("request_digest") != request_digest
        or request.get("owner_checkpoint_digest") != checkpoint_digest
        or claim.get("request_digest") != request_digest
        or claim.get("checkpoint_digest") != checkpoint_digest
        or not isinstance(claim_digest, str)
        or _DIGEST.fullmatch(claim_digest) is None
    ):
        _fail("PRIVATE_EVIDENCE_REQUEST_INVALID")
    return {
        "request_file": request_file,
        "owner_checkpoint_file": checkpoint_file,
        "consumption_claim_file": CONSUMPTION_CLAIM,
        "consumption_claim_digest": claim_digest,
    }


def _validate_physical_request_artifacts(
    private_root: Path,
    *,
    evidence: Mapping[str, Any],
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    """Recertify request, checkpoint and claim without a live-time gate."""

    code = "PRIVATE_EVIDENCE_REQUEST_INVALID"
    if not isinstance(private_root, Path):
        _fail(code)
    request_file = _private_file(evidence.get("request_file"), code)
    checkpoint_file = _private_file(
        evidence.get("owner_checkpoint_file"), code
    )
    claim_file = _private_file(evidence.get("consumption_claim_file"), code)
    if (
        claim_file != CONSUMPTION_CLAIM
        or len({request_file, checkpoint_file, claim_file}) != 3
        or {request_file, checkpoint_file}
        & (set(ARTIFACT_NAMES) | {EVIDENCE_MANIFEST_NAME})
    ):
        _fail(code)
    try:
        request = read_private_json(private_root, request_file)
        checkpoint = read_private_json(private_root, checkpoint_file)
        claim = read_private_json(private_root, claim_file)
        root_digest = private_root_binding_digest(private_root)
        request_start = _parse_stamp(request.get("not_before"), code)
        validated = validate_materialized_live_request(
            request,
            checkpoint,
            # Durable verification replays the structural validator at the
            # attested start, rather than requiring the old window to be live.
            now=request_start,
            expected_source_commit_sha=str(evidence.get("source_commit_sha")),
            expected_source_tree_sha=str(evidence.get("source_tree_sha")),
            expected_host_digest=str(request.get("host_digest")),
            expected_private_root_digest=root_digest,
            expected_approval_reference_digest=str(
                evidence.get("approval_reference_digest")
            ),
        )
    except (CollectorError, LiveRequestMaterializationError) as exc:
        raise LiveExecutorError(code) from exc
    request = validated.request
    checkpoint = validated.owner_checkpoint
    try:
        request_end = _parse_stamp(request["expires_at"], code)
        claimed_at = _parse_stamp(claim.get("claimed_at"), code)
    except KeyError as exc:
        raise LiveExecutorError(code) from exc
    claim_body = {
        key: value for key, value in claim.items() if key != "claim_digest"
    }
    expected_claim_bindings = {
        "source_commit_sha": evidence.get("source_commit_sha"),
        "source_tree_sha": evidence.get("source_tree_sha"),
        "request_digest": evidence.get("request_digest"),
        "checkpoint_digest": evidence.get("checkpoint_digest"),
        "approval_reference_digest": evidence.get(
            "approval_reference_digest"
        ),
        "host_digest": request.get("host_digest"),
        "private_root_digest": root_digest,
    }
    authority_plan = request.get("authority_plan")
    identity_plan = request.get("identity_center_plan")
    if (
        request.get("record_type") != REQUEST_RECORD_TYPE
        or request.get("request_file") != request_file
        or request.get("owner_checkpoint_file") != checkpoint_file
        or request.get("request_digest") != evidence.get("request_digest")
        or checkpoint.get("record_type") != CHECKPOINT_RECORD_TYPE
        or checkpoint.get("request_file") != request_file
        or checkpoint.get("owner_checkpoint_file") != checkpoint_file
        or checkpoint.get("checkpoint_digest")
        != evidence.get("checkpoint_digest")
        or request.get("owner_checkpoint_digest")
        != checkpoint.get("checkpoint_digest")
        or not isinstance(authority_plan, Mapping)
        or not isinstance(identity_plan, Mapping)
        or authority_plan.get("not_before") != evidence.get("not_before")
        or authority_plan.get("not_after") != evidence.get("not_after")
        or identity_plan.get("not_before") != evidence.get("not_before")
        or identity_plan.get("not_after") != evidence.get("not_after")
        or checkpoint.get("plan_window_digest")
        != evidence.get("window_digest")
        or set(claim) != _CONSUMPTION_CLAIM_FIELDS
        or claim.get("record_type")
        != "scanalyze.platform_authority.gug376_live_consumption_claim.v1"
        or claim.get("implementation_issue") != "GUG-392"
        or claim.get("parent_issue") != "GUG-376"
        or any(
            claim.get(key) != value
            for key, value in expected_claim_bindings.items()
        )
        or claim.get("read_only") is not True
        or type(claim.get("aws_mutations")) is not int
        or claim.get("aws_mutations") != 0
        or claim.get("deployment_authorized") is not False
        or claim.get("production_status") != "NO-GO"
        or claim.get("claim_digest") != canonical_digest(claim_body)
        or claim.get("claim_digest")
        != evidence.get("consumption_claim_digest")
        or not request_start <= claimed_at < request_end
    ):
        _fail(code)
    return request, checkpoint, claim


def _authority_plan_binding(
    plan: Mapping[str, Any], *, code: str
) -> tuple[dict[str, Any], str]:
    try:
        targets = plan["targets"]
        policy_digest = plan["expected_policy_digest"]
        runtime_target_digest = canonical_digest(
            {
                "policy_digest": policy_digest,
                "runtime_source_function_version_arn": targets[
                    "runtime_source_function_version_arn"
                ],
            }
        )
        binding = {
            "account_id": plan["expected_account_id"],
            "principal_arn": plan["expected_principal_arn"],
            "not_before": plan["not_before"],
            "not_after": plan["not_after"],
            "policy_digest": policy_digest,
            "authority_verification_digest": plan[
                "authority_verification_digest"
            ],
            "runtime_target_digest": runtime_target_digest,
            "target_digest": canonical_digest(targets),
            "region": "us-east-1",
        }
    except (KeyError, TypeError) as exc:
        raise LiveExecutorError(code) from exc
    if any(
        _DIGEST.fullmatch(str(binding[key])) is None
        for key in (
            "policy_digest",
            "authority_verification_digest",
            "runtime_target_digest",
            "target_digest",
        )
    ):
        _fail(code)
    return binding, canonical_digest(binding)


def _identity_plan_binding(
    plan: Mapping[str, Any], *, code: str
) -> tuple[dict[str, Any], str]:
    try:
        private = plan["private_targets"]
        binding = {
            key: value
            for key, value in plan.items()
            if key not in {"private_targets", "not_before", "not_after"}
        }
        binding.update(
            {
                "private_target_digest": canonical_digest(private),
                "identity_store_id_digest": canonical_digest(
                    private["identity_store_id"]
                ),
                "application_name_digest": canonical_digest(
                    private["application_name"]
                ),
                "not_before": plan["not_before"],
                "not_after": plan["not_after"],
                "region": "us-east-1",
                "identity_center_instance_arn": private[
                    "identity_center_instance_arn"
                ],
                "identity_center_kms_binding_digest": private[
                    "identity_center_kms_binding_digest"
                ],
            }
        )
    except (KeyError, TypeError) as exc:
        raise LiveExecutorError(code) from exc
    return binding, canonical_digest(binding)


def _validate_cross_domain_identity_role_state(
    *,
    authority_private: list[Mapping[str, Any]],
    identity_private: list[Mapping[str, Any]],
    authority_plan: Mapping[str, Any],
    authority_classification: str,
    identity_classification: str,
) -> None:
    """Require provisioned permission sets and generated IAM roles to agree."""

    code = "CROSS_DOMAIN_ROLE_TOPOLOGY_INVALID"
    if len(authority_private) != 2 or len(identity_private) != 2:
        _fail(code)
    if identity_classification == "ABSENT_READY":
        if any(
            snapshot.get("surfaces", {})
            .get("iam_roles", {})
            .get("items")
            != []
            for snapshot in authority_private
        ):
            _fail(code)
        return
    if identity_classification != "EXACT_PRESENT_NO_TOUCH":
        return
    if authority_classification != "PREEXISTING_NO_TOUCH":
        _fail(code)
    try:
        targets = authority_plan["targets"]
        policy_digests = []
        for snapshot in identity_private:
            permissions = snapshot["facts"]["permission_sets"]
            rendered_permission_policies = render_permission_set_inline_policies(
                authority_account_id=str(authority_plan["expected_account_id"]),
                identity_center_targets=snapshot["targets"],
            )
            if {
                name: permissions[name]["inline_policy"]["policy_digest"]
                for name in rendered_permission_policies
            } != {
                name: value[1]
                for name, value in rendered_permission_policies.items()
            }:
                _fail(code)
            policy_digests.append(
                {
                    targets["retire_approve_generated_role_arn"]: permissions[
                        "ScanalyzeAuthorityRetireApprove"
                    ]["inline_policy"]["policy_digest"],
                    targets["retire_class_generated_role_arn"]: permissions[
                        "ScanalyzeAuthorityRetireClass"
                    ]["inline_policy"]["policy_digest"],
                }
            )
        if policy_digests[0] != policy_digests[1]:
            _fail(code)
        trust_expectations = authority_plan[
            "expected_generated_role_trust_policy_digests"
        ]
        expected_role_trust_policy_digests = {
            targets["retire_approve_generated_role_arn"]: trust_expectations[
                "retire_approve"
            ],
            targets["retire_class_generated_role_arn"]: trust_expectations[
                "retire_class"
            ],
        }
        for snapshot in authority_private:
            validate_live_generated_identity_center_roles(
                snapshot,
                expected_role_policy_digests=policy_digests[0],
                expected_role_trust_policy_digests=(
                    expected_role_trust_policy_digests
                ),
            )
    except LiveExecutorError:
        raise
    except (
        CollectorError,
        LiveRequestMaterializationError,
        KeyError,
        TypeError,
    ) as exc:
        raise LiveExecutorError(code) from exc


def _validate_physical_live_snapshots(
    private_root: Path,
    *,
    authority_collector: Mapping[str, Any],
    identity_collector: Mapping[str, Any],
    approved_request: Mapping[str, Any],
    owner_checkpoint: Mapping[str, Any],
) -> tuple[list[str], list[str]]:
    """Read, recertify and bind all four owner-only v2 snapshots."""

    if not isinstance(private_root, Path):
        _fail("PRIVATE_EVIDENCE_SNAPSHOT_INVALID")
    code = "PRIVATE_EVIDENCE_SNAPSHOT_INVALID"
    try:
        authority_private = [
            read_private_json(private_root, name) for name in ARTIFACT_NAMES[:2]
        ]
        identity_private = [
            read_private_json(private_root, name) for name in ARTIFACT_NAMES[2:]
        ]
        authority_binding, authority_plan_digest = _authority_plan_binding(
            approved_request["authority_plan"], code=code
        )
        identity_binding, identity_plan_digest = _identity_plan_binding(
            approved_request["identity_center_plan"], code=code
        )
        authority_start = _parse_stamp(authority_binding["not_before"], code)
        authority_end = _parse_stamp(authority_binding["not_after"], code)
        if (
            owner_checkpoint.get("authority_plan_digest")
            != authority_plan_digest
            or owner_checkpoint.get("identity_center_plan_digest")
            != identity_plan_digest
            or approved_request.get("authorization", {}).get(
                "authority_plan_digest"
            )
            != authority_plan_digest
            or approved_request.get("authorization", {}).get(
                "identity_center_plan_digest"
            )
            != identity_plan_digest
        ):
            _fail(code)
        for snapshot in authority_private:
            identity = snapshot["identity"]
            observed = _parse_stamp(identity["observed_at"], code)
            expires = _parse_stamp(identity["expires_at"], code)
            if (
                snapshot.get("policy_digest")
                != authority_binding["policy_digest"]
                or snapshot.get("runtime_target_digest")
                != authority_binding["runtime_target_digest"]
                or identity.get("account_id") != authority_binding["account_id"]
                or identity.get("principal_arn")
                != authority_binding["principal_arn"]
                or identity.get("policy_digest")
                != authority_binding["policy_digest"]
                or identity.get("authority_verification_digest")
                != authority_binding["authority_verification_digest"]
                or identity.get("region") != authority_binding["region"]
                or not authority_start <= observed < authority_end <= expires
            ):
                _fail(code)
        if any(
            snapshot.get("plan_binding") != identity_binding
            or snapshot.get("plan_binding_digest") != identity_plan_digest
            for snapshot in identity_private
        ):
            _fail(code)
        authority_recomputed = certify_authority(
            *authority_private,
            expected_runtime_target_digest=authority_binding[
                "runtime_target_digest"
            ],
        )
        identity_recomputed = certify_identity_center(
            *identity_private,
            expected_plan_binding_digest=identity_plan_digest,
        )
        authority_recomputed = validate_authority_receipt(authority_recomputed)
        identity_recomputed = validate_identity_center_receipt(identity_recomputed)
        _validate_cross_domain_identity_role_state(
            authority_private=authority_private,
            identity_private=identity_private,
            authority_plan=approved_request["authority_plan"],
            authority_classification=str(authority_recomputed["classification"]),
            identity_classification=str(identity_recomputed["classification"]),
        )
    except LiveExecutorError:
        raise
    except (CollectorError, HandoffError, KeyError, TypeError) as exc:
        raise LiveExecutorError(code) from exc
    if (
        authority_recomputed != authority_collector
        or identity_recomputed != identity_collector
        or authority_collector.get("runtime_target_digest")
        != authority_binding["runtime_target_digest"]
        or authority_collector.get("snapshot_digests")
        != [item.get("snapshot_digest") for item in authority_private]
        or identity_collector.get("snapshot_digests")
        != [item.get("snapshot_digest") for item in identity_private]
    ):
        _fail("PRIVATE_EVIDENCE_SNAPSHOT_INVALID")
    authority_sessions = [
        item["identity"]["session_id_digest"] for item in authority_private
    ]
    identity_sessions = [
        session
        for item in identity_private
        for session in item["session_digests"]
    ]
    if (
        len(authority_sessions) != len(set(authority_sessions))
        or len(identity_sessions) != len(set(identity_sessions))
        or set(authority_sessions) & set(identity_sessions)
        or set(authority_collector["snapshot_digests"])
        & set(identity_collector["snapshot_digests"])
    ):
        _fail("PRIVATE_EVIDENCE_SNAPSHOT_INVALID")
    return authority_sessions, identity_sessions


def validate_private_live_evidence_manifest(
    value: Mapping[str, Any],
    *,
    private_root: Path,
    run_record: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Recompute the physical snapshots, receipts, transcript and run link."""

    item = _normalized(value, "PRIVATE_EVIDENCE_MANIFEST_INVALID")
    if set(item) != _PRIVATE_EVIDENCE_FIELDS:
        _fail("PRIVATE_EVIDENCE_MANIFEST_INVALID")
    events = item.get("transcript_events")
    authority_collector = item.get("authority_collector_receipt")
    identity_collector = item.get("identity_center_collector_receipt")
    if (
        item.get("record_type")
        != "scanalyze.platform_authority.gug392_private_live_evidence.v1"
        or not isinstance(events, list)
        or not events
        or not isinstance(authority_collector, Mapping)
        or not isinstance(identity_collector, Mapping)
        or item.get("read_only") is not True
        or type(item.get("aws_mutations")) is not int
        or item.get("aws_mutations") != 0
        or item.get("repository_persisted") is not False
        or any(
            _DIGEST.fullmatch(str(item.get(key))) is None
            for key in (
                "window_digest",
                "request_digest",
                "checkpoint_digest",
                "consumption_claim_digest",
                "approval_reference_digest",
                "transcript_digest",
                "evidence_manifest_digest",
            )
        )
        or not isinstance(item.get("source_commit_sha"), str)
        or _SHA.fullmatch(item["source_commit_sha"]) is None
        or not isinstance(item.get("source_tree_sha"), str)
        or _SHA.fullmatch(item["source_tree_sha"]) is None
    ):
        _fail("PRIVATE_EVIDENCE_MANIFEST_INVALID")
    start = _parse_stamp(item["not_before"], "PRIVATE_EVIDENCE_MANIFEST_INVALID")
    end = _parse_stamp(item["not_after"], "PRIVATE_EVIDENCE_MANIFEST_INVALID")
    sealed = _parse_stamp(item["sealed_at"], "PRIVATE_EVIDENCE_MANIFEST_INVALID")
    if (
        not start <= sealed < end
        or item["window_digest"]
        != canonical_digest(
            {
                "not_before": item["not_before"],
                "not_after": item["not_after"],
                "region": "us-east-1",
            }
        )
    ):
        _fail("PRIVATE_EVIDENCE_MANIFEST_INVALID")
    approved_request, owner_checkpoint, _ = (
        _validate_physical_request_artifacts(
            private_root,
            evidence=item,
        )
    )

    checked_events: list[dict[str, Any]] = []
    previous_completed: datetime | None = None
    for ordinal, raw in enumerate(events, 1):
        if not isinstance(raw, Mapping):
            _fail("PRIVATE_EVIDENCE_MANIFEST_INVALID")
        event = _normalized(raw, "PRIVATE_EVIDENCE_MANIFEST_INVALID")
        started = _parse_stamp(
            event.get("started_at"), "PRIVATE_EVIDENCE_MANIFEST_INVALID"
        )
        completed = _parse_stamp(
            event.get("completed_at"), "PRIVATE_EVIDENCE_MANIFEST_INVALID"
        )
        digest_values = (
            event.get("session_digest"),
            event.get("request_digest"),
            event.get("response_digest"),
        )
        optional_digests = (
            event.get("pagination_stream_digest"),
            event.get("page_token_digest"),
            event.get("next_token_digest"),
        )
        if (
            set(event) != _PRIVATE_EVENT_FIELDS
            or event.get("ordinal") != ordinal
            or event.get("domain") not in ALLOWED_OPERATIONS
            or event.get("operation")
            not in ALLOWED_OPERATIONS[event["domain"]]
            or any(_DIGEST.fullmatch(str(raw_digest)) is None for raw_digest in digest_values)
            or any(
                raw_digest is not None
                and _DIGEST.fullmatch(str(raw_digest)) is None
                for raw_digest in optional_digests
            )
            or event.get("outcome") != "SUCCESS"
            or type(event.get("complete")) is not bool
            or type(event.get("truncated")) is not bool
            or event["complete"] is event["truncated"]
            or (event["next_token_digest"] is not None) is not event["truncated"]
            or not start <= started <= completed <= sealed < end
            or previous_completed is not None and started < previous_completed
        ):
            _fail("PRIVATE_EVIDENCE_MANIFEST_INVALID")
        checked_events.append(event)
        previous_completed = completed
    _validate_private_transcript_causality(checked_events)
    if (
        type(item.get("provider_calls")) is not int
        or item.get("provider_calls") != len(checked_events)
        or item.get("aws_calls") != len(checked_events)
        or item.get("transcript_digest") != canonical_digest(checked_events)
        or authority_collector.get("receipt_digest")
        != canonical_digest(
            {
                key: raw
                for key, raw in authority_collector.items()
                if key != "receipt_digest"
            }
        )
        or identity_collector.get("receipt_digest")
        != canonical_digest(
            {
                key: raw
                for key, raw in identity_collector.items()
                if key != "receipt_digest"
            }
        )
    ):
        _fail("PRIVATE_EVIDENCE_MANIFEST_INVALID")
    authority_events = [
        event for event in checked_events if event["domain"] == "authority"
    ]
    identity_events = [
        event
        for event in checked_events
        if event["domain"] == "identity_center"
    ]
    try:
        authority_collector = validate_authority_receipt(authority_collector)
        identity_collector = validate_identity_center_receipt(identity_collector)
    except HandoffError as exc:
        raise LiveExecutorError("PRIVATE_EVIDENCE_MANIFEST_INVALID") from exc
    authority_receipt = _validate_private_domain_receipt(
        item["authority_receipt"],
        domain="authority",
        collector_receipt=authority_collector,
        events=authority_events,
    )
    identity_receipt = _validate_private_domain_receipt(
        item["identity_center_receipt"],
        domain="identity_center",
        collector_receipt=identity_collector,
        events=identity_events,
    )
    authority_sessions, identity_sessions = _validate_physical_live_snapshots(
        private_root,
        authority_collector=authority_collector,
        identity_collector=identity_collector,
        approved_request=approved_request,
        owner_checkpoint=owner_checkpoint,
    )
    if (
        authority_receipt["session_digests"] != authority_sessions
        or identity_receipt["session_digests"] != identity_sessions
    ):
        _fail("PRIVATE_EVIDENCE_SNAPSHOT_INVALID")
    if item.get("evidence_manifest_digest") != canonical_digest(
        {
            key: raw
            for key, raw in item.items()
            if key != "evidence_manifest_digest"
        }
    ):
        _fail("PRIVATE_EVIDENCE_MANIFEST_INVALID")
    if run_record is not None:
        run = validate_live_run_record(run_record)
        bindings = {
            "source_commit_sha": item["source_commit_sha"],
            "source_tree_sha": item["source_tree_sha"],
            "window_digest": item["window_digest"],
            "request_digest": item["request_digest"],
            "checkpoint_digest": item["checkpoint_digest"],
            "approval_reference_digest": item["approval_reference_digest"],
            "transcript_digest": item["transcript_digest"],
            "provider_calls": item["provider_calls"],
            "aws_calls": item["aws_calls"],
            "sealed_at": item["sealed_at"],
            "evidence_manifest_digest": item["evidence_manifest_digest"],
            "authority_receipt_digest": authority_receipt["receipt_digest"],
            "identity_center_receipt_digest": identity_receipt["receipt_digest"],
            "authority_snapshot_digests": authority_receipt["snapshot_digests"],
            "identity_center_snapshot_digests": identity_receipt["snapshot_digests"],
            "authority_session_digests": authority_receipt["session_digests"],
            "identity_center_session_digests": identity_receipt["session_digests"],
            "authority_classification": authority_receipt["classification"],
            "identity_center_classification": identity_receipt["classification"],
        }
        if any(run.get(key) != expected for key, expected in bindings.items()):
            _fail("PRIVATE_EVIDENCE_RUN_BINDING_INVALID")
    return item


def validate_private_live_evidence_bundle(
    manifest: Mapping[str, Any],
    run_record: Mapping[str, Any],
    public_handoff: Mapping[str, Any],
    *,
    private_root: Path,
) -> dict[str, Any]:
    """Return a public-safe receipt after recertifying all private snapshots."""

    run, handoff = validate_live_bundle(run_record, public_handoff)
    evidence = validate_private_live_evidence_manifest(
        manifest, private_root=private_root, run_record=run
    )
    body: dict[str, Any] = {
        "record_type": (
            "scanalyze.platform_authority.gug392_evidence_verification.v1"
        ),
        "status": "PRIVATE_EVIDENCE_VERIFIED",
        "run_digest": run["run_digest"],
        "handoff_digest": handoff["handoff_digest"],
        "evidence_manifest_digest": evidence["evidence_manifest_digest"],
        "transcript_digest": evidence["transcript_digest"],
        "provider_calls": evidence["provider_calls"],
        "aws_calls": evidence["aws_calls"],
        "read_only": True,
        "aws_mutations": 0,
        "deployment_authorized": False,
        "production_status": "NO-GO",
    }
    return {**body, "verification_digest": canonical_digest(body)}


def _provider_summary(
    provider_factory: ConcreteProviderFactory,
    *,
    calls: int,
    transcript_digest: str,
) -> None:
    try:
        summary = _normalized(provider_factory.transcript_summary(), "LIVE_PROVIDER_TRANSCRIPT_INVALID")
    except AttributeError as exc:
        raise LiveExecutorError("LIVE_PROVIDER_TRANSCRIPT_INVALID") from exc
    expected_fields = {
        "provider_calls",
        "aws_calls",
        "aws_mutations",
        "live_provider_evidence",
        "transcript_digest",
    }
    if (
        set(summary) != expected_fields
        or type(summary.get("provider_calls")) is not int
        or type(summary.get("aws_calls")) is not int
        or summary.get("provider_calls") != calls
        or summary.get("aws_calls") != calls
        or summary.get("aws_mutations") != 0
        or summary.get("live_provider_evidence") is not True
        or summary.get("transcript_digest") != transcript_digest
    ):
        _fail("LIVE_PROVIDER_TRANSCRIPT_INVALID")


def _final_execution_gate(
    config: Mapping[str, Any],
    provider_factory: ConcreteProviderFactory,
    execution_capability: object,
) -> datetime:
    """Recheck private custody and both live windows immediately before sealing."""

    try:
        final_time = provider_factory.evaluation_time()
        execution_capability_validity_gate(execution_capability)()
    except LiveRequestMaterializationError as exc:
        raise LiveExecutorError(exc.code) from exc
    except Exception as exc:
        raise LiveExecutorError("LIVE_PROVIDER_FINAL_GATE_INVALID") from exc
    try:
        plans = (config["authority_plan"], config["identity_center_plan"])
        starts = [plan["not_before"] for plan in plans]
        ends = [plan["not_after"] for plan in plans]
        values = [final_time, *starts, *ends]
        if any(
            not isinstance(value, datetime) or value.tzinfo is None
            for value in values
        ):
            _fail("WINDOW_INVALID")
        normalized_time, *normalized_bounds = [
            value.astimezone(UTC).replace(microsecond=0) for value in values
        ]
        normalized_starts = normalized_bounds[:2]
        normalized_ends = normalized_bounds[2:]
    except (KeyError, TypeError, AttributeError) as exc:
        raise LiveExecutorError("WINDOW_INVALID") from exc
    if (
        normalized_starts[0] != normalized_starts[1]
        or normalized_ends[0] != normalized_ends[1]
        or not normalized_starts[0] <= normalized_time < normalized_ends[0]
    ):
        _fail("WINDOW_INVALID")
    return normalized_time


def execute_live(
    config: Mapping[str, Any],
    provider_factory: ConcreteProviderFactory,
    *,
    private_root: Path,
    now: datetime,
    actual_source_commit_sha: str,
    actual_source_tree_sha: str,
    request_digest: str,
    checkpoint_digest: str,
    approval_reference_digest: str,
    execution_capability: object,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Capture two stable snapshots per domain through the concrete adapter."""

    if not is_attested_live_provider(provider_factory, execution_capability):
        _fail("ATTESTED_LIVE_PROVIDER_REQUIRED")
    if any(
        _DIGEST.fullmatch(str(value)) is None
        for value in (request_digest, checkpoint_digest, approval_reference_digest)
    ):
        _fail("PRIVATE_REQUEST_BINDING_INVALID")
    try:
        assert_live_request_execution_capability(
            execution_capability,
            private_root=private_root,
            source_commit_sha=actual_source_commit_sha,
            source_tree_sha=actual_source_tree_sha,
            request_digest=request_digest,
            checkpoint_digest=checkpoint_digest,
            approval_reference_digest=approval_reference_digest,
            runtime_config=config,
        )
        private_target_absent(private_root, EVIDENCE_MANIFEST_NAME)
    except LiveRequestMaterializationError as exc:
        raise LiveExecutorError(exc.code) from exc
    except CollectorError as exc:
        raise LiveExecutorError(exc.code) from exc
    local = _preflight(
        config,
        private_root=private_root,
        now=now,
        actual_source_commit_sha=actual_source_commit_sha,
        actual_source_tree_sha=actual_source_tree_sha,
        attested_live=True,
    )
    ledger = CallLedger("ATTESTED_LIVE")
    try:
        authority_private: list[dict[str, Any]] = []
        for index, name in enumerate(ARTIFACT_NAMES[:2], 1):
            factory = provider_factory.build_authority(
                profile=local["profiles"]["authority"]["name"],
                ledger=ledger,
                capture_index=index,
                retries=0,
            )
            capture_authority(
                config["authority_plan"],
                factory,
                private_root=private_root,
                artifact_name=name,
                now=now,
                validation_clock=provider_factory.evaluation_time,
            )
            ledger.raise_if_failed()
            snapshot = read_private_json(private_root, name)
            if any(
                surface.get("complete") is not True
                for surface in snapshot.get("surfaces", {}).values()
            ):
                _fail("RECONCILIATION_READ_ONLY_REQUIRED")
            authority_private.append(snapshot)
        authority_receipt = certify_authority(
            *authority_private,
            expected_runtime_target_digest=local["authority_runtime_digest"],
        )

        identity_private: list[dict[str, Any]] = []
        for index, name in enumerate(ARTIFACT_NAMES[2:], 1):
            factory = provider_factory.build_identity(
                profile=local["profiles"]["identity_center"]["name"],
                ledger=ledger,
                capture_index=index,
                retries=0,
            )
            capture_identity_center(
                config["identity_center_plan"],
                factory,
                private_root=private_root,
                artifact_name=name,
                now=now,
                validation_clock=provider_factory.evaluation_time,
            )
            ledger.raise_if_failed()
            snapshot = read_private_json(private_root, name)
            if snapshot.get("classification") in _PARTIAL:
                _fail("RECONCILIATION_READ_ONLY_REQUIRED")
            identity_private.append(snapshot)
        identity_receipt = certify_identity_center(
            *identity_private,
            expected_plan_binding_digest=local["identity_binding_digest"],
        )
        authority_receipt = validate_authority_receipt(authority_receipt)
        identity_receipt = validate_identity_center_receipt(identity_receipt)
    except LiveExecutorError:
        raise
    except OrchestratorError as exc:
        raise LiveExecutorError(exc.code) from exc
    except (CollectorError, HandoffError) as exc:
        raise LiveExecutorError(getattr(exc, "code", "PROVIDER_EXECUTION_FAILED")) from exc
    except Exception as exc:
        raise LiveExecutorError("PROVIDER_EXECUTION_FAILED") from exc

    authority_classification = authority_receipt["classification"]
    identity_classification = identity_receipt["classification"]
    if (
        authority_receipt["stable"] is not True
        or identity_receipt["stable"] is not True
        or authority_classification not in _AUTHORITY_CLASSES
        or identity_classification not in _IDENTITY_CLASSES
    ):
        _fail("RECONCILIATION_READ_ONLY_REQUIRED")
    _validate_cross_domain_identity_role_state(
        authority_private=authority_private,
        identity_private=identity_private,
        authority_plan=config["authority_plan"],
        authority_classification=str(authority_classification),
        identity_classification=str(identity_classification),
    )
    authority_sessions = [item["identity"]["session_id_digest"] for item in authority_private]
    identity_sessions = [
        session for item in identity_private for session in item["session_digests"]
    ]
    if (
        authority_sessions != ledger.session_digests("authority")
        or identity_sessions != ledger.session_digests("identity_center")
        or set(authority_sessions) & set(identity_sessions)
        or set(authority_receipt["snapshot_digests"])
        & set(identity_receipt["snapshot_digests"])
    ):
        _fail("CROSS_DOMAIN_EVIDENCE_SUBSTITUTION")
    calls, transcript_digest = ledger.finalize()
    _provider_summary(
        provider_factory,
        calls=calls,
        transcript_digest=transcript_digest,
    )
    sealed_time = _final_execution_gate(
        config, provider_factory, execution_capability
    )
    transcript_events = ledger.evidence_events()
    authority_events = [
        event for event in transcript_events if event["domain"] == "authority"
    ]
    identity_events = [
        event
        for event in transcript_events
        if event["domain"] == "identity_center"
    ]
    authority_live_receipt = _live_domain_receipt(
        domain="authority",
        collector_receipt=authority_receipt,
        session_digests=authority_sessions,
        events=authority_events,
    )
    identity_live_receipt = _live_domain_receipt(
        domain="identity_center",
        collector_receipt=identity_receipt,
        session_digests=identity_sessions,
        events=identity_events,
    )
    not_before = config["authority_plan"]["not_before"]
    not_after = config["authority_plan"]["not_after"]
    if not isinstance(not_before, datetime) or not isinstance(not_after, datetime):
        _fail("WINDOW_INVALID")

    def stamp(value: datetime) -> str:
        return (
            value.astimezone(UTC)
            .replace(microsecond=0)
            .isoformat()
            .replace("+00:00", "Z")
        )

    private_request_references = _private_request_manifest_references(
        private_root,
        request_digest=request_digest,
        checkpoint_digest=checkpoint_digest,
    )
    evidence_body: dict[str, Any] = {
        "record_type": (
            "scanalyze.platform_authority.gug392_private_live_evidence.v1"
        ),
        "source_commit_sha": actual_source_commit_sha,
        "source_tree_sha": actual_source_tree_sha,
        "not_before": stamp(not_before),
        "not_after": stamp(not_after),
        "sealed_at": stamp(sealed_time),
        "window_digest": local["window_digest"],
        **private_request_references,
        "request_digest": request_digest,
        "checkpoint_digest": checkpoint_digest,
        "approval_reference_digest": approval_reference_digest,
        "authority_receipt": authority_live_receipt,
        "identity_center_receipt": identity_live_receipt,
        "authority_collector_receipt": authority_receipt,
        "identity_center_collector_receipt": identity_receipt,
        "transcript_events": transcript_events,
        "transcript_digest": transcript_digest,
        "provider_calls": calls,
        "aws_calls": calls,
        "read_only": True,
        "aws_mutations": 0,
        "repository_persisted": False,
    }
    evidence_manifest = {
        **evidence_body,
        "evidence_manifest_digest": canonical_digest(evidence_body),
    }
    evidence_manifest = validate_private_live_evidence_manifest(
        evidence_manifest, private_root=private_root
    )
    try:
        write_private_json(
            private_root, EVIDENCE_MANIFEST_NAME, evidence_manifest
        )
        persisted_evidence = read_private_json(
            private_root, EVIDENCE_MANIFEST_NAME
        )
    except CollectorError as exc:
        raise LiveExecutorError(exc.code) from exc
    if persisted_evidence != evidence_manifest:
        _fail("PRIVATE_EVIDENCE_READBACK_MISMATCH")
    post_persist_time = _final_execution_gate(
        config, provider_factory, execution_capability
    )
    if post_persist_time < sealed_time:
        _fail("PROVIDER_CLOCK_INVALID")

    record: dict[str, Any] = {
        "record_type": "scanalyze.platform_authority.gug376_live_readonly_run.v2",
        "status": "LIVE_READ_ONLY_CAPTURED",
        "classification": "LIVE_DUAL_DOMAIN_CAPTURED",
        "source_commit_sha": actual_source_commit_sha,
        "source_tree_sha": actual_source_tree_sha,
        "window_digest": local["window_digest"],
        "policy_digest": LIVE_POLICY_DIGEST,
        "authorization_digest": config["authorization_digest"],
        "attestation_digest": config["attestation_digest"],
        "trust_anchor_digest": config["trust_anchor_digest"],
        "run_id_digest": local["run_id_digest"],
        "profile_binding_digest": local["profile_binding_digest"],
        "request_digest": request_digest,
        "checkpoint_digest": checkpoint_digest,
        "approval_reference_digest": approval_reference_digest,
        "authority_receipt_digest": authority_live_receipt["receipt_digest"],
        "identity_center_receipt_digest": identity_live_receipt["receipt_digest"],
        "authority_snapshot_digests": authority_live_receipt["snapshot_digests"],
        "identity_center_snapshot_digests": identity_live_receipt["snapshot_digests"],
        "authority_session_digests": authority_sessions,
        "identity_center_session_digests": identity_sessions,
        "transcript_digest": transcript_digest,
        "provider_calls": calls,
        "aws_calls": calls,
        "authority_classification": authority_classification,
        "identity_center_classification": identity_classification,
        "evidence_manifest_digest": evidence_manifest[
            "evidence_manifest_digest"
        ],
        "sealed_at": evidence_manifest["sealed_at"],
        "evidence_complete": True,
        "evidence_stable": True,
        "live_provider_evidence": True,
        "read_only": True,
        "aws_mutations": 0,
        "reconciliation_only": False,
        "deployment_authorized": False,
        "two_human_status": "NOT_PROVEN",
        "independent_approval_present": False,
        "production_status": "NO-GO",
    }
    record["run_digest"] = canonical_digest(record)
    record = validate_live_run_record(record)
    validate_private_live_evidence_manifest(
        persisted_evidence, private_root=private_root, run_record=record
    )
    public_seal_time = _final_execution_gate(
        config, provider_factory, execution_capability
    )
    if public_seal_time < post_persist_time:
        _fail("PROVIDER_CLOCK_INVALID")
    projected = {
        key: record[key]
        for key in _LIVE_HANDOFF_FIELDS - {"record_type", "handoff_digest"}
    }
    handoff = {
        "record_type": "scanalyze.platform_authority.gug376_live_readonly_handoff.v2",
        **projected,
    }
    handoff["handoff_digest"] = canonical_digest(handoff)
    return validate_live_bundle(record, handoff)


__all__ = [
    "LiveExecutorError",
    "execute_live",
    "validate_live_bundle",
    "validate_live_public_handoff",
    "validate_live_run_record",
    "validate_private_live_evidence_manifest",
    "validate_private_live_evidence_bundle",
]
