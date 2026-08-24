"""Offline-only GUG-386 composer for the GUG-383 public handoff."""
from __future__ import annotations

import json, re
from pathlib import Path
from typing import Any, Mapping

from tooling.platform_authority_gug365_upstream_inventory import canonical_digest, canonical_json
from tooling.platform_authority_gug376_identity_center_inventory_collector import (
    CollectorError as IdentityReceiptError,
    validate_public_receipt as validate_gug385_receipt,
)

DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
GIT_SHA = re.compile(r"^[0-9a-f]{40}$")
TOKEN = re.compile(r"^[A-Z][A-Z0-9_]{2,95}$")
STABLE_AUTHORITY_CLASSES = {
    "ABSENT_READY", "EXACT_PRESENT_NO_TOUCH", "PREEXISTING_NO_TOUCH", "DRIFT_BLOCKED_NO_REPAIR",
}
AUTHORITY_CLASSES = STABLE_AUTHORITY_CLASSES | {"NOT_AUTHORIZED", "UNCERTAIN_RECONCILE_ONLY"}
AUTHORITY_FIELDS = {
    "record_type", "status", "classification", "policy_digest", "facts_digest",
    "runtime_target_digest", "snapshot_digests", "surface_counts_digest",
    "external_certification_digest", "external_verifier_identity_digest",
    "external_trust_anchor_digest", "session_count", "stable", "read_only",
    "aws_mutations", "two_human_status", "independent_approval_present",
    "deployment_authorized", "production_status", "receipt_digest",
}
COMMON_BINDINGS = {
    "run_id_digest", "source_commit_sha", "source_tree_sha", "window_digest", "authorization_digest",
}
DOMAIN_FIELDS = {
    "receipt_digest", "snapshot_digests", "session_digests", "binding_digest", *COMMON_BINDINGS,
}
RUN_FIELDS = {
    "record_type", "authority", "identity_center", "evidence_complete", "evidence_stable",
    "private_run_digest", *COMMON_BINDINGS,
}
HANDOFF_FIELDS = {
    "record_type", "status", "classification", "authority_receipt_digest",
    "identity_center_receipt_digest", "source_commit_sha", "source_tree_sha",
    "window_digest", "authorization_digest", "private_run_digest",
    "session_isolation_digest", "evidence_complete", "evidence_stable",
    "live_provider_evidence", "read_only", "aws_calls", "aws_mutations",
    "deployment_authorized", "two_human_status", "independent_approval_present",
    "production_status", "handoff_digest",
}


class HandoffError(RuntimeError):
    """Closed, public-safe failure from the offline composer."""

    def __init__(self, code: str) -> None:
        self.code = code if TOKEN.fullmatch(code) else "DUAL_DOMAIN_HANDOFF_BLOCKED"
        super().__init__(self.code)


def _fail(code: str) -> None:
    raise HandoffError(code)


def _normalized(value: Mapping[str, Any], code: str) -> dict[str, Any]:
    try:
        result = json.loads(canonical_json(value))
    except (TypeError, ValueError, json.JSONDecodeError) as exc:
        raise HandoffError(code) from exc
    if not isinstance(result, dict):
        _fail(code)
    return result


def _pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in items:
        if key in result:
            _fail("INPUT_DUPLICATE_KEY")
        result[key] = value
    return result


def read_json(path: Path) -> dict[str, Any]:
    """Read one bounded JSON object without ever echoing its path or contents."""
    try:
        if not path.is_file() or not 0 < path.stat().st_size <= 4 * 1024 * 1024:
            _fail("INPUT_FILE_INVALID")
        value = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_pairs)
    except HandoffError:
        raise
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise HandoffError("INPUT_FILE_INVALID") from exc
    if not isinstance(value, dict):
        _fail("INPUT_FILE_INVALID")
    return value


def validate_authority_receipt(value: Mapping[str, Any]) -> dict[str, Any]:
    """Strictly validate the public GUG-384 receipt missing its own validator."""
    receipt = _normalized(value, "GUG384_RECEIPT_INVALID")
    snapshots = receipt.get("snapshot_digests")
    external = [
        receipt.get("external_certification_digest"),
        receipt.get("external_verifier_identity_digest"),
        receipt.get("external_trust_anchor_digest"),
    ]
    fixed = (
        receipt.get("record_type") == "scanalyze.platform_authority.gug376_authority_inventory_receipt.v1"
        and receipt.get("status") == "AUTHORITY_INVENTORY_LIVE_NOT_PROVEN"
        and receipt.get("read_only") is True
        and type(receipt.get("aws_mutations")) is int and receipt.get("aws_mutations") == 0
        and receipt.get("two_human_status") == "NOT_PROVEN"
        and receipt.get("independent_approval_present") is False
        and receipt.get("deployment_authorized") is False
        and receipt.get("production_status") == "NO-GO"
    )
    digests = [receipt.get(key) for key in (
        "policy_digest", "facts_digest", "runtime_target_digest", "surface_counts_digest", "receipt_digest",
    )]
    classification = receipt.get("classification")
    valid_shape = (
        set(receipt) == AUTHORITY_FIELDS and fixed and isinstance(classification, str) and classification in AUTHORITY_CLASSES
        and isinstance(snapshots, list) and len(snapshots) in (1, 2)
        and len(set(map(str, snapshots))) == len(snapshots)
        and all(DIGEST.fullmatch(str(item)) for item in [*digests, *snapshots])
        and type(receipt.get("session_count")) is int
        and receipt.get("session_count") == len(snapshots)
        and type(receipt.get("stable")) is bool
        and (classification not in STABLE_AUTHORITY_CLASSES or (len(snapshots) == 2 and receipt["stable"] is True))
        and (classification not in {"NOT_AUTHORIZED", "UNCERTAIN_RECONCILE_ONLY"} or receipt["stable"] is False)
        and ((classification == "EXACT_PRESENT_NO_TOUCH" and all(DIGEST.fullmatch(str(item)) for item in external))
             or (classification != "EXACT_PRESENT_NO_TOUCH" and all(item is None for item in external)))
        and receipt.get("receipt_digest") == canonical_digest({key: item for key, item in receipt.items() if key != "receipt_digest"})
    )
    if not valid_shape:
        _fail("GUG384_RECEIPT_INVALID")
    return receipt


def validate_identity_center_receipt(value: Mapping[str, Any]) -> dict[str, Any]:
    """Validate and require a terminal, stable GUG-385 receipt."""
    receipt = _normalized(value, "GUG385_RECEIPT_INVALID")
    try:
        validate_gug385_receipt(receipt)
    except IdentityReceiptError as exc:
        raise HandoffError("GUG385_RECEIPT_INVALID") from exc
    return receipt


def _domain(value: object, code: str) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        _fail(code)
    domain = _normalized(value, code)
    snapshots, sessions = domain.get("snapshot_digests"), domain.get("session_digests")
    digest_fields = [domain.get(key) for key in ("receipt_digest", "run_id_digest", "window_digest", "authorization_digest", "binding_digest")]
    valid = (
        set(domain) == DOMAIN_FIELDS
        and isinstance(domain.get("source_commit_sha"), str) and GIT_SHA.fullmatch(domain["source_commit_sha"]) is not None
        and isinstance(domain.get("source_tree_sha"), str) and GIT_SHA.fullmatch(domain["source_tree_sha"]) is not None
        and isinstance(snapshots, list) and len(snapshots) == 2 and len(set(map(str, snapshots))) == 2
        and isinstance(sessions, list) and 2 <= len(sessions) <= 4 and len(set(map(str, sessions))) == len(sessions)
        and all(DIGEST.fullmatch(str(item)) for item in [*digest_fields, *snapshots, *sessions])
        and domain.get("binding_digest") == canonical_digest({key: item for key, item in domain.items() if key != "binding_digest"})
    )
    if not valid:
        _fail(code)
    return domain


def _run_envelope(
    value: Mapping[str, Any], authority: Mapping[str, Any], identity: Mapping[str, Any], *,
    expected_source_commit_sha: str, expected_source_tree_sha: str,
    expected_window_digest: str, expected_authorization_digest: str,
    expected_run_id_digest: str, expected_private_run_digest: str,
) -> dict[str, Any]:
    envelope = _normalized(value, "RUN_ENVELOPE_INVALID")
    expected = {
        "source_commit_sha": expected_source_commit_sha, "source_tree_sha": expected_source_tree_sha,
        "window_digest": expected_window_digest, "authorization_digest": expected_authorization_digest,
        "run_id_digest": expected_run_id_digest,
    }
    if (
        set(envelope) != RUN_FIELDS
        or envelope.get("record_type") != "scanalyze.platform_authority.gug383_dual_domain_inventory_run_envelope.v1"
        or envelope.get("evidence_complete") is not True or envelope.get("evidence_stable") is not True
        or not isinstance(expected_source_commit_sha, str) or GIT_SHA.fullmatch(expected_source_commit_sha) is None
        or not isinstance(expected_source_tree_sha, str) or GIT_SHA.fullmatch(expected_source_tree_sha) is None
        or any(DIGEST.fullmatch(str(expected[key])) is None for key in ("window_digest", "authorization_digest", "run_id_digest"))
        or DIGEST.fullmatch(str(expected_private_run_digest)) is None
    ):
        _fail("RUN_ENVELOPE_INVALID")
    authority_binding = _domain(envelope["authority"], "AUTHORITY_RUN_BINDING_INVALID")
    identity_binding = _domain(envelope["identity_center"], "IDENTITY_CENTER_RUN_BINDING_INVALID")
    if any(envelope.get(key) != item for key, item in expected.items()):
        _fail("EXPECTED_RUN_BINDING_MISMATCH")
    if any(domain[key] != envelope[key] for domain in (authority_binding, identity_binding) for key in COMMON_BINDINGS):
        _fail("CROSS_RUN_BINDING_MISMATCH")
    if authority_binding["receipt_digest"] != authority["receipt_digest"] or authority_binding["snapshot_digests"] != authority["snapshot_digests"]:
        _fail("GUG384_RECEIPT_SUBSTITUTED")
    if identity_binding["receipt_digest"] != identity["receipt_digest"] or identity_binding["snapshot_digests"] != identity["snapshot_digests"]:
        _fail("GUG385_RECEIPT_SUBSTITUTED")
    expected_identity_sessions = identity["snapshot_count"] * (2 if all(item is not None for item in identity["surface_counts"].values()) else 1)
    if len(authority_binding["session_digests"]) != authority["session_count"] or len(identity_binding["session_digests"]) != expected_identity_sessions:
        _fail("SESSION_CARDINALITY_INVALID")
    if set(authority_binding["snapshot_digests"]) & set(identity_binding["snapshot_digests"]):
        _fail("CROSS_DOMAIN_SNAPSHOT_REUSE")
    if set(authority_binding["session_digests"]) & set(identity_binding["session_digests"]):
        _fail("CROSS_DOMAIN_SESSION_REUSE")
    expected_private = canonical_digest({key: item for key, item in envelope.items() if key != "private_run_digest"})
    if envelope.get("private_run_digest") != expected_private or expected_private != expected_private_run_digest:
        _fail("PRIVATE_RUN_DIGEST_MISMATCH")
    return envelope


def validate_public_handoff(value: Mapping[str, Any]) -> dict[str, Any]:
    """Enforce the only public shape and evidence classification GUG-386 may emit."""
    handoff = _normalized(value, "PUBLIC_HANDOFF_INVALID")
    fixed = (
        handoff.get("record_type") == "scanalyze.platform_authority.gug383_dual_domain_inventory_handoff.v1"
        and handoff.get("status") == "STOP_LIVE_ORCHESTRATOR_NOT_IMPLEMENTED"
        and handoff.get("classification") == "REPOSITORY_VALIDATED_NO_LIVE_EXECUTION"
        and handoff.get("evidence_complete") is True and handoff.get("evidence_stable") is True
        and handoff.get("live_provider_evidence") is False and handoff.get("read_only") is True
        and type(handoff.get("aws_calls")) is type(handoff.get("aws_mutations")) is int
        and handoff.get("aws_calls") == handoff.get("aws_mutations") == 0
        and handoff.get("deployment_authorized") is False
        and handoff.get("two_human_status") == "NOT_PROVEN"
        and handoff.get("independent_approval_present") is False
        and handoff.get("production_status") == "NO-GO"
    )
    digests = [handoff.get(key) for key in (
        "authority_receipt_digest", "identity_center_receipt_digest", "window_digest",
        "authorization_digest", "private_run_digest", "session_isolation_digest", "handoff_digest",
    )]
    if (
        set(handoff) != HANDOFF_FIELDS or not fixed
        or not isinstance(handoff.get("source_commit_sha"), str) or GIT_SHA.fullmatch(handoff["source_commit_sha"]) is None
        or not isinstance(handoff.get("source_tree_sha"), str) or GIT_SHA.fullmatch(handoff["source_tree_sha"]) is None
        or any(DIGEST.fullmatch(str(item)) is None for item in digests)
        or handoff.get("handoff_digest") != canonical_digest({key: item for key, item in handoff.items() if key != "handoff_digest"})
    ):
        _fail("PUBLIC_HANDOFF_INVALID")
    return handoff


def compose(
    authority_receipt: Mapping[str, Any], identity_center_receipt: Mapping[str, Any],
    run_envelope: Mapping[str, Any], *, expected_source_commit_sha: str,
    expected_source_tree_sha: str, expected_window_digest: str,
    expected_authorization_digest: str, expected_run_id_digest: str,
    expected_private_run_digest: str,
) -> dict[str, Any]:
    """Compose two terminal receipts into a sanitized repository-only handoff."""
    authority = validate_authority_receipt(authority_receipt)
    identity = validate_identity_center_receipt(identity_center_receipt)
    if authority["stable"] is not True or authority["session_count"] != 2 or identity["stable"] is not True or identity["snapshot_count"] != 2:
        _fail("EVIDENCE_INCOMPLETE_OR_UNSTABLE")
    envelope = _run_envelope(
        run_envelope, authority, identity,
        expected_source_commit_sha=expected_source_commit_sha,
        expected_source_tree_sha=expected_source_tree_sha,
        expected_window_digest=expected_window_digest,
        expected_authorization_digest=expected_authorization_digest,
        expected_run_id_digest=expected_run_id_digest,
        expected_private_run_digest=expected_private_run_digest,
    )
    result: dict[str, Any] = {
        "record_type": "scanalyze.platform_authority.gug383_dual_domain_inventory_handoff.v1",
        "status": "STOP_LIVE_ORCHESTRATOR_NOT_IMPLEMENTED",
        "classification": "REPOSITORY_VALIDATED_NO_LIVE_EXECUTION",
        "authority_receipt_digest": authority["receipt_digest"],
        "identity_center_receipt_digest": identity["receipt_digest"],
        "source_commit_sha": envelope["source_commit_sha"], "source_tree_sha": envelope["source_tree_sha"],
        "window_digest": envelope["window_digest"], "authorization_digest": envelope["authorization_digest"],
        "private_run_digest": envelope["private_run_digest"],
        "session_isolation_digest": canonical_digest({
            "authority": envelope["authority"]["session_digests"],
            "identity_center": envelope["identity_center"]["session_digests"],
        }),
        "evidence_complete": True, "evidence_stable": True, "live_provider_evidence": False,
        "read_only": True, "aws_calls": 0, "aws_mutations": 0, "deployment_authorized": False,
        "two_human_status": "NOT_PROVEN", "independent_approval_present": False, "production_status": "NO-GO",
    }
    result["handoff_digest"] = canonical_digest(result)
    return validate_public_handoff(result)
