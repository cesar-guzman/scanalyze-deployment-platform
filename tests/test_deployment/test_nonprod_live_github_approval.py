from __future__ import annotations

import copy
import json
from datetime import UTC, datetime, timedelta

import pytest

from tooling.nonprod_live_github_approval import (
    GitHubApprovalError,
    build_approval_evidence,
    load_private_approval_evidence,
    persist_approval_evidence,
    validate_approval_evidence,
)


NOW = datetime(2026, 8, 28, 12, 0, tzinfo=UTC)
REPOSITORY = "cesar-guzman/scanalyze-deployment-platform"
ENVIRONMENT = "scanalyze-dep_01ARZ3NDEKTSV4RRFFQ69G5FAV-dev"
STAGING_ENVIRONMENT = "scanalyze-dep_01ARZ3NDEKTSV4RRFFQ69G5FAV-staging"
PRODUCTION_ENVIRONMENT = "scanalyze-dep_01ARZ3NDEKTSV4RRFFQ69G5FAV-production"
WORKFLOW_SHA = "4" * 40
REVIEWER_PACKET_DIGEST = "sha256:" + ("5" * 64)
ENVIRONMENT_ANCHOR_DIGEST = "sha256:" + ("6" * 64)
APPROVAL_AUTHORITY_DIGEST = "sha256:" + ("7" * 64)


def _reviews(
    *,
    approver: int = 2002,
    state: str = "approved",
    environment: str = ENVIRONMENT,
) -> list[dict]:
    return [
        {
            "state": state,
            "comment": "not persisted",
            "environments": [
                {
                    "id": 88,
                    "name": environment,
                    "url": "https://example.invalid/private",
                }
            ],
            "user": {"id": approver, "login": "not-persisted"},
        }
    ]


def _workflow_run(**overrides: object) -> dict:
    run = dict(
        id=4004,
        run_attempt=1,
        event="workflow_dispatch",
        status="in_progress",
        head_branch="main",
        head_sha=WORKFLOW_SHA,
        created_at="2026-08-28T11:55:00Z",
        repository=dict(id=3003),
        actor=dict(id=1001),
    )
    run.update(overrides)
    return run


def _evidence(**overrides: object) -> dict:
    values = {
        "repository": REPOSITORY,
        "repository_id": 3003,
        "workflow_sha": WORKFLOW_SHA,
        "workflow_run_id": 4004,
        "workflow_run_attempt": 1,
        "github_environment": ENVIRONMENT,
        "reviewer_packet_digest": REVIEWER_PACKET_DIGEST,
        "apply_environment_anchor_digest": ENVIRONMENT_ANCHOR_DIGEST,
        "approval_authority_digest": APPROVAL_AUTHORITY_DIGEST,
        "initiator_user_id": 1001,
        "expected_approver_user_id": 2002,
        "workflow_run": _workflow_run(),
        "reviews": _reviews(),
        "observed_at": NOW,
    }
    values.update(overrides)
    return build_approval_evidence(**values)


@pytest.mark.parametrize("environment", [ENVIRONMENT, STAGING_ENVIRONMENT])
def test_builds_sanitized_independent_exact_approval(environment: str) -> None:
    evidence = _evidence(
        github_environment=environment,
        reviews=_reviews(environment=environment),
    )

    assert evidence["approver_user_id"] == 2002
    assert evidence["expected_approver_user_id"] == 2002
    assert evidence["matching_review_count"] == 1
    assert evidence["workflow_run_created_at"] == "2026-08-28T11:55:00Z"
    assert evidence["approval_observed_at"] == "2026-08-28T12:00:00Z"
    assert evidence["freshness_basis"] == "WORKFLOW_RUN_CREATED_AT_CONSERVATIVE_BOUND"
    assert evidence["expires_at"] == "2026-08-28T12:05:00Z"
    serialized = json.dumps(evidence)
    assert "not-persisted" not in serialized
    assert "example.invalid" not in serialized


def test_rejects_production_environment_before_approval_projection() -> None:
    with pytest.raises(GitHubApprovalError, match="APPROVAL_SELECTOR_INVALID"):
        _evidence(
            github_environment=PRODUCTION_ENVIRONMENT,
            reviews=_reviews(environment=PRODUCTION_ENVIRONMENT),
        )


@pytest.mark.parametrize(
    "reviews",
    [
        [],
        _reviews(state="rejected"),
        _reviews(approver=1001),
        _reviews(approver=2003),
        _reviews() + _reviews(approver=2003),
    ],
)
def test_rejects_missing_ambiguous_or_self_approval(reviews: list[dict]) -> None:
    with pytest.raises(
        GitHubApprovalError,
        match="INDEPENDENT_ENVIRONMENT_APPROVAL_NOT_PROVEN",
    ):
        _evidence(reviews=reviews)


def test_rejects_stale_or_foreign_workflow_run_metadata() -> None:
    with pytest.raises(
        GitHubApprovalError,
        match="GITHUB_WORKFLOW_RUN_NOT_FRESH",
    ):
        _evidence(workflow_run=_workflow_run(created_at="2026-08-28T11:44:59Z"))

    for workflow_run in (
        _workflow_run(head_sha="5" * 40),
        _workflow_run(status="completed"),
        _workflow_run(actor=dict(id=9999)),
    ):
        with pytest.raises(
            GitHubApprovalError,
            match="GITHUB_WORKFLOW_RUN_BINDING_INVALID",
        ):
            _evidence(workflow_run=workflow_run)


def test_rejects_digest_binding_and_freshness_drift() -> None:
    evidence = _evidence()
    tampered = copy.deepcopy(evidence)
    tampered["repository_id"] = 99
    with pytest.raises(GitHubApprovalError, match="APPROVAL_EVIDENCE_DIGEST_MISMATCH"):
        validate_approval_evidence(
            tampered,
            repository=REPOSITORY,
            repository_id=3003,
            workflow_sha=WORKFLOW_SHA,
            workflow_run_id=4004,
            workflow_run_attempt=1,
            github_environment=ENVIRONMENT,
            reviewer_packet_digest=REVIEWER_PACKET_DIGEST,
            apply_environment_anchor_digest=ENVIRONMENT_ANCHOR_DIGEST,
            approval_authority_digest=APPROVAL_AUTHORITY_DIGEST,
            initiator_user_id=1001,
            expected_approver_user_id=2002,
            now=NOW,
        )

    with pytest.raises(GitHubApprovalError, match="APPROVAL_EVIDENCE_NOT_CURRENT"):
        validate_approval_evidence(
            evidence,
            repository=REPOSITORY,
            repository_id=3003,
            workflow_sha=WORKFLOW_SHA,
            workflow_run_id=4004,
            workflow_run_attempt=1,
            github_environment=ENVIRONMENT,
            reviewer_packet_digest=REVIEWER_PACKET_DIGEST,
            apply_environment_anchor_digest=ENVIRONMENT_ANCHOR_DIGEST,
            approval_authority_digest=APPROVAL_AUTHORITY_DIGEST,
            initiator_user_id=1001,
            expected_approver_user_id=2002,
            now=NOW + timedelta(minutes=5),
        )

    with pytest.raises(
        GitHubApprovalError,
        match="APPROVAL_EVIDENCE_BINDING_MISMATCH",
    ):
        validate_approval_evidence(
            evidence,
            repository=REPOSITORY,
            repository_id=3003,
            workflow_sha=WORKFLOW_SHA,
            workflow_run_id=4004,
            workflow_run_attempt=1,
            github_environment=ENVIRONMENT,
            reviewer_packet_digest=REVIEWER_PACKET_DIGEST,
            apply_environment_anchor_digest=ENVIRONMENT_ANCHOR_DIGEST,
            approval_authority_digest=APPROVAL_AUTHORITY_DIGEST,
            initiator_user_id=1001,
            expected_approver_user_id=2003,
            now=NOW,
        )

    with pytest.raises(GitHubApprovalError, match="APPROVAL_SELECTOR_INVALID"):
        _evidence(workflow_run_attempt=2)


def test_persists_once_with_private_custody(tmp_path) -> None:
    private_root = tmp_path / "private"
    controller = private_root / "materialized/controller"
    controller.mkdir(parents=True, mode=0o700)
    private_root.chmod(0o700)
    (private_root / "materialized").chmod(0o700)
    controller.chmod(0o700)
    evidence = _evidence()

    path = persist_approval_evidence(private_root, evidence)

    assert path.stat().st_mode & 0o777 == 0o600
    assert load_private_approval_evidence(private_root) == evidence
    original = path.read_bytes()
    with pytest.raises(GitHubApprovalError, match="APPROVAL_EVIDENCE_WRITE_FAILED"):
        persist_approval_evidence(private_root, evidence)
    assert path.read_bytes() == original
    assert load_private_approval_evidence(private_root) == evidence
