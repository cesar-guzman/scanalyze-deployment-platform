#!/usr/bin/env python3
"""Materialize or validate exact GitHub Environment approval evidence."""
from __future__ import annotations

import argparse
import os
import sys
from datetime import UTC, datetime
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from tooling.nonprod_live_github_approval import (  # noqa: E402
    GitHubApprovalError,
    build_approval_evidence,
    fetch_review_history,
    fetch_workflow_run,
    load_private_approval_evidence,
    persist_approval_evidence,
    validate_approval_evidence,
)


def _positive_int(value: str) -> int:
    parsed = int(value)
    if parsed < 1:
        raise argparse.ArgumentTypeError("value must be positive")
    return parsed


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("materialize", "validate"):
        command = commands.add_parser(name)
        command.add_argument("--private-root", type=Path, required=True)
        command.add_argument("--repository", required=True)
        command.add_argument("--repository-id", type=_positive_int, required=True)
        command.add_argument("--workflow-sha", required=True)
        command.add_argument("--run-id", type=_positive_int, required=True)
        command.add_argument("--run-attempt", type=_positive_int, required=True)
        command.add_argument("--environment", required=True)
        command.add_argument("--reviewer-packet-digest", required=True)
        command.add_argument("--apply-environment-anchor-digest", required=True)
        command.add_argument("--approval-authority-digest", required=True)
        command.add_argument("--initiator-user-id", type=_positive_int, required=True)
        command.add_argument(
            "--expected-approver-user-id", type=_positive_int, required=True
        )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    now = datetime.now(UTC).replace(microsecond=0)
    try:
        if args.command == "materialize":
            token = os.environ.pop("GH_TOKEN", "")
            try:
                workflow_run = fetch_workflow_run(
                    args.repository, args.run_id, token
                )
                reviews = fetch_review_history(args.repository, args.run_id, token)
            finally:
                token = ""
            evidence = build_approval_evidence(
                repository=args.repository,
                repository_id=args.repository_id,
                workflow_sha=args.workflow_sha,
                workflow_run_id=args.run_id,
                workflow_run_attempt=args.run_attempt,
                github_environment=args.environment,
                reviewer_packet_digest=args.reviewer_packet_digest,
                apply_environment_anchor_digest=(
                    args.apply_environment_anchor_digest
                ),
                approval_authority_digest=args.approval_authority_digest,
                initiator_user_id=args.initiator_user_id,
                expected_approver_user_id=args.expected_approver_user_id,
                workflow_run=workflow_run,
                reviews=reviews,
                observed_at=now,
            )
            persist_approval_evidence(args.private_root, evidence)
        else:
            evidence = load_private_approval_evidence(args.private_root)
            validate_approval_evidence(
                evidence,
                repository=args.repository,
                repository_id=args.repository_id,
                workflow_sha=args.workflow_sha,
                workflow_run_id=args.run_id,
                workflow_run_attempt=args.run_attempt,
                github_environment=args.environment,
                reviewer_packet_digest=args.reviewer_packet_digest,
                apply_environment_anchor_digest=(
                    args.apply_environment_anchor_digest
                ),
                approval_authority_digest=args.approval_authority_digest,
                initiator_user_id=args.initiator_user_id,
                expected_approver_user_id=args.expected_approver_user_id,
                now=now,
            )
    except GitHubApprovalError as exc:
        print(f"FAIL: {exc.code}", file=sys.stderr)
        return 1
    print("PASS: exact independent GitHub Environment approval verified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
