#!/usr/bin/env python3
"""Offline GUG-386 dual-domain handoff entrypoint; no live runner is shipped."""
from __future__ import annotations

import argparse, json, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]; sys.path.insert(0, str(ROOT))

from tooling.platform_authority_gug383_dual_domain_inventory_handoff import (  # noqa: E402
    HandoffError,
    compose,
    read_json,
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("capture", help="STOP: no live orchestrator is implemented")
    command = commands.add_parser("compose", help="compose a pinned private envelope offline")
    command.add_argument("--authority-receipt", type=Path, required=True); command.add_argument("--identity-center-receipt", type=Path, required=True); command.add_argument("--run-envelope", type=Path, required=True)
    command.add_argument("--expected-source-commit-sha", required=True); command.add_argument("--expected-source-tree-sha", required=True)
    command.add_argument("--expected-window-digest", required=True); command.add_argument("--expected-authorization-digest", required=True)
    command.add_argument("--expected-run-id-digest", required=True); command.add_argument("--expected-private-run-digest", required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "capture":
            raise HandoffError("STOP_LIVE_ORCHESTRATOR_NOT_IMPLEMENTED")
        handoff = compose(
            read_json(args.authority_receipt), read_json(args.identity_center_receipt), read_json(args.run_envelope),
            expected_source_commit_sha=args.expected_source_commit_sha,
            expected_source_tree_sha=args.expected_source_tree_sha,
            expected_window_digest=args.expected_window_digest,
            expected_authorization_digest=args.expected_authorization_digest,
            expected_run_id_digest=args.expected_run_id_digest,
            expected_private_run_digest=args.expected_private_run_digest,
        )
        print(json.dumps(handoff, sort_keys=True, separators=(",", ":")))
        return 0
    except HandoffError as exc:
        print(json.dumps({"status": "BLOCKED", "code": exc.code}, sort_keys=True, separators=(",", ":")), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
