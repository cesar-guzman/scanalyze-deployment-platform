#!/usr/bin/env python3
"""Offline GUG-384 capture/certify entrypoint; no provider factory is shipped."""
from __future__ import annotations
import argparse, json, sys
from pathlib import Path
ROOT = Path(__file__).resolve().parents[2]; sys.path.insert(0, str(ROOT))
from tooling.platform_authority_gug376_authority_inventory_collector import CollectorError, certify, read_private_json  # noqa: E402
def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__); commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("capture", help="STOP: a reviewed private factory is required")
    command = commands.add_parser("certify", help="certify two owner-only captures offline")
    command.add_argument("--private-root", type=Path, required=True)
    command.add_argument("--first", required=True); command.add_argument("--second", required=True); command.add_argument("--expected-runtime-target-digest", required=True); command.add_argument("--expected-facts-digest")
    args = parser.parse_args(argv)
    try:
        if args.command == "capture": raise CollectorError("STOP_LIVE_ORCHESTRATOR_NOT_IMPLEMENTED")
        receipt = certify(read_private_json(args.private_root, args.first), read_private_json(args.private_root, args.second), expected_runtime_target_digest=args.expected_runtime_target_digest, expected_facts_digest=args.expected_facts_digest)
        print(json.dumps(receipt, sort_keys=True, separators=(",", ":"))); return 0
    except CollectorError as exc:
        print(json.dumps({"status": "BLOCKED", "code": exc.code}, sort_keys=True, separators=(",", ":")), file=sys.stderr); return 2
if __name__ == "__main__":
    raise SystemExit(main())
