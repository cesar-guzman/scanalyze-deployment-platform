#!/usr/bin/env python3
"""Offline GUG-385 certification entrypoint; no AWS/provider factory is shipped."""
from __future__ import annotations
import argparse, json, sys; from pathlib import Path
ROOT = Path(__file__).resolve().parents[2]; sys.path.insert(0, str(ROOT))
from tooling.platform_authority_gug376_identity_center_inventory_collector import CollectorError, certify, read_private_json  # noqa: E402
def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__); commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("capture", help="STOP: a reviewed private live factory is required")
    command = commands.add_parser("certify", help="certify two owner-only snapshots offline")
    command.add_argument("--private-root", type=Path, required=True); command.add_argument("--first", required=True); command.add_argument("--second", required=True); command.add_argument("--expected-plan-binding-digest", required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "capture": raise CollectorError("STOP_LIVE_ORCHESTRATOR_NOT_IMPLEMENTED")
        receipt = certify(read_private_json(args.private_root, args.first), read_private_json(args.private_root, args.second), expected_plan_binding_digest=args.expected_plan_binding_digest)
        print(json.dumps(receipt, sort_keys=True, separators=(",", ":"))); return 0
    except CollectorError as exc:
        print(json.dumps({"status": "BLOCKED", "code": exc.code}, sort_keys=True, separators=(",", ":")), file=sys.stderr); return 2
if __name__ == "__main__": raise SystemExit(main())
