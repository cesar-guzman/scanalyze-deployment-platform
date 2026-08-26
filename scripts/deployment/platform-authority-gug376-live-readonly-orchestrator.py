#!/usr/bin/env python3
"""Public-safe CLI for synthetic records; no live provider is enabled here."""
from __future__ import annotations

import argparse, json, sys
from pathlib import Path


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Validate GUG-376 guarded read-only public records; live provider execution is not enabled.")
    sub = parser.add_subparsers(dest="command")
    for command in ("validate-run", "validate-handoff"):
        child = sub.add_parser(command); child.add_argument("input", type=Path)
    sub.add_parser("live", help="fail closed until a repository-attested live provider exists")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.command in (None, "live"):
        print(json.dumps({"error": "LIVE_PROVIDER_NOT_IMPLEMENTED", "status": "HUMAN_DECISION_REQUIRED"}, sort_keys=True), file=sys.stderr)
        return 2
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
    try:
        from tooling.platform_authority_gug376_live_readonly_orchestrator import validate_public_handoff, validate_run_record
        value = json.loads(args.input.read_text(encoding="utf-8"))
        result = validate_run_record(value) if args.command == "validate-run" else validate_public_handoff(value)
    except Exception:
        print(json.dumps({"error": "PUBLIC_RECORD_INVALID", "status": "HUMAN_DECISION_REQUIRED"}, sort_keys=True), file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
