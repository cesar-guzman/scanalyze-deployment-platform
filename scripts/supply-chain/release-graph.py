#!/usr/bin/env python3
"""Render a deterministic planning-only release inventory.

This command is intentionally incapable of producing promotion authority. The
only release authority is a verified release.v2 manifest plus its signed VSA,
evaluated by tooling/release_policy_gate.py.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


SERVICES = (
    "scanalyze-ingest-api",
    "scanalyze-ocr-worker",
    "scanalyze-postprocess-worker",
    "scanalyze-classifier-worker",
    "scanalyze-bank-worker",
    "scanalyze-personal-worker",
    "scanalyze-gov-worker",
)
RUNTIME_ARTIFACTS = (
    "identity-pre-token-lambda",
    "identity-control-processor-lambda",
    "scanalyze-frontend-ui",
)


def planning_inventory() -> dict[str, object]:
    return {
        "schema_version": "release-planning-inventory.v1",
        "classification": "planning-only",
        "eligible_for_promotion": False,
        "production_status": "NO-GO",
        "artifacts": list(SERVICES + RUNTIME_ARTIFACTS),
        "required_evidence": [
            "immutable artifact digest",
            "SPDX 2.3 JSON SBOM",
            "vulnerability scan",
            "SLSA provenance",
            "signature bundle",
            "signed release verification summary",
        ],
        "authority": "tooling/release_policy_gate.py",
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--no-dry-run", action="store_true")
    parser.add_argument("--output", type=Path)
    args, unknown = parser.parse_known_args(argv)

    if unknown:
        parser.error("legacy release graph arguments are no longer accepted")
    if args.no_dry_run or not args.dry_run:
        print(
            "ERROR: the legacy release graph cannot authorize a release; use "
            "tooling/release_policy_gate.py with complete signed evidence",
            file=sys.stderr,
        )
        return 2

    rendered = json.dumps(planning_inventory(), indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.write_text(rendered, encoding="utf-8")
    else:
        sys.stdout.write(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
