#!/usr/bin/env python3
"""Generate a release graph for Scanalyze OCI artifacts.

The release graph records the lineage of every image published in a release:
commit, service, tag, digest, base image digest, ECR repo, scan status,
SBOM path, signature status, and timestamp.

Usage:
    python scripts/supply-chain/release-graph.py \
        --deployment-id dep_01SYNTH3T1CABC0XAMP0EHABCD \
        --commit abc123 \
        --tag sha-abc123def456 \
        --base-image-digest sha256:000...000 \
        --output release-graph.json

    python scripts/supply-chain/release-graph.py --dry-run
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

SERVICES = [
    "ingest-api",
    "ocr-worker",
    "postprocess-worker",
    "classifier-worker",
    "bank-worker",
    "personal-worker",
    "gov-worker",
]


def build_graph(args: argparse.Namespace) -> dict:
    timestamp = datetime.now(timezone.utc).isoformat()

    entries = []
    for service in SERVICES:
        entry = {
            "service": service,
            "commit": args.commit,
            "tag": args.tag,
            "image_digest": f"sha256:{'0' * 64}",  # placeholder until actual push
            "base_image_digest": args.base_image_digest,
            "ecr_repo": f"{args.ecr_prefix}/{service}" if args.ecr_prefix else f"scanalyze/{service}",
            "scan_status": "SKIPPED" if args.dry_run else "PENDING",
            "sbom_path": None,
            "signature_status": "SKIPPED" if args.dry_run else "PENDING",
            "timestamp": timestamp,
        }
        entries.append(entry)

    return {
        "schema_version": "1",
        "deployment_id": args.deployment_id,
        "release_tag": args.tag,
        "commit": args.commit,
        "base_image_digest": args.base_image_digest,
        "generated_at": timestamp,
        "dry_run": args.dry_run,
        "services": entries,
        "supply_chain_tools": {
            "cosign": _tool_status("cosign"),
            "syft": _tool_status("syft"),
            "trivy": _tool_status("trivy"),
        },
    }


def _tool_status(tool: str) -> str:
    import shutil

    if shutil.which(tool):
        return "available"
    return "not_installed"


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate Scanalyze release graph")
    parser.add_argument("--deployment-id", default="dep_01SYNTH3T1CABC0XAMP0EHABCD")
    parser.add_argument("--commit", default="synthetic")
    parser.add_argument("--tag", default="synthetic-dry-run")
    parser.add_argument("--base-image-digest", default=f"sha256:{'0' * 64}")
    parser.add_argument("--ecr-prefix", default="")
    parser.add_argument("--output", type=Path, default=None)
    parser.add_argument("--dry-run", action="store_true", default=True)
    parser.add_argument("--no-dry-run", action="store_false", dest="dry_run")
    args = parser.parse_args()

    graph = build_graph(args)

    output_json = json.dumps(graph, indent=2)

    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(output_json + "\n")
        print(f"Release graph written to: {args.output}")
    else:
        print(output_json)

    # Report tool availability
    tools = graph["supply_chain_tools"]
    for tool, status in tools.items():
        if status == "available":
            print(f"  {tool}: AVAILABLE", file=sys.stderr)
        else:
            print(f"  {tool}: SKIPPED (not installed)", file=sys.stderr)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
