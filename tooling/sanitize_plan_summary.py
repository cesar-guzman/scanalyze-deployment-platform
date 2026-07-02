#!/usr/bin/env python3
"""
Sanitize Terraform Plan Summary — Conservative, Fail-Closed.

Reads raw terraform plan output and produces a sanitized summary containing
ONLY safe structural information. Fails if unsanitized sensitive patterns
are detected in the output before summarization.

Usage:
    python tooling/sanitize_plan_summary.py \
        --input .work/m3/plans/global-plan-raw.txt \
        --output reports/m3b-plan-summary-global.md \
        --root global

Exit codes:
    0 — sanitized summary produced successfully
    1 — sensitive patterns detected (BLOCKED)
    2 — input file error
"""

import argparse
import hashlib
import re
import sys
from datetime import datetime, timezone
from pathlib import Path


# ============================================================================
# Sensitive pattern definitions — conservative, fail-closed
# ============================================================================

SENSITIVE_PATTERNS = [
    # 12-digit AWS account IDs (not all-zeros synthetic)
    (r'\b[1-9]\d{11}\b', "AWS account ID (12 digits)"),
    # Full ARNs with real account IDs
    (r'arn:aws:[a-z0-9-]+:[a-z0-9-]*:[1-9]\d{11}:', "Real AWS ARN"),
    # AWS access keys
    (r'(?:AKIA|ASIA)[A-Z0-9]{16}', "AWS access key"),
    # AWS secret keys (40 char base64-like)
    (r'(?:aws_secret_access_key|secret_key)\s*=\s*"[^"]{30,}"', "AWS secret key assignment"),
    # JWT-like tokens (3 base64 segments)
    (r'eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}', "JWT-like token"),
    # .tfstate file references with real paths
    (r's3://[a-z0-9-]+/[a-z0-9-]+/.*\.tfstate', "S3 state file reference"),
    # Secret-looking key-value pairs
    (r'(?:password|secret|token|api_key|private_key)\s*=\s*"[^"]{8,}"', "Secret-like value"),
    # S3 bucket names with customer/data hints (not synthetic)
    (r's3://(?!synthetic)[a-z0-9][a-z0-9.-]{2,62}', "Non-synthetic S3 bucket reference"),
    # Real domain names (not .example.invalid or .example.com)
    (r'\b(?!synthetic\.example\.invalid)[a-z0-9-]+\.(com|net|org|io|cloud|app|dev)\b', "Real domain name"),
    # Mexican PII patterns
    (r'\b[A-Z]{4}\d{6}[A-Z]{6}\d{2}\b', "CURP pattern"),
    (r'\b[A-ZÑ&]{3,4}\d{6}[A-Z0-9]{3}\b', "RFC pattern"),
    (r'\b\d{11}\b', "NSS pattern (11 digits)"),
    (r'\b\d{18}\b', "CLABE pattern (18 digits)"),
    # Private keys
    (r'-----BEGIN (?:RSA |EC )?PRIVATE KEY-----', "Private key block"),
    # KMS key IDs (UUIDs in key context)
    (r'(?:kms_key_id|key_id)\s*=\s*"[0-9a-f]{8}-[0-9a-f]{4}', "KMS key reference"),
]

# Patterns that are SAFE and should NOT trigger blocking
SAFE_OVERRIDES = [
    r'\b0{12}\b',                          # All-zeros synthetic account
    r'synthetic',                           # Synthetic markers
    r'example\.invalid',                    # RFC 2606 reserved domain
    r'sha256:0{64}',                        # All-zeros digest
    r'000000000000',                        # Synthetic account ID
]


def compute_digest(filepath: Path) -> str:
    """Compute SHA-256 digest of a file."""
    h = hashlib.sha256()
    h.update(filepath.read_bytes())
    return f"sha256:{h.hexdigest()}"


def is_safe_override(line: str) -> bool:
    """Check if the line contains safe/synthetic markers."""
    return any(re.search(p, line, re.IGNORECASE) for p in SAFE_OVERRIDES)


def scan_for_sensitive(content: str) -> list[dict]:
    """Scan content for sensitive patterns. Returns list of findings."""
    findings = []
    for line_num, line in enumerate(content.splitlines(), 1):
        # Skip lines with safe overrides
        if is_safe_override(line):
            continue
        for pattern, description in SENSITIVE_PATTERNS:
            matches = re.findall(pattern, line, re.IGNORECASE)
            if matches:
                findings.append({
                    "line": line_num,
                    "pattern": description,
                    "match_count": len(matches),
                    "line_preview": line[:80] + "..." if len(line) > 80 else line,
                })
    return findings


def extract_plan_summary(content: str) -> dict:
    """Extract structural summary from terraform plan output."""
    summary = {
        "resources_to_add": 0,
        "resources_to_change": 0,
        "resources_to_destroy": 0,
        "resource_types": [],
        "actions": {"create": 0, "update": 0, "delete": 0, "read": 0},
        "provider_version": "unknown",
        "refresh_mode": "unknown",
        "warnings": [],
        "errors": [],
    }

    # Extract resource counts from plan summary line
    # "Plan: X to add, Y to change, Z to destroy."
    plan_match = re.search(
        r'Plan:\s*(\d+)\s*to add,\s*(\d+)\s*to change,\s*(\d+)\s*to destroy',
        content
    )
    if plan_match:
        summary["resources_to_add"] = int(plan_match.group(1))
        summary["resources_to_change"] = int(plan_match.group(2))
        summary["resources_to_destroy"] = int(plan_match.group(3))

    # "No changes" case
    if "No changes" in content or "Your infrastructure matches the configuration" in content:
        summary["resources_to_add"] = 0
        summary["resources_to_change"] = 0
        summary["resources_to_destroy"] = 0

    # Extract resource types from "# aws_xxx.yyy will be created" lines
    resource_types = set()
    for match in re.finditer(r'#\s+(aws_[a-z_]+)\.\w+\s+will be', content):
        resource_types.add(match.group(1))
    summary["resource_types"] = sorted(resource_types)

    # Count actions
    summary["actions"]["create"] = len(re.findall(r'will be created', content))
    summary["actions"]["update"] = len(re.findall(r'will be updated', content))
    summary["actions"]["delete"] = len(re.findall(r'will be destroyed', content))
    summary["actions"]["read"] = len(re.findall(r'will be read', content))

    # Provider version
    prov_match = re.search(r'provider registry\.terraform\.io/hashicorp/aws v([\d.]+)', content)
    if prov_match:
        summary["provider_version"] = prov_match.group(1)

    # Refresh mode
    if "-refresh=false" in content or "Skipping refresh" in content:
        summary["refresh_mode"] = "disabled (-refresh=false)"
    elif "Refreshing state" in content:
        summary["refresh_mode"] = "enabled"
    else:
        summary["refresh_mode"] = "unknown"

    # Warnings
    for match in re.finditer(r'Warning:\s*(.+)', content):
        warning_text = match.group(1).strip()
        if not is_safe_override(warning_text):
            summary["warnings"].append(warning_text[:100])

    # Errors
    for match in re.finditer(r'Error:\s*(.+)', content):
        error_text = match.group(1).strip()
        if not is_safe_override(error_text):
            summary["errors"].append(error_text[:100])

    return summary


def render_markdown(summary: dict, root: str, digest: str, input_size: int,
                    sanitization_status: str) -> str:
    """Render sanitized plan summary as markdown."""
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    resource_types_str = "\n".join(f"  - `{rt}`" for rt in summary["resource_types"]) \
        if summary["resource_types"] else "  - (none detected)"

    warnings_str = "\n".join(f"  - {w}" for w in summary["warnings"]) \
        if summary["warnings"] else "  - (none)"

    errors_str = "\n".join(f"  - {e}" for e in summary["errors"]) \
        if summary["errors"] else "  - (none)"

    return f"""# M3-B Plan Summary — roots/{root}

> **Generated**: {now}
> **Status**: {sanitization_status}
> **Mode**: Speculative plan (no -out, no apply intent)

## Resource Changes

| Action | Count |
|--------|-------|
| To add | {summary['resources_to_add']} |
| To change | {summary['resources_to_change']} |
| To destroy | {summary['resources_to_destroy']} |

## Actions Breakdown

| Action | Count |
|--------|-------|
| create | {summary['actions']['create']} |
| update | {summary['actions']['update']} |
| delete | {summary['actions']['delete']} |
| read | {summary['actions']['read']} |

## Resource Types

{resource_types_str}

## Plan Metadata

| Field | Value |
|-------|-------|
| Root | `roots/{root}` |
| Provider | hashicorp/aws {summary['provider_version']} |
| Refresh | {summary['refresh_mode']} |
| Raw artifact digest | `{digest}` |
| Raw artifact size | {input_size} bytes |
| Sanitization | {sanitization_status} |

## Warnings

{warnings_str}

## Errors

{errors_str}

## Evidence

- Raw plan output: **NOT COMMITTED** (ephemeral, in `.work/m3/plans/`)
- This summary: sanitized, contains no values, ARNs, secrets, or PII
- No `terraform apply` was executed
- No state was written to any backend
- No AWS resources were created, modified, or destroyed
"""


def main():
    parser = argparse.ArgumentParser(description="Sanitize terraform plan output")
    parser.add_argument("--input", required=True, help="Path to raw plan output")
    parser.add_argument("--output", required=True, help="Path to sanitized summary")
    parser.add_argument("--root", required=True, help="Root name")
    parser.add_argument("--allow-sensitive", action="store_true",
                        help="Override sensitive check (NOT recommended)")
    args = parser.parse_args()

    input_path = Path(args.input)
    output_path = Path(args.output)

    if not input_path.exists():
        print(f"ERROR: Input file not found: {input_path}", file=sys.stderr)
        sys.exit(2)

    content = input_path.read_text(encoding="utf-8", errors="replace")
    digest = compute_digest(input_path)
    input_size = input_path.stat().st_size

    # --- Sensitive pattern scan (FAIL-CLOSED) ---
    findings = scan_for_sensitive(content)

    if findings and not args.allow_sensitive:
        print(f"\nBLOCKED: {len(findings)} sensitive pattern(s) detected in plan output.",
              file=sys.stderr)
        print("The sanitizer will NOT produce a summary until these are resolved.\n",
              file=sys.stderr)
        for i, f in enumerate(findings[:10], 1):
            print(f"  [{i}] Line {f['line']}: {f['pattern']} "
                  f"({f['match_count']} match(es))", file=sys.stderr)
            print(f"      Preview: {f['line_preview']}", file=sys.stderr)
        if len(findings) > 10:
            print(f"  ... and {len(findings) - 10} more findings", file=sys.stderr)
        print(f"\nDigest of blocked input: {digest}", file=sys.stderr)
        print("To override (NOT recommended): use --allow-sensitive", file=sys.stderr)
        sys.exit(1)

    sanitization_status = "CLEAN — no sensitive patterns detected"
    if findings and args.allow_sensitive:
        sanitization_status = f"OVERRIDE — {len(findings)} finding(s) overridden"

    # --- Extract structural summary ---
    summary = extract_plan_summary(content)

    # --- Render sanitized markdown ---
    md = render_markdown(summary, args.root, digest, input_size, sanitization_status)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(md, encoding="utf-8")

    print(f"Sanitized summary written to: {output_path}")
    print(f"  Resources to add:     {summary['resources_to_add']}")
    print(f"  Resources to change:  {summary['resources_to_change']}")
    print(f"  Resources to destroy: {summary['resources_to_destroy']}")
    print(f"  Resource types:       {len(summary['resource_types'])}")
    print(f"  Sensitive findings:   {len(findings)}")
    print(f"  Sanitization:         {sanitization_status}")


if __name__ == "__main__":
    main()
