#!/usr/bin/env python3
"""Forbidden pattern detection for platform code.

Scans modules/ and roots/ for patterns forbidden by the Ownership Matrix §9.
Semantically scoped: only checks platform code, not provider declarations or tests.
"""

import re
import sys
from pathlib import Path


# Forbidden patterns with context
FORBIDDEN_PATTERNS = [
    {
        "name": "terraform_remote_state",
        "pattern": re.compile(r'data\s+"terraform_remote_state"'),
        "severity": "ERROR",
        "reason": "Cross-layer coupling forbidden (ADR-006 rev3). Use SSM contracts.",
    },
    {
        "name": "hardcoded_account_id",
        "pattern": re.compile(r'"[^"]*\b\d{12}\b[^"]*"'),
        "severity": "ERROR",
        "reason": "Hardcoded account IDs are not replicable across deployments.",
        "exclude_context": ["pattern", "regex", "test", "$defs", "description", "error_message", "validation", "condition", "match"],
    },
    {
        "name": "timestamp_function",
        "pattern": re.compile(r'\btimestamp\(\)'),
        "severity": "ERROR",
        "reason": "Non-deterministic plans (ADR-010 rev3).",
    },
    {
        "name": "terraform_workspace",
        "pattern": re.compile(r'\bterraform\.workspace\b'),
        "severity": "ERROR",
        "reason": "Workspace-based isolation forbidden. Use deployment_id.",
    },
    {
        "name": "check_block_contracts",
        "pattern": re.compile(r'\bcheck\s*\{'),
        "severity": "WARNING",
        "reason": "check blocks are non-blocking (only warnings). Use precondition for fail-closed (ADR-006 rev3).",
        "context_required": "contract",
    },
    {
        "name": "ecs_register_task",
        "pattern": re.compile(r'aws\s+ecs\s+register-task-definition'),
        "severity": "ERROR",
        "reason": "Pipeline must not register task definitions. TF is sole owner (ADR-010 rev3).",
    },
    {
        "name": "ssm_put_parameter_contract",
        "pattern": re.compile(r'aws\s+ssm\s+put-parameter.*contract'),
        "severity": "ERROR",
        "reason": "Scripts must not write SSM contracts. Producer root is sole writer (ADR-006 rev3).",
    },
]


def scan_file(filepath: Path) -> list[dict]:
    """Scan a single file for forbidden patterns."""
    findings = []
    try:
        content = filepath.read_text(errors="ignore")
        lines = content.splitlines()
    except (OSError, UnicodeDecodeError):
        return findings

    for rule in FORBIDDEN_PATTERNS:
        for line_num, line in enumerate(lines, 1):
            # Skip comment lines to avoid false positives from documentation
            stripped = line.strip()
            if stripped.startswith("#") or stripped.startswith("//") or stripped.startswith("*"):
                continue

            if rule["pattern"].search(line):
                # Check exclusion contexts
                exclude_contexts = rule.get("exclude_context", [])
                if any(ctx in line.lower() for ctx in exclude_contexts):
                    continue

                # Check if context_required matches the file path
                context_required = rule.get("context_required")
                if context_required and context_required not in str(filepath).lower():
                    continue

                findings.append({
                    "file": str(filepath),
                    "line": line_num,
                    "rule": rule["name"],
                    "severity": rule["severity"],
                    "reason": rule["reason"],
                    "content": line.strip()[:100],
                })

    return findings


def main():
    scan_dirs = sys.argv[1:] if len(sys.argv) > 1 else ["modules/", "roots/"]
    all_findings = []

    print("=== Forbidden Pattern Detection ===")
    print(f"Scanning: {', '.join(scan_dirs)}")

    for scan_dir in scan_dirs:
        scan_path = Path(scan_dir)
        if not scan_path.exists():
            print(f"  SKIP: {scan_dir} does not exist")
            continue

        for filepath in sorted(scan_path.rglob("*")):
            if not filepath.is_file():
                continue
            if filepath.suffix not in {".tf", ".sh", ".py", ".json", ".yaml", ".yml"}:
                continue

            findings = scan_file(filepath)
            all_findings.extend(findings)

    if all_findings:
        errors = [f for f in all_findings if f["severity"] == "ERROR"]
        warnings = [f for f in all_findings if f["severity"] == "WARNING"]

        for f in all_findings:
            icon = "❌" if f["severity"] == "ERROR" else "⚠️"
            print(f"  {icon} [{f['severity']}] {f['rule']} in {f['file']}:{f['line']}")
            print(f"     {f['reason']}")

        print(f"\n{len(errors)} errors, {len(warnings)} warnings")
        if errors:
            sys.exit(1)
    else:
        print("  No forbidden patterns found.")

    sys.exit(0)


if __name__ == "__main__":
    main()
