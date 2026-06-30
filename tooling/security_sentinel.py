#!/usr/bin/env python3
"""Security sentinel scanner.

Scans all source files for:
- PII patterns (CURP, RFC, NSS, CLABE, Mexican phone numbers)
- Secret patterns (AWS keys, JWTs, .env credentials)
- Terraform state content
- Raw plan JSON content

Uses sentinel_allowlist.yaml for documented exceptions (NOT blanket directory exclusions).
"""

import re
import sys
from pathlib import Path

# PII patterns (Mexican financial/identity documents)
PII_PATTERNS = {
    "CURP": re.compile(r"[A-Z]{4}[0-9]{6}[HM][A-Z]{5}[A-Z0-9]{2}"),
    "RFC": re.compile(r"[A-Z&]{3,4}[0-9]{6}[A-Z0-9]{3}"),
    "NSS": re.compile(r"\b[0-9]{11}\b"),
    "CLABE": re.compile(r"\b[0-9]{18}\b"),
    "MX_PHONE": re.compile(r"\+?52[0-9]{10}"),
}

# Secret patterns
SECRET_PATTERNS = {
    "AWS_ACCESS_KEY": re.compile(r"AKIA[0-9A-Z]{16}"),
    "AWS_SECRET_KEY": re.compile(r"(?:AWS_SECRET_ACCESS_KEY|aws_secret_access_key)\s*[=:]\s*\S+"),
    "JWT_TOKEN": re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}"),
    "PRIVATE_KEY": re.compile(r"-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----"),
}

# State/plan patterns
STATE_PLAN_PATTERNS = {
    "TFSTATE_CONTENT": re.compile(r'"terraform_version"\s*:\s*"\d+\.\d+\.\d+"'),
    "TFSTATE_LINEAGE": re.compile(r'"lineage"\s*:\s*"[a-f0-9-]{36}"'),
    "RAW_PLAN_OUTPUT": re.compile(r'"resource_changes"\s*:\s*\['),
}

# File extensions to scan
SCAN_EXTENSIONS = {".py", ".json", ".md", ".yaml", ".yml", ".toml", ".tf", ".sh", ".txt", ".hcl"}

# Directories to skip (only build/cache dirs — NOT content dirs like ADR/)
SKIP_DIRS = {".git", "__pycache__", "node_modules", ".terraform", ".venv", "venv", ".pytest_cache"}


def load_allowlist(allowlist_path: Path) -> list[dict]:
    """Load sentinel allowlist from YAML (simple parser, no dependency)."""
    entries = []
    if not allowlist_path.exists():
        return entries

    current_entry: dict = {}
    with open(allowlist_path) as f:
        for line in f:
            stripped = line.strip()
            if stripped.startswith("#") or not stripped:
                continue
            if stripped.startswith("- path:"):
                if current_entry:
                    entries.append(current_entry)
                current_entry = {"path": stripped.split(":", 1)[1].strip()}
            elif ":" in stripped and current_entry:
                key, val = stripped.split(":", 1)
                key = key.strip()
                val = val.strip().strip('"')
                current_entry[key] = val

    if current_entry:
        entries.append(current_entry)

    return entries


def is_allowlisted(filepath: Path, pattern_name: str, allowlist: list[dict]) -> bool:
    """Check if a finding is in the allowlist."""
    filepath_str = str(filepath)
    for entry in allowlist:
        entry_path = entry.get("path", "")
        entry_pattern = entry.get("pattern_id", "")
        if filepath_str.endswith(entry_path) and entry_pattern == pattern_name:
            return True
    return False


def scan_file(filepath: Path, patterns: dict[str, re.Pattern]) -> list[tuple[str, int, str]]:
    """Scan a file for pattern matches. Returns [(pattern_name, line_num, masked_match)]."""
    findings = []
    try:
        with open(filepath, "r", errors="ignore") as f:
            for line_num, line in enumerate(f, 1):
                for name, pattern in patterns.items():
                    if pattern.search(line):
                        # Mask the actual match for safety
                        masked = pattern.sub(f"[{name}_REDACTED]", line.strip())[:120]
                        findings.append((name, line_num, masked))
    except (OSError, UnicodeDecodeError):
        pass
    return findings


def should_scan(filepath: Path) -> bool:
    """Determine if a file should be scanned."""
    if any(skip in filepath.parts for skip in SKIP_DIRS):
        return False
    # Skip this sentinel script itself
    if filepath.name == "security_sentinel.py":
        return False
    # Skip test files that legitimately contain pattern definitions
    if "test_" in filepath.name and "sentinel" in filepath.name:
        return False
    return filepath.suffix in SCAN_EXTENSIONS


def main():
    root = Path(".")
    allowlist = load_allowlist(Path("sentinel_allowlist.yaml"))
    all_findings: dict[str, list] = {"PII": [], "SECRETS": [], "STATE_PLAN": []}
    allowlisted_count = 0

    print("=== PII Sentinel Scan ===")
    for filepath in sorted(root.rglob("*")):
        if not filepath.is_file() or not should_scan(filepath):
            continue
        pii_results = scan_file(filepath, PII_PATTERNS)
        for name, line, masked in pii_results:
            if is_allowlisted(filepath, name, allowlist):
                allowlisted_count += 1
                print(f"  ✓ ALLOWLISTED ({name}) in {filepath}:{line}")
            else:
                all_findings["PII"].append((filepath, name, line, masked))
                print(f"  ⚠ PII ({name}) in {filepath}:{line}")

    print("\n=== Secret Sentinel Scan ===")
    for filepath in sorted(root.rglob("*")):
        if not filepath.is_file() or not should_scan(filepath):
            continue
        secret_results = scan_file(filepath, SECRET_PATTERNS)
        for name, line, masked in secret_results:
            if is_allowlisted(filepath, name, allowlist):
                allowlisted_count += 1
                print(f"  ✓ ALLOWLISTED ({name}) in {filepath}:{line}")
            else:
                all_findings["SECRETS"].append((filepath, name, line, masked))
                print(f"  🔑 SECRET ({name}) in {filepath}:{line}")

    print("\n=== State/Plan Sentinel Scan ===")
    for filepath in sorted(root.rglob("*")):
        if not filepath.is_file() or not should_scan(filepath):
            continue
        state_results = scan_file(filepath, STATE_PLAN_PATTERNS)
        for name, line, masked in state_results:
            if is_allowlisted(filepath, name, allowlist):
                allowlisted_count += 1
                print(f"  ✓ ALLOWLISTED ({name}) in {filepath}:{line}")
            else:
                all_findings["STATE_PLAN"].append((filepath, name, line, masked))
                print(f"  📋 STATE/PLAN ({name}) in {filepath}:{line}")

    # Summary
    total = sum(len(v) for v in all_findings.values())
    print(f"\n=== Sentinel Results ===")
    print(f"  Findings:    {total}")
    print(f"  Allowlisted: {allowlisted_count}")
    for category, items in all_findings.items():
        if items:
            print(f"  {category}: {len(items)} findings")

    # PII and secrets are hard fails; state/plan are warnings
    hard_fails = len(all_findings["PII"]) + len(all_findings["SECRETS"])
    if hard_fails > 0:
        print(f"\nFAIL: {hard_fails} PII/secret findings (not allowlisted)")
        sys.exit(1)
    elif all_findings["STATE_PLAN"]:
        print(f"\nWARN: {len(all_findings['STATE_PLAN'])} state/plan findings (review required)")
        sys.exit(0)
    else:
        print("\nPASS: No unallowlisted PII, secrets, or state content found")
        sys.exit(0)


if __name__ == "__main__":
    main()
