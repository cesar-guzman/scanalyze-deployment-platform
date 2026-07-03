#!/usr/bin/env python3
"""
lint_cicd_safety.py — Static safety linter for CI/CD layer

Enforces Platform v2 rules:
  1. No Provider = "ECS" deploy action in pipelines
  2. No Provider = "CodeDeployToECS" in pipelines
  3. No imagedefinitions.json consumed by Deploy stage
  4. No ecs:* in IAM policies
  5. No iam:PassRole with Resource "*"
  6. No hardcoded ECS cluster names (pattern: <ULID>-cluster or <name>-cluster)
  7. No hardcoded CloudFront distribution IDs (pattern: E[A-Z0-9]{13})
  8. No hardcoded Cognito IDs (pattern: us-east-1_*)
  9. Image tags without @sha256 digest in services layer

Exit code 0 = pass, 1 = findings.
"""

import re
import sys
from pathlib import Path

FINDINGS: list[dict] = []


def finding(severity: str, file: str, line: int, rule: str, message: str):
    FINDINGS.append({
        "severity": severity,
        "file": str(file),
        "line": line,
        "rule": rule,
        "message": message,
    })


def scan_file(filepath: Path):
    """Scan a single .tf file for policy violations."""
    try:
        content = filepath.read_text()
    except (PermissionError, UnicodeDecodeError):
        return

    lines = content.splitlines()

    for i, line in enumerate(lines, 1):
        stripped = line.strip()

        # Skip comments
        if stripped.startswith("#") or stripped.startswith("//"):
            continue

        # Rule 1: No ECS deploy provider
        if re.search(r'provider\s*=\s*"ECS"', line):
            finding("BLOCKER", filepath, i, "CICD-001",
                    "Provider = \"ECS\" deploy action detected. "
                    "Pipeline must NOT deploy to ECS. Terraform owns ECS services.")

        # Rule 2: No CodeDeployToECS
        if re.search(r'provider\s*=\s*"CodeDeployToECS"', line):
            finding("BLOCKER", filepath, i, "CICD-002",
                    "Provider = \"CodeDeployToECS\" detected. "
                    "CodeDeploy ECS blue/green mutates task definitions.")

        # Rule 3: imagedefinitions.json in Deploy context
        if "imagedefinitions" in line and "Deploy" in content[max(0, content.find(line) - 500):content.find(line) + 500]:
            # Only flag if near a Deploy stage, not in buildspec metadata
            if re.search(r'category\s*=\s*"Deploy"', content):
                if "FileName" in line and "imagedefinitions" in line:
                    finding("BLOCKER", filepath, i, "CICD-003",
                            "imagedefinitions.json used as Deploy stage input. "
                            "This enables implicit register-task-definition.")

        # Rule 4: ecs:* wildcard
        if re.search(r'"ecs:\*"', line):
            finding("BLOCKER", filepath, i, "CICD-004",
                    "ecs:* wildcard in IAM policy. "
                    "Allows register-task-definition and update-service.")

        # Rule 5: iam:PassRole with Resource "*"
        if "iam:PassRole" in line:
            # Check if Resource is "*" nearby
            context = "\n".join(lines[max(0, i - 5):min(len(lines), i + 10)])
            if re.search(r'resources?\s*=\s*\[?\s*"\*"\s*\]?', context, re.IGNORECASE):
                finding("BLOCKER", filepath, i, "CICD-005",
                        "iam:PassRole with Resource \"*\". "
                        "Must be scoped to specific CI/CD role ARNs.")

        # Rule 6: Hardcoded cluster names
        if re.search(r'[A-Z0-9]{26}-cluster', line) and not stripped.startswith("#"):
            finding("WARNING", filepath, i, "CICD-006",
                    "Hardcoded cluster name detected. "
                    "Must come from platform contract, not tfvars.")

        # Rule 7: Hardcoded CloudFront distribution IDs
        if re.search(r'"E[A-Z0-9]{13}"', line):
            finding("WARNING", filepath, i, "CICD-007",
                    "Hardcoded CloudFront distribution ID. "
                    "Must come from edge contract output.")

        # Rule 8: Hardcoded Cognito IDs
        if re.search(r'us-east-1_[A-Za-z0-9]{9}', line) and not stripped.startswith("#"):
            finding("WARNING", filepath, i, "CICD-008",
                    "Hardcoded Cognito User Pool ID. "
                    "Must come from edge-identity contract output.")

        # Rule 9: Image tag without digest in services
        if "services" in str(filepath):
            if re.search(r'image\s*=', line) and "@sha256:" not in line:
                if not re.search(r'var\.|local\.|each\.|module\.', line):
                    finding("WARNING", filepath, i, "CICD-009",
                            "Image reference without @sha256: digest. "
                            "Services layer must use digest-pinned images.")


def scan_buildspec(filepath: Path):
    """Scan buildspec YAML for deploy-related patterns."""
    try:
        content = filepath.read_text()
    except (PermissionError, UnicodeDecodeError):
        return

    lines = content.splitlines()
    for i, line in enumerate(lines, 1):
        # update-service or register-task-definition in buildspec
        if "update-service" in line:
            finding("BLOCKER", filepath, i, "CICD-010",
                    "ecs update-service in buildspec. "
                    "Buildspec must only build/push, not deploy.")

        if "register-task-definition" in line:
            finding("BLOCKER", filepath, i, "CICD-011",
                    "register-task-definition in buildspec. "
                    "Terraform owns task definitions.")


def main():
    # Paths to scan
    scan_roots = []

    # CI/CD module (new v2)
    cicd_v2 = Path(__file__).parent.parent / "modules" / "cicd"
    if cicd_v2.exists():
        scan_roots.append(cicd_v2)

    # CI/CD brownfield (original)
    cicd_brownfield = Path(__file__).parent.parent.parent / "scanalyze-micros" / "ci-cd-micros"
    if cicd_brownfield.exists():
        scan_roots.append(cicd_brownfield)

    # Services module
    services = Path(__file__).parent.parent / "modules" / "services"
    if services.exists():
        scan_roots.append(services)

    if not scan_roots:
        print("⚠ No scan roots found")
        sys.exit(0)

    for root in scan_roots:
        for tf_file in root.rglob("*.tf"):
            if ".terraform" in str(tf_file):
                continue
            scan_file(tf_file)

        for buildspec in root.rglob("buildspec*.yml"):
            scan_buildspec(buildspec)

    # Report
    blockers = [f for f in FINDINGS if f["severity"] == "BLOCKER"]
    warnings = [f for f in FINDINGS if f["severity"] == "WARNING"]

    # Separate brownfield vs v2 findings
    v2_blockers = [f for f in blockers if "ci-cd-micros" not in f["file"]]
    brownfield_blockers = [f for f in blockers if "ci-cd-micros" in f["file"]]

    print(f"\n{'='*70}")
    print(f"CI/CD Safety Lint Results")
    print(f"{'='*70}")
    print(f"Scanned: {len(scan_roots)} root(s)")
    print(f"V2 Blockers: {len(v2_blockers)}")
    print(f"Brownfield Blockers: {len(brownfield_blockers)} (informational)")
    print(f"Warnings: {len(warnings)}")
    print(f"{'='*70}\n")

    if v2_blockers:
        print("── V2 (Platform v2) Findings ──")
        for f in v2_blockers:
            print(f"🔴 [{f['rule']}] {f['file']}:{f['line']}")
            print(f"   {f['message']}\n")

    if brownfield_blockers:
        print("── Brownfield (ci-cd-micros, informational) ──")
        for f in brownfield_blockers:
            print(f"ℹ️  [{f['rule']}] {f['file']}:{f['line']}")
            print(f"   {f['message']}\n")

    for f in warnings:
        print(f"⚠️ [{f['rule']}] {f['file']}:{f['line']}")
        print(f"   {f['message']}\n")

    if v2_blockers:
        print(f"\n❌ FAILED: {len(v2_blockers)} V2 blocker(s) found")
        sys.exit(1)
    elif brownfield_blockers:
        print(f"\n⚠️ PASSED: V2 clean, {len(brownfield_blockers)} brownfield blocker(s) (informational)")
        sys.exit(0)
    elif warnings:
        print(f"\n⚠️ PASSED with {len(warnings)} warning(s)")
        sys.exit(0)
    else:
        print("\n✅ PASSED: No findings")
        sys.exit(0)


if __name__ == "__main__":
    main()
