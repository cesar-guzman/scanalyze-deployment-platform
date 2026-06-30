#!/usr/bin/env python3
"""Services ownership linter — enforces task definition ownership rules.

modules/services/ must:
- Use image references with @sha256 digest
- Include SCANALYZE_DEPLOYMENT_CUSTOMER_ID as required env var

modules/services/ must NOT:
- Own imagedefinitions.json
- Use register-task-definition pipeline mutation
- Use ignore_changes = [task_definition]
- Use mutable image tags (e.g., :latest without @sha256)
- Use SCANALYZE_TENANT as canonical identity
- Use custom:tenantId as authoritative claim
"""
import re
import sys
from pathlib import Path

SERVICES_MODULE = Path("modules/services")

# Patterns that must NOT appear
FORBIDDEN_PATTERNS = [
    (r"imagedefinitions\.json", "imagedefinitions.json ownership (pipeline anti-pattern)"),
    (r"register-task-definition", "register-task-definition CLI call (pipeline anti-pattern)"),
    (r"ignore_changes\s*=\s*\[.*task_definition", "ignore_changes on task_definition (drift anti-pattern)"),
    (r"SCANALYZE_TENANT", "SCANALYZE_TENANT as canonical identity (replaced by SCANALYZE_DEPLOYMENT_CUSTOMER_ID)"),
    (r"custom:tenantId", "custom:tenantId as authoritative claim (replaced by deployment customer ID)"),
    (r'image\s*=\s*"[^"]*:latest"', "mutable :latest tag without @sha256 digest"),
]


def lint_services_module() -> list[str]:
    errors = []
    if not SERVICES_MODULE.exists():
        return errors

    for tf_file in sorted(SERVICES_MODULE.glob("*.tf")):
        content = tf_file.read_text()
        lines = content.splitlines()

        for line_num, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith("#") or stripped.startswith("//"):
                continue

            for pattern, description in FORBIDDEN_PATTERNS:
                if re.search(pattern, line, re.IGNORECASE):
                    errors.append(f"  {tf_file}:{line_num}: forbidden pattern '{description}' — {stripped[:80]}")

    return errors


def main():
    errors = lint_services_module()
    if errors:
        print("FAIL: modules/services/ contains forbidden ownership patterns:")
        for e in errors:
            print(e)
        sys.exit(1)
    else:
        print("  modules/services/ ownership check PASS — no anti-patterns found")


if __name__ == "__main__":
    main()
