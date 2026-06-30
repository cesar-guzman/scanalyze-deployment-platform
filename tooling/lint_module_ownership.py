#!/usr/bin/env python3
"""Module ownership linter — ensures modules/global/ does not declare baseline resources.

modules/global/ may only declare workload/application IAM resources.
It must NOT declare or appear to own:
- ScanalyzeCustomer-* roles (Plan, Apply, Promotion, Validation, Diagnostic, StateRecovery)
- State/evidence/contracts S3 buckets
- State/recovery/plan-execution KMS keys
- Account baseline roles, boundaries, trust policies
- AccountVendingProvider-owned resources
"""
import re
import sys
from pathlib import Path

GLOBAL_MODULE = Path("modules/global")

# Patterns that must NOT appear in modules/global/
FORBIDDEN_PATTERNS = [
    (r"ScanalyzeCustomer-", "ScanalyzeCustomer control-plane role"),
    (r"AccountVendingProvider", "AccountVendingProvider-owned resource"),
    (r"state[-_]bucket", "state bucket (owned by account baseline)"),
    (r"evidence[-_]bucket", "evidence bucket (owned by account baseline)"),
    (r"contracts[-_]bucket", "contracts bucket (owned by account baseline)"),
    (r"plan[-_]execution", "plan-execution resource (owned by account baseline)"),
    (r"state[-_]recovery", "state-recovery resource (owned by account baseline)"),
    (r"\"Plan\"", "Plan role reference"),
    (r"\"Apply\"", "Apply role reference"),
    (r"\"Promotion\"", "Promotion role reference"),
    (r"\"Validation\"", "Validation role reference"),
    (r"\"Diagnostic\"", "Diagnostic role reference"),
    (r"\"StateRecovery\"", "StateRecovery role reference"),
]

# Resource types that are NOT allowed in global module
FORBIDDEN_RESOURCE_PATTERNS = [
    (r'resource\s+"aws_s3_bucket"\s+"(state|evidence|contracts)', "S3 bucket for state/evidence/contracts"),
    (r'resource\s+"aws_kms_key"\s+"(state|recovery|plan)', "KMS key for state/recovery/plan"),
    (r'resource\s+"aws_iam_role"\s+"(plan|apply|promotion|validation|diagnostic|state_recovery)', "Baseline IAM role"),
]


def lint_global_module() -> list[str]:
    errors = []
    if not GLOBAL_MODULE.exists():
        return errors

    for tf_file in sorted(GLOBAL_MODULE.glob("*.tf")):
        content = tf_file.read_text()
        lines = content.splitlines()

        for line_num, line in enumerate(lines, 1):
            # Skip comments
            stripped = line.strip()
            if stripped.startswith("#") or stripped.startswith("//"):
                continue

            for pattern, description in FORBIDDEN_PATTERNS:
                if re.search(pattern, line):
                    errors.append(f"  {tf_file}:{line_num}: forbidden pattern '{description}' — {stripped[:80]}")

            for pattern, description in FORBIDDEN_RESOURCE_PATTERNS:
                if re.search(pattern, line, re.IGNORECASE):
                    errors.append(f"  {tf_file}:{line_num}: forbidden resource '{description}' — {stripped[:80]}")

    return errors


def main():
    errors = lint_global_module()
    if errors:
        print("FAIL: modules/global/ contains forbidden baseline resource patterns:")
        for e in errors:
            print(e)
        sys.exit(1)
    else:
        print("  modules/global/ ownership check PASS — no baseline resources found")


if __name__ == "__main__":
    main()
