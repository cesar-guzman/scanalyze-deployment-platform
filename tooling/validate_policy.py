#!/usr/bin/env python3
"""IAM/S3/KMS policy fixture validation.

Validates policy JSON files are structurally valid IAM policy documents.
Does NOT evaluate policies (no AWS calls) — only validates structure.
"""

import json
import sys
from pathlib import Path


VALID_EFFECTS = {"Allow", "Deny"}
VALID_IAM_ACTION_PREFIXES = {
    "s3:", "ec2:", "ecs:", "ecr:", "iam:", "kms:", "ssm:", "sqs:",
    "dynamodb:", "logs:", "cloudwatch:", "route53:", "cloudfront:",
    "wafv2:", "cognito-idp:", "apigateway:", "lambda:", "sts:",
    "elasticloadbalancing:", "autoscaling:", "application-autoscaling:",
    "sns:", "signer:", "acm:", "waf:",
}
# Known invalid IAM actions per ADR-003 rev3
INVALID_IAM_ACTIONS = {"s3:CopyObject"}


def validate_policy(policy: dict, filename: str) -> list[str]:
    """Validate an IAM policy document structure."""
    errors = []

    if "Version" not in policy:
        errors.append(f"{filename}: Missing 'Version'")

    if "Statement" not in policy:
        errors.append(f"{filename}: Missing 'Statement'")
        return errors

    if not isinstance(policy["Statement"], list):
        errors.append(f"{filename}: 'Statement' must be an array")
        return errors

    for i, stmt in enumerate(policy["Statement"]):
        prefix = f"{filename}[{i}]"

        if "Effect" not in stmt:
            errors.append(f"{prefix}: Missing 'Effect'")
        elif stmt["Effect"] not in VALID_EFFECTS:
            errors.append(f"{prefix}: Invalid Effect '{stmt['Effect']}'")

        if "Action" not in stmt and "NotAction" not in stmt:
            errors.append(f"{prefix}: Missing 'Action' or 'NotAction'")
        else:
            actions = stmt.get("Action", stmt.get("NotAction", []))
            if isinstance(actions, str):
                actions = [actions]
            for action in actions:
                # A wildcard Allow grants unbounded authority. A wildcard
                # Deny is the inverse: it is the strict zero-authority session
                # boundary used by GUG-217 proof roles and must remain valid.
                if action == "*" and stmt.get("Effect") != "Deny":
                    errors.append(f"{prefix}: Wildcard '*' action found — too broad")
                elif action in INVALID_IAM_ACTIONS:
                    errors.append(f"{prefix}: Invalid IAM action '{action}' — not a real S3 action")

        # Trust policies have Principal instead of Resource
        is_trust_policy = "Principal" in stmt
        if not is_trust_policy and "Resource" not in stmt and "NotResource" not in stmt:
            errors.append(f"{prefix}: Missing 'Resource'")

    return errors


def main():
    import argparse
    parser = argparse.ArgumentParser(description="Validate IAM/S3/KMS policy fixtures")
    parser.add_argument("--policies-dir", default="policies", help="Path to policies directory")
    args = parser.parse_args()

    policies_dir = Path(args.policies_dir)
    all_errors = []

    for json_file in sorted(policies_dir.rglob("*.json")):
        try:
            with open(json_file) as f:
                policy = json.load(f)
        except json.JSONDecodeError as e:
            all_errors.append(f"{json_file.name}: Invalid JSON — {e}")
            continue

        if "Version" in policy and "Statement" in policy:
            errors = validate_policy(policy, json_file.name)
            if errors:
                all_errors.extend(errors)
                print(f"  FAIL: {json_file.name}")
                for e in errors:
                    print(f"    {e}")
            else:
                print(f"  PASS: {json_file.name}")
        else:
            # Trust policies, session policies, etc. — just check JSON validity
            print(f"  JSON OK: {json_file.name} (not an IAM policy document)")

    if all_errors:
        print(f"\n{len(all_errors)} policy validation errors")
        sys.exit(1)
    else:
        print("\nAll policy fixtures valid")
        sys.exit(0)


if __name__ == "__main__":
    main()
