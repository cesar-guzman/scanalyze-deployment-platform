#!/usr/bin/env python3
"""Edge split linter — enforces edge-identity / edge resource boundaries.

edge-identity (regional): Cognito, API Gateway, JWT authorizer
edge (global): CloudFront, WAF CLOUDFRONT, ACM us-east-1, Route53

This linter ensures:
- edge-identity does NOT contain CloudFront, WAF CLOUDFRONT, global ACM, or Route53
- edge does NOT own Cognito or API Gateway authorizer resources
"""
import re
import sys
from pathlib import Path

EDGE_IDENTITY_MODULE = Path("modules/edge-identity")
EDGE_MODULE = Path("modules/edge")

# Patterns forbidden in edge-identity
EDGE_IDENTITY_FORBIDDEN = [
    (r'resource\s+"aws_cloudfront_', "CloudFront resource (belongs in edge)"),
    (r'resource\s+"aws_wafv2_web_acl".*scope.*=.*"CLOUDFRONT"', "WAF CLOUDFRONT scope (belongs in edge)"),
    (r'aws_wafv2_web_acl.*CLOUDFRONT', "WAF CLOUDFRONT reference (belongs in edge)"),
    (r'resource\s+"aws_route53_record"', "Route53 record (belongs in edge)"),
    (r'resource\s+"aws_route53_zone"', "Route53 zone (belongs in edge)"),
    (r'resource\s+"aws_acm_certificate"', "ACM certificate (belongs in edge for global cert)"),
]

# Patterns forbidden in edge
EDGE_FORBIDDEN = [
    (r'resource\s+"aws_cognito_user_pool"', "Cognito user pool (belongs in edge-identity)"),
    (r'resource\s+"aws_cognito_user_pool_client"', "Cognito client (belongs in edge-identity)"),
    (r'resource\s+"aws_cognito_user_pool_domain"', "Cognito domain (belongs in edge-identity)"),
    (r'resource\s+"aws_cognito_resource_server"', "Cognito resource server (belongs in edge-identity)"),
    (r'resource\s+"aws_apigatewayv2_authorizer"', "API GW authorizer (belongs in edge-identity)"),
    (r'resource\s+"aws_apigatewayv2_api"', "API GW HTTP API (belongs in edge-identity)"),
]


def lint_module(module_path: Path, forbidden: list[tuple[str, str]], module_name: str) -> list[str]:
    errors = []
    if not module_path.exists():
        return errors

    for tf_file in sorted(module_path.glob("*.tf")):
        content = tf_file.read_text()
        lines = content.splitlines()

        for line_num, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith("#") or stripped.startswith("//"):
                continue

            for pattern, description in forbidden:
                if re.search(pattern, line, re.IGNORECASE):
                    errors.append(f"  {tf_file}:{line_num}: {description} — {stripped[:80]}")

    return errors


def main():
    errors = []

    ei_errors = lint_module(EDGE_IDENTITY_MODULE, EDGE_IDENTITY_FORBIDDEN, "edge-identity")
    if ei_errors:
        errors.append("FAIL: modules/edge-identity/ contains resources that belong in modules/edge/:")
        errors.extend(ei_errors)

    e_errors = lint_module(EDGE_MODULE, EDGE_FORBIDDEN, "edge")
    if e_errors:
        errors.append("FAIL: modules/edge/ contains resources that belong in modules/edge-identity/:")
        errors.extend(e_errors)

    if errors:
        for e in errors:
            print(e)
        sys.exit(1)
    else:
        print("  edge-identity / edge split check PASS — no boundary violations")


if __name__ == "__main__":
    main()
