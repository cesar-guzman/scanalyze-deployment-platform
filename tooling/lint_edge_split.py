#!/usr/bin/env python3
"""Identity/edge split linter for the three portable ownership boundaries.

identity-control-plane (regional): Cognito, membership/audit, identity Lambdas
edge-identity (regional): API Gateway and JWT authorizer
edge (global): CloudFront, WAF CLOUDFRONT, ACM us-east-1, Route53

This linter ensures:
- identity-control-plane does not own API Gateway or global edge resources
- edge-identity does not own Cognito or global edge resources
- edge does not own Cognito or API Gateway resources
"""
import re
import sys
from pathlib import Path

EDGE_IDENTITY_MODULE = Path("modules/edge-identity")
IDENTITY_CONTROL_PLANE_MODULE = Path("modules/identity-control-plane")
EDGE_MODULE = Path("modules/edge")

IDENTITY_CONTROL_PLANE_FORBIDDEN = [
    (r'resource\s+"aws_apigatewayv2_', "API Gateway resource (belongs in edge-identity)"),
    (r'resource\s+"aws_cloudfront_', "CloudFront resource (belongs in edge)"),
    (r'resource\s+"aws_wafv2_', "WAF resource (belongs in edge)"),
    (r'resource\s+"aws_route53_', "Route53 resource (belongs in edge)"),
    (r'resource\s+"aws_ecs_', "ECS resource (belongs in services/platform)"),
]

# Patterns forbidden in edge-identity
EDGE_IDENTITY_FORBIDDEN = [
    (r'resource\s+"aws_cognito_', "Cognito resource (belongs in identity-control-plane)"),
    (r'resource\s+"aws_cloudfront_', "CloudFront resource (belongs in edge)"),
    (r'resource\s+"aws_wafv2_web_acl".*scope.*=.*"CLOUDFRONT"', "WAF CLOUDFRONT scope (belongs in edge)"),
    (r'aws_wafv2_web_acl.*CLOUDFRONT', "WAF CLOUDFRONT reference (belongs in edge)"),
    (r'resource\s+"aws_route53_record"', "Route53 record (belongs in edge)"),
    (r'resource\s+"aws_route53_zone"', "Route53 zone (belongs in edge)"),
    (r'resource\s+"aws_acm_certificate"', "ACM certificate (belongs in edge for global cert)"),
]

# Patterns forbidden in edge
EDGE_FORBIDDEN = [
    (r'resource\s+"aws_cognito_', "Cognito resource (belongs in identity-control-plane)"),
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

    identity_errors = lint_module(
        IDENTITY_CONTROL_PLANE_MODULE,
        IDENTITY_CONTROL_PLANE_FORBIDDEN,
        "identity-control-plane",
    )
    if identity_errors:
        errors.append(
            "FAIL: modules/identity-control-plane/ crosses its regional identity boundary:"
        )
        errors.extend(identity_errors)

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
        print(
            "  identity-control-plane / edge-identity / edge split check PASS — "
            "no boundary violations"
        )


if __name__ == "__main__":
    main()
