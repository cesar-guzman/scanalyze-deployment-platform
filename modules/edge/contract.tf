# Contract producer gate for edge module.
# This module produces: edge/v2
# Consumers: downstream layers that declare dependency on this contract.
#
# The contract is written by the root that calls this module,
# NOT by the module itself. The module only exposes outputs
# that the root's contracts.tf will publish to SSM.
#
# Single Contract Writer Rule (ADR-006 rev3):
# Each contract is written by EXACTLY ONE root.

# Contract output structure — root will publish this to SSM.
output "contract_payload" {
  description = "Structured contract payload for edge/v2"
  value = {
    schema_version = "2"
    layer          = local.layer_name
    state_scope    = local.state_scope
    outputs = {
      cloudfront_domain_name      = aws_cloudfront_distribution.main.domain_name
      cloudfront_distribution_id  = aws_cloudfront_distribution.main.id
      cloudfront_distribution_arn = aws_cloudfront_distribution.main.arn
      waf_web_acl_arn             = aws_wafv2_web_acl.cloudfront.arn
      acm_certificate_arn         = aws_acm_certificate.main.arn
      route53_zone_id             = var.route53_zone_id
    }
  }
}
