# Contract-aligned outputs for edge layer.
# Status: authored_not_provider_validated

output "cloudfront_domain_name" {
  description = "CloudFront distribution domain name"
  value       = aws_cloudfront_distribution.main.domain_name
}

output "cloudfront_distribution_id" {
  description = "CloudFront distribution ID"
  value       = aws_cloudfront_distribution.main.id
}

output "cloudfront_distribution_arn" {
  description = "CloudFront distribution ARN"
  value       = aws_cloudfront_distribution.main.arn
}

output "waf_web_acl_arn" {
  description = "WAF Web ACL ARN (CLOUDFRONT scope)"
  value       = aws_wafv2_web_acl.cloudfront.arn
}

output "acm_certificate_arn" {
  description = "ACM certificate ARN (us-east-1)"
  value       = aws_acm_certificate.main.arn
}

output "route53_zone_id" {
  description = "Route53 hosted zone ID (passed through from input)"
  value       = var.route53_zone_id
}

output "frontend_runtime_config" {
  description = "Closed public frontend-config/v3 object; contains no secrets and grants no authority"
  value       = local.frontend_runtime_config
  sensitive   = false
}

output "frontend_runtime_config_json" {
  description = "Deterministic JSON encoding of the public frontend-config/v3 object"
  value       = local.frontend_runtime_config_json
  sensitive   = false
}

output "frontend_runtime_config_sha256" {
  description = "SHA-256 digest of the exact emitted frontend-config/v3 JSON bytes"
  value       = local.frontend_runtime_config_sha256
  sensitive   = false
}
