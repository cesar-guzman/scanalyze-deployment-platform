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
