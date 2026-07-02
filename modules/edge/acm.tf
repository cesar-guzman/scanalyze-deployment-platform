# Edge — ACM Certificate (us-east-1 for CloudFront)
#
# Status: authored_not_provider_validated

resource "aws_acm_certificate" "main" {
  provider                  = aws.us_east_1
  domain_name               = var.domain_name
  subject_alternative_names = var.domain_aliases
  validation_method         = "DNS"

  lifecycle {
    create_before_destroy = true
  }

  tags = {
    deployment_id = var.deployment_id
    managed_by    = "terraform"
    layer         = "edge"
  }
}

resource "aws_acm_certificate_validation" "main" {
  provider                = aws.us_east_1
  certificate_arn         = aws_acm_certificate.main.arn
  validation_record_fqdns = [for record in aws_route53_record.cert_validation : record.fqdn]
}
