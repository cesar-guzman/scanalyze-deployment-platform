# Edge — Route53 DNS Records
#
# Status: authored_not_provider_validated

resource "aws_route53_record" "main" {
  provider = aws.us_east_1
  zone_id  = var.route53_zone_id
  name     = var.domain_name
  type     = "A"

  alias {
    name                   = aws_cloudfront_distribution.main.domain_name
    zone_id                = aws_cloudfront_distribution.main.hosted_zone_id
    evaluate_target_health = false
  }
}

resource "aws_route53_record" "main_aaaa" {
  provider = aws.us_east_1
  zone_id  = var.route53_zone_id
  name     = var.domain_name
  type     = "AAAA"

  alias {
    name                   = aws_cloudfront_distribution.main.domain_name
    zone_id                = aws_cloudfront_distribution.main.hosted_zone_id
    evaluate_target_health = false
  }
}

# ACM DNS validation records
resource "aws_route53_record" "cert_validation" {
  provider = aws.us_east_1
  for_each = {
    for dvo in aws_acm_certificate.main.domain_validation_options : dvo.domain_name => {
      name   = dvo.resource_record_name
      record = dvo.resource_record_value
      type   = dvo.resource_record_type
    }
  }

  allow_overwrite = true
  name            = each.value.name
  records         = [each.value.record]
  ttl             = 60
  type            = each.value.type
  zone_id         = var.route53_zone_id
}
