# Edge — WAF with CLOUDFRONT scope
#
# Status: authored_not_provider_validated

resource "aws_wafv2_web_acl" "cloudfront" {
  provider = aws.us_east_1
  name     = "${var.deployment_id}-waf-cloudfront"
  scope    = "CLOUDFRONT"

  default_action {
    allow {}
  }

  rule {
    name     = "AWSManagedRulesCommonRuleSet"
    priority = 1

    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesCommonRuleSet"
        vendor_name = "AWS"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "${var.deployment_id}-common-rules"
      sampled_requests_enabled   = true
    }
  }

  rule {
    name     = "AWSManagedRulesKnownBadInputsRuleSet"
    priority = 2

    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesKnownBadInputsRuleSet"
        vendor_name = "AWS"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "${var.deployment_id}-bad-inputs"
      sampled_requests_enabled   = true
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "${var.deployment_id}-waf"
    sampled_requests_enabled   = true
  }

  tags = {
    deployment_id = var.deployment_id
    managed_by    = "terraform"
    layer         = "edge"
    purpose       = "cloudfront-waf"
  }
}
