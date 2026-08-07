# Edge — CloudFront Distribution
#
# Status: authored_not_provider_validated
#
# This module owns the global edge resources: CloudFront, OAC, WAF, ACM, Route53.
# Frontend S3 bucket is consumed from contract/input (NOT created here).

resource "aws_cloudfront_distribution" "main" {
  provider            = aws.us_east_1
  enabled             = true
  is_ipv6_enabled     = true
  default_root_object = "index.html"
  http_version        = "http2and3"
  web_acl_id          = aws_wafv2_web_acl.cloudfront.arn

  aliases = distinct(concat([var.domain_name], var.domain_aliases))

  # S3 origin for frontend (bucket consumed from contract, not created here)
  origin {
    domain_name              = var.frontend_bucket_domain_name
    origin_id                = "s3-frontend"
    origin_access_control_id = aws_cloudfront_origin_access_control.s3.id
  }

  # Runtime config is mutable deployment state, isolated from immutable assets.
  # /config.json resolves to /{deployment_id}/config.json in the shared bucket.
  origin {
    domain_name              = var.frontend_bucket_domain_name
    origin_id                = "s3-runtime-config"
    origin_path              = "/${var.deployment_id}"
    origin_access_control_id = aws_cloudfront_origin_access_control.s3.id
  }

  # API Gateway origin
  origin {
    domain_name = local.api_gateway_domain
    origin_id   = "api-gateway"

    custom_origin_config {
      http_port              = 80
      https_port             = 443
      origin_protocol_policy = "https-only"
      origin_ssl_protocols   = ["TLSv1.2"]
    }
  }

  default_cache_behavior {
    allowed_methods        = ["GET", "HEAD", "OPTIONS"]
    cached_methods         = ["GET", "HEAD"]
    target_origin_id       = "s3-frontend"
    viewer_protocol_policy = "redirect-to-https"
    compress               = true

    forwarded_values {
      query_string = false
      cookies {
        forward = "none"
      }
    }

    function_association {
      event_type   = "viewer-request"
      function_arn = aws_cloudfront_function.spa_route_rewrite.arn
    }
  }

  ordered_cache_behavior {
    path_pattern               = "/config.json"
    allowed_methods            = ["GET", "HEAD", "OPTIONS"]
    cached_methods             = ["GET", "HEAD"]
    target_origin_id           = "s3-runtime-config"
    viewer_protocol_policy     = "redirect-to-https"
    compress                   = true
    cache_policy_id            = aws_cloudfront_cache_policy.runtime_config.id
    response_headers_policy_id = aws_cloudfront_response_headers_policy.runtime_config.id
  }

  dynamic "ordered_cache_behavior" {
    for_each = toset(["/api", "/api/*"])

    content {
      path_pattern           = ordered_cache_behavior.value
      allowed_methods        = ["GET", "HEAD", "OPTIONS", "PUT", "POST", "PATCH", "DELETE"]
      cached_methods         = ["GET", "HEAD"]
      target_origin_id       = "api-gateway"
      viewer_protocol_policy = "redirect-to-https"

      forwarded_values {
        query_string = true
        headers      = ["Authorization", "x-tenant-id", "Origin"]
        cookies {
          forward = "none"
        }
      }

      function_association {
        event_type   = "viewer-request"
        function_arn = aws_cloudfront_function.api_path_rewrite.arn
      }

      min_ttl     = 0
      default_ttl = 0
      max_ttl     = 0
    }
  }

  restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }

  viewer_certificate {
    acm_certificate_arn      = aws_acm_certificate_validation.main.certificate_arn
    ssl_support_method       = "sni-only"
    minimum_protocol_version = "TLSv1.2_2021"
  }

  tags = {
    deployment_id = var.deployment_id
    managed_by    = "terraform"
    layer         = "edge"
  }
}

resource "aws_cloudfront_cache_policy" "runtime_config" {
  provider    = aws.us_east_1
  name        = "${var.deployment_id}-runtime-config-no-store"
  comment     = "Disable edge caching for the mutable public SPA runtime config"
  default_ttl = 0
  max_ttl     = 0
  min_ttl     = 0

  parameters_in_cache_key_and_forwarded_to_origin {
    enable_accept_encoding_brotli = false
    enable_accept_encoding_gzip   = false

    cookies_config {
      cookie_behavior = "none"
    }

    headers_config {
      header_behavior = "none"
    }

    query_strings_config {
      query_string_behavior = "none"
    }
  }
}

resource "aws_cloudfront_response_headers_policy" "runtime_config" {
  provider = aws.us_east_1
  name     = "${var.deployment_id}-runtime-config-no-store"
  comment  = "Prevent browsers and intermediaries from retaining SPA runtime config"

  custom_headers_config {
    items {
      header   = "Cache-Control"
      override = true
      value    = "no-store, max-age=0, must-revalidate"
    }
  }
}

resource "aws_cloudfront_function" "spa_route_rewrite" {
  provider = aws.us_east_1
  name     = "${var.deployment_id}-spa-route-rewrite"
  runtime  = "cloudfront-js-2.0"
  comment  = "Rewrite navigation routes without masking missing files such as config.json"
  publish  = true
  code     = <<-JAVASCRIPT
    function handler(event) {
      var request = event.request;
      var uri = request.uri;
      var lastSegment = uri.substring(uri.lastIndexOf('/') + 1);

      if (uri === '/' || lastSegment.indexOf('.') === -1) {
        request.uri = '/index.html';
      }

      return request;
    }
  JAVASCRIPT
}

resource "aws_cloudfront_function" "api_path_rewrite" {
  provider = aws.us_east_1
  name     = "${var.deployment_id}-api-path-rewrite"
  runtime  = "cloudfront-js-2.0"
  comment  = "Remove only the same-origin SPA API prefix before API Gateway routing"
  publish  = true
  code     = file("${path.module}/api_path_rewrite.js")
}

resource "aws_cloudfront_origin_access_control" "s3" {
  provider                          = aws.us_east_1
  name                              = "${var.deployment_id}-oac"
  description                       = "OAC for frontend S3 bucket"
  origin_access_control_origin_type = "s3"
  signing_behavior                  = "always"
  signing_protocol                  = "sigv4"
}
