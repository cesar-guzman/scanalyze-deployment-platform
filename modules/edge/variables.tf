variable "deployment_id" {
  type        = string
  description = "Unique deployment identifier"
}

variable "account_id" {
  type        = string
  description = "AWS account ID"
}

variable "region" {
  type        = string
  description = "AWS region"
}

variable "release_version" {
  type        = string
  description = "Release version being deployed"
}

variable "release_manifest_digest" {
  type        = string
  description = "SHA-256 digest of the release manifest"
}

variable "domain_name" {
  type        = string
  description = "Primary domain name for the deployment"
}

variable "domain_aliases" {
  type        = list(string)
  description = "Alternative domain names for CloudFront"
  default     = []
}

variable "route53_zone_id" {
  type        = string
  description = "Route53 hosted zone ID for DNS records"
}

# From upstream edge-identity contract
variable "api_gateway_endpoint" {
  type        = string
  description = "API Gateway HTTP API endpoint URL from edge-identity contract"
}

variable "frontend_bucket_domain_name" {
  type        = string
  description = "S3 bucket regional domain name for frontend static assets"
}

# Upstream contract
variable "upstream_contract_digest" {
  type        = string
  description = "SHA-256 digest of upstream edge-identity contract"
}

variable "expected_upstream_digest" {
  type        = string
  description = "Expected upstream contract digest"
}
