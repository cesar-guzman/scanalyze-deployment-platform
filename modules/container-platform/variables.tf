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

# From network contract
variable "vpc_id" {
  type        = string
  description = "VPC ID from network layer contract"
}

variable "private_subnet_ids" {
  type        = map(string)
  description = "Map of AZ ID to private subnet ID from network layer"
}

variable "vpc_cidr_block" {
  type        = string
  description = "VPC CIDR block from network layer"
}

variable "internal_certificate_arn" {
  type        = string
  description = "ACM certificate ARN for internal ALB HTTPS listener"
}

# Upstream contract
variable "upstream_contract_digest" {
  type        = string
  description = "SHA-256 digest of upstream network contract"
}

variable "expected_upstream_digest" {
  type        = string
  description = "Expected upstream contract digest"
}
