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

# Upstream contract
variable "upstream_contract_digest" {
  type        = string
  description = "SHA-256 digest of upstream platform contract"
}

variable "expected_upstream_digest" {
  type        = string
  description = "Expected upstream contract digest"
}
