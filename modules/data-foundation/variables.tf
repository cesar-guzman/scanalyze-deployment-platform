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

variable "browser_origins" {
  type        = list(string)
  description = "GUG-543: HTTPS origins of the frontend that upload (PUT) and download (GET) document objects through presigned URLs. Empty means no CORS rule, so browsers cannot use presigned URLs."
  default     = []

  validation {
    condition = alltrue([
      for origin in var.browser_origins : can(regex("^https://[a-z0-9]([a-z0-9-]*[a-z0-9])?(\\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+(:[0-9]{1,5})?$", origin))
    ]) && length(distinct(var.browser_origins)) == length(var.browser_origins)
    error_message = "browser_origins must be distinct lowercase https://host[:port] origins, without paths, trailing slashes or wildcards."
  }
}
