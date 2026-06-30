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

variable "service_names" {
  type        = list(string)
  description = "List of microservice names for monitoring"
  default = [
    "ingest-api",
    "ocr-worker",
    "postprocess-worker",
    "classifier-worker",
    "bank-worker",
    "personal-worker",
    "gov-worker",
  ]
}

variable "dlq_queue_names" {
  type        = list(string)
  description = "List of worker names with DLQs to monitor"
  default = [
    "ocr",
    "postprocess",
    "classifier",
    "bank",
    "personal",
    "gov",
  ]
}

# Upstream contract
variable "upstream_contract_digest" {
  type        = string
  description = "SHA-256 digest of upstream edge contract"
}

variable "expected_upstream_digest" {
  type        = string
  description = "Expected upstream contract digest"
}
