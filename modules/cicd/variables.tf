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

variable "upstream_contract_digest" {
  type        = string
  description = "SHA-256 digest of the upstream contract"
  default     = ""
}

variable "expected_upstream_digest" {
  type        = string
  description = "Expected upstream contract digest"
  default     = ""
}

variable "ecs_cluster_name" {
  type        = string
  description = "ECS cluster name from platform contract"
}

variable "source_provider" {
  type    = string
  default = "codecommit"
}

variable "default_branch" {
  type    = string
  default = "main"
}

variable "default_buildspec_path" {
  type        = string
  description = "Default buildspec path for build projects"
  default     = "buildspec.yml"
}

variable "microservices" {
  type = map(object({
    service_name   = string
    ecr_repo_name  = string
    container_name = optional(string)
    source = optional(object({
      provider       = optional(string)
      repo_name      = optional(string)
      branch         = optional(string)
      connection_arn = optional(string)
      full_repo_id   = optional(string)
    }))
    buildspec_path = optional(string)
    build_env      = optional(map(string), {})
  }))
  description = "Microservice definitions (build-only)"
}

variable "enable_ecr_lifecycle_policy" {
  type    = bool
  default = true
}

variable "ecr_lifecycle_keep_last" {
  type    = number
  default = 20
}

variable "enable_release_metadata_ssm" {
  type    = bool
  default = true
}
