# replicated-data is a sub-module of data-foundation.
# It does NOT have an independent lifecycle or state in M1.
# This interface exists for future HA/DR work only.

variable "deployment_id" {
  type        = string
  description = "Deployment identifier (passed from data-foundation)"
}

variable "primary_region" {
  type        = string
  description = "Primary AWS region"
}

variable "replica_regions" {
  type        = list(string)
  default     = []
  description = "List of replica regions (empty in M1)"
}
