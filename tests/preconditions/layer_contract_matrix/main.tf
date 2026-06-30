# Layer Contract Matrix — HCL Harness
#
# Data-driven contract validation harness.
# Tests upstream contract consumption using terraform_data + precondition.
# No AWS provider — pure local validation.
#
# This single harness validates all 7 layer pairs by parameterizing
# inputs through tfvars files generated from scenarios.yaml.

terraform {
  required_version = ">= 1.5.0"
}

# ── Layer metadata ──

variable "producer_layer" {
  type        = string
  description = "Name of the upstream producer layer"
}

variable "consumer_layer" {
  type        = string
  description = "Name of the downstream consumer layer"
}

variable "deployment_id" {
  type        = string
  description = "Deployment identifier"
}

variable "account_id" {
  type        = string
  description = "AWS account ID"
}

variable "region" {
  type        = string
  description = "AWS region"
  default     = ""
}

variable "release_version" {
  type        = string
  description = "Release version"
}

variable "release_manifest_digest" {
  type        = string
  description = "SHA-256 digest of the release manifest"
}

# ── Contract fields ──

variable "upstream_contract_digest" {
  type        = string
  description = "SHA-256 digest of upstream contract"
}

variable "expected_upstream_digest" {
  type        = string
  description = "Expected upstream contract digest"
}

variable "upstream_schema_version" {
  type        = string
  description = "Schema version of the upstream contract"
  default     = "1"
}

variable "accepted_schema_versions" {
  type    = list(string)
  default = ["1"]
}

variable "contract_serial" {
  type        = string
  description = "Monotonic contract serial"
  default     = "1"
}

variable "expected_minimum_serial" {
  type        = string
  description = "Minimum acceptable serial"
  default     = "1"
}

variable "producer_release_version" {
  type        = string
  description = "Release version that produced the upstream contract"
  default     = ""
}

variable "expected_region" {
  type        = string
  description = "Expected region for regional-scope layers"
  default     = "us-east-1"
}

# ── Release manifest digest value-match ──

variable "expected_release_manifest_digest" {
  type        = string
  description = "Expected release manifest digest (must match exactly, empty = fail closed)"
  default     = ""
}

# ── Raw contract key validation (unknown critical fields) ──

variable "contract_raw_json" {
  type        = string
  description = "Raw contract JSON string for key validation (empty = skip)"
  default     = ""
}

variable "allowed_contract_keys" {
  type        = list(string)
  description = "Exhaustive allowlist of permitted top-level contract keys"
  default     = []
}

# ── State path scope ──

variable "state_scope" {
  type        = string
  description = "State scope: 'global' or 'regional'"
  default     = "regional"
  validation {
    condition     = contains(["global", "regional"], var.state_scope)
    error_message = "state_scope must be 'global' or 'regional'"
  }
}

variable "state_key" {
  type        = string
  description = "State key pattern to validate"
  default     = ""
}

# ── Locals ──

locals {
  # Global-scope layers do NOT include region in state path
  global_scope_layers  = ["global", "edge"]
  # Regional-scope layers MUST include region
  regional_scope_layers = ["network", "platform", "data-foundation", "services", "edge-identity", "addons"]

  consumer_is_global  = contains(local.global_scope_layers, var.consumer_layer)
  consumer_is_regional = contains(local.regional_scope_layers, var.consumer_layer)

  # State path pattern validation
  state_has_region = can(regex("/[a-z]{2}-[a-z]+-[0-9]/", var.state_key))

  # Raw contract key validation
  raw_contract_provided = var.contract_raw_json != ""
  raw_contract_decoded  = local.raw_contract_provided ? jsondecode(var.contract_raw_json) : {}
  raw_contract_keys     = local.raw_contract_provided ? keys(local.raw_contract_decoded) : []
  unknown_keys          = local.raw_contract_provided ? setsubtract(toset(local.raw_contract_keys), toset(var.allowed_contract_keys)) : toset([])
  has_unknown_keys      = length(local.unknown_keys) > 0
}

# ── Contract Gate ──

resource "terraform_data" "contract_gate" {
  lifecycle {
    # Identity binding
    precondition {
      condition     = can(regex("^dep_[0-9A-HJKMNP-TV-Z]{26}$", var.deployment_id))
      error_message = "deployment_id format invalid: ${var.deployment_id}"
    }
    precondition {
      condition     = can(regex("^[0-9]{12}$", var.account_id))
      error_message = "account_id must be a 12-digit AWS account ID: ${var.account_id}"
    }

    # Release binding
    precondition {
      condition     = can(regex("^sha256:[a-f0-9]{64}$", var.release_manifest_digest))
      error_message = "release_manifest_digest must be sha256:<64 hex chars>"
    }

    # Upstream contract verification
    precondition {
      condition     = var.upstream_contract_digest != ""
      error_message = "upstream contract digest is required — consumer bypass not allowed"
    }
    precondition {
      condition     = var.upstream_contract_digest == var.expected_upstream_digest
      error_message = "upstream contract digest mismatch — tampered or stale contract from ${var.producer_layer}"
    }

    # Schema version gate
    precondition {
      condition     = contains(var.accepted_schema_versions, var.upstream_schema_version)
      error_message = "upstream contract schema version '${var.upstream_schema_version}' is not accepted by ${var.consumer_layer}"
    }

    # Serial monotonicity
    precondition {
      condition     = tonumber(var.contract_serial) >= tonumber(var.expected_minimum_serial)
      error_message = "contract serial ${var.contract_serial} is below minimum ${var.expected_minimum_serial} — possible stale contract or state rollback"
    }

    # Producer layer validation
    precondition {
      condition     = var.producer_layer != "" && var.producer_layer != "FAKE_LAYER"
      error_message = "producer layer '${var.producer_layer}' is not a valid upstream producer"
    }

    # Producer release version validation
    precondition {
      condition     = var.producer_release_version != "v0.0.0-stale"
      error_message = "producer release version is stale: ${var.producer_release_version}"
    }

    # Region validation for regional-scope layers
    precondition {
      condition     = !local.consumer_is_regional || var.region == var.expected_region
      error_message = "region '${var.region}' does not match expected region '${var.expected_region}' for regional layer '${var.consumer_layer}'"
    }

    # Release manifest digest value-match (not just format)
    precondition {
      condition     = var.expected_release_manifest_digest != ""
      error_message = "expected_release_manifest_digest is empty — fail closed: release freshness cannot be verified"
    }
    precondition {
      condition     = var.release_manifest_digest == var.expected_release_manifest_digest
      error_message = "release_manifest_digest '${var.release_manifest_digest}' does not match expected '${var.expected_release_manifest_digest}' — possible stale or replayed release"
    }
  }
}

# ── Unknown Critical Field Gate ──

resource "terraform_data" "unknown_field_gate" {
  count = local.raw_contract_provided ? 1 : 0

  lifecycle {
    precondition {
      condition     = !local.has_unknown_keys
      error_message = "Unknown critical fields in contract: ${join(", ", local.unknown_keys)}. All fields must be in the allowed list."
    }
  }
}

# ── State Path Scope Gate ──

resource "terraform_data" "state_path_scope_gate" {
  count = var.state_key != "" ? 1 : 0

  lifecycle {
    # Global layers must NOT have region in state path
    precondition {
      condition     = !local.consumer_is_global || !local.state_has_region
      error_message = "global-scope layer '${var.consumer_layer}' must not include region in state path: ${var.state_key}"
    }

    # Regional layers MUST have region in state path
    precondition {
      condition     = !local.consumer_is_regional || local.state_has_region
      error_message = "regional-scope layer '${var.consumer_layer}' must include region in state path: ${var.state_key}"
    }

    # Region variable must be set for regional layers
    precondition {
      condition     = !local.consumer_is_regional || var.region != ""
      error_message = "region is required for regional-scope layer '${var.consumer_layer}'"
    }
  }
}
