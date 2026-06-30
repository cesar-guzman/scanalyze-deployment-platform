# Contract Fail-Closed HCL Harness
#
# This is a TEST-ONLY configuration. It does NOT deploy any AWS resources.
# It uses terraform_data + precondition blocks to verify that identity,
# digest, schema, and freshness mismatches cause terraform plan to fail.
#
# Usage:
#   terraform init
#   terraform plan -var-file=fixtures/<scenario>.tfvars
#
# Expected behavior:
#   Valid scenario   → plan succeeds (no changes)
#   Invalid scenario → plan fails with precondition error

terraform {
  required_version = ">= 1.5.0"
  # No provider required — pure local validation
}

# ── Inputs (simulating what orchestrator provides) ───────────────────

variable "contract_deployment_id" {
  type        = string
  description = "deployment_id from the contract being verified"
}

variable "contract_account_id" {
  type        = string
  description = "account_id from the contract being verified"
}

variable "contract_region" {
  type        = string
  description = "region from the contract being verified"
}

variable "contract_schema_version" {
  type        = string
  description = "schema_version from the contract"
}

variable "contract_digest" {
  type        = string
  description = "SHA-256 digest from the contract"
}

variable "contract_producer_release" {
  type        = string
  description = "Release version that produced this contract"
}

# ── Expected values (from deployment record / release manifest) ──────

variable "expected_deployment_id" {
  type        = string
  description = "Expected deployment_id from deployment record"
}

variable "expected_account_id" {
  type        = string
  description = "Expected account_id from deployment record"
}

variable "expected_region" {
  type        = string
  description = "Expected region from deployment record"
}

variable "expected_schema_version" {
  type        = string
  description = "Expected/supported schema version"
  default     = "1"
}

variable "expected_digest" {
  type        = string
  description = "Expected digest (recomputed from canonical contract)"
}

variable "expected_release_version" {
  type        = string
  description = "Expected release version from release manifest"
}

# ── Contract Gate — fail-closed with precondition ────────────────────

resource "terraform_data" "contract_gate" {
  # This resource exists solely to carry preconditions.
  # It never creates any infrastructure.

  lifecycle {
    precondition {
      condition     = var.contract_deployment_id == var.expected_deployment_id
      error_message = "FAIL_CLOSED: contract deployment_id '${var.contract_deployment_id}' does not match expected '${var.expected_deployment_id}'"
    }

    precondition {
      condition     = var.contract_account_id == var.expected_account_id
      error_message = "FAIL_CLOSED: contract account_id '${var.contract_account_id}' does not match expected '${var.expected_account_id}'"
    }

    precondition {
      condition     = var.contract_region == var.expected_region
      error_message = "FAIL_CLOSED: contract region '${var.contract_region}' does not match expected '${var.expected_region}'"
    }

    precondition {
      condition     = var.contract_schema_version == var.expected_schema_version
      error_message = "FAIL_CLOSED: unsupported schema version '${var.contract_schema_version}', expected '${var.expected_schema_version}'"
    }

    precondition {
      condition     = var.contract_digest == var.expected_digest
      error_message = "FAIL_CLOSED: contract digest mismatch — possible tampering or stale contract"
    }

    precondition {
      condition     = var.contract_producer_release == var.expected_release_version
      error_message = "FAIL_CLOSED: contract producer release '${var.contract_producer_release}' does not match expected '${var.expected_release_version}' — possible replay of old contract"
    }
  }
}

# ── Outputs for diagnostic ──────────────────────────────────────────

output "gate_status" {
  value = "PASS: all contract preconditions satisfied"
}

output "verified_deployment_id" {
  value = var.contract_deployment_id
}

output "verified_digest" {
  value = var.contract_digest
}
