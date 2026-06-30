# Contract consumer validation for edge-identity root.
# Consumes: services/v1,global/v1
# Scope: regional
# State key: {dep_id}/{region}/edge-identity/terraform.tfstate
#
# This gate runs BEFORE any resource creation.
# It validates upstream contract integrity using fail-closed preconditions.
# Uses terraform_data + precondition (ADR-006 rev3).
# NEVER uses check {} blocks (can be silently ignored).

resource "terraform_data" "contract_gate" {
  lifecycle {
    # ── Identity binding ──
    precondition {
      condition     = var.deployment_id != ""
      error_message = "deployment_id is required"
    }
    precondition {
      condition     = can(regex("^dep_[0-9A-HJKMNP-TV-Z]{26}$", var.deployment_id))
      error_message = "deployment_id format invalid"
    }
    precondition {
      condition     = can(regex("^[0-9]{12}$", var.account_id))
      error_message = "account_id must be a 12-digit AWS account ID"
    }

    # ── Release manifest binding ──
    precondition {
      condition     = can(regex("^sha256:[a-f0-9]{64}$", var.release_manifest_digest))
      error_message = "release_manifest_digest must be sha256:<64 hex chars>"
    }

    # ── Upstream contract digest ──
    precondition {
      condition     = var.upstream_contract_digest != ""
      error_message = "upstream contract digest is required — cannot proceed without verified upstream"
    }
    precondition {
      condition     = var.upstream_contract_digest == var.expected_upstream_digest
      error_message = "upstream contract digest does not match expected value — tampered or stale contract"
    }

    # ── Schema version ──
    precondition {
      condition     = contains(var.accepted_schema_versions, var.upstream_schema_version)
      error_message = "upstream contract schema version is not accepted by this consumer"
    }
  }
}
