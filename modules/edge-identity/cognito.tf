# Cognito has one Terraform owner: modules/identity-control-plane. Existing
# edge-identity state MUST first be imported into that root and reviewed. These
# declarations then forget the legacy addresses without destroying live identity
# resources. There is deliberately no moved block: Terraform cannot move state
# across independent roots, and pretending otherwise would risk replacement.

removed {
  from = aws_cognito_user_pool.main

  lifecycle {
    destroy = false
  }
}

removed {
  from = aws_cognito_user_pool_domain.main

  lifecycle {
    destroy = false
  }
}

removed {
  from = aws_cognito_resource_server.api

  lifecycle {
    destroy = false
  }
}

removed {
  from = aws_cognito_user_pool_client.spa

  lifecycle {
    destroy = false
  }
}

removed {
  from = aws_cognito_user_pool_client.m2m

  lifecycle {
    destroy = false
  }
}

resource "terraform_data" "identity_handoff_gate" {
  input = {
    customer_id              = var.customer_id
    deployment_id            = var.deployment_id
    identity_contract_digest = var.upstream_contract_digest
    issuer                   = var.cognito_issuer_url
    audiences                = local.authorizer_audiences
  }

  lifecycle {
    precondition {
      condition     = var.legacy_identity_handoff_complete
      error_message = "edge-identity is blocked until legacy Cognito state is imported into identity-control-plane or a reviewed no-legacy-state assertion exists."
    }

    precondition {
      condition     = var.upstream_contract_digest == var.expected_upstream_digest
      error_message = "identity-control-plane contract digest is stale, tampered, or unexpected."
    }

    precondition {
      condition     = var.cognito_issuer_url == "https://cognito-idp.${var.region}.${local.aws_dns_suffix}/${var.cognito_user_pool_id}"
      error_message = "Cognito issuer must exactly bind the selected partition, region, and verified user-pool identifier."
    }
  }
}
