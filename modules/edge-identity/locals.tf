locals {
  layer_name  = "edge-identity"
  state_scope = "regional"
  aws_dns_suffix = {
    aws        = "amazonaws.com"
    aws-us-gov = "amazonaws.com"
    aws-cn     = "amazonaws.com.cn"
  }[var.aws_partition]

  canonical_scopes = toset([
    "scanalyze.api.v1/read",
    "scanalyze.api.v1/write",
    "scanalyze.api.v1/admin",
  ])

  authorizer_audiences = concat(
    [var.cognito_spa_client_id],
    var.cognito_m2m_client_ids,
  )

  common_tags = {
    customer_id   = var.customer_id
    deployment_id = var.deployment_id
    managed_by    = "terraform"
    layer         = local.layer_name
  }
}
