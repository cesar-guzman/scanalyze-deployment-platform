locals {
  authority_tags = merge(var.tags, {
    service             = "scanalyze-platform-authority"
    managed_by          = "terraform"
    data_classification = "control-metadata-only"
  })

  aws_dns_suffix = var.aws_partition == "aws-cn" ? "amazonaws.com.cn" : "amazonaws.com"

  orchestrator_policy_document = jsonencode(jsondecode(replace(
    replace(
      replace(
        replace(
          replace(
            replace(
              file("${path.module}/../../policies/iam/orchestrator-role.json"),
              "$${aws_partition}",
              var.aws_partition,
            ),
            "$${aws_dns_suffix}",
            local.aws_dns_suffix,
          ),
          "$${platform_authority_kms_key_arn}",
          aws_kms_key.control_plane.arn,
        ),
        "$${region}",
        var.authority_region,
      ),
      "$${shared_services_account_id}",
      var.authority_account_id,
    ),
    "$${release_bucket_name}",
    var.release_bucket_name,
  )))

  orchestrator_role_bindings = {
    for deployment_key, deployment in var.deployments : deployment_key => {
      role_name                          = "ScanalyzeOrchestrator-${deployment.deployment_id}"
      customer_id                        = deployment.customer_id
      deployment_id                      = deployment.deployment_id
      destination_account_id             = deployment.destination_account_id
      region                             = deployment.region
      environment                        = deployment.environment
      github_oidc_subject                = deployment.github_oidc_subject
      repository_owner_id                = tostring(deployment.repository_owner_id)
      repository_id                      = tostring(deployment.repository_id)
      requested_session_duration_seconds = 900
    }
  }

  github_trust_documents = {
    for deployment_key, deployment in var.deployments : deployment_key => jsonencode({
      Version = "2012-10-17"
      Statement = [{
        Sid    = "ExactGitHubEnvironment"
        Effect = "Allow"
        Action = "sts:AssumeRoleWithWebIdentity"
        Principal = {
          Federated = aws_iam_openid_connect_provider.github.arn
        }
        Condition = {
          StringEquals = {
            "token.actions.githubusercontent.com:aud"                 = "sts.amazonaws.com"
            "token.actions.githubusercontent.com:sub"                 = deployment.github_oidc_subject
            "token.actions.githubusercontent.com:repository_owner_id" = tostring(deployment.repository_owner_id)
            "token.actions.githubusercontent.com:repository_id"       = tostring(deployment.repository_id)
          }
        }
      }]
    })
  }
}
