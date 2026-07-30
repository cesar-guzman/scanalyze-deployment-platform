resource "aws_iam_openid_connect_provider" "github" {
  url            = "https://token.actions.githubusercontent.com"
  client_id_list = ["sts.amazonaws.com"]

  tags = local.authority_tags

  depends_on = [terraform_data.contract]

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_iam_policy" "orchestrator_runtime" {
  name        = "ScanalyzePlatformAuthorityOrchestratorRuntime"
  description = "Runtime permissions for deployment-bound Scanalyze orchestrators."
  policy      = local.orchestrator_policy_document
  tags        = local.authority_tags

  depends_on = [terraform_data.contract]

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_iam_policy" "orchestrator_boundary" {
  name        = "ScanalyzePlatformAuthorityOrchestratorBoundary"
  description = "Maximum permissions boundary for Scanalyze orchestrator roles."
  policy      = local.orchestrator_policy_document
  tags        = local.authority_tags

  depends_on = [terraform_data.contract]

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_iam_role" "orchestrator" {
  for_each = var.deployments

  name               = "ScanalyzeOrchestrator-${each.value.deployment_id}"
  description        = "Deployment-bound GitHub OIDC orchestrator for ${each.value.deployment_id}."
  assume_role_policy = local.github_trust_documents[each.key]
  # AWS IAM role configuration accepts a minimum ceiling of one hour. The
  # OIDC caller contract must explicitly request the STS minimum of 900s.
  max_session_duration = 3600
  permissions_boundary = aws_iam_policy.orchestrator_boundary.arn

  tags = merge(local.authority_tags, {
    service       = "scanalyze-orchestrator"
    customer_id   = each.value.customer_id
    deployment_id = each.value.deployment_id
    account_id    = each.value.destination_account_id
    region        = each.value.region
    environment   = each.value.environment
    repository_id = tostring(each.value.repository_id)
  })

  depends_on = [terraform_data.contract]

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_iam_role_policy_attachment" "orchestrator_runtime" {
  for_each = var.deployments

  role       = aws_iam_role.orchestrator[each.key].name
  policy_arn = aws_iam_policy.orchestrator_runtime.arn
}
