# This ceiling does not grant runtime access by itself. The data resource owner
# supplies the narrower producer/consumer/model grants for each workload role.
locals {
  document_runtime_visibility_stages = [
    "ingest", "ocr", "classify", "bank-extract", "personal-extract",
    "gov-extract", "validate", "persist", "notify",
  ]
  document_runtime_boundary_statements = concat(
    try(var.document_runtime_boundary.sqs_visibility_enabled, false) == true ? [{
      Sid    = "ExtendDeploymentStageVisibility"
      Effect = "Allow"
      Action = ["sqs:ChangeMessageVisibility"]
      Resource = [
        for stage in local.document_runtime_visibility_stages :
        "arn:${var.aws_partition}:sqs:${var.region}:${var.account_id}:${var.deployment_id}-${stage}-stage-queue"
      ]
    }] : [],
    length(try(var.document_runtime_boundary.bedrock_model_arns, [])) > 0 ? [{
      Sid      = "InvokeSelectedRegionalModels"
      Effect   = "Allow"
      Action   = ["bedrock:InvokeModel"]
      Resource = sort(tolist(var.document_runtime_boundary.bedrock_model_arns))
    }] : []
  )
}
