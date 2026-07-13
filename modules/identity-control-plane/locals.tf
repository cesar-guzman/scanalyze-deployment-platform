locals {
  layer_name      = "identity-control-plane"
  state_scope     = "regional"
  identity_prefix = "${var.deployment_id}-identity"

  pre_token_function_name         = "${local.identity_prefix}-pre-token"
  control_processor_function_name = "${local.identity_prefix}-control-processor"

  canonical_scopes = {
    read  = "Read explicitly authorized resources within the bound customer and deployment."
    write = "Create or mutate explicitly authorized resources within the bound customer and deployment."
    admin = "Perform explicitly cataloged privileged operations without bypassing ownership."
  }

  role_precedence = {
    customer_admin    = 10
    document_operator = 20
    document_reviewer = 30
    auditor           = 40
  }

  hosted_ui_prefix = lower(replace(local.identity_prefix, "_", "-"))
  aws_dns_suffix = {
    aws        = "amazonaws.com"
    aws-us-gov = "amazonaws.com"
    aws-cn     = "amazonaws.com.cn"
  }[var.aws_partition]
  cognito_domain_suffix = {
    aws        = "amazoncognito.com"
    aws-us-gov = "amazoncognito.com"
    aws-cn     = "amazoncognito.com.cn"
  }[var.aws_partition]

  common_tags = {
    customer_id   = var.customer_id
    deployment_id = var.deployment_id
    managed_by    = "terraform"
    layer         = local.layer_name
  }

  alarm_definitions = {
    pre-token-errors = {
      namespace   = "AWS/Lambda"
      metric_name = "Errors"
      dimensions  = { FunctionName = aws_lambda_function.pre_token.function_name }
      threshold   = 1
    }
    pre-token-throttles = {
      namespace   = "AWS/Lambda"
      metric_name = "Throttles"
      dimensions  = { FunctionName = aws_lambda_function.pre_token.function_name }
      threshold   = 1
    }
    control-processor-errors = {
      namespace   = "AWS/Lambda"
      metric_name = "Errors"
      dimensions  = { FunctionName = aws_lambda_function.control_processor.function_name }
      threshold   = 1
    }
    control-processor-throttles = {
      namespace   = "AWS/Lambda"
      metric_name = "Throttles"
      dimensions  = { FunctionName = aws_lambda_function.control_processor.function_name }
      threshold   = 1
    }
    bootstrap-dlq-depth = {
      namespace   = "AWS/SQS"
      metric_name = "ApproximateNumberOfMessagesVisible"
      dimensions  = { QueueName = aws_sqs_queue.bootstrap_dlq.name }
      threshold   = 1
    }
  }
}
