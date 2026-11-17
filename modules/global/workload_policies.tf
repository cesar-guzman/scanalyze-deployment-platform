# Global layer — Workload identity policies (GUG-541)
#
# A permissions boundary only caps permissions; it never grants them. Before
# this file no module attached an identity policy to aws_iam_role.workload, so
# every service would fail with AccessDenied on its first AWS call.
#
# Each role gets exactly the actions its service code calls, on the resources
# of this deployment only. The global layer is applied before the layers that
# create those resources, so ARNs are derived from their deterministic physical
# names:
#
#   * documents bucket, documents table, stage queues: modules/data-foundation
#   * data KMS key (tagged, random key ID):             modules/data-foundation/kms.tf
#   * Cognito user pool (tagged, random pool ID):       modules/identity-control-plane/cognito.tf
#
# tests/test_gug541_workload_iam.py fails if these names, the queue topology
# or the default Bedrock models drift from their sources.

locals {
  # modules/data-foundation/s3.tf
  workload_documents_bucket_arn = "arn:${var.aws_partition}:s3:::${lower(replace(var.deployment_id, "_", "-"))}-documents"

  # modules/data-foundation/dynamodb.tf
  workload_documents_table_arn = "arn:${var.aws_partition}:dynamodb:${var.region}:${var.account_id}:table/${var.deployment_id}-documents"

  # Canonical GUG-89 stage topology: producers and consumer per stage
  # (modules/data-foundation/locals.tf, queue_topology).
  workload_queue_topology = {
    ingest             = { producers = ["ingest-api"], consumer = "ocr-worker" }
    ocr                = { producers = ["ocr-worker"], consumer = "ocr-worker" }
    classify           = { producers = ["ocr-worker"], consumer = "classifier-worker" }
    "bank-extract"     = { producers = ["ocr-worker", "classifier-worker"], consumer = "bank-worker" }
    "personal-extract" = { producers = ["ocr-worker", "classifier-worker"], consumer = "personal-worker" }
    "gov-extract"      = { producers = ["ocr-worker", "classifier-worker"], consumer = "gov-worker" }
    validate           = { producers = ["bank-worker", "personal-worker", "gov-worker"], consumer = "postprocess-worker" }
    persist            = { producers = ["postprocess-worker"], consumer = "postprocess-worker" }
    notify             = { producers = ["postprocess-worker"], consumer = "postprocess-worker" }
  }

  workload_stage_queue_arns = {
    for stage in keys(local.workload_queue_topology) :
    stage => "arn:${var.aws_partition}:sqs:${var.region}:${var.account_id}:${var.deployment_id}-${stage}-stage-queue"
  }

  # Per-service access, from each service's boto3 calls (backend/workers/*).
  #   s3_object_actions:  HeadObject is authorized by s3:GetObject. The OCR
  #                       worker needs GetObject because Textract reads the
  #                       source object with the caller's credentials.
  #   table_actions:      TransactWriteItems is authorized per item action;
  #                       the ingest API uses ConditionCheck + Update items.
  #   bedrock:            which model list the service may invoke.
  workload_access_profiles = {
    "ingest-api" = {
      s3_object_actions = ["s3:GetObject", "s3:PutObject"]
      s3_list_bucket    = true
      table_actions     = ["dynamodb:ConditionCheckItem", "dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:Query", "dynamodb:UpdateItem"]
      sends_queue_url   = true
      textract          = false
      bedrock           = "none"
      cognito_admin     = true
    }
    "ocr-worker" = {
      s3_object_actions = ["s3:GetObject", "s3:PutObject"]
      s3_list_bucket    = false
      table_actions     = ["dynamodb:GetItem", "dynamodb:UpdateItem"]
      sends_queue_url   = false
      textract          = true
      bedrock           = "none"
      cognito_admin     = false
    }
    "postprocess-worker" = {
      s3_object_actions = ["s3:GetObject"]
      s3_list_bucket    = false
      table_actions     = ["dynamodb:GetItem", "dynamodb:UpdateItem"]
      sends_queue_url   = false
      textract          = false
      bedrock           = "none"
      cognito_admin     = false
    }
    "classifier-worker" = {
      s3_object_actions = ["s3:GetObject"]
      s3_list_bucket    = false
      table_actions     = ["dynamodb:GetItem", "dynamodb:UpdateItem"]
      sends_queue_url   = false
      textract          = false
      bedrock           = "classifier"
      cognito_admin     = false
    }
    "bank-worker" = {
      s3_object_actions = ["s3:GetObject", "s3:PutObject"]
      s3_list_bucket    = false
      table_actions     = ["dynamodb:GetItem", "dynamodb:UpdateItem"]
      sends_queue_url   = false
      textract          = false
      bedrock           = "extractor"
      cognito_admin     = false
    }
    "personal-worker" = {
      s3_object_actions = ["s3:GetObject", "s3:PutObject"]
      s3_list_bucket    = false
      table_actions     = ["dynamodb:GetItem", "dynamodb:UpdateItem"]
      sends_queue_url   = false
      textract          = false
      bedrock           = "extractor"
      cognito_admin     = false
    }
    "gov-worker" = {
      s3_object_actions = ["s3:GetObject", "s3:PutObject"]
      s3_list_bucket    = false
      table_actions     = ["dynamodb:GetItem", "dynamodb:UpdateItem"]
      sends_queue_url   = false
      textract          = false
      bedrock           = "extractor"
      cognito_admin     = false
    }
  }

  # A model ID with a geography prefix (us., eu., apac., us-gov., global.) is
  # a cross-region inference profile: the caller needs the profile ARN plus the
  # foundation model in every region the profile may route to.
  workload_bedrock_model_arns = {
    for list_name, model_ids in {
      classifier = var.bedrock_classifier_model_ids
      extractor  = var.bedrock_extractor_model_ids
      } : list_name => sort(distinct(flatten([
        for model_id in model_ids : (
          can(regex("^(us|eu|apac|us-gov|global)\\.", model_id))
          ? [
            "arn:${var.aws_partition}:bedrock:${var.region}:${var.account_id}:inference-profile/${model_id}",
            "arn:${var.aws_partition}:bedrock:*::foundation-model/${replace(model_id, "/^(us|eu|apac|us-gov|global)\\./", "")}",
          ]
          : ["arn:${var.aws_partition}:bedrock:${var.region}::foundation-model/${model_id}"]
        )
    ])))
  }

  workload_runtime_parameter_arns = [
    "arn:${var.aws_partition}:ssm:${var.region}:${var.account_id}:parameter${var.runtime_parameter_path_prefix}",
    "arn:${var.aws_partition}:ssm:${var.region}:${var.account_id}:parameter${var.runtime_parameter_path_prefix}/*",
  ]

  workload_policy_statements = {
    for service in var.service_names : service => concat(
      [
        {
          Sid      = "ReadRuntimeParameters"
          Effect   = "Allow"
          Action   = ["ssm:GetParameter", "ssm:GetParameters", "ssm:GetParametersByPath"]
          Resource = local.workload_runtime_parameter_arns
        },
        {
          Sid      = "UseDeploymentDataKeyThroughDataServices"
          Effect   = "Allow"
          Action   = ["kms:Decrypt", "kms:GenerateDataKey"]
          Resource = "arn:${var.aws_partition}:kms:${var.region}:${var.account_id}:key/*"
          Condition = {
            StringEquals = {
              "aws:ResourceTag/deployment_id" = var.deployment_id
              "aws:ResourceTag/layer"         = "data-foundation"
              "aws:ResourceTag/purpose"       = "application-data-encryption"
              "kms:ViaService" = [
                "dynamodb.${var.region}.amazonaws.com",
                "s3.${var.region}.amazonaws.com",
                "sqs.${var.region}.amazonaws.com",
              ]
            }
          }
        },
        {
          Sid      = "DocumentObjects"
          Effect   = "Allow"
          Action   = local.workload_access_profiles[service].s3_object_actions
          Resource = "${local.workload_documents_bucket_arn}/*"
        },
        {
          Sid    = "DocumentsTable"
          Effect = "Allow"
          Action = local.workload_access_profiles[service].table_actions
          Resource = concat(
            [local.workload_documents_table_arn],
            contains(local.workload_access_profiles[service].table_actions, "dynamodb:Query") ? ["${local.workload_documents_table_arn}/index/*"] : [],
          )
        },
      ],
      local.workload_access_profiles[service].s3_list_bucket ? [
        {
          Sid      = "ListDocumentObjects"
          Effect   = "Allow"
          Action   = ["s3:ListBucket"]
          Resource = local.workload_documents_bucket_arn
        },
      ] : [],
      length([for stage, binding in local.workload_queue_topology : stage if contains(binding.producers, service)]) > 0 ? [
        {
          Sid      = "SendToDownstreamStageQueues"
          Effect   = "Allow"
          Action   = local.workload_access_profiles[service].sends_queue_url ? ["sqs:GetQueueUrl", "sqs:SendMessage"] : ["sqs:SendMessage"]
          Resource = sort([for stage, binding in local.workload_queue_topology : local.workload_stage_queue_arns[stage] if contains(binding.producers, service)])
        },
      ] : [],
      length([for stage, binding in local.workload_queue_topology : stage if binding.consumer == service]) > 0 ? [
        {
          Sid      = "ConsumeOwnStageQueues"
          Effect   = "Allow"
          Action   = ["sqs:ChangeMessageVisibility", "sqs:DeleteMessage", "sqs:GetQueueAttributes", "sqs:ReceiveMessage"]
          Resource = sort([for stage, binding in local.workload_queue_topology : local.workload_stage_queue_arns[stage] if binding.consumer == service])
        },
      ] : [],
      local.workload_access_profiles[service].textract ? [
        {
          # Textract text detection has no resource-level permissions.
          Sid      = "TextractTextDetection"
          Effect   = "Allow"
          Action   = ["textract:GetDocumentTextDetection", "textract:StartDocumentTextDetection"]
          Resource = "*"
        },
      ] : [],
      local.workload_access_profiles[service].bedrock != "none" ? [
        {
          # The Converse API is authorized by bedrock:InvokeModel.
          Sid      = "InvokeApprovedBedrockModels"
          Effect   = "Allow"
          Action   = ["bedrock:InvokeModel"]
          Resource = local.workload_bedrock_model_arns[local.workload_access_profiles[service].bedrock]
        },
      ] : [],
      local.workload_access_profiles[service].cognito_admin ? [
        {
          Sid    = "AdministerDeploymentUsers"
          Effect = "Allow"
          Action = [
            "cognito-idp:AdminCreateUser",
            "cognito-idp:AdminDisableUser",
            "cognito-idp:AdminEnableUser",
            "cognito-idp:AdminGetUser",
            "cognito-idp:AdminUserGlobalSignOut",
          ]
          Resource = "arn:${var.aws_partition}:cognito-idp:${var.region}:${var.account_id}:userpool/*"
          Condition = {
            StringEquals = {
              "aws:ResourceTag/deployment_id" = var.deployment_id
              "aws:ResourceTag/purpose"       = "enterprise-human-identity"
            }
          }
        },
      ] : [],
    ) if contains(keys(local.workload_access_profiles), service)
  }
}

resource "aws_iam_role_policy" "workload" {
  for_each = aws_iam_role.workload

  name = "${var.deployment_id}-workload-${each.key}"
  role = each.value.id

  policy = jsonencode({
    Version   = "2012-10-17"
    Statement = try(local.workload_policy_statements[each.key], [])
  })

  lifecycle {
    precondition {
      condition     = contains(keys(local.workload_access_profiles), each.key)
      error_message = "Every workload role needs an access profile in modules/global/workload_policies.tf (GUG-541); unknown service: ${each.key}."
    }
  }
}
