# Runtime parameters contain resource coordinates and explicit feature/model
# selections only. They are never a secret transport or a readiness attestation.
locals {
  runtime_enabled = var.runtime_bindings != null
  runtime_roles   = local.runtime_enabled ? var.runtime_bindings.workload_role_arns : {}
  runtime_domains = local.runtime_enabled ? var.runtime_bindings.worker_domains : {}
  runtime_models  = local.runtime_enabled ? var.runtime_bindings.bedrock_model_arns : {}

  runtime_parameter_roots = {
    for service, domain in local.runtime_domains : service =>
    "/scanalyze/deployments/${var.deployment_id}/runtime/${service}/${domain}"
  }
  runtime_document_prefix = local.runtime_enabled ? "customers/${var.runtime_bindings.customer_id}/deployments/${var.deployment_id}/documents/" : ""

  # Queue permissions and parameter visibility use the same authoritative graph.
  runtime_consumer_stages = {
    for service in keys(local.runtime_roles) : service => [
      for stage, binding in local.queue_topology : stage
      if binding.consumer == trimprefix(service, "scanalyze-")
    ]
  }
  runtime_producer_stages = {
    for service in keys(local.runtime_roles) : service => [
      for stage, binding in local.queue_topology : stage
      if contains(binding.producers, trimprefix(service, "scanalyze-"))
    ]
  }

  runtime_worker_parameters = {
    for service in keys(local.runtime_domains) : service => merge(
      {
        "data-foundation/documents_table_name"   = aws_dynamodb_table.documents.name
        "data-foundation/raw_bucket_name"        = aws_s3_bucket.documents.id
        "data-foundation/ocr_bucket_name"        = aws_s3_bucket.documents.id
        "data-foundation/structured_bucket_name" = aws_s3_bucket.documents.id
      },
      {
        for stage in setunion(
          toset(try(local.runtime_consumer_stages[service], [])),
          toset(try(local.runtime_producer_stages[service], []))
        ) : "queues/${stage}_url" => aws_sqs_queue.stage[stage].url
      },
      contains(keys(local.runtime_models), service) ? { BEDROCK_MODEL_ID = local.runtime_models[service] } : {},
      service == "scanalyze-classifier-worker" ? {
        "features/bedrock_classification_enabled" = tostring(var.runtime_bindings.classifier_bedrock_enabled)
      } : {}
    )
  }
  runtime_parameters = merge({}, [
    for service, parameters in local.runtime_worker_parameters : {
      for key, value in parameters : "${service}/${key}" => {
        service = service
        name    = "${local.runtime_parameter_roots[service]}/${key}"
        value   = value
      }
    }
  ]...)

  # The same explicit schema is necessary in the API and every worker: the
  # managed table uses pk/sk, while unbound runtime defaults use documentId.
  runtime_document_environment = {
    DOCUMENTS_TABLE_PK_NAME     = "pk"
    DOCUMENTS_TABLE_SK_NAME     = "sk"
    DOCUMENTS_TABLE_PK_TEMPLATE = "{document_id}"
    DOCUMENTS_TABLE_SK_TEMPLATE = "METADATA"
  }
  runtime_service_environment = {
    for service in keys(local.runtime_roles) : service => merge(
      local.runtime_document_environment,
      service == "scanalyze-ingest-api" ? {
        APP_ENV                     = var.runtime_bindings.environment
        DOCUMENTS_TABLE_NAME        = aws_dynamodb_table.documents.name
        OPERATION_LEDGER_TABLE_NAME = aws_dynamodb_table.documents.name
        RAW_BUCKET                  = aws_s3_bucket.documents.id
        OCR_BUCKET                  = aws_s3_bucket.documents.id
        STRUCTURED_BUCKET           = aws_s3_bucket.documents.id
        ERRORS_BUCKET               = aws_s3_bucket.documents.id
        FIRST_STAGE                 = "ingest"
        SCANALYZE_PROCESSING_DOMAIN = var.runtime_bindings.processing_domain
        SQS_QUEUE_URLS_JSON         = jsonencode({ ingest = aws_sqs_queue.stage["ingest"].url })
        } : {
        SCANALYZE_ENV        = var.runtime_bindings.environment
        SCANALYZE_TENANT     = try(local.runtime_domains[service], "")
        SCANALYZE_PARAM_ROOT = try(local.runtime_parameter_roots[service], "")
      },
      service == "scanalyze-postprocess-worker" ? { WORKER_MODE = "ALL" } : {}
    )
  }
}

locals {
  # Embedded in contract_payload.outputs so identity, feature selection and
  # environment projection participate in the canonical contract digest.
  runtime_binding_payload = local.runtime_enabled ? {
    schema_version             = "1"
    customer_id                = var.customer_id
    deployment_id              = var.deployment_id
    aws_account_id             = var.account_id
    region                     = var.region
    aws_partition              = var.runtime_bindings.aws_partition
    environment                = var.runtime_bindings.environment
    processing_domain          = var.runtime_bindings.processing_domain
    classifier_bedrock_enabled = var.runtime_bindings.classifier_bedrock_enabled
    release_manifest_digest    = var.release_manifest_digest
    workload_role_arns         = local.runtime_roles
    worker_domains             = local.runtime_domains
    bedrock_model_arns         = local.runtime_models
    service_environment        = local.runtime_service_environment
    parameter_roots            = local.runtime_parameter_roots
    ocr_worker_modes = {
      INGEST   = { WORKER_MODE = "INGEST" }
      OCR_POLL = { WORKER_MODE = "OCR_POLL" }
    }
  } : null
}

resource "aws_ssm_parameter" "runtime" {
  depends_on = [terraform_data.runtime_boundary_gate]
  for_each   = local.runtime_parameters

  name  = each.value.name
  type  = "String"
  value = each.value.value

  tags = {
    deployment_id = var.deployment_id
    managed_by    = "terraform"
    layer         = "data-foundation"
    purpose       = "document-journey-runtime"
    service       = each.value.service
  }
}
