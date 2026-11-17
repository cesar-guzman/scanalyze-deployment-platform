# Services layer — runtime wiring (GUG-108, ADR-001)
#
# When var.runtime_wiring is set, Terraform injects every runtime setting the
# services read, so no service depends on the legacy SSM tenant tree or on
# SCANALYZE_TENANT:
#
#   * Workers run with SCANALYZE_RUNTIME_CONFIG_SOURCE=environment and read each
#     configuration key from SCANALYZE_CONFIG_<KEY>. The key-to-variable rule is
#     runtime_config_env_name() in backend/workers/*/src/*/config.py.
#   * The ingest API gets its table, buckets and ingest queue through its own
#     settings (backend/workers/scanalyze-ingest-api/app/config.py).
#   * Every service uses the canonical documents table keys pk/sk
#     (modules/data-foundation/dynamodb.tf).
#
# tests/test_gug108_worker_runtime_config.py fails if a key the code reads has
# no variable here.

locals {
  runtime_wiring_enabled = var.runtime_wiring != null

  # Service definitions may use bare or "scanalyze-" prefixed names.
  runtime_service_kind = {
    for svc in var.service_definitions : svc.name => trimprefix(svc.name, "scanalyze-")
  }

  # The OCR poller runs the OCR worker image in OCR_POLL mode, so it uses the
  # OCR worker's task role (modules/global/workload_policies.tf grants that
  # role both OCR stages).
  task_role_service = {
    for svc in var.service_definitions : svc.name => (
      local.runtime_service_kind[svc.name] == "ocr-poll-worker"
      ? replace(svc.name, "ocr-poll-worker", "ocr-worker")
      : svc.name
    )
  }

  runtime_documents_table_keys = [
    { name = "DOCUMENTS_TABLE_PK_NAME", value = "pk" },
    { name = "DOCUMENTS_TABLE_PK_TEMPLATE", value = "{document_id}" },
    { name = "DOCUMENTS_TABLE_SK_NAME", value = "sk" },
    { name = "DOCUMENTS_TABLE_SK_TEMPLATE", value = "METADATA" },
  ]

  runtime_worker_environment = local.runtime_wiring_enabled ? concat(
    [
      { name = "SCANALYZE_RUNTIME_CONFIG_SOURCE", value = "environment" },
      { name = "SCANALYZE_ENV", value = var.runtime_wiring.runtime_environment },
      { name = "SCANALYZE_CONFIG_DATA_FOUNDATION_DOCUMENTS_TABLE_NAME", value = var.runtime_wiring.documents_table_name },
      # The canonical design has one documents bucket; each stage writes under
      # its own prefix.
      { name = "SCANALYZE_CONFIG_DATA_FOUNDATION_RAW_BUCKET_NAME", value = var.runtime_wiring.documents_bucket_name },
      { name = "SCANALYZE_CONFIG_DATA_FOUNDATION_OCR_BUCKET_NAME", value = var.runtime_wiring.documents_bucket_name },
      { name = "SCANALYZE_CONFIG_DATA_FOUNDATION_STRUCTURED_BUCKET_NAME", value = var.runtime_wiring.documents_bucket_name },
    ],
    [
      for stage in sort(keys(var.runtime_wiring.stage_queue_urls)) : {
        name  = "SCANALYZE_CONFIG_QUEUES_${upper(replace(stage, "-", "_"))}_URL"
        value = var.runtime_wiring.stage_queue_urls[stage]
      }
    ],
    local.runtime_documents_table_keys,
  ) : []

  runtime_ingest_environment = local.runtime_wiring_enabled ? concat(
    [
      { name = "APP_ENV", value = var.runtime_wiring.runtime_environment },
      { name = "SCANALYZE_ENV", value = var.runtime_wiring.runtime_environment },
      { name = "DOCUMENTS_TABLE_NAME", value = var.runtime_wiring.documents_table_name },
      # The operation ledger shares the documents table (app/config.py).
      { name = "OPERATION_LEDGER_TABLE_NAME", value = var.runtime_wiring.documents_table_name },
      { name = "RAW_BUCKET", value = var.runtime_wiring.documents_bucket_name },
      { name = "OCR_BUCKET", value = var.runtime_wiring.documents_bucket_name },
      { name = "STRUCTURED_BUCKET", value = var.runtime_wiring.documents_bucket_name },
      { name = "ERRORS_BUCKET", value = var.runtime_wiring.documents_bucket_name },
      { name = "INGEST_QUEUE_URL", value = var.runtime_wiring.stage_queue_urls["ingest"] },
    ],
    local.runtime_documents_table_keys,
  ) : []

  runtime_processing_domain = {
    "bank-worker"     = "bank"
    "personal-worker" = "personal"
    "gov-worker"      = "gov"
  }

  # The OCR worker runs one mode per process; the poller is its own service.
  runtime_worker_mode = {
    "ocr-worker"      = "INGEST"
    "ocr-poll-worker" = "OCR_POLL"
  }

  runtime_environment_by_service = {
    for svc in var.service_definitions : svc.name => (
      !local.runtime_wiring_enabled ? [] : (
        local.runtime_service_kind[svc.name] == "ingest-api" ? local.runtime_ingest_environment : concat(
          local.runtime_worker_environment,
          contains(keys(local.runtime_processing_domain), local.runtime_service_kind[svc.name]) ? [
            { name = "SCANALYZE_PROCESSING_DOMAIN", value = local.runtime_processing_domain[local.runtime_service_kind[svc.name]] },
          ] : [],
          contains(keys(local.runtime_worker_mode), local.runtime_service_kind[svc.name]) ? [
            { name = "WORKER_MODE", value = local.runtime_worker_mode[local.runtime_service_kind[svc.name]] },
          ] : [],
        )
      )
    )
  }
}

resource "terraform_data" "runtime_wiring_gate" {
  for_each = { for svc in var.service_definitions : svc.name => svc }

  input = local.runtime_environment_by_service[each.key]

  lifecycle {
    precondition {
      condition = length(setintersection(
        toset([for item in each.value.extra_environment : upper(item.name)]),
        toset([for item in local.runtime_environment_by_service[each.key] : item.name]),
      )) == 0
      error_message = "extra_environment cannot override the runtime wiring Terraform injects (GUG-108): ${each.key}."
    }

    precondition {
      condition = !local.runtime_wiring_enabled || alltrue([
        for item in each.value.extra_environment :
        !contains(["SCANALYZE_TENANT", "SCANALYZE_TENANTS", "SCANALYZE_PARAM_ROOT"], upper(item.name))
      ])
      error_message = "SCANALYZE_TENANT, SCANALYZE_TENANTS and SCANALYZE_PARAM_ROOT are legacy settings; workers refuse them in environment mode (ADR-001): ${each.key}."
    }

    precondition {
      condition     = contains(keys(var.workload_role_arns), local.task_role_service[each.key])
      error_message = "No workload role for ${each.key} (expected key ${local.task_role_service[each.key]} in workload_role_arns)."
    }
  }
}
