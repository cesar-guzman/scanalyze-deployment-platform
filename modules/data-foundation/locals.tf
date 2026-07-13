locals {
  # Layer metadata
  layer_name   = "data-foundation"
  layer_number = "3"
  state_scope  = "regional" # "global" or "regional"

  # Contract identity binding
  contract_key = "data-foundation/v2"

  # Existing data-foundation/v1 resource instance keys. These addresses and
  # physical names are retained until a separately approved inventory/drain
  # proves that decommissioning cannot lose in-flight or DLQ messages.
  legacy_worker_queues = toset([
    "ocr",
    "postprocess",
    "classifier",
    "bank",
    "personal",
    "gov",
  ])

  # Canonical GUG-89 runtime topology. This is intentionally stage-oriented,
  # not worker-name-oriented: each accepted message has exactly one queue
  # contract and one consumer mode. FIFO and shared-stage queue decisions remain
  # owned by GUG-118; every queue in this contract is Standard.
  queue_topology = {
    ingest = {
      producers                  = ["ingest-api"]
      consumer                   = "ocr-worker"
      consumer_mode              = "INGEST"
      queue_type                 = "standard"
      visibility_timeout_seconds = 300
      max_receive_count          = 3
    }
    ocr = {
      producers                  = ["ocr-worker"]
      consumer                   = "ocr-worker"
      consumer_mode              = "OCR_POLL"
      queue_type                 = "standard"
      visibility_timeout_seconds = 300
      max_receive_count          = 3
    }
    classify = {
      producers                  = ["ocr-worker"]
      consumer                   = "classifier-worker"
      consumer_mode              = "CLASSIFY"
      queue_type                 = "standard"
      visibility_timeout_seconds = 300
      max_receive_count          = 3
    }
    "bank-extract" = {
      producers                  = ["ocr-worker", "classifier-worker"]
      consumer                   = "bank-worker"
      consumer_mode              = "BANK_EXTRACT"
      queue_type                 = "standard"
      visibility_timeout_seconds = 300
      max_receive_count          = 3
    }
    "personal-extract" = {
      producers                  = ["ocr-worker", "classifier-worker"]
      consumer                   = "personal-worker"
      consumer_mode              = "PERSONAL_EXTRACT"
      queue_type                 = "standard"
      visibility_timeout_seconds = 300
      max_receive_count          = 3
    }
    "gov-extract" = {
      producers                  = ["ocr-worker", "classifier-worker"]
      consumer                   = "gov-worker"
      consumer_mode              = "GOV_EXTRACT"
      queue_type                 = "standard"
      visibility_timeout_seconds = 300
      max_receive_count          = 3
    }
    validate = {
      producers                  = ["bank-worker", "personal-worker", "gov-worker"]
      consumer                   = "postprocess-worker"
      consumer_mode              = "VALIDATE"
      queue_type                 = "standard"
      visibility_timeout_seconds = 300
      max_receive_count          = 3
    }
    persist = {
      producers                  = ["postprocess-worker"]
      consumer                   = "postprocess-worker"
      consumer_mode              = "PERSIST"
      queue_type                 = "standard"
      visibility_timeout_seconds = 300
      max_receive_count          = 3
    }
    notify = {
      producers                  = ["postprocess-worker"]
      consumer                   = "postprocess-worker"
      consumer_mode              = "NOTIFY"
      queue_type                 = "standard"
      visibility_timeout_seconds = 300
      max_receive_count          = 3
    }
  }
}
