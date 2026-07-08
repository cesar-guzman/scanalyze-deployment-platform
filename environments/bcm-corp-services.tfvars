# Services layer — values from global, network, platform outputs
# Updated: 2026-07-06 — Token type fix + env var addition

# Root-level identity and contract variables
deployment_id              = "dep_01KWM783E0S1FZVAM8FRDV1HR2"
account_id                 = "905418363887"
region                     = "us-east-1"
release_version            = "1.0.0"
release_manifest_digest    = "sha256:0000000000000000000000000000000000000000000000000000000000000001"
upstream_contract_digest   = "sha256:0000000000000000000000000000000000000000000000000000000000000001"
expected_upstream_digest   = "sha256:0000000000000000000000000000000000000000000000000000000000000001"
upstream_schema_version    = "1"

vpc_id = "vpc-067048ae37526c106"

private_subnet_ids = {
  "use1-az1" = "subnet-00c1247bdad50f5db"
  "use1-az2" = "subnet-083dccebafb4d4634"
}

ecs_cluster_arn            = "arn:aws:ecs:us-east-1:905418363887:cluster/83E0S1FZVAM8FRDV1HR2-cluster"
ecs_task_execution_role_arn = "arn:aws:iam::905418363887:role/dep_01KWM783E0S1FZVAM8FRDV1HR2-ecs-task-execution"
alb_listener_arn           = "arn:aws:elasticloadbalancing:us-east-1:905418363887:listener/app/83E0S1FZVAM8FRDV1HR2-alb/3a793663b6ad2d73/c1dcc7ac61ac1a91"
alb_security_group_id      = "sg-09882e3ca72ae8f5a"

workload_role_arns = {
  "ingest-api"         = "arn:aws:iam::905418363887:role/dep_01KWM783E0S1FZVAM8FRDV1HR2-workload-ingest-api"
  "ocr-worker"         = "arn:aws:iam::905418363887:role/dep_01KWM783E0S1FZVAM8FRDV1HR2-workload-ocr-worker"
  "postprocess-worker" = "arn:aws:iam::905418363887:role/dep_01KWM783E0S1FZVAM8FRDV1HR2-workload-postprocess-worker"
  "classifier-worker"  = "arn:aws:iam::905418363887:role/dep_01KWM783E0S1FZVAM8FRDV1HR2-workload-classifier-worker"
  "bank-worker"        = "arn:aws:iam::905418363887:role/dep_01KWM783E0S1FZVAM8FRDV1HR2-workload-bank-worker"
  "personal-worker"    = "arn:aws:iam::905418363887:role/dep_01KWM783E0S1FZVAM8FRDV1HR2-workload-personal-worker"
  "gov-worker"         = "arn:aws:iam::905418363887:role/dep_01KWM783E0S1FZVAM8FRDV1HR2-workload-gov-worker"
}

service_definitions = [
  {
    name              = "ingest-api"
    image             = "905418363887.dkr.ecr.us-east-1.amazonaws.com/dep-01kwm783e0s1fzvam8frdv1hr2/scanalyze/ingest-api@sha256:626b5a814e44d7a5fbc521df1fd0d494b02e190208168ff2752fcab9000af0b2"
    cpu               = 256
    memory            = 512
    port              = 8080
    desired_count     = 1
    health_check_path = "/health"
    extra_environment = [
      { name = "AUTH_MODE",                  value = "cognito_jwt" },
      { name = "APP_ENV",                    value = "dev" },
      { name = "SCANALYZE_ENV",              value = "demo" },
      { name = "SCANALYZE_TENANT",           value = "platform" },
      { name = "COGNITO_USER_POOL_ID",       value = "us-east-1_IgGrmmowU" },
      { name = "COGNITO_ALLOWED_CLIENT_IDS", value = "6f69sptl6i2j9iuh47mnfqa69k,1gt7b7ir4elftfv95mvoa01nj7" },
      { name = "DEPLOYMENT_ID",              value = "dep_01KWM783E0S1FZVAM8FRDV1HR2" },
      { name = "AWS_DEFAULT_REGION",         value = "us-east-1" },
      { name = "SQS_OCR_QUEUE_URL",          value = "https://sqs.us-east-1.amazonaws.com/905418363887/dep_01KWM783E0S1FZVAM8FRDV1HR2-ocr-queue" },
      { name = "INGEST_QUEUE_URL",           value = "https://sqs.us-east-1.amazonaws.com/905418363887/dep_01KWM783E0S1FZVAM8FRDV1HR2-ocr-queue" },
      { name = "DOCUMENTS_TABLE_NAME",       value = "dep_01KWM783E0S1FZVAM8FRDV1HR2-documents" },
      { name = "JOBS_TABLE_NAME",            value = "dep_01KWM783E0S1FZVAM8FRDV1HR2-jobs" },
      { name = "DOCUMENTS_BUCKET",           value = "dep-01kwm783e0s1fzvam8frdv1hr2-documents" },
      { name = "RAW_BUCKET",                 value = "dep-01kwm783e0s1fzvam8frdv1hr2-documents" },
      { name = "PORT",                        value = "8080" },
      { name = "ROOT_PATH",                   value = "/ingest-api" },
      { name = "COGNITO_ALLOWED_TOKEN_USES",  value = "access,id" },
      { name = "DOCUMENTS_TABLE_PK_NAME",     value = "pk" },
      { name = "DOCUMENTS_TABLE_SK_NAME",     value = "sk" },
      { name = "DOCUMENTS_TABLE_PK_TEMPLATE", value = "DOC#{document_id}" },
      { name = "DOCUMENTS_TABLE_SK_TEMPLATE", value = "METADATA" },
      { name = "M2M_TENANT_RESOLUTION",       value = "client_id_map" },
      { name = "M2M_CLIENT_TENANT_MAP",       value = "{\"1gt7b7ir4elftfv95mvoa01nj7\":\"bcm-corp\"}" },
      { name = "BATCHES_TABLE_NAME",           value = "dep_01KWM783E0S1FZVAM8FRDV1HR2-batches" },
    ]
  },
  {
    name              = "ocr-worker"
    image             = "905418363887.dkr.ecr.us-east-1.amazonaws.com/dep-01kwm783e0s1fzvam8frdv1hr2/scanalyze/ocr-worker@sha256:0687b66b4719eeac22a156069830237437bd13556a3be39df5eb6ee4514b9690"
    cpu               = 256
    memory            = 512
    desired_count     = 1
    health_check_path = "/health"
    extra_environment = [
      { name = "APP_ENV",              value = "dev" },
      { name = "SCANALYZE_ENV",        value = "demo" },
      { name = "SCANALYZE_TENANT",     value = "platform" },
      { name = "DEPLOYMENT_ID",        value = "dep_01KWM783E0S1FZVAM8FRDV1HR2" },
      { name = "AWS_DEFAULT_REGION",   value = "us-east-1" },
      { name = "SQS_OCR_QUEUE_URL",    value = "https://sqs.us-east-1.amazonaws.com/905418363887/dep_01KWM783E0S1FZVAM8FRDV1HR2-ocr-queue" },
      { name = "SQS_POSTPROCESS_QUEUE_URL", value = "https://sqs.us-east-1.amazonaws.com/905418363887/dep_01KWM783E0S1FZVAM8FRDV1HR2-postprocess-queue" },
      { name = "DOCUMENTS_TABLE_NAME", value = "dep_01KWM783E0S1FZVAM8FRDV1HR2-documents" },
      { name = "DOCUMENTS_BUCKET",     value = "dep-01kwm783e0s1fzvam8frdv1hr2-documents" },
      { name = "SCANALYZE_PARAM_ROOT", value = "/scanalyze/demo/tenants" },
      # SSM fallback env vars (mapped from SSM keys)
      { name = "QUEUES_INGEST_URL",    value = "https://sqs.us-east-1.amazonaws.com/905418363887/dep_01KWM783E0S1FZVAM8FRDV1HR2-ocr-queue" },
      { name = "QUEUES_OCR_URL",       value = "https://sqs.us-east-1.amazonaws.com/905418363887/dep_01KWM783E0S1FZVAM8FRDV1HR2-ocr-queue" },
      { name = "QUEUES_VALIDATE_URL",  value = "https://sqs.us-east-1.amazonaws.com/905418363887/dep_01KWM783E0S1FZVAM8FRDV1HR2-postprocess-queue" },
      { name = "DATA_FOUNDATION_DOCUMENTS_TABLE_NAME", value = "dep_01KWM783E0S1FZVAM8FRDV1HR2-documents" },
      { name = "DATA_FOUNDATION_OCR_BUCKET_NAME", value = "dep-01kwm783e0s1fzvam8frdv1hr2-documents" },
      { name = "DATA_FOUNDATION_RAW_BUCKET_NAME", value = "dep-01kwm783e0s1fzvam8frdv1hr2-documents" },
      { name = "DATA_FOUNDATION_STRUCTURED_BUCKET_NAME", value = "dep-01kwm783e0s1fzvam8frdv1hr2-documents" },
      { name = "DOCUMENTS_TABLE_PK_NAME", value = "pk" },
      { name = "DOCUMENTS_TABLE_SK_NAME", value = "sk" },
      { name = "DOCUMENTS_TABLE_PK_TEMPLATE", value = "DOC#{document_id}" },
      { name = "DOCUMENTS_TABLE_SK_TEMPLATE", value = "METADATA" },
    ]
  },
  {
    name              = "postprocess-worker"
    image             = "905418363887.dkr.ecr.us-east-1.amazonaws.com/dep-01kwm783e0s1fzvam8frdv1hr2/scanalyze/postprocess-worker@sha256:69d744b5e5803655f287d389dea6cbea3d5ffa2a2ec8855616d2d6d83f66fb5b"
    cpu               = 256
    memory            = 512
    desired_count     = 1
    health_check_path = "/health"
    extra_environment = [
      { name = "APP_ENV",              value = "dev" },
      { name = "SCANALYZE_ENV",        value = "demo" },
      { name = "SCANALYZE_TENANT",     value = "platform" },
      { name = "SCANALYZE_TENANTS",    value = "platform" },
      { name = "WORKER_MODE",          value = "ALL" },
      { name = "DEPLOYMENT_ID",        value = "dep_01KWM783E0S1FZVAM8FRDV1HR2" },
      { name = "AWS_DEFAULT_REGION",   value = "us-east-1" },
      { name = "SQS_POSTPROCESS_QUEUE_URL", value = "https://sqs.us-east-1.amazonaws.com/905418363887/dep_01KWM783E0S1FZVAM8FRDV1HR2-postprocess-queue" },
      { name = "SQS_CLASSIFIER_QUEUE_URL",  value = "https://sqs.us-east-1.amazonaws.com/905418363887/dep_01KWM783E0S1FZVAM8FRDV1HR2-classifier-queue" },
      { name = "DOCUMENTS_TABLE_NAME", value = "dep_01KWM783E0S1FZVAM8FRDV1HR2-documents" },
      { name = "DOCUMENTS_BUCKET",     value = "dep-01kwm783e0s1fzvam8frdv1hr2-documents" },
      { name = "SCANALYZE_PARAM_ROOT", value = "/scanalyze/demo/tenants" },
      # SSM fallback env vars
      { name = "QUEUES_VALIDATE_URL",  value = "https://sqs.us-east-1.amazonaws.com/905418363887/dep_01KWM783E0S1FZVAM8FRDV1HR2-postprocess-queue" },
      { name = "QUEUES_PERSIST_URL",   value = "https://sqs.us-east-1.amazonaws.com/905418363887/dep_01KWM783E0S1FZVAM8FRDV1HR2-postprocess-queue" },
      { name = "QUEUES_NOTIFY_URL",    value = "https://sqs.us-east-1.amazonaws.com/905418363887/dep_01KWM783E0S1FZVAM8FRDV1HR2-postprocess-queue" },
      { name = "DATA_FOUNDATION_DOCUMENTS_TABLE_NAME", value = "dep_01KWM783E0S1FZVAM8FRDV1HR2-documents" },
      { name = "DATA_FOUNDATION_STRUCTURED_BUCKET_NAME", value = "dep-01kwm783e0s1fzvam8frdv1hr2-documents" },
      { name = "DATA_FOUNDATION_OCR_BUCKET_NAME", value = "dep-01kwm783e0s1fzvam8frdv1hr2-documents" },
      { name = "DOCUMENTS_TABLE_PK_NAME", value = "pk" },
      { name = "DOCUMENTS_TABLE_SK_NAME", value = "sk" },
      { name = "DOCUMENTS_TABLE_PK_TEMPLATE", value = "DOC#{document_id}" },
      { name = "DOCUMENTS_TABLE_SK_TEMPLATE", value = "METADATA" },
    ]
  },
  {
    name              = "classifier-worker"
    image             = "905418363887.dkr.ecr.us-east-1.amazonaws.com/dep-01kwm783e0s1fzvam8frdv1hr2/scanalyze/classifier-worker@sha256:7e9f6b9c61477ce6a3c56ec838a58f74c2cd0d9c63fae37a917bc895276833f7"
    cpu               = 256
    memory            = 512
    desired_count     = 1
    health_check_path = "/health"
    extra_environment = [
      { name = "APP_ENV",              value = "dev" },
      { name = "SCANALYZE_ENV",        value = "demo" },
      { name = "SCANALYZE_TENANT",     value = "platform" },
      { name = "DEPLOYMENT_ID",        value = "dep_01KWM783E0S1FZVAM8FRDV1HR2" },
      { name = "AWS_DEFAULT_REGION",   value = "us-east-1" },
      { name = "SQS_CLASSIFIER_QUEUE_URL", value = "https://sqs.us-east-1.amazonaws.com/905418363887/dep_01KWM783E0S1FZVAM8FRDV1HR2-classifier-queue" },
      { name = "SQS_BANK_QUEUE_URL",       value = "https://sqs.us-east-1.amazonaws.com/905418363887/dep_01KWM783E0S1FZVAM8FRDV1HR2-bank-queue" },
      { name = "SQS_PERSONAL_QUEUE_URL",   value = "https://sqs.us-east-1.amazonaws.com/905418363887/dep_01KWM783E0S1FZVAM8FRDV1HR2-personal-queue" },
      { name = "SQS_GOV_QUEUE_URL",        value = "https://sqs.us-east-1.amazonaws.com/905418363887/dep_01KWM783E0S1FZVAM8FRDV1HR2-gov-queue" },
      { name = "DOCUMENTS_TABLE_NAME", value = "dep_01KWM783E0S1FZVAM8FRDV1HR2-documents" },
      { name = "DOCUMENTS_BUCKET",     value = "dep-01kwm783e0s1fzvam8frdv1hr2-documents" },
      { name = "SCANALYZE_PARAM_ROOT", value = "/scanalyze/demo/tenants" },
      # SSM fallback env vars
      { name = "QUEUES_CLASSIFY_URL",  value = "https://sqs.us-east-1.amazonaws.com/905418363887/dep_01KWM783E0S1FZVAM8FRDV1HR2-classifier-queue" },
      { name = "DATA_FOUNDATION_OCR_BUCKET_NAME", value = "dep-01kwm783e0s1fzvam8frdv1hr2-documents" },
      { name = "DATA_FOUNDATION_DOCUMENTS_TABLE_NAME", value = "dep_01KWM783E0S1FZVAM8FRDV1HR2-documents" },
      { name = "DATA_FOUNDATION_STRUCTURED_BUCKET_NAME", value = "dep-01kwm783e0s1fzvam8frdv1hr2-documents" },
      { name = "FEATURES_BEDROCK_CLASSIFICATION_ENABLED", value = "false" },
      { name = "DOCUMENTS_TABLE_PK_NAME", value = "pk" },
      { name = "DOCUMENTS_TABLE_SK_NAME", value = "sk" },
      { name = "DOCUMENTS_TABLE_PK_TEMPLATE", value = "DOC#{document_id}" },
      { name = "DOCUMENTS_TABLE_SK_TEMPLATE", value = "METADATA" },
    ]
  },
  {
    name              = "bank-worker"
    image             = "905418363887.dkr.ecr.us-east-1.amazonaws.com/dep-01kwm783e0s1fzvam8frdv1hr2/scanalyze/bank-worker@sha256:f1c34e79252b5c9c0e7fa14bf6bfd5c48d527b369712936d9f8d320cac134af6"
    cpu               = 256
    memory            = 512
    desired_count     = 1
    health_check_path = "/health"
    extra_environment = [
      { name = "APP_ENV",              value = "dev" },
      { name = "SCANALYZE_ENV",        value = "demo" },
      { name = "SCANALYZE_TENANT",     value = "platform" },
      { name = "DEPLOYMENT_ID",        value = "dep_01KWM783E0S1FZVAM8FRDV1HR2" },
      { name = "AWS_DEFAULT_REGION",   value = "us-east-1" },
      { name = "SQS_BANK_QUEUE_URL",   value = "https://sqs.us-east-1.amazonaws.com/905418363887/dep_01KWM783E0S1FZVAM8FRDV1HR2-bank-queue" },
      { name = "DOCUMENTS_TABLE_NAME", value = "dep_01KWM783E0S1FZVAM8FRDV1HR2-documents" },
      { name = "DOCUMENTS_BUCKET",     value = "dep-01kwm783e0s1fzvam8frdv1hr2-documents" },
      { name = "SCANALYZE_PARAM_ROOT", value = "/scanalyze/demo/tenants" },
      # SSM fallback env vars
      { name = "QUEUES_BANK_EXTRACT_URL", value = "https://sqs.us-east-1.amazonaws.com/905418363887/dep_01KWM783E0S1FZVAM8FRDV1HR2-bank-queue" },
      { name = "DATA_FOUNDATION_OCR_BUCKET_NAME", value = "dep-01kwm783e0s1fzvam8frdv1hr2-documents" },
      { name = "DATA_FOUNDATION_STRUCTURED_BUCKET_NAME", value = "dep-01kwm783e0s1fzvam8frdv1hr2-documents" },
      { name = "QUEUES_VALIDATE_URL",  value = "https://sqs.us-east-1.amazonaws.com/905418363887/dep_01KWM783E0S1FZVAM8FRDV1HR2-postprocess-queue" },
      { name = "DATA_FOUNDATION_DOCUMENTS_TABLE_NAME", value = "dep_01KWM783E0S1FZVAM8FRDV1HR2-documents" },
      { name = "DOCUMENTS_TABLE_PK_NAME", value = "pk" },
      { name = "DOCUMENTS_TABLE_SK_NAME", value = "sk" },
      { name = "DOCUMENTS_TABLE_PK_TEMPLATE", value = "DOC#{document_id}" },
      { name = "DOCUMENTS_TABLE_SK_TEMPLATE", value = "METADATA" },
    ]
  },
  {
    name              = "personal-worker"
    image             = "905418363887.dkr.ecr.us-east-1.amazonaws.com/dep-01kwm783e0s1fzvam8frdv1hr2/scanalyze/personal-worker@sha256:ced091142af77004d94d9af04e43beea708a1e41fbf62c6ee54a16c094fd534f"
    cpu               = 256
    memory            = 512
    desired_count     = 1
    health_check_path = "/health"
    extra_environment = [
      { name = "APP_ENV",              value = "dev" },
      { name = "SCANALYZE_ENV",        value = "demo" },
      { name = "SCANALYZE_TENANT",     value = "personal" },
      { name = "DEPLOYMENT_ID",        value = "dep_01KWM783E0S1FZVAM8FRDV1HR2" },
      { name = "AWS_DEFAULT_REGION",   value = "us-east-1" },
      { name = "SQS_PERSONAL_QUEUE_URL", value = "https://sqs.us-east-1.amazonaws.com/905418363887/dep_01KWM783E0S1FZVAM8FRDV1HR2-personal-queue" },
      { name = "DOCUMENTS_TABLE_NAME", value = "dep_01KWM783E0S1FZVAM8FRDV1HR2-documents" },
      { name = "DOCUMENTS_BUCKET",     value = "dep-01kwm783e0s1fzvam8frdv1hr2-documents" },
      { name = "SCANALYZE_PARAM_ROOT", value = "/scanalyze/demo/tenants" },
      # SSM fallback env vars
      { name = "QUEUES_PERSONAL_EXTRACT_URL", value = "https://sqs.us-east-1.amazonaws.com/905418363887/dep_01KWM783E0S1FZVAM8FRDV1HR2-personal-queue" },
      { name = "DATA_FOUNDATION_OCR_BUCKET_NAME", value = "dep-01kwm783e0s1fzvam8frdv1hr2-documents" },
      { name = "DATA_FOUNDATION_STRUCTURED_BUCKET_NAME", value = "dep-01kwm783e0s1fzvam8frdv1hr2-documents" },
      { name = "QUEUES_VALIDATE_URL",  value = "https://sqs.us-east-1.amazonaws.com/905418363887/dep_01KWM783E0S1FZVAM8FRDV1HR2-postprocess-queue" },
      { name = "DATA_FOUNDATION_DOCUMENTS_TABLE_NAME", value = "dep_01KWM783E0S1FZVAM8FRDV1HR2-documents" },
      { name = "DOCUMENTS_TABLE_PK_NAME", value = "pk" },
      { name = "DOCUMENTS_TABLE_SK_NAME", value = "sk" },
      { name = "DOCUMENTS_TABLE_PK_TEMPLATE", value = "DOC#{document_id}" },
      { name = "DOCUMENTS_TABLE_SK_TEMPLATE", value = "METADATA" },
    ]
  },
  {
    name              = "gov-worker"
    image             = "905418363887.dkr.ecr.us-east-1.amazonaws.com/dep-01kwm783e0s1fzvam8frdv1hr2/scanalyze/gov-worker@sha256:1d8d6a7467e21ddaa935045639011f99a1464bb514c187732c25d2312e4e1c77"
    cpu               = 256
    memory            = 512
    desired_count     = 1
    health_check_path = "/health"
    extra_environment = [
      { name = "APP_ENV",              value = "dev" },
      { name = "SCANALYZE_ENV",        value = "demo" },
      { name = "SCANALYZE_TENANT",     value = "gov" },
      { name = "DEPLOYMENT_ID",        value = "dep_01KWM783E0S1FZVAM8FRDV1HR2" },
      { name = "AWS_DEFAULT_REGION",   value = "us-east-1" },
      { name = "SQS_GOV_QUEUE_URL",    value = "https://sqs.us-east-1.amazonaws.com/905418363887/dep_01KWM783E0S1FZVAM8FRDV1HR2-gov-queue" },
      { name = "DOCUMENTS_TABLE_NAME", value = "dep_01KWM783E0S1FZVAM8FRDV1HR2-documents" },
      { name = "DOCUMENTS_BUCKET",     value = "dep-01kwm783e0s1fzvam8frdv1hr2-documents" },
      { name = "SCANALYZE_PARAM_ROOT", value = "/scanalyze/demo/tenants" },
      # SSM fallback env vars
      { name = "QUEUES_GOV_EXTRACT_URL", value = "https://sqs.us-east-1.amazonaws.com/905418363887/dep_01KWM783E0S1FZVAM8FRDV1HR2-gov-queue" },
      { name = "DATA_FOUNDATION_OCR_BUCKET_NAME", value = "dep-01kwm783e0s1fzvam8frdv1hr2-documents" },
      { name = "DATA_FOUNDATION_STRUCTURED_BUCKET_NAME", value = "dep-01kwm783e0s1fzvam8frdv1hr2-documents" },
      { name = "QUEUES_VALIDATE_URL",  value = "https://sqs.us-east-1.amazonaws.com/905418363887/dep_01KWM783E0S1FZVAM8FRDV1HR2-postprocess-queue" },
      { name = "DATA_FOUNDATION_DOCUMENTS_TABLE_NAME", value = "dep_01KWM783E0S1FZVAM8FRDV1HR2-documents" },
      { name = "DOCUMENTS_TABLE_PK_NAME", value = "pk" },
      { name = "DOCUMENTS_TABLE_SK_NAME", value = "sk" },
      { name = "DOCUMENTS_TABLE_PK_TEMPLATE", value = "DOC#{document_id}" },
      { name = "DOCUMENTS_TABLE_SK_TEMPLATE", value = "METADATA" },
    ]
  },
]
customer_id = "bcm-corp"
