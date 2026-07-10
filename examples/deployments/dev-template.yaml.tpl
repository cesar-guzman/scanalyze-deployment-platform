# Scanalyze Deployment Manifest — Generated Local Dev Manifest
#
# DO NOT COMMIT THIS FILE — It is generated dynamically for local non-prod deployments.

schema_version: "1"

customer_id: "__CUSTOMER_ID__"
deployment_id: "dep___CLEAN_CUSTOMER_ID__000000000000"
environment: "dev"

aws_account_id: "__ACCOUNT_ID__"
aws_region: "__REGION__"

terraform_backend:
  bucket: "dep-__CLEAN_CUSTOMER_ID__000000000000-tfstate"
  lock_table: "dep___CLEAN_CUSTOMER_ID__000000000000-tflock"
  key_prefix: "scanalyze/dev"
  kms_key_alias: "alias/scanalyze-tfstate"

github:
  environment: "__CUSTOMER_ID__-dev"
  oidc_role_arn: "arn:aws:iam::__ACCOUNT_ID__:role/github-oidc-scanalyze-deploy"

ecr:
  prefix: "dep-__CLEAN_CUSTOMER_ID__000000000000/scanalyze"
  immutable_tags: true
  scan_on_push: true

base_image_uri: "__ACCOUNT_ID__.dkr.ecr.__REGION__.amazonaws.com/dep-__CLEAN_CUSTOMER_ID__000000000000/scanalyze/base:3.11-slim@sha256:0000000000000000000000000000000000000000000000000000000000000000"

enabled_domains:
  - bank
  - personal
  - gov

feature_flags:
  bedrock_classification: false
  multi_tenant: false
  batch_processing: true

identity:
  cognito_user_pool_id: "__REGION___DEV01"
  cognito_client_ids:
    - "dev0client0id0000000001"
  allowed_token_uses:
    - access
    - id
  deployment_claim: "custom:deployment_id"

frontend:
  asset_bucket: "dep-__CLEAN_CUSTOMER_ID__000000000000-frontend"
  cloudfront_distribution_id: "E0DEV00001"
  api_endpoint: "https://api.__CUSTOMER_ID__.example.com"

observability:
  log_retention_days: 7
  alarm_sns_topic_arn: "arn:aws:sns:__REGION__:__ACCOUNT_ID__:scanalyze-alarms"
  enable_container_insights: true

rollback:
  strategy: "digest-revert"
  last_known_good_tag: "sha-000000000000"
  last_known_good_digests:
    ingest-api: "sha256:0000000000000000000000000000000000000000000000000000000000000000"
    ocr-worker: "sha256:0000000000000000000000000000000000000000000000000000000000000000"
    postprocess-worker: "sha256:0000000000000000000000000000000000000000000000000000000000000000"
    classifier-worker: "sha256:0000000000000000000000000000000000000000000000000000000000000000"
    bank-worker: "sha256:0000000000000000000000000000000000000000000000000000000000000000"
    personal-worker: "sha256:0000000000000000000000000000000000000000000000000000000000000000"
    gov-worker: "sha256:0000000000000000000000000000000000000000000000000000000000000000"

approval:
  change_id: "CHG-0000-DEV"
  approved_by: "local-operator"
  approved_at: "2026-01-01T00:00:00Z"
  evidence_refs:
    - "local-evidence-placeholder"
