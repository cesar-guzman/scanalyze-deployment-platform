# Observability Guide

## Overview

Scanalyze uses AWS-native observability: CloudWatch Logs, CloudWatch Metrics, Container Insights, and CloudWatch Alarms. All observability resources are created by Terraform (no ClickOps).

## Log Groups

Each microservice gets a dedicated CloudWatch Log Group:

| Service | Log Group Pattern |
|---|---|
| ingest-api | `/<deployment_id>/services/ingest-api` |
| ocr-worker | `/<deployment_id>/services/ocr-worker` |
| postprocess-worker | `/<deployment_id>/services/postprocess-worker` |
| classifier-worker | `/<deployment_id>/services/classifier-worker` |
| bank-worker | `/<deployment_id>/services/bank-worker` |
| personal-worker | `/<deployment_id>/services/personal-worker` |
| gov-worker | `/<deployment_id>/services/gov-worker` |

## Retention

Default: 90 days. Configurable via `observability.log_retention_days` in the deployment manifest.

## Container Insights

Enabled by default via `observability.enable_container_insights: true`. Provides:
- CPU/Memory utilization per task
- Network I/O
- Storage I/O

## Key Metrics

| Metric | Source | Threshold |
|---|---|---|
| ECS Task CPU | Container Insights | > 80% sustained |
| ECS Task Memory | Container Insights | > 85% sustained |
| SQS ApproximateNumberOfMessagesVisible | CloudWatch | > 1000 (queue depth) |
| SQS ApproximateAgeOfOldestMessage | CloudWatch | > 3600s |
| ALB TargetResponseTime | CloudWatch | p99 > 5s |
| ALB UnhealthyHostCount | CloudWatch | > 0 |
| DynamoDB ConsumedReadCapacity | CloudWatch | > 80% provisioned |
| DynamoDB SystemErrors | CloudWatch | > 0 |

## Structured Logging

All services use structured JSON logging with fields:
- `deployment_id`
- `service_name`
- `timestamp`
- `level`
- `message`
- `request_id` (where applicable)
- `document_id` (where applicable)

> **CAUTION**: No PII in logs. Document content, user identifiers, and tenant data must not appear in log messages.

## Dashboard

Terraform creates a CloudWatch Dashboard per deployment. Access via AWS Console or CLI. The dashboard includes:
- Service health overview
- Queue depth trends
- Error rate by service
- Latency percentiles
