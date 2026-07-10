# Alarms Reference

## Alarm Strategy

All alarms are created by Terraform. SNS topic ARN is configured via `observability.alarm_sns_topic_arn` in the deployment manifest.

## Required Alarms

| Alarm | Resource | Condition | Severity |
|---|---|---|---|
| ECS-HighCPU-{service} | ECS Service | CPU > 80% for 5min | WARNING |
| ECS-HighMemory-{service} | ECS Service | Memory > 85% for 5min | WARNING |
| ECS-TaskFailed-{service} | ECS Service | RunningTaskCount = 0 | CRITICAL |
| ALB-Unhealthy-{service} | Target Group | UnhealthyHostCount > 0 for 2min | CRITICAL |
| ALB-HighLatency | ALB | p99 ResponseTime > 5s for 5min | WARNING |
| ALB-5xx | ALB | HTTPCode_ELB_5XX > 10/min | CRITICAL |
| SQS-QueueDepth-{queue} | SQS Queue | Messages > 1000 for 10min | WARNING |
| SQS-AgeOldest-{queue} | SQS Queue | AgeOfOldest > 3600s | CRITICAL |
| SQS-DLQ-{queue} | SQS DLQ | Messages > 0 | CRITICAL |
| DynamoDB-Throttle-{table} | DynamoDB | ThrottledRequests > 0 | WARNING |
| DynamoDB-SystemErrors-{table} | DynamoDB | SystemErrors > 0 | CRITICAL |

## Alarm Actions

- **WARNING**: Notification to SNS topic; no auto-remediation.
- **CRITICAL**: Notification to SNS topic + on-call page.

## Alarm Naming Convention

```
/<deployment_id>/alarms/<resource-type>/<resource-name>/<condition>
```

## Anti-Patterns

- ❌ Alarms created manually via Console (ClickOps)
- ❌ Alarms without SNS target
- ❌ CRITICAL alarms without runbook reference
- ❌ Alarms pointing to resources in different accounts
