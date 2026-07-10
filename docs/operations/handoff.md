# Operational Handoff Guide

## Purpose

This document defines the handoff process from the platform engineering team to the operations team or customer's operations staff.

## Handoff Package Contents

The `scanalyze-deploy.sh handoff-package` command generates:

| File | Description |
|---|---|
| `README.md` | Platform overview |
| `REPRODUCIBILITY.md` | Clone-to-verify guide |
| `manifest-ref.txt` | Pointer to the deployment manifest (not the manifest itself) |
| `handoff-summary.md` | Deployment status, commit, branch, and validation results |

## Pre-Handoff Checklist

- [ ] All Terraform layers applied and validated
- [ ] 7 ECS services running with correct digests
- [ ] CloudWatch log groups created and receiving logs
- [ ] CloudWatch alarms configured and subscribed to SNS
- [ ] ALB health checks passing for all services
- [ ] SQS queues operational with no DLQ messages
- [ ] DynamoDB tables accessible
- [ ] S3 buckets with correct policies
- [ ] Cognito user pool configured (if identity layer deployed)
- [ ] Frontend config.json valid and deployed (if edge layer deployed)
- [ ] Smoke E2E test passed with synthetic document
- [ ] Rollback procedure tested in non-production
- [ ] Deployment manifest updated with current digests
- [ ] Evidence artifacts generated and stored outside Git

## Handoff Meeting Agenda

1. Repository overview and clone verification
2. Deployment manifest walkthrough
3. Orchestrator demonstration (dry-run)
4. Monitoring dashboard tour
5. Alarm response procedures
6. Rollback demonstration
7. Escalation contacts and SLA review
8. Q&A

## Post-Handoff Responsibilities

| Responsibility | Owner |
|---|---|
| Repository maintenance | Platform Engineering |
| Terraform module updates | Platform Engineering |
| Deployment manifest updates | Customer Operations + Platform Engineering |
| Day-to-day monitoring | Customer Operations |
| Incident response | Customer Operations (L1/L2), Platform Engineering (L3) |
| Rollback execution | Customer Operations with Platform Engineering approval |
| Production releases | Platform Engineering with Customer Operations approval |

## Escalation Path

1. **L1**: Customer Operations — monitoring, basic troubleshooting
2. **L2**: Customer Operations — rollback, config changes
3. **L3**: Platform Engineering — infrastructure, code changes
4. **Emergency**: Platform Engineering + Customer Operations joint call
