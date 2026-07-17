# Module: platform-authority

This module creates the portable Scanalyze machine control plane in a dedicated
AWS account. It owns one GitHub Actions OIDC provider, deployment-bound
orchestrator roles, the deployment registry, the execution ledger, the release
manifest bucket, and a dedicated KMS key.

It never creates customer workloads, customer terminal roles, Terraform state
backends, document buckets, queues, Cognito tenants, or processing services.
Those resources remain in each customer destination account and are produced by
the account-vending and deployment DAG contracts.

Every role is bound to one exact `customer_id`, `deployment_id`, destination
account, region, non-production environment, and GitHub environment subject.
The authority account must differ from every destination account.

The module assumes that a human bootstrap boundary and remote backend already
exist. IAM Identity Center is the human access plane; GitHub OIDC is the machine
runtime plane. Static AWS credentials are outside the contract.
