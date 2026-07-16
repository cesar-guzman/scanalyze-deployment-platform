# Root: platform-authority

This is the dedicated Scanalyze machine control plane. It is intentionally
separate from every customer AWS account and must not contain a customer
workload, document, PII, Terraform state for a customer deployment, queue, or
runtime service.

## Bootstrap boundary

The root consumes a pre-existing, reviewed remote backend and a short-lived
human administration session supplied through IAM Identity Center. Bootstrap
creates only that state boundary and recovery path; it is not performed by this
root and it cannot use a customer destination account.

GitHub OIDC assumes one exact `ScanalyzeOrchestrator-<deployment_id>` role after
bootstrap. Every role is bound to a single customer, deployment, destination
account, region, environment, repository, and GitHub environment subject.
Static credentials and wildcard subjects are forbidden.

The root is a declaration only until a distinct authority account, profile,
backend binding, reviewed plan, and explicit non-production authorization exist.
