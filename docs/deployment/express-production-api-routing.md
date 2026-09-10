# Express production API routing

The new production environment in account `905418363887`, `us-east-1`, must
connect its existing IaC layers with explicit listener rules and verified TLS.
This patch changes local Terraform only. It does not establish connected
availability or authorize an AWS action.

## Required deployment inputs

`roots/services` requires `alb_service_routes`, keyed by the exact service name.
Every service with a non-null `port` must have exactly one entry. Workers without
a port must have none. Priorities must be unique integers in `1..50000`.
Patterns must stay under `/api/v1/` or `/api/v2/`; there is no catch-all route or
automatic choice of an ingest alias. Each entry permits up to three patterns.
Review overlaps between different rules because ALB evaluates priority first,
and verify that the selected priorities are free on the exact target listener.

Synthetic example only:

```hcl
alb_service_routes = {
  ingest-api = {
    priority      = 100
    path_patterns = ["/api/v1/*", "/api/v2/*"]
  }
}
```

Keep the selected image's listener port aligned with `service_definitions.port`.
The ingest Dockerfile sets `PORT=80`; use port 80, or provide an explicit matching
`PORT` in `extra_environment`. Terraform does not infer or alter that runtime
setting. The default health check uses HTTP `/health` on the target port.

`roots/edge-identity` also requires `alb_tls_server_name`: an exact lowercase
certificate hostname, without wildcard, URL scheme, trailing dot, port, or IP.
There is deliberately no default and no derivation from the ALB DNS name.

The deployment engine does not yet transport these inputs. Its contract renderer
in `scripts/deployment/validate-contract-resolution.py` and
`scripts/deployment/contract_projection.py` projects only catalog bindings;
`scripts/deployment/terraform-layer.sh` supplies additional identity/release
fields but neither routing nor TLS hostname. `service_definitions` also lacks
an engine transport path. The root modules accept reviewed explicit tfvars,
but the existing engine cannot execute this route as-is. A separately reviewed
input-materialization change must carry these non-secret inputs before engine
execution; do not fabricate a contract field or rely on an untracked override.
The services root takes a raw listener ARN: the materialization/preflight packet
must bind it to the verified `platform/v2` output for this customer, deployment,
account, Region, release, and contract digest. That binding now authorizes a
listener mutation and cannot be replaced by an ARN-format check.

## Certificate binding before execution

The current `platform/v2` contract publishes `alb_listener_arn`, but does not
publish a TLS hostname or certificate ARN. This patch does not extend that
contract or add an AWS data source. FQDN validation alone cannot prove the
certificate binding.

Before a provider plan or execution, the separately authorized readback must
establish that the exact deployment/account/Region listener uses the same ACM
certificate ARN supplied to `roots/platform.internal_certificate_arn`, that the
certificate is issued and valid, and that its SAN covers `alb_tls_server_name`.
Review its trust chain and hostname coverage; do not substitute a different
listener, certificate, or hostname if verification fails. The deployment input
and evidence packet must preserve this pairing. API Gateway then verifies the
certificate hostname during TLS and sends it as SNI.

## End-to-end path semantics

| Hop | Behavior |
| --- | --- |
| Browser to CloudFront | HTTPS `/api/v2/...` for the document journey. |
| CloudFront function | Preserves `/api/v2/...`; historical `/api/documents` becomes `/api/v1/documents`. |
| API Gateway | Matches the existing explicit JWT-protected routes. |
| Private integration | HTTPS to the existing ALB listener on 443; `overwrite:path = "$request.path"` removes the stage only. |
| ALB rule | Forwards the matching path unchanged to the service's own HTTP/IP target group. |
| Ingest | Receives `/api/v1/...` or `/api/v2/...`, never an invented `/v2/...` prefix. |

The ALB's default 404, security groups, scopes, and backend authorization are
unchanged. A direct `/api/v1/...` request to the CloudFront historical facade
currently rewrites twice; callers should use its documented `/api/...` facade
or the canonical `/api/v2/...` journey. This patch does not alter that function.

ECS creation depends on listener-rule creation so its target group is already
associated with the ALB. The API deployment digest includes both TLS hostname
and request mapping because the API stage does not auto-deploy.

## Execution permission prerequisite

The terminal-role bootstrap's services runtime permissions and permissions
boundary in `bootstrap/cfn-terminal-roles.yaml` do not currently permit ALB
listener-rule creation/modification (`elasticloadbalancing:CreateRule` and
`elasticloadbalancing:ModifyRule`). Adding a Terraform resource alone cannot
make the deployed role authorized to manage it. Review the exact lifecycle
permissions and resource scope in both policies, then republish and verify the
pinned bootstrap artifact before execution. This patch does not alter IAM,
the bootstrap baseline, or its artifact hash.

## Validation and rollback

Mock-provider tests cover rule ownership, HTTP/worker coverage, priorities,
paths, TLS names, and backend path preservation. They do not validate a live
certificate, target health, or connectivity. Connected release evidence must
cover TLS success and wrong-name failure, healthy targets, preserved V2 paths,
and denied unauthenticated access before claiming availability.

Local verification passed with Terraform 1.14.6 and the locked AWS provider
5.100.0 in isolated copies without backends: 39 services tests (including the
physical-name regressions), 20 edge-identity tests, two services-root tests,
and validation of both modules and roots. The synthetic before/after plan also
confirmed that changing the TLS hostname changes the reviewed deployment
digest. Mock providers do not establish AWS replacement or connectivity.
Ownership/interface checks, focused contract schemas, 32 strict-contract tests,
Terraform formatting, and whitespace checks passed.

Rollback restores the previously reviewed rules/integration and publishes the
corresponding reviewed API deployment; preserve the ALB default denial, audit,
and authorization. Do not delete the ALB or remove JWT protection as rollback.

Sources: [AWS private integrations](https://docs.aws.amazon.com/apigateway/latest/developerguide/http-api-develop-integrations-private.html),
[TLS hostname validation and SNI](https://docs.aws.amazon.com/apigatewayv2/latest/api-reference/apis-apiid-integrations.html),
[ALB path conditions](https://docs.aws.amazon.com/elasticloadbalancing/latest/application/rule-condition-types.html),
[ECS target-group association](https://docs.aws.amazon.com/AmazonECS/latest/developerguide/alb.html).
