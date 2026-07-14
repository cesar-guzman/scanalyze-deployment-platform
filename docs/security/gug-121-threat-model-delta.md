# GUG-121 Threat Model Delta — Strict Deployment Contracts

Production status: **NO-GO**. This delta covers repository behavior only.

| Threat | Previous exposure | Control introduced | Residual boundary |
|---|---|---|---|
| Dependency spoofing | Values could be supplied through environment defaults | Catalog-owned binding plus exact envelope tuple and producer validation | GUG-123 terminal IAM |
| Cross-customer/deployment plan | Contracts lacked mandatory customer binding | v2 envelope and exact customer/deployment/account/region checks | Authorized two-deployment proof |
| Stale or replayed output | Release/digest checks did not enforce freshness | Explicit resolution time, maximum age, immutable release version, release digest, and content digests | GUG-124 signed provenance |
| Wrong target consumption | A valid contract could be passed to an undeclared layer | Catalog consumer binding and exact DAG upstream-set validation | GUG-125 protected engine |
| Ambiguous multi-upstream merge | Equal output names were merged by key | Explicit per-consumer output/metadata/typed-object bindings | Schema review for future versions |
| Producer/schema drift | Several schemas named nonexistent outputs | Real nested producer outputs and additive v2 schemas | Provider-backed non-production plan |
| Arbitrary plan inputs | Plan wrapper fabricated missing values | Mandatory verified resolution; exact DAG set and producer revalidation; zero fallback; owner-only ephemeral tfvars | GUG-122 backend and locking |
| Mutable contract locator | Unversioned paths permit silent replacement | Version-, release-, and digest-addressed SSM template; no `latest` | GUG-125 live publication |
| Sensitive evidence leakage | Full rejected values could enter errors or files | Sanitized errors, no value echo, outside-repo mode-0600 artifacts | CI log review |

The resolution digest prevents accidental or post-resolution alteration but is
not a signature and does not authenticate its writer. GUG-123 and GUG-124 must
provide terminal writer identity and signed provenance before live use.

No AWS, SSM, Terraform provider, backend, plan apply, data migration, customer
document, real token, or production validation is included in GUG-121.
