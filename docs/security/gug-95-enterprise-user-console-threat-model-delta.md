# GUG-95 Enterprise User Console Threat-Model Delta

- **Base model:** `docs/production-readiness/threat-model.md`
- **Decision:** ADR-028
- **Baseline:** `6ed7e34204c9f404c3d05a3dbdbef512000bd6ee`
- **Live validation:** No
- **Production:** NO-GO

## Assets and boundaries

Assets are exact deployment/customer binding, enterprise membership state,
approval and operation evidence, access-token custody, invitation locator,
provider notification effect, audit privacy, and browser diagnostics.

Boundaries are access token to display-only capability parser; runtime config
to exact deployment binding; SPA to protected lifecycle API; GUG-153 PEP to
current authority state; lifecycle service to DynamoDB/provider/audit ports;
and API/edge response to browser CORS visibility.

## Threats and controls

| Threat | Control |
|---|---|
| UI role hiding treated as authorization | Backend PEP is mandatory for every route; UX claims are explicitly display-only |
| Cross-customer/deployment console access | Exact token/runtime customer and deployment equality; zero API calls on mismatch; backend owner-bound queries |
| M2M or inactive membership elevation | Access-token-only human contract, active state, closed role/catalog/digest/time checks |
| Request identity spoofing | Typed client never emits customer, deployment, tenant, subject, provider key, or legacy header authority |
| Enumeration through list or error detail | Owner-bound storage query and cursor; generic 403/404; closed response parser |
| Stale write or unsafe retry | Expected membership version, random idempotency key, conflict state, explicit refresh |
| Duplicate invitation notification | Durable provider-applied checkpoint before conditional membership refresh |
| Resend to foreign provider user | Exact membership owner plus provider subject/reference/key and immutable owner reconciliation before effect |
| Last-admin removal | Existing conditional replacement-admin transaction remains mandatory |
| PII in list, audit, telemetry, or logs | Opaque references only; invitation locator is transient request input; allowlisted bounded in-memory telemetry |
| Error payload or token disclosure | Error bodies never render; token payload is not logged or persisted outside OIDC session storage |
| Correlation header injection | Backend hashes external values to opaque references; frontend accepts only exact `ref_...` pattern |
| Browser preflight bypass or failure | Exact CORS origins and allow headers; diagnostic response allowlist only |
| Unknown/malformed API response | Closed runtime validators fail degraded before rendering or acting |
| Keyboard-inaccessible privileged action | Semantic dialog/table labels, explicit confirmation, focus placement, Escape dismissal |

## Residual risk

Residual risk remains **High**. Local synthetic tests do not prove Cognito,
CloudFront/API Gateway, a provider notification, live CORS behavior, accessible
operation with assistive technology, or isolation between two real authorized
non-production deployments. Human runtime, feature activation, deployment,
migration, and production remain blocked.
