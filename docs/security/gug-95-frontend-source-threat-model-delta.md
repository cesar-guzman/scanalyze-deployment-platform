# GUG-95 Prerequisite Frontend Source Threat-Model Delta

- **Base model:** `docs/production-readiness/threat-model.md`
- **Decision:** ADR-027
- **Target baseline:** `e9daaaaa19f5e58505b642a06213588178d212b8`
- **Live validation:** No
- **Production:** NO-GO

## Assets and trust boundaries

The protected assets are source integrity, dependency reproducibility, exact
deployment/runtime binding, access-token custody, frontend/backend authority
separation, and absence of customer or operational evidence in the canonical
source tree.

Trust boundaries are: legacy Git object to import allowlist; clean clone to npm
lockfile; `/config.json` to the closed v2 parser; OIDC session storage to the API
client; SPA route visibility to backend PDP/PEP; and browser tests to synthetic
network mocks.

## Threats and controls

| Threat | Control |
|---|---|
| Dirty-source or secret import | Exact cached commit/tree, allowlist export, denied classes, Git safety and security sentinel |
| Build-time/customer fork | One target path and release line; no `.env` or live `config.json` |
| Config spoofing or legacy fallback | Closed v2 parser, exact policy digest/scopes/issuer/region, no local/build-time fallback |
| ID token or missing token sent to API | Access-token OIDC storage binding; request fails before network if session is absent, invalid, or expired |
| Spreadsheet formula injection in local exports | All browser-generated CSV cells are quoted, quote-escaped, and formula-neutralized |
| Unsafe presigned/download navigation | Central HTTPS-only browser boundary rejects credentials and non-HTTPS schemes; new windows use `noopener,noreferrer` |
| Frontend claim treated as authority | Runtime identity fields explicitly non-authoritative; GUG-153/GUG-114 remain required backend controls |
| Dependency compromise or drift | Lockfile, `npm ci`, low-threshold audit, pinned CI action and clean-clone reproduction |
| Browser/evidence leakage | No traffic console logging, no remote page assets, synthetic E2E only |
| Operational deployment by import PR | No publish workflow, AWS permission, deploy script, runtime config, or live action in scope |

Residual risk remains **High** until CI is green, the prerequisite is reviewed
and merged, GUG-95 enforces privilege-aware UX over the backend authority, and
an authorized two-deployment non-production proof exists.

The HTML CSP is a source-level defense-in-depth policy. Browser-enforced
`frame-ancestors`, HSTS, X-Content-Type-Options, and the final production CSP
must be emitted by the reviewed CloudFront response-headers policy; a meta tag
cannot prove those edge controls. This prerequisite neither implements nor
live-validates that policy.
