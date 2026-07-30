# ADR-027: Portable Frontend Source Ownership

- **Status:** Proposed; accepted only after reviewed merge and main verification
- **Date:** 2026-07-13
- **Work package:** GUG-95 prerequisite
- **Target baseline:** `e9daaaaa19f5e58505b642a06213588178d212b8`
- **Source snapshot:** locally cached `origin/main` at
  `959b52e57fc0a6f70cc57725ced3dae07a6bf2db`
- **Phase gate:** GUG-117
- **Live source verification:** No
- **AWS activity:** None

Production: **NO-GO**

## Context

The deployment-platform monorepo was already the declared canonical source for
Scanalyze services, infrastructure, policy, and contracts, but it did not
contain the SPA source needed by GUG-95. The only identified frontend was a
separate CodeCommit-backed repository. Its checked-out working tree was dirty,
its local branch was behind its cached remote-tracking ref, and the committed
tree mixed application source with environment files, runtime configuration,
deployment automation, build output, and operational evidence.

Implementing GUG-95 directly in that checkout would violate one-issue/one-
worktree discipline, preserve a customer-account source dependency, and make a
clean-clone CI proof impossible. Copying the working tree would also risk
importing unreviewed or sensitive material.

## Decision

The canonical frontend source path is:

```text
frontend/scanalyze-frontend-ui
```

The initial import is an allowlisted export of committed Git objects from the
last locally available `refs/remotes/origin/main`. It includes application
source, tests, TypeScript/Vite configuration, and the npm lockfile. It excludes
environment files, generated `public/config.json`, deployment scripts, the
legacy buildspec, build output, operational evidence, and every dirty or
untracked working-tree file.

`SOURCE_PROVENANCE.v1.json` records the source commit/tree and explicitly marks
that the CodeCommit ref was not fetched or live-verified. Its closed schema and
repository tests prevent the evidence class from being upgraded silently.

The SPA consumes only the closed `frontend-config.v2` runtime contract. Missing,
oversized, malformed, legacy, mixed-region, identity-authoritative, HTTP, or
policy-digest-conflicting configuration blocks application initialization.
There is no build-time environment or local endpoint fallback. Runtime identity
values remain routing/display material; backend GUG-153 and GUG-114 enforcement
remain authoritative.

The frontend gate runs a clean npm install, dependency audit, TypeScript check,
ESLint, native Node contract tests, Vite build, and synthetic Playwright tests.
It is attached to the existing required PR validation job to avoid introducing
an ungoverned branch-protection context. The clean-clone workflow repeats the
install, audit, checks, and build.

Browser-side effects use a central boundary: external upload, artifact, and
result URLs must be credential-free HTTPS; external previews use
`noopener,noreferrer`; browser-generated CSV neutralizes spreadsheet formulas;
and authenticated exports use the validated API interceptor rather than reading
the access token directly. These are defense-in-depth controls and never
replace backend authorization.

## Consequences

Positive:

- one reviewed GitHub source line can serve every customer/account;
- GUG-95 can proceed in a new worktree after this prerequisite merges;
- runtime configuration fails closed and cannot establish backend authority;
- source history and exclusions are machine-readable; and
- CI uses no AWS, customer configuration, tokens, or real data.

Trade-offs and residual risks:

- the source snapshot is the last locally cached remote ref, not a live
  CodeCommit comparison;
- the first import preserves existing product behavior and design debt outside
  the security/reproducibility boundary;
- the legacy repository is retained until a separately reviewed retirement
  decision; and
- production CSP headers, immutable asset publication, and live browser/provider
  integration still require authorized non-production evidence.

The source-level CSP meta policy cannot enforce `frame-ancestors` and does not
establish the CloudFront response-headers policy. Clickjacking, HSTS, MIME
sniffing, and the final connect-src allowlist remain edge-owned GUG-95 acceptance
work and block production.

## Rollout and rollback

Merge alone publishes no asset and changes no AWS resource. GUG-95 must start
from verified `main` in its already dedicated branch/worktree and must not be
combined with this prerequisite PR.

Rollback is a normal revert of the consolidation commit before any frontend
consumer switches to this path. Do not delete the legacy repository, its
history, or runtime assets as part of rollback. If a later source comparison
finds divergence, reconcile it through a separate reviewed change; never copy a
dirty working tree or infer which branch is authoritative.

## Evidence classification

- **Implemented:** source import, provenance, fail-closed config, local gates,
  workflow integration, tests, and documentation in the candidate branch.
- **Locally validated:** only the named results recorded in the PR.
- **CI validated:** pending the exact PR commit.
- **Live validated:** no.
- **Blocked:** GUG-95 implementation until reviewed merge/main verification;
  live asset publication and provider/browser proof.
- **Production:** **NO-GO**.
