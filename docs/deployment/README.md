# Enterprise deployment documentation

This directory contains the distributable deployment guide for Scanalyze. The
authoritative operational source remains
[`playbooks/enterprise-client-deployment.md`](../../playbooks/enterprise-client-deployment.md).
The Word file is a derived, sanitized artifact for enterprise review and
handoff; operators must resolve discrepancies in favor of the Markdown source.

## Current execution status

The guide is **DRAFT - NON-EXECUTABLE - NO-GO**. It describes the reviewed
target process, controls, stop conditions, ownership boundaries and evidence
requirements. It does not authorize AWS changes. Production execution remains
blocked until every P0 blocker in the guide is closed, the relevant CI gates
pass, and an approved non-production deployment and rollback produce reviewable
evidence.

## Artifacts

- `../production-readiness/README.md`: Phase 0 architecture, threat model,
  ownership, evidence, gates, work packages, and recovery boundaries.
- `Scanalyze_Enterprise_Deployment_Guide.docx`: generated locally from the
  canonical playbook when a Word handoff is required; the binary is not
  versioned in this repository.
- `../../playbooks/enterprise-client-deployment.md`: canonical runbook.
- `gitops-orchestrator.md`: accepted dry-run GitOps orchestration architecture,
  contracts, stage graph, and live-enablement boundary.
- `strict-contract-resolution.md`: GUG-121 content-addressed contract catalog,
  producer/consumer bindings, pre-plan failure behavior, migration, and rollback.
- `registry-account-baseline-backend-locking.md`: GUG-122 registry anchor,
  ACCOUNT_READY v2, derived native-lockfile backend, distributed execution lock,
  migration boundary, and recovery controls.
- `github-oidc-terminal-identity.md`: GUG-123 exact GitHub Environment/OIDC
  identity, independent protection anchor, terminal IAM roles, and live boundary.
- `platform-authority-account-bootstrap.md`: GUG-206 dedicated authority-account
  state bootstrap, exact Change Set approval, minimum Identity Center permission
  set, verification, and live activation boundary.
- `durable-founder-bootstrap-pep.md`: GUG-211 durable compare-and-swap PEP,
  exact management seed, one-shot founder Plan/Apply boundary, uncertainty and
  revocation requirements.
- `../operations/durable-founder-bootstrap-pep.md`: reviewed one-shot seed,
  private evidence, execution, reconciliation and revocation runbook.
- `../operations/platform-authority-bootstrap-recovery.md`: uncertain-result,
  rollback-failure, retained-resource, GUG-214 exact-shell/Change Set preflight,
  and decommission recovery boundary.
- `../operations/github-oidc-terminal-identity-rollout.md`: staged OIDC trust,
  Environment rollout, negative proof, evidence, and rollback procedure.
- `identity-contract.md`: v1/v2 identity semantics and M2M fail-closed rules.
- `enterprise-authorization.md`: portable enterprise RBAC+ABAC catalog, exact
  customer/deployment authorization, lifecycle, privileged-access, migration,
  and downstream enforcement boundaries.
- `human-authorization-enforcement.md`: GUG-153 typed PDP/PEP, exact 30-route
  operation inventory, bounded membership snapshots, step-up, audit, M2M
  compatibility, and rollout/rollback boundary.
- `identity-control-plane.md`: portable GUG-93 Cognito/control-plane boundary,
  access-token claims, non-authoritative groups, runtime bootstrap/M2M custody,
  contract handoff, legacy adoption, and retain-first retirement.
- `m2m-identity-v2-migration.md`: sanitized, repeatable migration inventory and
  per-deployment sequence; live identity inventories stay outside Git.
- `../operations/identity-bootstrap-retirement.md`: one-use bootstrap failure,
  retirement, legacy classification, state-adoption, blue/green migration, and
  decommission procedure; live execution remains blocked.
- `../operations/github-governance.md`: stable CI contract, required-check drift
  reconciliation, deployment-scoped GitHub Environments, and rollback.
- `../../_NotebookLM_Brain/00_INDEX_AND_SOURCE_MAP.md`: curated knowledge-base
  entry point and source hierarchy.

Do not commit rendered page images, PDFs used only for QA, raw plans, state,
real customer variables, logs, credentials, documents or evidence containing
customer data.

## Rebuild the Word guide

Install the pinned documentation dependency in an isolated environment:

```bash
python -m pip install -e '.[docs]'
```

Generate the derived document from the canonical Markdown:

```bash
python scripts/docs/build_enterprise_deployment_guide.py
```

The cover records the SHA-256 of the source Markdown. A review must regenerate
the DOCX whenever the canonical playbook changes and confirm that the recorded
hash changes with it.

## Release-quality verification

Before distributing a regenerated guide:

1. Run the repository safety and security gates.
2. Remove document metadata that is not intentionally public within Scanalyze.
3. Run the DOCX accessibility audit and resolve high-severity findings.
4. Render the full document to PDF and PNG pages in an ignored temporary
   directory.
5. Inspect every rendered page for clipping, overflow, orphaned headings,
   unreadable tables and accidental blank pages.
6. Confirm the document contains no secrets, PII, customer identifiers,
   Terraform state/plan output, raw operational evidence or unredacted logs.
7. Record the source commit, guide version and reviewer in the approved change
   or document-management system. Do not write operational evidence to this
   repository or to NotebookLM.

The exporter is deterministic at the document-content level and records the
canonical source hash on the cover. ZIP container timestamps can make two
otherwise identical DOCX packages have different binary checksums; compare the
unpacked package or the recorded source hash when proving content equivalence.
Page layout can also vary across office suites, so visual inspection remains
mandatory after any content or exporter change.

## NotebookLM publication boundary

Only the sanitized Markdown files under `../../_NotebookLM_Brain/` are intended
for NotebookLM ingestion. The Brain is a curated explanatory layer, not an
execution engine or evidence store. Never ingest credentials, tokens, plans,
state, customer documents, raw logs, screenshots or unredacted audit bundles.
Any claim lacking repository or approved live evidence must be labeled
`Target`, `Blocked` or `Unknown`, never inferred as implemented.

For GUG-116, ingest only
`../../_NotebookLM_Brain/10_Production_Readiness_Foundation.md`; do not ingest
the repository, `reports/`, operational artifacts, or the full documentation
tree as a convenience bundle.

For GUG-92, ingest only
`../../_NotebookLM_Brain/12_GUG92_Enterprise_Authorization.md`. Provider
exports, membership inventories, user/group lists, tokens, grant records,
screenshots, logs, and live evidence remain outside NotebookLM.

For GUG-93, ingest only
`../../_NotebookLM_Brain/13_GUG93_Identity_Control_Plane.md`. Do not ingest
provider exports, user/group/client inventories, credentials, tokens,
bootstrap/approval records, Terraform plans/state, logs, screenshots, or live
identity evidence.

For GUG-153, ingest only
`../../_NotebookLM_Brain/14_GUG153_Human_Authorization_Enforcement.md`. Do not
ingest access tokens, raw claims, membership/grant inventories, audit streams,
object locators, customer data, screenshots, logs, or live evidence.

For GUG-94, ingest only
`../../_NotebookLM_Brain/15_GUG94_Enterprise_User_Lifecycle.md`. Do not ingest
user locators, provider payloads, membership/approval/operation/audit records,
temporary credentials, tokens, Terraform plans/state, screenshots, logs, or
live evidence.

For GUG-122, ingest only
`../../_NotebookLM_Brain/19_GUG122_Registry_Backend_Locking.md`. Do not ingest
deployment registry records, ACCOUNT_READY payloads, backend files, state keys,
lock records, ARNs, plans, state, AWS inventories, screenshots, logs, or live
evidence.

For GUG-123, ingest only
`../../_NotebookLM_Brain/20_GUG123_GitHub_OIDC_Terminal_Identity.md`. Do not
ingest repository/Environment IDs, reviewers, variables, OIDC tokens/claims,
role ARNs, IAM/API exports, registry/baseline records, plans, state, CloudTrail,
screenshots, logs, or live evidence.

For GUG-124, ingest only
`../../_NotebookLM_Brain/21_GUG124_Build_Once_Supply_Chain.md`. Do not ingest
private signing material, live artifact inventories, registry exports, trust
roots, waivers, scan reports, credentials, plans, state, logs, or live evidence.

For GUG-125, ingest only
`../../_NotebookLM_Brain/22_GUG125_Nonproduction_Live_Engine.md`. Do not ingest
registry or ACCOUNT_READY records, platform-authority/Environment evidence,
reviewer identities, role/account identifiers, saved plans, plan JSON, state,
backend files, contracts, ledgers, AWS responses, credentials, logs, screenshots,
or live evidence.

For GUG-206, ingest only
`../../_NotebookLM_Brain/23_GUG206_Platform_Authority_Account_Bootstrap.md`.
Do not ingest account/principal identifiers, permission-set assignments, Change
Sets, plans, approvals, verification receipts, backend files, state, bucket/KMS
identifiers, AWS responses, stack events, logs, screenshots, or live evidence.

For GUG-211, ingest only
`../../_NotebookLM_Brain/28_GUG211_Durable_Founder_Bootstrap_PEP.md`.
Do not ingest management/authority account exports, organization topology,
Identity Center subjects or assignments, temporary policies, intents, ledgers,
Change Sets, plans, backend outputs, AWS responses, logs, screenshots, or live
evidence.

For GUG-214, ingest only
`../../_NotebookLM_Brain/29_GUG214_Authority_Recovery_Preflight.md`.
Do not ingest account/principal identifiers, permission-set assignments,
stack IDs, Change Set names/ARNs, resource inventories, raw policies, AWS
responses, audit exports, logs, screenshots or live evidence.
