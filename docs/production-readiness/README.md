# Scanalyze Production Readiness Foundation

> **Program:** GUG-115  
> **Phase gate:** GUG-116  
> **Repository baseline:** `7dd9647d93bbf2fd88dfdada97ece95f93e81eaf`  
> **Production:** **NO-GO**  
> **Live execution:** disabled

This directory is the canonical documentation set for Phase 0 of the Scanalyze
Production Readiness program. It records planning and governance decisions only.
It does not authorize AWS access, Terraform apply or destroy, a deployment,
GitHub governance changes, or production activity.

## Source hierarchy

Resolve conflicts in this order:

1. the reviewed repository revision and its tests;
2. accepted ADRs, including ADR-019 for this program;
3. `deployment/layers.yaml` for the canonical stage graph;
4. the enterprise deployment playbook and operational runbooks;
5. this Phase 0 documentation set;
6. the sanitized NotebookLM source as a derived explanation;
7. historical reports only as dated evidence after explicit classification and
   sanitization, never as current instructions.

Draft ADRs remain target design inputs. Their existence does not prove that a
control is implemented or live validated.

## Documents

| Document | Purpose |
|---|---|
| [ADR-019](../../ADR/ADR-019-production-readiness-foundation.md) | Normative Phase 0 decisions, compatibility, saved-plan policy, single-region scope, and phase authorization semantics |
| [Architecture foundation](architecture.md) | Current versus target architecture, trust boundaries, GitOps stages, and phase sequence |
| [Threat model](threat-model.md) | Repository and delivery-control-plane threats, controls, residual risk, and owners |
| [Ownership and RACI](ownership-raci.md) | Authoritative owner for roots, contracts, state, evidence, approvals, and operations |
| [Evidence policy](evidence-policy.md) | Evidence taxonomy, sanitization, retention, integrity, and publication boundaries |
| [Phase gates](phase-gates.md) | Entry, exit, evidence, dependencies, automatic NO-GO, and exception policy for Phases 0-11 |
| [Work packages](work-packages.md) | Linear mapping, implementation order, gaps, and duplicate avoidance |
| [Rollback and recovery boundaries](../operations/rollback-recovery-boundaries.md) | Application rollback, infrastructure rollback, and break-glass state recovery |
| [Phase 0 playbook](../../playbooks/phase-0-foundation.md) | Repeatable execution, validation, NotebookLM checks, and closeout procedure |
| [NotebookLM source](../../_NotebookLM_Brain/10_Production_Readiness_Foundation.md) | Sanitized, derived source for the existing Scanalyze notebook |

## Phase 0 exit contract

Phase 0 can recommend GO only for the next eligible implementation work package
when all of the following are true:

- no P0 decision in this documentation is ambiguous;
- every root input has an authoritative source and every output has one
  producer;
- the threat model has owners, residual risk, and preventive, detective, and
  recovery controls;
- evidence states cannot be promoted by inference;
- future work maps to existing Linear issues or a documented gap without
  creating duplicates;
- the single-maintainer risk and independent-production-approval requirement
  are explicit;
- Phase 0 documentation and local validations are reviewable;
- the sanitized NotebookLM source is ingested and passes the fail-closed
  questions; and
- live execution and production remain disabled.

A Phase 0 GO does not authorize AWS access or automatically start multiple
phases. GUG-128 remains **Blocked — Production NO-GO** until its independent,
manual prerequisites are met.

## Evidence status of this change

The repository files are `Implemented` when present in the working tree.
Validation results are recorded in the Phase 0 playbook only after execution.
No Phase 0 artifact is `Live validated`, and no AWS evidence was collected.

## Publication boundary

Only the curated file under `_NotebookLM_Brain/` is eligible for NotebookLM
ingestion. Do not ingest this directory wholesale. Never publish credentials,
real identifiers, resolved manifests, state, plans, real variable files, raw
outputs, logs, customer material, PII, or unsanitized historical reports to Git,
Linear, or NotebookLM.

