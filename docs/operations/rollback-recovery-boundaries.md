# Rollback and Recovery Boundaries

> [!CAUTION]
> **TARGET-STATE / LIVE EXECUTION NO-GO.** This document defines authority and
> evidence boundaries. It is not an executable incident command sequence and
> does not authorize AWS access, Terraform apply, or state operations.

## Purpose

Scanalyze uses three distinct change paths:

1. application rollback to a known-good immutable release;
2. infrastructure rollback through a new reviewed Terraform plan; and
3. break-glass Terraform state recovery after confirmed state corruption or
   loss.

They have different triggers, authorities, evidence, and risk. Terraform state
restore is never routine rollback.

## Decision tree

```text
Is the runtime release/configuration unhealthy but state trustworthy?
  -> application rollback

Is a Terraform-managed infrastructure change wrong but state trustworthy?
  -> infrastructure rollback

Is Terraform state itself proven corrupt, lost, or inconsistent with its
authoritative object/version history?
  -> break-glass state recovery

Is the outcome uncertain?
  -> stop, preserve evidence, read back state/runtime, and reconcile before
     choosing a path
```

An operator must not choose StateRecovery because it appears faster or because
a normal rollback plan contains unexpected changes. Unexpected scope is a stop
condition.

## Application rollback

**Trigger:** application health, compatibility, or release behavior is
unacceptable while Terraform state and infrastructure ownership remain
trustworthy.

**Target method:** select the last-known-good complete release manifest, create
a new `services` Terraform plan that changes only approved immutable digests and
configuration, review it, apply the exact saved plan, and validate runtime
health.

**Authority:**

- PE prepares the plan;
- SRE owns execution and health decision;
- APP reviews compatibility;
- PS reviews security-sensitive changes;
- production requires IPA approval.

**Required evidence:** current and target release digests, complete manifest
verification, saved-plan digest and bounds, approval, state freshness, applied
plan identity, running digest readback, health/smoke results, queue/backlog
condition, and incident/change reference.

**Prohibited shortcuts:** mutable tag rollback, production rebuild, imperative
ECS update, force-stopping tasks as a deployment mechanism, partial release
selection, or Terraform state restore.

## Infrastructure rollback

**Trigger:** a Terraform-managed resource or configuration change is wrong, but
the current state is readable, locked/owned correctly, and not corrupt.

**Target method:** express the intended known-good configuration in the reviewed
source/registry, create a new plan from current state, review all changes,
approve and apply that exact plan, then reconcile contracts and runtime.

Infrastructure rollback is a forward change. It may not be safe or fully
reversible for data stores, identity, encryption, DNS, retention, or destructive
changes; those components require a separate impact assessment and may instead
need a recovery or migration plan.

**Authority:**

- PE owns configuration and plan;
- SRE owns execution controls and service health;
- PS approves identity, network, encryption, state, and security-control scope;
- APP/COPS are consulted for application/customer impact;
- production requires IPA approval.

**Required evidence:** incident/change, current state version, target source and
release, plan digest, complete action summary, destructive/irreversible action
assessment, contract compatibility, approval, apply result, state version,
drift/readback, and health result.

**Automatic NO-GO:** state uncertainty, plan scope outside the accepted rollback,
missing contract owner, destructive action without explicit treatment, stale
approval, or inability to validate service health.

## Break-glass state recovery

**Trigger:** confirmed Terraform state corruption, loss, wrong object version,
or a state-store failure for which the authoritative version history proves the
required recovery point. Runtime failure or an undesirable infrastructure
change alone is not a trigger.

**Target method:** use the dedicated StateRecovery identity to restore or repair
the exact approved state object/version under an incident, then disable that
authority and create a new reviewed plan to compare recovered state with live
resources. The recovered state is not trusted until reconciliation completes.

**Authority:**

- SRE proposes the recovery point and executes under the incident;
- PS authorizes StateRecovery and is accountable for the security boundary;
- PE verifies Terraform ownership and reconciliation;
- dual human approval is mandatory;
- production requires IPA awareness/approval according to incident policy.

**Required evidence:** incident ID, proof of corruption/loss, current and target
state object versions and digests, backup/version provenance, dual approval,
short-lived session identity, alarm/audit receipt, exact actions, restored object
version, new plan and drift review, runtime validation, authority revocation, and
post-incident review.

**Prohibited actions:** routine restore, unreviewed `state` commands,
force-unlock without proven stale ownership, copying state across deployments,
using Diagnostic as a writer, using StateRecovery to deploy, or declaring
success before a new plan reconciles state and reality.

## Comparison

| Dimension | Application rollback | Infrastructure rollback | Break-glass state recovery |
|---|---|---|---|
| Primary problem | Bad release behavior | Bad Terraform-managed configuration | Corrupt/lost state |
| State assumed trustworthy | Yes | Yes | No |
| Normal mechanism | New services plan to known-good digests | New plan from current state to reviewed configuration | Restore/repair exact state version, then new reconciliation plan |
| Routine operation | Controlled release operation | Controlled infrastructure operation | No; incident-only |
| Core authority | SRE + PE | PE + SRE | SRE + PS dual approval |
| Production approval | IPA | IPA | Dual recovery approval plus production incident authority |
| Completion proof | Running digests and health | State/readback, contracts, drift, and health | State provenance, reconciliation plan, drift, and health |

## Partial and uncertain outcomes

On timeout, runner loss, API uncertainty, or partial wave failure:

1. stop all downstream stages;
2. preserve only approved sanitized evidence and external raw evidence;
3. do not rerun Apply blindly;
4. read back workflow status, state version/lock, contracts, running digests, and
   health through authorized read-only paths;
5. classify the outcome as not-started, applied, partially applied, failed, or
   unknown;
6. reconcile unknown/partial state with a new plan before resuming; and
7. block the failed release until the incident/change is reviewed.

An ECS automatic rollback is not completion. Terraform and the deployment
record must be reconciled through a new reviewed forward plan.

## Evidence and publication boundary

Raw state, plans, outputs, backend coordinates, identifiers, logs, and customer
data remain in the approved encrypted systems. Git, Linear, and NotebookLM may
contain only the sanitized decision, evidence state, opaque references, digests,
owners, time, and outcome.

StateRecovery evidence is incident evidence and follows the strictest applicable
retention and access policy. A NotebookLM answer is never recovery authority.

## Current status

The repository has documentation and local scaffolding but no executable live
rollback or StateRecovery evidence. Application rollback, infrastructure
rollback, and state recovery are all `Target / Blocked` for live use until their
respective phases implement and exercise them in approved non-production.

## Related sources

- [Existing rollback procedures](rollback.md)
- [ADR-019](../../ADR/ADR-019-production-readiness-foundation.md)
- [Evidence policy](../production-readiness/evidence-policy.md)
- [Phase gates](../production-readiness/phase-gates.md)
- [GitOps orchestrator](../deployment/gitops-orchestrator.md)
