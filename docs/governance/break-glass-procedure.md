# Break-Glass Procedure

## Purpose and current status

Break-glass is a time-bounded incident-containment procedure, never a shortcut
for GUG-119 review or GitHub administration. No qualified independent backup
actor is established by this repository change. If `guguce-google` is
unavailable, unattested, or conflicted, the GUG-119 change is **BLOCKED**. A
separately approved qualified human may help contain an unrelated incident,
but cannot substitute for the required candidate or advance this governance
package.

`@Ferrusca08` remains an authorized additional code owner, but must not be
treated as the required candidate and sole break-glass approver at the same
time. Administrator access, CI success, urgency, or an AI recommendation does
not substitute for an independent human.

## Controls that break-glass cannot waive

Break-glass MUST NOT:

- permit an author to approve or merge their own change;
- bypass administrator enforcement or introduce a bypass actor;
- lower the technical approval floor below one;
- satisfy the manual P0 requirement with fewer than two humans;
- disable, remove, rename, or silently unbind any of the six required checks;
- waive CODEOWNER review, stale-review dismissal, last-push approval, or
  conversation resolution;
- permit force-push or deletion of `main`;
- enable auto-merge;
- create a missing GitHub Environment or weaken an existing one;
- use public vulnerability details in place of the private triage path; or
- authorize AWS, Terraform, deployment, customer-data, or production activity.

If containment cannot be performed while preserving these invariants, stop and
escalate to the incident owner. Production remains **NO-GO**.

## Preconditions for an allowed emergency action

A named incident owner must record, outside the affected control plane when
necessary:

- incident identifier, severity, and exact affected repository/control;
- exact proposed action and why normal operation cannot contain the incident;
- named operator and independent approver;
- start time, expiration time, and least-privilege credential boundary;
- fresh remote-before evidence and conflicting-ruleset check;
- deterministic payload digest when a GitHub write is proposed;
- monitoring, stop conditions, rollback/forward-fix plan, and evidence owner;
- explicit confirmation that no missing Environment will be created; and
- explicit production **NO-GO** unless a separate production authorization
  exists for one exact action.

No action begins while any precondition is missing.

## Procedure

1. Prefer read-only containment and revoke exposed credentials through their
   owning system when applicable.
2. Open an incident record and obtain the independent approval described above.
3. Re-read the exact GitHub endpoint immediately before an approved write.
4. Stop on drift, reviewer mismatch, unavailable prevention control, overlapping
   ruleset, or unknown state.
5. Apply only the exact reviewed action using short-lived least privilege.
6. Read the endpoint back; do not infer success from a request response alone.
7. Roll back only while state still matches the approved expected state. Never
   overwrite third-party drift or retry an unknown outcome blindly.
8. Revoke temporary access at expiry and conduct independent retrospective
   review of the final state and evidence.

## Closeout

Retain sanitized timestamps, actors, exact revisions, endpoint responses,
readbacks, control invariants, and rollback disposition. Open a permanent
remediation issue. An emergency action does not close GUG-119, attest a
reviewer, or establish production readiness.
