# Production Readiness Evidence Policy

> **Owner:** Technical Program Owner\
> **Control owner:** Platform Security\
> **Cross-cutting risk:** GUG-120\
> **Production:** **NO-GO**

## Purpose

This policy prevents design, implementation, local checks, CI, dry-runs, and
live execution from being conflated. It also defines what may cross repository,
customer, Linear, and NotebookLM boundaries.

Evidence is valid only for the exact revision, tool/workflow, control,
environment, release, and time identified by its record. An evidence record
never proves a broader claim by implication.

## Normative taxonomy

| State | Minimum proof | Does not prove |
|---|---|---|
| `Implemented` | The identified revision contains the behavior or document | That it passed a check, ran remotely, or exists in AWS |
| `Locally validated` | Named local command, exact revision/snapshot, tool versions, timestamp, and result | CI, AWS behavior, protected GitHub settings, or production readiness |
| `CI validated` | Named workflow/check, commit, run identity, runner context, timestamp, and result | AWS behavior unless the named control explicitly ran against an approved bound environment |
| `Live validated` | Sanitized evidence from an approved non-production execution with the complete binding tuple, release, control, time, and result | Production approval, another account/region, or future releases |
| `Target` | Accepted or draft design identifies the intended control and owner | Implementation or any validation |
| `Blocked` | A named unmet dependency or stop condition | Failure of unrelated completed controls |

`Accepted`, `Proposed`, and `Draft` are decision statuses, not evidence states.
`Passed`, without an evidence state and source, is invalid.

## Promotion rules

Evidence state can advance only through a new observation:

```text
Target -> Implemented -> Locally validated -> CI validated -> Live validated
```

The sequence is not automatic. A control may skip a non-applicable observation
only when the gate documents why and supplies evidence of the higher state. For
example, a CI run may establish both `CI validated` and `Live validated` only if
it is an approved privileged non-production run with the complete live binding
and evidence contract.

Rules:

1. A file's presence is only `Implemented`.
2. A unit test, Terraform validate, policy simulation, synthetic fixture, or
   dry-run is at most `Locally validated` or `CI validated`.
3. A Terraform plan is not deployment evidence.
4. A dry-run explicitly proves absence of intended mutation; it never proves an
   apply, deployed resource, runtime health, or AWS control.
5. A declaration in Terraform is not proof the resource exists or matches
   state.
6. An accepted ADR is not proof its target control is implemented.
7. CI status is bound to the exact commit and workflow identity.
8. Live evidence is bound to one exact customer, deployment, account, region,
   environment, release, change, layer/operation, and time.
9. Stale, partial, mixed-environment, unverifiable, or ambiguous evidence is
   `Blocked`.
10. Production requires independent review of the evidence; `Live validated`
    alone is not a production GO.

## Evidence record

A durable evidence index entry contains only sanitized metadata:

- evidence ID and schema version;
- evidence state and control/gate ID;
- source revision or immutable release digest;
- sanitized deployment reference or opaque binding digest;
- logical environment and region classification without protected identifiers;
- workflow/tool identity and version;
- execution start/end time and result;
- plan, contract, artifact, and evidence digests when applicable;
- approval reference and approver role, not credentials or personal contact
  data;
- owner, reviewer, retention class, and expiry;
- external encrypted evidence reference; and
- redaction/sanitization status.

The index never contains raw Terraform outputs, resource identifiers, backend
coordinates, customer data, or logs.

## Storage and publication boundaries

| System | Allowed | Prohibited |
|---|---|---|
| Git repository | Code, schemas, policies, synthetic fixtures, sanitized docs, and non-sensitive digests | Credentials, tokens, cookies, private keys, real manifests, real variable files, state, saved plans, plan JSON, backend files, raw outputs, protected identifiers, customer data, PII, or sensitive logs |
| GitHub PR / CI summary | Sanitized status, counts, opaque evidence IDs, and digests | Raw plan/state/output/manifest payloads, credentials, customer data, or sensitive logs |
| General GitHub artifacts | Sanitized reports explicitly classified for that destination | Raw saved plans, state, resolved manifests, real variables, or unrestricted operational evidence |
| Linear | Scope, decisions, statuses, risks, validation names/results, sanitized references, and GO/NO-GO | Secrets, credentials, protected identifiers, state, plans, real manifests/variables, outputs, logs, PII, customer data, or raw evidence |
| NotebookLM | Reviewed, curated, derived Markdown from the explicit allowlist | Codebase-wide ingestion, historical reports, secrets, protected identifiers, state, plans, real variables/manifests, outputs, logs, PII, customer data, or approval artifacts |
| External evidence store | Encrypted, least-privilege evidence required by the approved workflow | Public access, cross-deployment prefixes, unbounded retention, or use as an informal data lake |
| Plan-execution prefix | Encrypted raw plan and bounded plan JSON for one execution | Durable general access, immutable default retention, GitHub artifact export, or reuse after expiry |

Actual account numbers, ARNs, backend coordinates, customer names, domains,
email addresses, document identifiers, and raw deployment references are
treated as protected operational identifiers for Git, Linear, and NotebookLM.
Synthetic placeholders may be used only when clearly marked and validated.

## Sanitization

Sanitization is transformation, not omission by hope. Before crossing a trust
boundary, the producer must:

1. select a destination-specific schema with an allowlist of fields;
2. drop raw inputs, outputs, environment dumps, command lines with values, and
   unstructured logs;
3. replace deployment/customer/account references with an opaque approved
   evidence ID or binding digest;
4. retain only aggregate action counts and control results;
5. scan the resulting artifact for credentials, protected identifiers, PII,
   state/plan signatures, and customer content;
6. record the sanitizer version, result, and owner; and
7. fail closed when any field is unknown or a scanner cannot complete.

Redaction that leaves a reversible, partial, or structurally revealing value is
not sanitization. Hashes of low-entropy identifiers must not be published unless
they use an approved keyed or opaque mapping.

## Integrity and traceability

Evidence must be traceable from decision to observation without copying the raw
artifact into an unsafe system:

```text
phase decision
  -> evidence index entry
  -> external evidence object/version
  -> workflow execution identity
  -> source/release/plan/contract digests
  -> bound deployment and approval record
```

Required integrity controls are content digests, object versioning, a declared
single writer, encryption, access audit, retention class, and immutable
retention where the evidence class requires it. A digest proves content
integrity, not source authority; the authorized producer and execution identity
must also match.

Linear comments and NotebookLM answers are not evidence authorities. They may
point to an approved index entry but cannot create or upgrade it.

## Retention classes

These are target minimums. Phase implementation must prove the configured
retention before relying on it, and legal/customer requirements may extend it.

| Class | Content | Target retention | Disposal |
|---|---|---|---|
| R0 Ephemeral execution | Raw saved plan, bounded plan JSON, temporary resolver inputs | Delete after apply/rejection/expiry and no later than 24 hours | Verified lifecycle deletion; never default immutable retention |
| R1 CI and local validation | Sanitized test/check reports | At least 90 days and through the dependent review | CI/evidence policy deletion with index tombstone |
| R2 Release and deployment | Approval metadata, sanitized plan/apply/promotion/validation evidence | At least 400 days and through the next certification or customer requirement | Approved disposition with preserved index and digest |
| R3 Phase and risk decisions | Sanitized gate decisions, risk acceptances, and evidence index | Life of the deployment plus at least one year | Program owner plus records-policy approval |
| R4 Incident / recovery | Incident and break-glass evidence | Per incident, legal-hold, customer, and regulatory policy; never shorter than R2 | Security and legal/records approval |

Retention is not permission to publish. Raw sensitive evidence remains in its
approved encrypted store for only the minimum necessary duration.

## Exception and incident handling

No exception may permit restricted material in Git, Linear, or NotebookLM;
static credentials; ambiguous customer binding; evidence overclaim; or skipped
sanitization. If prohibited material is found:

1. stop publication and phase progression;
2. quarantine the artifact without reproducing its contents;
3. engage the applicable security/records incident process;
4. rotate or remediate affected credentials or access outside this repository;
5. create a sanitized replacement and new evidence record; and
6. record the blocker and containment in GUG-120 and the affected phase gate.

Historical reports are not automatically safe because they are versioned. They
must be explicitly classified and sanitized before reuse and are excluded from
NotebookLM by default.

## Phase 0 classification

The Phase 0 documents and validators can be `Implemented`, `Locally validated`,
and later `CI validated`. They are not AWS or `Live validated` evidence. The
NotebookLM question results prove only that the curated source was ingested and
answered consistently; they do not prove a deployment or security control.
