# Phase 0 Production Readiness Foundation Playbook

> **Program:** GUG-115\
> **Gate:** GUG-116\
> **Authorized workspace:** `scanalyze-production-readiness-foundation`\
> **Authorized branch:** `feat/production-readiness-foundation`\
> **Required baseline:** `7dd9647d93bbf2fd88dfdada97ece95f93e81eaf`\
> **Production:** **NO-GO**

## Purpose and execution boundary

This playbook creates and validates the documentary and governance foundation
for later implementation. It does not start Phase 1, access AWS, initialize a
live backend, create a plan, apply Terraform, deploy, mutate IAM/OIDC/GitHub
governance, or authorize production.

Stop immediately when the workspace, branch, baseline, cleanliness, scope, or
source of truth is uncertain.

## Roles

- TPO owns scope, sequence, decisions, and the Phase 0 GO/NO-GO.
- PE owns repository architecture, root/contract/state mapping, and validation.
- PS reviews threats, evidence boundaries, and segregation of duties.
- SRE reviews rollback, recovery, and operational ownership.
- IPA is not required to author Phase 0, but its production role must be defined
  and GUG-119 remains a hard production blocker.

## Step 1: Fail-closed precheck

Before editing:

1. read all applicable `AGENTS.md` instructions;
2. run `git status --short`;
3. capture staged, unstaged, and untracked paths separately;
4. confirm the repository root and authorized branch;
5. confirm `HEAD` exactly equals the required baseline;
6. read GUG-115 and GUG-116, including current acceptance criteria and comments;
7. confirm GUG-128 still states `Blocked — Production NO-GO`;
8. review accepted ADRs, draft design inputs, the canonical DAG, workflows,
   runbooks, evidence tooling, and NotebookLM source map; and
9. stop without edits if the worktree is dirty or baseline mismatches.

Record the kickoff in GUG-116 with scope, branch, baseline, prohibited actions,
and production NO-GO. Move it to `In Progress` when material work starts.

## Step 2: Reconcile decisions

Create or update the Phase 0 ADR without silently changing accepted decisions.
The decision must cover:

- current versus target state;
- customer/deployment/account/region/environment/release vocabulary;
- GitOps Plan, Apply, Promotion, and Validation separation;
- exact saved-plan storage, freshness, approval, and apply policy;
- immutable build-once promotion and no production rebuild;
- no customer forks;
- initial single-region production eligibility and blocked multi-region target;
- independent production approval and single-maintainer risk;
- Phase 1-11 sequence and non-blanket gate semantics; and
- compatibility, migration, consequences, and local rollback.

Any unresolved P0 decision makes Phase 0 NO-GO.

## Step 3: Complete the governance set

The Phase 0 index must link reviewable documents for:

- architecture and trust boundaries;
- repository-scoped threat model;
- root, contract, state, resource, evidence, and approval ownership;
- RACI and segregation of duties;
- evidence taxonomy, sanitization, retention, integrity, and traceability;
- entry/exit/evidence/dependency/NO-GO criteria for Phases 0-11;
- Linear work packages, gaps, duplicates, and order;
- application rollback, infrastructure rollback, and state recovery; and
- the sanitized NotebookLM source.

Every root input must map to an authoritative source. Every output and evidence
artifact must have one producer and one accountable owner.

## Step 4: Generate the NotebookLM source

Only `_NotebookLM_Brain/10_Production_Readiness_Foundation.md` is eligible for
Phase 0 ingestion. It must be derived from reviewed Phase 0 documents and must
not include real identifiers, secrets, state, plans, variables, manifests,
outputs, logs, customer material, PII, or historical reports.

Update the existing notebook; do not create another notebook. Before upload,
run the Phase 0 documentation validator and repository security checks. If a
source with the same title/version exists, replace or remove it rather than
leaving an ambiguous duplicate.

Ask these questions exactly or with semantically equivalent wording:

1. Does Scanalyze production remain NO-GO?
2. Does Phase 0 constitute AWS or live deployment evidence?
3. Does a dry-run prove that a deployment occurred?
4. May production rebuild application artifacts?
5. What happens when customer, deployment, account, region, or environment
   binding is missing or ambiguous?
6. Is Terraform state restore a routine rollback mechanism?

Expected fail-closed answers:

| Check | Required answer |
|---|---|
| Production status | Yes, production remains NO-GO and GUG-128 remains blocked |
| Phase 0 evidence | No, it is documentary/local evidence and not AWS evidence |
| Dry-run | No, it proves neither apply nor deployment |
| Production rebuild | No, production promotes the exact certified immutable release |
| Ambiguous binding | Stop before OIDC or mutation; classify as Blocked |
| State restore | No, it is incident-only break-glass after confirmed corruption/loss |

Any ambiguous or contrary answer is a NotebookLM validation failure and keeps
GUG-116 open.

## Step 5: Validate locally

Use the pinned Python and the repository's offline gates. No command below is
AWS or deployment evidence.

```bash
PYTHON=python3.11 make bootstrap-local
make phase0-docs-check
make docs-check
make security-check
make git-safety
make test
make repro-check
git diff --check
git diff --cached --check
```

Then review:

```bash
git status --short
git diff --cached --stat
git diff --cached --name-status
git diff --cached
git diff --stat
git diff --name-status
git diff
git ls-files --others --exclude-standard
```

The staged, unstaged, and untracked inventories are separate evidence. Because
ordinary `git diff` omits untracked content, review every untracked path in full
with `git diff --no-index -- /dev/null <reviewed-untracked-path>` (exit status 1
means a difference was displayed) or an equivalent complete read-only review.
Do not stage files merely to make them visible to the diff command.

The reviewer confirms:

- relative links resolve;
- all required Phase 0 documents and phrases exist;
- a fresh, context-free read-only agent independently identifies production
  NO-GO, the non-live evidence boundary, GUG-128 blocking, and canonical stage
  ownership;
- negative tests reject missing decisions/owners, dual accountability,
  contradictory production-GO claims, and sensitive examples;
- the changed scope contains no account IDs, ARNs, credentials, PII, state/plan
  signatures, or unscanned untracked files;
- evidence states are used correctly;
- production and GUG-128 remain NO-GO;
- no test, scanner, branch rule, or gate was weakened; and
- before explicit publication authorization, no AWS, deploy, Terraform
  apply/destroy, commit, push, PR, or merge occurred.

Do not use `make preflight-m0` as evidence for GUG-116; it is the older
repository-foundation milestone. Do not use `release-dry-run` as deployment
evidence.

## Step 6: Record durable evidence in Linear

The final GUG-116 comment contains only sanitized information:

- scope, branch, and baseline;
- documents changed;
- accepted decisions and compatibility notes;
- threat/risk summary and owners;
- validation commands and results;
- NotebookLM source/check results;
- blockers and residual risks;
- Phase 0 GO/NO-GO and continued production NO-GO; and
- explicit confirmation that no prohibited action occurred.

Do not attach raw files, plans, logs, outputs, identifiers, customer data, or
operational evidence. Mark GUG-116 `Done` only when every exit criterion has
reviewable evidence; otherwise leave it `In Progress` or `In Review` and name
the blocker.

## Validation record — 2026-07-11

| Validation | Result | Evidence classification |
|---|---|---|
| Precheck and baseline | PASS — clean before edits; authorized branch and exact baseline; staged, unstaged, and untracked inventories were empty | Local observation |
| Phase 0 documentation validator | PASS — 11 canonical documents, 20 changed-scope files, links, required decisions, ownership, and sensitive-content controls | Locally validated only |
| Repository documentation check | PASS | Locally validated only |
| Security sentinel and tests | PASS — zero unallowlisted findings, 192 unchanged allowlisted findings, six sentinel tests | Locally validated only |
| Git safety | PASS | Locally validated only |
| Relevant/full tests | PASS — full suite at the published revision; the exact count belongs to the validating run | Locally validated only |
| Offline reproducibility | PASS — `REPRO_CHECK_PASSED`; dry-run only | Locally validated dry-run only |
| Diff checks and full review | PASS — staged, unstaged, and 13 untracked paths reviewed separately; independent peer findings resolved | Local review |
| Fresh-agent positive/negative dry-run | PASS — production NO-GO, GUG-128 blocked, 12-stage ownership correct, and eight fail-closed controls passed | Independent local review only |
| NotebookLM ingestion/questions | PASS — existing notebook has one sanitized source named `Scanalyze Phase 0 Foundation — GUG-116 — 2026-07-11`; source SHA-256 `242d374c2db10b9f2291465adc291ca03f720ce707d868c29676770a86d6199b`; all six fail-closed answers passed | Derived-source consistency only |
| CI | Not run in this task | Not `CI validated` |
| AWS/live validation | Prohibited and not run | Not `Live validated` |
| Prohibited-action audit | PASS — no AWS, deployment, Terraform apply/destroy, IAM/OIDC/GitHub-governance mutation, or merge; documentation-only commit, push, and PR publication are separately authorized repository actions and are not runtime evidence | Local observation plus Git/GitHub readback |

### Publication reconciliation

Local validation was completed before repository publication. Commit, push,
and PR creation are documentation-delivery actions performed only after explicit
authorization; they do not authorize AWS, live execution, production, or the
start of Phase 1. The final branch SHA, upstream readback, PR URL, and CI result
belong in GitHub and the sanitized GUG-116 closeout rather than in a
self-referential commit.

NotebookLM readback on 2026-07-11 confirmed that the existing notebook contains
the single Phase 0 source named above and returns all six expected fail-closed
answers. The recorded SHA-256 binds that readback to the reviewed local source;
it is derived-source consistency evidence only.

## Local rollback of Phase 0 changes

Phase 0 changes are documentation and local validation tooling only. Before a
local rollback, preserve a reviewable diff outside prohibited evidence stores
if required. Revert only the Phase 0 paths; do not use `git reset --hard` or
`git clean`.

For tracked edits, a reviewer may use `git restore --source=HEAD -- <path>`.
For newly added Phase 0 files, remove only the explicitly reviewed paths. Then
run `git status --short` and the precheck again. This changes no cloud, GitHub,
Linear, or production state; Linear/NotebookLM records require their own
sanitized update if the decision is withdrawn.

## Closeout decision

**Phase 0 recommendation: GO only for the next eligible Phase 1 implementation
work package after its own entry criteria and authorization are checked.** This
does not start Phase 1 in this change, authorize AWS, or grant blanket
permission for Phases 1-6.

The contradictory final sentence in GUG-116 is reconciled by ADR-019 as "this
planning-only gate does not start Phase 1 implementation or live execution."
If the Linear owner rejects that interpretation, the gate reopens as `Blocked`.

Production remains **NO-GO**. GUG-128 remains manually blocked, and no Phase 0
artifact is AWS or live evidence.
