# GUG-211 — Durable Founder Bootstrap PEP

## What problem is closed

GUG-209 described a transparent single-operator risk exception but intentionally
could not execute AWS. GUG-211 adds the missing durable enforcement point: an
AWS-native compare-and-swap ledger that is consumed before a single protected
Plan or Apply effect. It does not normalize self-approval.

## Architecture

- The AWS Organizations management account seeds only an S3 organization Block
  Public Access policy and one retained DynamoDB table in the dedicated
  platform-authority account.
- Audit, shared-services and customer accounts are not authority owners.
- The founder Plan and Apply permission sets are temporary, distinct,
  time-bound, direct-user and subject-bound. No group or membership is created.
- Plan can create/review one exact Change Set but never execute it.
- Apply can execute that reviewed Change Set once but cannot create/cancel it,
  administer identity, change Organizations, or mutate account S3 BPA.
- DynamoDB uses create-only plus CAS; there is no Scan, Delete, fallback or
  request-selected table.
- A lost response becomes `UNCERTAIN`; retries are forbidden.
- A separate management-account identity administrator may mutate only tagged
  GUG-211 permission sets and assign them only to the authority account.
- Management seed and identity lifecycle require the exact least-privilege
  `ScanalyzeFounderPepSeed` and `ScanalyzeFounderPepIdentityAdmin` permission
  sets; generic administrator sessions are rejected.
- Tagged Organizations policy creation requires the dependent
  `organizations:TagResource` action. It is co-located with `CreatePolicy` and
  constrained by the exact S3 policy type, request tags and tag-key set; no
  independent retag, untag or update permission is granted.
- The exception closes only after authoritative zero-assignment readback and a
  durable `SUCCEEDED -> REVOKED` CAS; expired denials remain for twelve hours.

## Portable customer model

The founder path exists only to initialize Scanalyze's platform authority. It
is not copied into customer accounts. Customer deployments continue to use the
portable, account-per-deployment contracts from GUG-121 through GUG-125, with
exact customer/deployment/account/Region/environment/release bindings.

## Current evidence

- Implemented: only when the reviewed commit contains ADR-039, typed intent and
  ledger, protected table template, disjoint IAM policies, integrated CLI,
  negative tests, runbook and threat-model delta.
- Locally validated: only named local gates.
- CI validated: pending exact-commit checks until the PR runs.
- Live validated: no seed, temporary assignment, CAS, Change Set or revocation
  is claimed by repository evidence.
- Production: **NO-GO**.
- Residual boundary: DynamoDB IAM cannot force a caller to use the reviewed
  conditional-write expression. The workflow is replay/concurrency safe, but
  does not claim resistance to a malicious broad administrator; broad admin
  access must be absent from the live window and trusted compute is future
  hardening.

## Fail-closed questions

1. Does a durable zero-attempt ledger exist before temporary authority?
2. Did CAS commit before the external effect?
3. Are account, Region, subject, role, time, Change Set, template and resources exact?
4. Is effective S3 Block Public Access enforced independently of founder Apply?
5. Is an ambiguous outcome terminal and retry-free?
6. Were both temporary roles removed and absence read back?
7. Is the assertion repository, CI, live, or only target evidence?

If any answer is missing, malformed, stale, conflicting or unverifiable, the
correct result is deny/blocked, never inferred success.
