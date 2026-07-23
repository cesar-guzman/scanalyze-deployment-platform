# Security Policy

## Supported code

Security fixes are accepted against the current `main` branch. Historical
branches, local worktrees, unmerged prototypes, and deployed environments may
have different states; include the exact commit and environment classification
in a report without including customer data or credentials.

## Report a vulnerability privately

Do not open a public GitHub issue, pull request, discussion, or Linear comment
with exploit details, secrets, customer data, or production evidence.

As of the 2026-07-23 readback, public private-vulnerability reporting is not
enabled for this repository. Repository administrators and security managers
should create a draft GitHub Security Advisory. Other reporters must contact the
repository owner through the established corporate security channel and provide
only enough non-sensitive information to establish a private case.

Do not open a public placeholder issue asking for a security contact when the
report itself may disclose the affected component, exploit path, or customer
impact.

Never send:

- passwords, access keys, session tokens, cookies, JWTs, private keys, or OTPs;
- customer documents, PII, bank/financial data, or extracted document content;
- raw Terraform state/plans, database dumps, queue payloads, or signed URLs;
- production logs containing sensitive values.

If proof requires sensitive material, describe how an authorized responder can
reproduce it in the controlled environment. Do not copy the material.

## Report contents

Include:

- concise title and affected component;
- exact commit, tag, or image digest when known;
- affected environment class without real customer/account identifiers;
- preconditions and trust boundary;
- synthetic reproduction steps;
- observed and expected behavior;
- potential impact to confidentiality, integrity, availability, tenant
  isolation, authorization, or deployment authority;
- suggested mitigation if known;
- whether exploitation or sensitive-data exposure is suspected.

Do not perform destructive testing, persistence, privilege escalation, customer
access, denial of service, or production exploitation to prove impact.

## Response process

The security owner will:

1. acknowledge and establish a private tracking record;
2. classify severity and affected versions/environments;
3. preserve sanitized evidence;
4. define containment, remediation, validation, and rollback;
5. use a private branch/advisory process when disclosure risk requires it;
6. coordinate release and disclosure with authorized stakeholders;
7. create public documentation only after sensitive details are removed and
   disclosure is approved.

Security reports do not authorize AWS writes, production access, data
collection, or bypass of repository controls.

## Accidental secret or data disclosure

If sensitive data appears in Git or GitHub:

1. stop copying, quoting, or transforming it;
2. notify the security/repository owner privately;
3. revoke or rotate the credential through its owning system;
4. preserve only sanitized incident evidence;
5. follow an approved history-remediation plan when required;
6. assess forks, caches, artifacts, logs, and downstream systems;
7. add a preventive control or regression test.

Deleting a visible file in a later commit does not remove it from Git history.
Do not rewrite history without an approved incident plan.
