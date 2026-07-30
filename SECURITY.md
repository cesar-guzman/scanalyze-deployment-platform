# Security Policy

## Supported code

Security fixes are accepted against the current `main` branch. Historical
branches, local worktrees, unmerged prototypes, and deployed environments may
have different states; include the exact commit and environment classification
in a report without including customer data or credentials.

## Report a vulnerability privately

Do not open a public GitHub issue, pull request, discussion, or Linear comment
with exploit details, secrets, customer data, or production evidence.

The canonical private reporting channel is **GitHub private vulnerability
reporting** for this repository: open the repository **Security** tab and choose
**"Report a vulnerability"**
(`https://github.com/cesar-guzman/scanalyze-deployment-platform/security/advisories/new`).
This creates a private advisory visible only to the reporter and repository
security managers. Repository administrators and security managers may also
create a draft GitHub Security Advisory directly.

This channel is only operable once GitHub private vulnerability reporting is
enabled on the repository. Enabling it is a required governance action tracked
in [GUG-262](https://linear.app/guguce/issue/GUG-262/establish-and-validate-claude-code-contributor-baseline)
and reflected in
[`docs/engineering/GITHUB_ENFORCEMENT_BASELINE.md`](docs/engineering/GITHUB_ENFORCEMENT_BASELINE.md).
Until this repository control is confirmed enabled, this document MUST NOT be
cited as an operable private route, and a repository administrator MUST enable it
before external reporting is relied upon. Changing this setting is a reviewed
repository-administration action; it is never performed automatically or by an
AI assistant.

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
