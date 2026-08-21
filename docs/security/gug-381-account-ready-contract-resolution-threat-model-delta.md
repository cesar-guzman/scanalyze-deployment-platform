# GUG-381 threat-model delta: ACCOUNT_READY contract resolution

Production status: **NO-GO**. This delta covers repository code, synthetic
fixtures, and CI only. It does not prove an AWS account baseline, backend,
identity, deployment, runtime health, rollback, or production readiness.

## Trust boundary

`account-ready/v2` is external evidence owned by the `account-baseline`
authority. The resolver may carry it, but its content digest is not authority.
The pre-plan validator accepts it only when the existing ACCOUNT_READY verifier
passes and its canonical digest equals `account_ready_digest` from the backend
binding already authorized against the deployment target, independent anchor,
ACCOUNT_READY contract, and execution lock.

Resolution v3 is the only active representation. It keeps raw Terraform v2
envelopes and wraps ACCOUNT_READY as `{contract_id, contract}` so the evidence
type is unambiguous. It contains no materialized variable authority.

## Threats and controls

| Threat | Repository control | Required negative evidence |
|---|---|---|
| DAG prerequisite collapses to an empty set | the supported resolvable set includes the exact catalog-owned `account-ready/v2` record | `global` resolves exactly one requirement; missing evidence fails |
| caller self-anchors a forged baseline | validator requires the digest from the already-authorized backend binding | missing or wrong expected digest fails with no output |
| cross-target baseline is consumed | schema plus verifier require exact customer, deployment, account, and region bindings | each foreign tuple fails without logging identifiers |
| partial or weak baseline passes | approved ACCOUNT_READY v2 schema and verifier require eight exact roles, six state resources, and six controls | v1, partial, malformed, false-control, role, ARN, and digest variants fail |
| evidence type is confused with a Terraform envelope | v3 uses disjoint closed evidence shapes and semantic catalog-authority dispatch | wrong wrapper, producer, authority, or consumer fails |
| caller injects Terraform variables | the artifact has no `variables` field; only catalog metadata bindings are reconstructed | extra field and duplicate destination tests fail |
| v1/v2 bypasses the new external evidence check | active validator requires resolution v3 even with a caller-selected historical schema | v1 and v2 artifacts fail as downgrades |
| altered resolution is re-digested | semantic validation reruns after the resolution digest check | altered contract, wrapper, tuple, or digest fails before materialization |
| unsupported external authority becomes trusted | only the exact account-baseline deployment-record tuple is supported | release and identity evidence remain outside the resolvable set |
| test flow reaches AWS | fixture mode is explicit and `--live` remains blocked before I/O | acknowledged and unacknowledged live invocations create no output or AWS call |

## Residual boundaries

- The backend binding and its digest are repository evidence until a separately
  authorized live engine supplies them from protected, authenticated sources.
- A matching hash proves content integrity, not AWS existence, writer identity,
  publication, freshness of cloud state, or operational health.
- Release and identity external-contract validation remain separate work.
- The Terraform wrapper still reaches STS and remote backend operations only in
  a future separately authorized live plan; GUG-381 does not execute that path.

## Rollback

Before any authorized engine consumes v3, revert the single GUG-381 commit and
remove only unpublished temporary resolution/variable files. Never silently
fall back to v1/v2, mutate Terraform state, or delete cloud evidence.
