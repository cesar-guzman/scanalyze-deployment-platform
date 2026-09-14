# Configure the real GUG-274 bootstrap signing root

The canonical AWS Signer profile now has an observed active version. The source
contract and CloudFormation template bind that exact version and contract
digest. This permits the configured signing root to pass validation; it does
not supply a signed package, source approval, human approval or production
readiness. `activation_authorized=false` and `production_status=NO-GO` remain
unchanged.

## Exact binding

- Authority account and Region: `042360977644`, `us-east-1`.
- Profile: `scanalyze_gug274_bootstrap_artifact_authority`.
- Version: `fo5PB1XOji`.
- Version ARN: `arn:aws:signer:us-east-1:042360977644:/signing-profiles/scanalyze_gug274_bootstrap_artifact_authority/fo5PB1XOji`.
- Platform: `AWSLambda-SHA384-ECDSA`; status read back as `Active`.
- Domain-separated contract digest: `sha256:2909fb75ecb695b9891062ac4dafcba664128658d2351690557e0708c2de4bef`.

The reviewed installation created the profile once and compared its returned
version with GetSigningProfile. Do not repeat creation or substitute another
version. The separate P-256 release VSA key is not this Lambda signing root.

## CloudFormation compatibility

The configured flag is now closed to `true` and both version and digest have
exact AllowedValues. Its default must be `true` because the signed-artifact
collector does not emit this flag. The existing rule still requires it. The
previous default and sole allowed value `false` made the rule unsatisfiable.

AWS CloudFormation rejects YAML aliases in the source template. Use the fixed
[renderer](../../scripts/deployment/render-bootstrap-authority-template.py) to
produce equivalent JSON in a new caller-owned private directory:

```sh
umask 077
SCANALYZE_GUG274_TEMPLATE_DIRECTORY="$(mktemp -d /private/tmp/scanalyze-gug274-template.XXXXXX)"
python3 scripts/deployment/render-bootstrap-authority-template.py \
  --expected-source-sha256 70916cdd8300626ea4d61bea62c24dcd644d55bdff77029e0378dd42d36dea72 \
  --output "$SCANALYZE_GUG274_TEMPLATE_DIRECTORY/authority.json"
```

The expected source hash above belongs to this reviewed template version.
Review a new pin whenever that source changes. The renderer rejects duplicate
keys, unrecognized tags, recursion, invalid JSON values, unsafe output paths
and overwrite attempts. It has no cloud calls.

The template also replaces nonexistent IAM transaction action names with the
actual item actions conditioned on `dynamodb:EnclosingOperation`. Both role and
resource policies deny transactional access. Existing direct compare-and-swap
permissions remain bounded by the absence of EnclosingOperation.

## Artifact storage

The separate [foundation template](../../bootstrap/cfn-platform-authority-gug274-artifact-foundation.yaml)
owns exactly one private versioned bucket, one symmetric KMS key and its bucket
policy. It was installed as `scanalyze-gug274-artifact-foundation` and verified
`CREATE_COMPLETE` on 2026-09-14. The bucket is
`scanalyze-gug274-artifacts-042360977644-us-east-1`; the KMS ARN is
`arn:aws:kms:us-east-1:042360977644:key/755700ab-1cd4-472f-8642-3ba9cb35dadb`.

Readback confirmed the policies, versioning, public-access blocks,
BucketOwnerEnforced ownership, exact SSE-KMS key, Bucket Keys and key rotation.
Unsigned reads and signed writes use separate GUG-274 prefixes. The policy
requires TLS and denies explicit wrong encryption, out-of-prefix writes and
artifact deletion. Headerless writes use the fixed KMS default. All three
resources have Retain policies. The earlier July state-backend change set was
not executed or changed.

This foundation contains no deployment registry or application runtime. No
bootstrap package was uploaded or signed by its installation.

## Validation and remaining execution

- GUG-274 trust-root, identity, importer and renderer suite: 103 tests passed
  with the existing authenticated SDK closure; its seven distribution pins
  were unchanged.
- AWS ValidateTemplate accepted the rendered 17-resource authority JSON.
- Foundation cfn-lint: exit 0. Authority JSON: no errors; eight existing
  redundant DependsOn warnings remain.
- Reviewed foundation change set: exactly three additions. GetTemplate bytes
  matched the reviewed template before its one execution; subsequent resource
  and policy readbacks matched.

Build the canonical package from a clean exact commit using
[the existing package CLI](../../scripts/deployment/platform-authority-bootstrap-artifact-package.py).
The package now includes the complete pinned SDK; follow the
[vendored SDK build procedure](gug274-vendored-sdk.md), including its required
`--sdk-runtime-root` argument. The earlier 103-test checkpoint above predates
this package-v2 change and is not its integration evidence.
The later signed-artifact collector independently requires protected-main
evidence, real signing-job and versioned object readbacks, and its authenticated
SDK closure. A premerge build is local verification only and must be rebuilt
after merge because the source commit is embedded in the package. Continue with
[the existing bootstrap procedure](platform-authority-account-bootstrap.md);
do not use local hashes as replacement authorization.

Rollback of source configuration means restoring the previous reviewed pin and
template in a new change. It does not revoke a deployed signing version, remove
the retained bucket/key, or undo a later installation. Preserve the private
creation/readback evidence before temporary-directory cleanup. Resource
retirement and signing-version revocation require their own reviewed impact
and recovery plan.
