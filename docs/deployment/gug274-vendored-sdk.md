# GUG-274 vendored SDK package

The canonical builder emits package manifest v2 and runtime lock v2. The ZIP
contains the complete reviewed Python SDK closure together with the authority
handlers. The signed-artifact collector accepts that closure only after
rebuilding it from the exact clean source commit and independently checking
the committed SDK distribution hashes. Trust-root generation 1, the configured
Signer version, function versions, IAM policies, identity gates and CAS remain
unchanged. This change performs no AWS operation.

The previous package contained eight files and loaded the managed Lambda SDK.
Its exact version check could reject the SDK installed by a runtime update.
AWS documents that the runtime SDK changes, recommends packaging all
dependencies, and gives `/var/task` precedence over managed SDKs and layers.
See [Python deployment packages](https://docs.aws.amazon.com/lambda/latest/dg/python-package.html)
and [runtime updates](https://docs.aws.amazon.com/lambda/latest/dg/runtimes-update.html).
The new package does not depend on observing or freezing the managed SDK.

## Reviewed closure

The seven existing wheel and installed-manifest pins are preserved exactly:

| Distribution | Version |
| --- | --- |
| boto3 | 1.42.57 |
| botocore | 1.42.97 |
| s3transfer | 0.16.1 |
| jmespath | 1.1.0 |
| python-dateutil | 2.9.0.post0 |
| urllib3 | 2.7.0 |
| six | 1.17.0 |

The authenticated export contains 2,133 files and 21,460,247 bytes; its largest
file is 1,256,900 bytes. Every distribution is a pure-Python wheel compatible
with Python 3.12. Wheel code, service models, certificate bundles, licenses and
reviewed distribution metadata are included. Installer-specific `RECORD`,
`INSTALLER` and `REQUESTED` files are excluded from the export because their
bytes are not part of the committed installed-manifest hash. The exporter
still validates the complete installation, including its RECORD, before taking
a bounded byte snapshot and validating that snapshot again against the pins.
No dependency resolution, download or installation occurs during packaging.

The fixed limits are 24 MiB for SDK bytes, 2 MiB per entry, 4,096 entries and
32 MiB for the complete archive and its uncompressed contents. These limits
cover the measured closure with bounded source/signature headroom. The package
has 2,142 entries and approximately 22.4 MB with the current handler source.
Exact archive hashes and sizes are outputs of the clean-commit build, not
constants copied from a synthetic test. ZIP metadata is fixed and storage is
uncompressed, so the same source commit and authenticated SDK bytes produce
identical archives independently of zlib versions or filesystem enumeration.

## Build and verify

Provide the reviewed commit, a dedicated authenticated SDK installation root
containing `site-packages`, and a new external output directory whose parent
already exists. The SDK directory is operational input; its location does not
authorize its contents. The committed pins determine the accepted contents.

```sh
env -u PYTHONPATH -u PYTHONHOME /opt/homebrew/bin/python3 -I -S \
  scripts/deployment/platform-authority-bootstrap-artifact-package.py \
  --source-commit "$SCANALYZE_GUG274_SOURCE_COMMIT" \
  --sdk-runtime-root "$SCANALYZE_GUG274_SDK_RUNTIME_ROOT" \
  --expected-boto3-version 1.42.57 \
  --expected-botocore-version 1.42.97 \
  --output-directory "$SCANALYZE_GUG274_UNSIGNED_DIRECTORY"
```

The command verifies clean HEAD and committed source/provenance bytes before
exporting the SDK. It writes a private new directory and refuses overwrite.
It emits an unsigned artifact with `deployable=false` and `production_status=NO-GO`.
The protected-main/PR checks still gate signed-artifact evidence. A premerge
candidate must be rebuilt after merge because the commit is embedded in the ZIP.

The collector uses the same SDK root through the existing
`SCANALYZE_GUG274_SDK_RUNTIME_ROOT` variable and authenticates it independently.
It verifies every unsigned and signed archive entry, source bytes, SDK pins,
object version and signing profile version. It rejects oversized or conflicting
central-directory sizes before decompressing entries. The existing receipt
remains v1 with a bounded 32 MiB artifact limit and its existing 15-minute
freshness requirement. An old managed-SDK package cannot satisfy the v2 builder
and runtime lock; historical v1 schema fixtures remain historical validation only.

## Runtime custody

Before the first SDK import, the runtime rejects all SDK modules already in
`sys.modules`, authenticates the full on-disk closure against the signed lock
and committed distribution pins, and captures the Python source bytes. A
dedicated finder compiles that source directly, never bytecode. Missing modules
raise `ModuleNotFoundError` without searching a layer or managed SDK.
Subsequent invocations require the same finder and the same recorded module
objects/loaders. The narrow `six.moves` importer is owned by the reviewed six
module. Version checks remain mandatory before any provider client is created.

Optional third-party SDK imports such as CRT, Brotli, certifi and OpenSSL are
deliberately absent. Their external modules and preloads are rejected rather
than allowed to change signing, compression, TLS or transport behavior.
`BOTOCORE_EXPERIMENTAL__PLUGINS` and a programmatic botocore plugin context are
also rejected before provider construction. No environment override silently
selects a different SDK or installs another package.

## Validation and operational limits

Run the existing trust-boundary matrix and real-closure integration together:

```sh
SCANALYZE_GUG274_SDK_RUNTIME_ROOT="$SCANALYZE_GUG274_SDK_RUNTIME_ROOT" \
  /opt/homebrew/bin/python3 -m pytest -q -p no:cacheprovider \
  tests/test_deployment/test_gug274_bootstrap_artifact_trust_root.py \
  tests/test_deployment/test_gug274_vendored_sdk.py
```

The existing identity/CAS/Git/receipt unit matrix uses explicitly synthetic SDK
entries so those tests do not require a download. The separate integration
suite uses the actual seven committed pins, with no substituted validator. It
requires the explicit SDK root and Python 3.12; missing prerequisites are
reported as skipped integration tests and do not establish package readiness.
It checks deterministic archives, changed/missing/extra files, forged preloads,
warm module replacement, optional dependencies, plugin overrides and archive
size lies. A Python 3.12 subprocess imports the real SDK cold and warm and
loads DynamoDB, SSO OIDC, STS, CloudFormation and S3 Control models locally.
The probe blocks socket connections and creates no AWS clients.

Local checkpoint: the combined trust-boundary and real-closure run passed 130
tests; the subsequently added runtime-wiring test also passed independently.
That test calls the real authority `_validate_runtime_lock` on the extracted
2,133-entry closure and imports the same SDK cold and warm. Package v1/v2 and
receipt v1 schema/fixture checks returned zero errors. An independent reviewer
reproduced the 25-test integration checkpoint and identical archive bytes with
Python 3.12 and Python 3.14.2, using an explicitly synthetic source commit.

Successful local tests do not establish AWS Lambda execution, code-signing
acceptance, connected identity proof, protected-main approval or an installed
authority. Those require the existing fresh provider evidence and authorized
installation. No key, profile, grant, role, stack or artifact is created by this
patch. Source rollback requires another reviewed source/package change; it
does not alter previously signed objects or retained resources.
