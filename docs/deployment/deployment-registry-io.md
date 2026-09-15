# Deployment registry conditional I/O

Status: local adapter and synthetic tests. **Not installed, authenticated, or
production validated.** No AWS call, registry write, credential access or IAM
change was performed to develop or test this adapter.

[deployment_registry_io.py](../../tooling/deployment_registry_io.py) connects the
existing [registry transition model](../../tooling/deployment_registry.py) to an
injected low-level DynamoDB client. It does not construct clients, discover a
table, retrieve credentials, grant writer authority, authenticate an input pin,
or publish an anchor to consumers. There is no default client or CLI that could
accidentally select an AWS profile.

## Reviewed operation boundary

Each function requires `authority` and `expected_authority_digest` separately.
The latter is the canonical SHA-256 digest of the complete reviewed operation,
supplied by an independently authenticated control-plane source. It must never
be computed from incoming caller input and then treated as approval. Record and
ACCOUNT_READY digests are different pins and cannot replace it. A digest checks
integrity against an approved value; it does not identify an approver or provide
a signature.

`authority` is a closed JSON object with exactly these fields:

| Field | Required meaning |
| --- | --- |
| `schema_version` | `deployment-registry-operation.v1` |
| `operation` | `create`, `update` or `read`, matching the called function |
| `authority_account_id` | Independently approved platform-authority account, different from the customer destination |
| `authority_region` | Exact registry region |
| `registry_table_arn` | Full ARN of the installed `scanalyze-deployment-registry` table; account/region/partition must match the approved authority |
| `valid_from`, `expires_at` | Explicit UTC seconds, `YYYY-MM-DDTHH:MM:SSZ`; operation is admitted only in the half-open interval |
| `expected_anchor` | Closed existing `deployment-target-anchor.v1`: exact deployment ID, resulting registry version and record digest |
| `previous_anchor` | Exact predecessor anchor for `update`; JSON null for `create` and `read` |
| `account_ready_anchor` | Existing verifier's closed independent tuple, `baseline_version` and `expected_contract_digest` |

The ACCOUNT_READY anchor contains exactly `customer_id`, `deployment_id`,
`account_id`, `region`, `environment`, `baseline_version` and
`expected_contract_digest`. The real `verify_account_ready` gate validates its
schema, all eight roles, tags, ownership, state/plan controls and contract digest.
The record must preserve the full tuple and exact ACCOUNT_READY/state binding.
Registration requires the real baseline to exist already. Use the separate
bootstrap-request/candidate phase before those resources and digests exist; a
placeholder `ACCOUNT_READY` is not a registration shortcut.

The reviewed interval is input authority, not a new lease implementation. Its
issuance, maximum permitted duration, revocation, authenticated custody and
action-time owner approval remain responsibilities of the external control
plane. The default clock is actual UTC; the Python clock argument is a test
dependency and must not be controlled by a deployment request. Inputs are copied
to private snapshots before client or clock callbacks run. Clients receive a
detached write request, so callback mutation cannot change the approved record.

## Functions and exact I/O

All three functions take keyword-only `client`, `authority`,
`expected_authority_digest` and `account_ready`. The two publication functions
also take `record`. The result is only the existing four-field anchor, constructed
from validated readback. No success digest, provider response, resource
coordinates, ACCOUNT_READY content or full target is logged or returned.

| Function | Sequence |
| --- | --- |
| `publish_registry_create` | Verify operation/baseline/record; require registry version 1; one conditional `PutItem`; one consistent exact readback |
| `publish_registry_update` | Verify operation/baseline/proposed record; consistently read the pinned predecessor; run the real transition gate; one CAS `PutItem`; one consistent exact readback |
| `retrieve_registry_anchor` | Verify a separately approved `read` operation and baseline; consistently read and validate only the pinned version/digest |

The table's [actual key](../../modules/platform-authority/storage.tf) is
`deployment_id`, with the target's attributes stored at the top level. The
adapter adds no `document` wrapper, sidecar field, alternate key, index or table.
Unknown target attributes cause rejection before an update; the adapter does
not silently discard auxiliary fields. A schema migration beyond the existing
v1-to-v2 transition needs its own reviewed contract.

Create retains `attribute_not_exists(deployment_id)`. Update retains the core
version, digest, customer, account and region condition; the existing v1-to-v2
migration also checks the prior schema. The proposed version increments exactly
once. Immutable tuple, ACCOUNT_READY, state and v2 runtime origin remain guarded;
v1-to-v2 migration preserves status. All lifecycle states remain registry states:
successfully recording `SUSPENDED` does not make it executable. Consumers still
run their existing admission gates.

`TableName` is always the complete pinned ARN. Every `GetItem` uses that same ARN,
the exact deployment key and `ConsistentRead=True`, without a projection that
could hide unexpected attributes. Every write requests `ALL_OLD` and checks the
returned predecessor against the private current snapshot; create requires no
old record. Readback must satisfy the real record schema/digest, match the
approved anchor and baseline, and equal the entire proposed document. A concurrent
later version is rejected, even if valid in its own right. Readback is evidence
for that observation instant, not a promise the registry can never advance.

The adapter uses the existing full-item conditional-write contract; all writers
must preserve its version/digest discipline. It is not a transaction with an
execution lock or other resource. Malformed data or a race producing unexpected
old attributes stops confirmation and requires independent reconciliation.

The injected client must be an externally authenticated low-level DynamoDB
connection for the approved account/region. Before dispatch the adapter checks
the DynamoDB service, exact regional HTTPS endpoint, region and explicit
`config.retries.total_max_attempts == 1`. Custom/dual-stack/FIPS endpoints are not
admitted by this version; adding one requires a reviewed endpoint contract. These
local client metadata checks do not prove the AWS principal. The caller must
establish actual identity and installed permissions separately. The code does
not assume that a profile name or an object's metadata authenticates a client.

AWS specifies conditional replacement and table ARN support for
[PutItem](https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_PutItem.html),
and exact-key strong reads for
[GetItem](https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_GetItem.html).
The [Botocore retry setting](https://docs.aws.amazon.com/botocore/latest/reference/config.html)
`total_max_attempts=1` includes the initial request, preventing SDK retries as
well as adapter retries. The fake test port evaluates the actual emitted
conditions and copies AWS AttributeValue shapes; it does not mock a verifier.

## Conflict and ambiguous outcomes

There is no retry loop and no unconditional-write path. An identical create
replay fails its condition. An update replay fails its pinned predecessor check;
a concurrent CAS change fails the conditional write. A confirmed single-attempt
conditional failure raises `RegistryConflict` without issuing an anchor.

Timeout, transport failure, missing/retried/invalid response metadata,
inconsistent old attributes, missing/substituted readback and expiration after
the write raise `RegistryOutcomeUncertain`. The write may already have happened.
No anchor or success receipt is issued and the adapter does not infer success
from finding equivalent data after an exception. Raw SDK exception contents are
suppressed from exposed errors. Validity is checked before initial I/O, again
immediately before the effect, and after the final read; an update that expires
during its predecessor read is rejected before `PutItem`.

An uncertain operation must stop. Its approved controller must retain the
uncertainty and reconcile through a separately approved exact read; never call
the write again blindly or manufacture a new predecessor pin. This adapter has
no persistent attempt ledger and does not clear uncertainty across process
restarts. A successful later read establishes the observed record, not attribution
to a particular failed request. The new operation pin must still come from the
authenticated authority source.

## Validation and remaining decisions

[Focused tests](../../tests/test_deployment/test_deployment_registry_io.py) run
real registry and ACCOUNT_READY gates with synthetic records and a network-free
client. They cover create/read/CAS, v1/v2 and migration, production tuple binding,
non-executable lifecycle states, replay, concurrent change, mutated pins/records,
request-hash confusion, baseline control failures, substituted table/client,
ambiguous write/readback responses, expiry before and after effect, and mutation
of caller-owned inputs from I/O callbacks.

Before any real invocation, the owner must identify the approved writer and
reader principals, installed table identity/control evidence, real baseline,
authenticated reviewed-operation source and pin custody, and authenticated anchor
delivery to each consumer. The existing source does not define that final
authentication/issuance service; this change intentionally does not invent it.
Deployment callers and workflows are unchanged. No CI, installed IAM, connected
registry, actual anchor delivery or production success is claimed.

Rollback of this local addition is removal/revert of the three new adapter,
test and documentation files. No production rollback was attempted. A registry
transition already performed in a future authorized run must use a separately
approved forward lifecycle/CAS operation, not a version decrement, deletion or
unconditional replacement.
