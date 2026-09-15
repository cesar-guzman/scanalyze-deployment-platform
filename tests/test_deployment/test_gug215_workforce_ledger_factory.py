"""Public, synthetic in-memory metadata only; no SDK, Git or network calls."""

from copy import deepcopy
from dataclasses import FrozenInstanceError
from hashlib import sha256
from io import BytesIO
import base64
import json
from pathlib import Path
from types import SimpleNamespace
from zipfile import ZipFile

import pytest
from jsonschema import Draft202012Validator

from tooling import platform_authority_retirement_ledger_factory as runtime
from tooling import platform_authority_retirement_ledger_factory_package as package


ROOT = Path(__file__).resolve().parents[2]
RUNTIME_ARN = "arn:aws:lambda:us-east-1::runtime:" + "a" * 64
COMMIT = "b" * 40  # Synthetic test assertion, never a deployable commit.
KEY_ID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
KEY_ARN = "arn:aws:kms:us-east-1:042360977644:key/" + KEY_ID
VERSION = "17"  # Synthetic observed context, not an installation prediction.
VERSION_ARN = ("arn:aws:lambda:us-east-1:042360977644:function:"
               + runtime.WORKFORCE_FACTORY_FUNCTION_NAME + ":" + VERSION)


class PublicFailure(Exception):
    def __init__(self, code="SyntheticFailure"):
        self.response = {"Error": {"Code": code}}
        super().__init__("synthetic-provider-detail-never-returned")


class World:
    def __init__(self, *, workforce=True, exists=False):
        self.workforce = workforce
        self.exists = exists
        self.calls = []
        self.creates = 0
        self.updates = 0
        self.create_fails = False
        self.update_fails = False
        self.fail_read = None
        self.flip_tags_at_final = False
        self.tags_reads = 0
        self.policy_reads = 0
        self.context = SimpleNamespace(
            function_version=VERSION,
            invoked_function_arn=(VERSION_ARN if workforce else
                f"arn:aws:lambda:us-east-1:042360977644:function:{runtime.FACTORY_FUNCTION_NAME}:{VERSION}"))
        self.identity = {"Account": "042360977644", "Arn":
            "arn:aws:sts::042360977644:assumed-role/" +
            (runtime.WORKFORCE_FACTORY_ROLE_NAME if workforce else runtime.FACTORY_ROLE_NAME) + "/synthetic"}
        self.tags = (runtime.create_workforce_table_request() if workforce
                     else runtime.create_table_request())["Tags"]
        self.table = {
            "TableName": runtime.LEDGER_TABLE_NAME, "TableArn": runtime._table_arn(),
            "TableStatus": "ACTIVE",
            "KeySchema": [{"AttributeName": "retirement_id", "KeyType": "HASH"}],
            "AttributeDefinitions": [{"AttributeName": "retirement_id", "AttributeType": "S"}],
            "DeletionProtectionEnabled": True,
            "BillingModeSummary": {"BillingMode": "PAY_PER_REQUEST"},
            "SSEDescription": {"Status": "ENABLED", "SSEType": "KMS", "KMSMasterKeyArn": KEY_ARN},
            "TableClassSummary": {"TableClass": "STANDARD"},
        }
        self.kms = {"KeyMetadata": {
            "AWSAccountId": "042360977644", "Arn": KEY_ARN, "KeyId": KEY_ID,
            "Enabled": True, "KeyUsage": "ENCRYPT_DECRYPT", "KeyState": "Enabled",
            "Origin": "AWS_KMS", "KeyManager": "AWS", "KeySpec": "SYMMETRIC_DEFAULT",
            "MultiRegion": False, "EncryptionAlgorithms": ["SYMMETRIC_DEFAULT"],
        }}
        self.policy = (runtime.canonical_workforce_resource_policy() if workforce
                       else runtime.canonical_resource_policy())
        self.ttl = {"TimeToLiveDescription": {"TimeToLiveStatus": "DISABLED"}}
        self.empty = {"Count": 0, "ScannedCount": 0}

    def record(self, name, kwargs):
        self.calls.append((name, deepcopy(kwargs)))
        if self.fail_read == name:
            raise PublicFailure()

    def get_caller_identity(self):
        self.record("sts", {})
        return deepcopy(self.identity)

    def describe_table(self, **kwargs):
        self.record("describe_table", kwargs)
        assert kwargs == {"TableName": runtime.LEDGER_TABLE_NAME}
        if not self.exists:
            raise PublicFailure("ResourceNotFoundException")
        return {"Table": deepcopy(self.table)}

    def describe_key(self, **kwargs):
        self.record("describe_key", kwargs)
        assert kwargs == {"KeyId": "alias/aws/dynamodb"}
        return deepcopy(self.kms)

    def create_table(self, **kwargs):
        self.record("create_table", kwargs)
        self.creates += 1
        self.exists = True
        if self.create_fails:
            raise PublicFailure()
        return {"TableDescription": deepcopy(self.table)}

    def get_resource_policy(self, **kwargs):
        self.record("get_resource_policy", kwargs)
        self.policy_reads += 1
        return {"Policy": json.dumps(self.policy), "RevisionId": "synthetic-revision"}

    def list_tags_of_resource(self, **kwargs):
        self.record("list_tags_of_resource", kwargs)
        self.tags_reads += 1
        tags = deepcopy(self.tags)
        if self.flip_tags_at_final and self.tags_reads > 1:
            tags[0]["Value"] = "drift"
        return {"Tags": tags}

    def scan(self, **kwargs):
        self.record("scan", kwargs)
        assert kwargs == {"TableName": runtime.LEDGER_TABLE_NAME,
                          "ConsistentRead": True, "Select": "COUNT", "Limit": 1}
        return deepcopy(self.empty)

    def describe_time_to_live(self, **kwargs):
        self.record("describe_time_to_live", kwargs)
        return deepcopy(self.ttl)

    def update_continuous_backups(self, **kwargs):
        self.record("update_continuous_backups", kwargs)
        assert kwargs == runtime.update_pitr_request()
        self.updates += 1
        if self.update_fails:
            raise PublicFailure()
        return {}

    def describe_continuous_backups(self, **kwargs):
        self.record("describe_continuous_backups", kwargs)
        return {"ContinuousBackupsDescription": {"ContinuousBackupsStatus": "ENABLED",
            "PointInTimeRecoveryDescription": {"PointInTimeRecoveryStatus": "ENABLED",
                                               "RecoveryPeriodInDays": 35}}}

    def run(self, event=None, sleeper=None):
        execute = runtime.execute_workforce if self.workforce else runtime.execute
        return execute(event={} if event is None else event, context=self.context,
                       clients=runtime.BotoClients(self, self, self),
                       sleeper=sleeper or (lambda _: None))


def schema(name):
    return Draft202012Validator(json.loads((ROOT / "schemas" / name).read_text()))


def reseal(document, key):
    document[key] = package.canonical_digest({k: v for k, v in document.items() if k != key})


def snapshot():
    # Deliberately arbitrary public test bytes. A v2 capture does NOT certify
    # that these implement the compiled contract, signing, source CI or AWS.
    return {path: (b"" if path == Path("tooling/__init__.py") else
                   b"# Synthetic test snapshot; not deployable.\n")
            for path in package.SOURCE_PATHS + package.WORKFORCE_PROVENANCE_PATHS}


def build():
    return package.build_workforce_ledger_factory_package(source_root=ROOT,
        source_commit=COMMIT, runtime_version_arn=RUNTIME_ARN, committed_sources=snapshot())


def check_receipt(receipt, *, pin=None, arn=VERSION_ARN):
    return package.validate_workforce_ledger_factory_causal_receipt(receipt,
        expected_receipt_digest=receipt["receipt_sha256"] if pin is None else pin,
        expected_function_version_arn=arn)


def test_fixed_contract_is_immutable_and_does_not_mutate_legacy():
    original = runtime.create_table_request()
    expected = deepcopy(original)
    expected["ResourcePolicy"] = runtime.canonical_json(runtime.canonical_workforce_resource_policy())
    expected["Tags"] = [{"Key": row["Key"], "Value":
        "production" if row["Key"] == "environment" else
        "true" if row["Key"] == "production" else row["Value"]} for row in original["Tags"]]
    assert runtime.create_workforce_table_request() == expected
    assert runtime.create_table_request() == original
    assert runtime.WORKFORCE_CONTRACT_SHA256 != runtime.CONTRACT_SHA256
    legacy_policy = runtime.canonical_resource_policy()
    production_policy = runtime.canonical_workforce_resource_policy()
    expected_actions = [action for action in legacy_policy["Statement"][0]["Action"]
                        if action != "dynamodb:TransactWriteItems"]
    assert len(expected_actions) == 7
    assert production_policy["Statement"][0]["Action"] == expected_actions
    legacy_policy["Statement"][0]["Action"] = expected_actions
    assert legacy_policy == production_policy
    with pytest.raises(FrozenInstanceError):
        runtime.WORKFORCE_CONTRACT.workforce = False
    request = runtime.create_workforce_table_request()
    request["Tags"][0]["Value"] = "foreign"
    assert runtime.create_workforce_table_request() == expected


@pytest.mark.parametrize("update_fails", [False, True])
def test_real_runtime_causal_creation_and_consumer(update_fails):
    world = World()
    world.update_fails = update_fails
    receipt = world.run()
    assert receipt["status"] == ("CREATED_RECONCILED" if update_fails else "CREATED")
    assert world.creates == world.updates == 1
    names = [name for name, _ in world.calls]
    assert names[:4] == ["sts", "describe_table", "describe_table", "describe_key"]
    assert next(kwargs for name, kwargs in world.calls if name == "create_table") == runtime.create_workforce_table_request()
    assert names.index("get_resource_policy") < names.index("update_continuous_backups")
    assert names.count("scan") == names.count("describe_time_to_live") == 2
    assert check_receipt(receipt) is None
    schema("platform-authority-retirement-ledger-factory-receipt.v2.schema.json").validate(receipt)
    assert not schema("platform-authority-retirement-ledger-factory-receipt.v1.schema.json").is_valid(receipt)
    assert receipt["deployment_authorized"] is False
    assert receipt["next_required_action"] == "REVOKE_FACTORY_AUTHORITY"


@pytest.mark.parametrize("race", [False, True])
@pytest.mark.parametrize("tags", ["production", "legacy", "foreign"])
def test_every_existing_table_is_denied_without_certification(race, tags):
    world = World(exists=not race)
    if tags == "legacy": world.tags = runtime.create_table_request()["Tags"]
    if tags == "foreign": world.tags = [{"Key": "foreign", "Value": "foreign"}]
    receipt = world.run(sleeper=lambda _: setattr(world, "exists", True))
    assert receipt["status"] == "DENY"
    assert receipt["reason_code"] == "WORKFORCE_EXISTING_TABLE_DENIED"
    assert world.creates == world.updates == 0
    assert {name for name, _ in world.calls} == {"sts", "describe_table"}
    schema("platform-authority-retirement-ledger-factory-receipt.v2.schema.json").validate(receipt)
    with pytest.raises(package.LedgerFactoryPackageError): check_receipt(receipt)


def test_legacy_success_and_existing_readonly_classification_stay_legacy():
    for exists, status in [(False, "CREATED"), (True, "ALREADY_EXACT")]:
        world = World(workforce=False, exists=exists)
        receipt = world.run()
        assert receipt["status"] == status
        assert receipt["schema_version"] == 1
        assert "authorization_mode" not in receipt
        assert receipt["contract_sha256"] == runtime.CONTRACT_SHA256
        with pytest.raises(package.LedgerFactoryPackageError): check_receipt(receipt)


@pytest.mark.parametrize("event", [{"mode": "workforce"}, {"production": True},
                                   {"TableName": "other"}, [], True, "{}"])
def test_event_cannot_select_contract(event):
    world = World()
    with pytest.raises(runtime.LedgerFactoryError, match="EMPTY_EVENT_REQUIRED"):
        world.run(event=event)
    assert world.calls == []


@pytest.mark.parametrize("version", ["$LATEST", "alias", "0", "01", "", 17])
def test_context_requires_observed_numeric_version(version):
    world = World()
    world.context.function_version = version
    with pytest.raises(runtime.LedgerFactoryError): world.run()
    assert world.calls == []


@pytest.mark.parametrize("other", [runtime.FACTORY_FUNCTION_NAME,
    "scanalyze-platform-authority-gug215-broker", "foreign"])
def test_context_rejects_other_function_even_with_numeric_version(other):
    world = World()
    world.context.invoked_function_arn = VERSION_ARN.replace(runtime.WORKFORCE_FACTORY_FUNCTION_NAME, other)
    with pytest.raises(runtime.LedgerFactoryError): world.run()
    assert world.calls == []


@pytest.mark.parametrize("role", [runtime.FACTORY_ROLE_NAME, runtime.RETIREMENT_BROKER_ROLE_NAME,
                                  "AWSAdministratorAccess", "foreign"])
def test_factory_identity_never_inherits_legacy_or_broker_authority(role):
    world = World()
    world.identity["Arn"] = world.identity["Arn"].replace(runtime.WORKFORCE_FACTORY_ROLE_NAME, role)
    with pytest.raises(runtime.LedgerFactoryError): world.run()
    assert [name for name, _ in world.calls] == ["sts"]


@pytest.mark.parametrize("failure", ["create", "tags", "ttl", "pitr", "final_tags"])
def test_post_create_uncertainty_is_terminal_and_not_causal_success(failure):
    world = World()
    if failure == "create": world.create_fails = True
    if failure == "tags": world.tags = runtime.create_table_request()["Tags"]
    if failure == "ttl": world.ttl["TimeToLiveDescription"]["AttributeName"] = "expires"
    if failure == "pitr": world.fail_read = "describe_continuous_backups"
    if failure == "final_tags": world.flip_tags_at_final = True
    receipt = world.run()
    assert receipt["status"] == "UNCERTAIN_RECONCILE_ONLY"
    assert world.creates == 1
    assert world.updates == (1 if failure in {"pitr", "final_tags"} else 0)
    assert "synthetic-provider-detail" not in json.dumps(receipt)
    schema("platform-authority-retirement-ledger-factory-receipt.v2.schema.json").validate(receipt)
    with pytest.raises(package.LedgerFactoryPackageError): check_receipt(receipt)


def test_read_error_is_not_absence_and_never_causes_create():
    world = World()
    world.fail_read = "describe_table"
    with pytest.raises(runtime.LedgerFactoryError, match="LEDGER_TABLE_READ_UNAVAILABLE"):
        world.run()
    assert world.creates == world.updates == 0


def test_fixed_handler_rejects_before_sdk_factory(monkeypatch):
    def unexpected(): raise AssertionError("SDK factory must not run")
    monkeypatch.setattr(runtime.BotoClients, "create", unexpected)
    receipt = runtime.handler_workforce({"mode": "legacy"}, World().context)
    assert receipt["reason_code"] == "EMPTY_EVENT_REQUIRED"
    schema("platform-authority-retirement-ledger-factory-receipt.v2.schema.json").validate(receipt)


@pytest.mark.parametrize("field,value", [
    ("deployment_authorized", True), ("production_status", "READY"),
    ("schema_version", 1), ("authorization_mode", "legacy"),
    ("contract_sha256", runtime.CONTRACT_SHA256), ("status", "ALREADY_EXACT"),
    ("create_table_call_count", 0), ("create_table_call_count", True),
    ("update_pitr_call_count", 0), ("attempt", 2), ("retry_permitted", 0),
    ("kms_key_metadata_sha256", None), ("active_readback_attempt_count", 1),
    ("policy_readback_attempt_count", 13), ("pitr_readback_attempt_count", True),
    ("extra", "field"),
])
def test_resealed_receipt_cannot_promote_wrong_contract_or_noncausal_result(field, value):
    receipt = World().run()
    receipt[field] = value
    reseal(receipt, "receipt_sha256")
    with pytest.raises(package.LedgerFactoryPackageError): check_receipt(receipt)


@pytest.mark.parametrize("arn", [VERSION_ARN.replace(":17", ":18"),
    VERSION_ARN.replace(":17", ":$LATEST"), VERSION_ARN.replace(":17", ":live"),
    VERSION_ARN.replace("042360977644", "905418381929"),
    VERSION_ARN.replace(runtime.WORKFORCE_FACTORY_FUNCTION_NAME, runtime.FACTORY_FUNCTION_NAME)])
def test_receipt_requires_independently_pinned_exact_version(arn):
    with pytest.raises(package.LedgerFactoryPackageError): check_receipt(World().run(), arn=arn)


def test_receipt_self_hash_does_not_replace_external_pin():
    with pytest.raises(package.LedgerFactoryPackageError, match="PIN_MISMATCH"):
        check_receipt(World().run(), pin="sha256:" + "c" * 64)


def test_v2_package_is_deterministic_closed_unsigned_and_rejected_by_default():
    first, second = build(), build()
    assert first == second
    manifest = first.manifest
    assert manifest["handler"] == package.WORKFORCE_HANDLER
    assert manifest["environment"] == {}
    assert manifest["production"] is True and manifest["deployment_authorized"] is False
    assert manifest["function_version_arn"] is None
    assert manifest["source_snapshot_status"] == "CAPTURED_BYTES_NOT_AUTHENTICATED"
    assert manifest["source_ci_status"] == "PENDING_CONNECTED_REVALIDATION"
    assert manifest["artifact_status"] == "UNSIGNED_SOURCE_NOT_DEPLOYABLE"
    assert manifest["signature_status"] == "PENDING_SIGNING_AND_IMMUTABLE_VERSION_READBACK"
    with ZipFile(BytesIO(first.archive)) as archive:
        assert archive.namelist() == [path.as_posix() for path in package.SOURCE_PATHS]
        assert len(archive.namelist()) == 2
    schema("platform-authority-retirement-ledger-factory-package.v2.schema.json").validate(manifest)
    with pytest.raises(package.LedgerFactoryPackageError):
        package.validate_ledger_factory_package_manifest(manifest, archive=first.archive)


def test_legacy_package_default_unchanged_and_not_promoted_by_v2_validator():
    captured = snapshot()
    built = package.build_ledger_factory_package(source_root=ROOT, source_commit=COMMIT,
        runtime_version_arn=RUNTIME_ARN, committed_sources={p: captured[p] for p in package.SOURCE_PATHS})
    assert built.manifest["schema_version"] == 1
    assert built.manifest["handler"] == package.HANDLER
    assert built.manifest["production"] is False
    assert "provenance" not in built.manifest
    schema("platform-authority-retirement-ledger-factory-package.v1.schema.json").validate(built.manifest)
    with pytest.raises(package.LedgerFactoryPackageError):
        package.validate_workforce_ledger_factory_package_manifest(built.manifest, archive=built.archive)


@pytest.mark.parametrize("field,value", [
    ("handler", package.HANDLER), ("schema_version", True), ("production", 1),
    ("deployment_authorized", True), ("deployment_authorized", 0),
    ("production_status", "READY"), ("artifact_status", "SIGNED_READY"),
    ("signature_status", "VERIFIED"), ("source_ci_status", "VERIFIED"),
    ("source_snapshot_status", "AUTHENTICATED"), ("function_version_arn", VERSION_ARN),
    ("environment", {"MODE": "workforce"}), ("factory_contract_sha256", runtime.CONTRACT_SHA256),
    ("extra", "field"),
])
def test_resealed_manifest_cannot_promote_captured_bytes(field, value):
    built = build()
    manifest = deepcopy(built.manifest)
    manifest[field] = value
    reseal(manifest, "manifest_digest")
    with pytest.raises(package.LedgerFactoryPackageError):
        package.validate_workforce_ledger_factory_package_manifest(manifest, archive=built.archive)


@pytest.mark.parametrize("wrapper", [b"synthetic-prefix", b"synthetic-trailer"])
def test_resealed_wrapper_bytes_outside_source_closure_are_rejected(wrapper):
    built = build()
    archive = wrapper + built.archive if wrapper.endswith(b"prefix") else built.archive + wrapper
    manifest = deepcopy(built.manifest)
    manifest.update(archive_sha256=sha256(archive).hexdigest(), archive_size_bytes=len(archive),
                    lambda_code_sha256=base64.b64encode(sha256(archive).digest()).decode())
    reseal(manifest, "manifest_digest")
    with pytest.raises(package.LedgerFactoryPackageError, match="NOT_CANONICAL"):
        package.validate_workforce_ledger_factory_package_manifest(manifest, archive=archive)


@pytest.mark.parametrize("mutation", ["missing_source", "extra_source", "missing_provenance", "mutable_bytes", "oversize"])
def test_snapshot_closure_and_byte_custody_rejected(mutation):
    captured = snapshot()
    if mutation == "missing_source": captured.pop(package.SOURCE_PATHS[1])
    if mutation == "extra_source": captured[Path("foreign.py")] = b"foreign"
    if mutation == "missing_provenance": captured.pop(package.WORKFORCE_PROVENANCE_PATHS[0])
    if mutation == "mutable_bytes": captured[package.SOURCE_PATHS[1]] = bytearray(b"mutable")
    if mutation == "oversize": captured[package.SOURCE_PATHS[1]] = b"a" * 262145
    with pytest.raises(package.LedgerFactoryPackageError):
        package.build_workforce_ledger_factory_package(source_root=ROOT, source_commit=COMMIT,
            runtime_version_arn=RUNTIME_ARN, committed_sources=captured)


def test_provenance_changes_manifest_but_never_enters_lambda_zip():
    captured = snapshot()
    first = build()
    captured[package.WORKFORCE_PROVENANCE_PATHS[0]] += b"# changed builder\n"
    second = package.build_workforce_ledger_factory_package(source_root=ROOT, source_commit=COMMIT,
        runtime_version_arn=RUNTIME_ARN, committed_sources=captured)
    assert first.archive == second.archive
    assert first.manifest["manifest_digest"] != second.manifest["manifest_digest"]


@pytest.mark.parametrize("change", ["none", "head_before", "dirty_before", "head_after", "dirty_after", "source_drift", "provenance_drift"])
def test_real_source_gate_checks_head_clean_blobs_and_provenance_twice(monkeypatch, change):
    captured = snapshot()
    calls = []
    def fake_git(root, *args, text=True):
        calls.append(args)
        if args == ("rev-parse", "HEAD"):
            changed = change == "head_before" or (change == "head_after" and calls.count(args) == 2)
            return "c" * 40 if changed else COMMIT
        if args[0] == "status":
            changed = change == "dirty_before" or (change == "dirty_after" and calls.count(args) == 2)
            return " M public.py" if changed else ""
        assert args[0] == "show" and text is False
        return captured[Path(args[1].split(":", 1)[1])]
    def read_source(root, path):
        if change == "source_drift" and path == package.SOURCE_PATHS[1]: return b"drift"
        if change == "provenance_drift" and path == package.WORKFORCE_PROVENANCE_PATHS[0]: return b"drift"
        return captured[path]
    monkeypatch.setattr(package, "_git", fake_git)
    monkeypatch.setattr(package, "_read_source", read_source)
    if change == "none":
        built = package.build_workforce_ledger_factory_package(source_root=ROOT,
            source_commit=COMMIT, runtime_version_arn=RUNTIME_ARN)
        assert built.manifest["source_snapshot_status"] == "CAPTURED_BYTES_NOT_AUTHENTICATED"
        assert len([c for c in calls if c[0] == "show"]) == len(captured)
        assert calls.count(("rev-parse", "HEAD")) == 2
    else:
        with pytest.raises(package.LedgerFactoryPackageError):
            package.build_workforce_ledger_factory_package(source_root=ROOT,
                source_commit=COMMIT, runtime_version_arn=RUNTIME_ARN)


@pytest.mark.parametrize("arn", [RUNTIME_ARN.replace("us-east-1", "us-west-2"), "", None])
def test_workforce_runtime_region_pin_is_exact(arn):
    with pytest.raises(package.LedgerFactoryPackageError):
        package.build_workforce_ledger_factory_package(source_root=ROOT,
            source_commit=COMMIT, runtime_version_arn=arn, committed_sources=snapshot())


@pytest.mark.parametrize("name", ["package", "receipt"])
def test_v2_schemas_are_valid(name):
    candidate = schema(f"platform-authority-retirement-ledger-factory-{name}.v2.schema.json")
    Draft202012Validator.check_schema(candidate.schema)
