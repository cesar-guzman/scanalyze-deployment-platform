"""Offline workforce CLI/compiler tests; synthetic identities and signing metadata.
Only Git subprocess I/O is replaced with public source snapshots. No credential
objects, SDK, actual Git processes, network or claims of authentic signatures.
"""
from __future__ import annotations
import ast
import base64
import copy
from datetime import UTC, datetime
from hashlib import sha256
import importlib.util
from io import BytesIO
import json
from pathlib import Path
import subprocess
from zipfile import ZipFile
import pytest
from tooling import platform_authority_change_set_retirement_package as package
from tooling import platform_authority_retirement_entrypoint_materializer as mat
from tooling import platform_authority_retirement_entrypoint_service_role_materializer as compiler

ROOT = Path(__file__).resolve().parents[2]
CLI = ROOT / "scripts/deployment/platform-authority-retirement-entrypoint-materializer.py"
COMMIT, TREE = "a" * 40, "b" * 40
NOW = datetime(2026, 9, 15, 12, tzinfo=UTC)
RUNTIME = "arn:aws:lambda:us-east-1::runtime:" + "c" * 64
KEY = "arn:aws:kms:us-east-1:042360977644:key/00000000-0000-4000-8000-000000000001"
CSC = "arn:aws:lambda:us-east-1:042360977644:code-signing-config:csc-" + "1" * 17
JOB = "00000000-0000-4000-8000-000000000002"
PROFILE = "arn:aws:signer:us-east-1:042360977644:/signing-profiles/synthetic_gug215/abcdefghij"
DIGEST = "sha256:" + "d" * 64

@pytest.fixture
def world(monkeypatch):
    paths = (*package.WORKFORCE_SOURCE_PATHS, *package.WORKFORCE_PROVENANCE_PATHS, *mat.WORKFORCE_MATERIALIZER_PATHS)
    blobs = {p.as_posix(): (ROOT / p).read_bytes() for p in paths}
    state = {"dirty": "", "head": COMMIT, "tree": TREE, "git_calls": [], "blobs": blobs}

    def git_run(argv, **kwargs):
        state["git_calls"].append(tuple(argv))
        assert argv[0] == "git"
        if argv[1:] == ["rev-parse", "HEAD"]:
            value = state["head"]
        elif argv[1:] == ["rev-parse", "HEAD^{tree}"]:
            value = state["tree"]
        elif argv[1] == "status":
            value = state["dirty"]
        elif argv[1] == "show":
            commit, path = argv[2].split(":", 1)
            assert commit == COMMIT
            value = state["blobs"][path]
        else:
            raise AssertionError("Unreviewed Git command")
        if kwargs.get("text") and isinstance(value, bytes):
            value = value.decode()
        elif not kwargs.get("text") and isinstance(value, str):
            value = value.encode()
        return subprocess.CompletedProcess(argv, 0, value, "")
    monkeypatch.setattr(subprocess, "run", git_run)
    sources = {p: blobs[p.as_posix()] for p in package.WORKFORCE_SOURCE_PATHS}
    built = package.build_retirement_package(source_root=ROOT, source_commit=COMMIT,
        broker_runtime_version_arn=RUNTIME, authorization_mode=package.WORKFORCE_AUTHORIZATION_MODE, committed_sources=sources)
    buffer = BytesIO(built.archive)
    with ZipFile(buffer, "a") as archive:
        archive.comment = b"SYNTHETIC_NOT_A_CRYPTOGRAPHIC_SIGNATURE"
    signed_bytes, manifest = buffer.getvalue(), built.manifest
    unsigned = {"bucket": "synthetic-gug215-artifacts",
        "key": f"scanalyze/platform-authority/gug-215/unsigned/{COMMIT}/scanalyze-gug215-change-set-retirement-broker.zip",
        "version_id": "synthetic-source-version", "sse_algorithm": "aws:kms", "sse_kms_key_arn": KEY,
        **{k: manifest[k] for k in ("archive_sha256", "lambda_code_sha256", "archive_size_bytes", "artifact_type", "work_package", "manifest_digest")}}
    signed = {"bucket": unsigned["bucket"], "key": f"scanalyze/platform-authority/gug-215/signed/{JOB}.zip",
        "version_id": "synthetic-signed-version", "sse_algorithm": "aws:kms", "sse_kms_key_arn": KEY,
        "archive_sha256": sha256(signed_bytes).hexdigest(),
        "lambda_code_sha256": base64.b64encode(sha256(signed_bytes).digest()).decode(), "archive_size_bytes": len(signed_bytes)}
    contract = {"contract_version": 1, "unsigned_source": unsigned, "signed_destination": signed,
        "signer": {"job_id": JOB, "status": "Succeeded", "job_owner": "042360977644", "job_invoker": "042360977644",
            "platform_id": "AWSLambda-SHA384-ECDSA", "profile_name": "synthetic_gug215", "profile_version_id": "abcdefghij",
            "profile_version_arn": PROFILE, "signature_expires_at": "2026-10-01T00:00:00Z"},
        "code_signing_config": {"arn": CSC, "allowed_signing_profile_version_arns": [PROFILE], "untrusted_artifact_on_deployment": "Enforce"}}
    roles = {}
    for op, name, suffix in [("classify", "ScanalyzeAuthorityRetireClass", "1"), ("retire", "ScanalyzeAuthorityRetireApprove", "2")]:
        roles[op] = {"role_arn": f"arn:aws:iam::042360977644:role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_{name}_{suffix * 16}",
            "role_id": "AROA" + suffix * 17, "permission_set_arn": "arn:aws:sso:::permissionSet/ssoins-7223feaee61e2475/ps-" + suffix * 16,
            "policy_sha256": DIGEST, "trust_sha256": DIGEST}
    intent = {"record_type": mat.WORKFORCE_INTENT_TYPE, "schema_version": 1, "authorization_mode": mat.WORKFORCE_MODE,
        "authority_account_id": "042360977644", "region": "us-east-1",
        "source": {"commit": COMMIT, "tree": TREE, "policy_template_sha256": "sha256:" + sha256(blobs[mat.WORKFORCE_POLICY_PATH.as_posix()]).hexdigest()},
        "source_ci_evidence_digest": DIGEST,
        "target": {"stack_id": "arn:aws:cloudformation:us-east-1:042360977644:stack/scanalyze-platform-authority-state-backend/00000000-0000-4000-8000-000000000003",
            "change_set_id": "arn:aws:cloudformation:us-east-1:042360977644:changeSet/scanalyze-platform-authority-bootstrap-20260717150949/00000000-0000-4000-8000-000000000004",
            "expected_template_sha256": DIGEST, "expected_evidence_sha256": DIGEST},
        "api_id": "testapi123", "owner": {"operator_id": "cesar-guzman", "subject_digest": DIGEST, "assignment_readback_digest": DIGEST},
        "roles": roles, "reader": {"role_arn": "arn:aws:iam::839393571433:role/ScanalyzeGug215WorkforceAssignmentReader",
            "readback_digest": DIGEST, "not_before": "2026-09-15T00:00:00Z", "not_after": "2026-09-16T00:00:00Z"},
        "effect_window": {"authorized_at": "2026-09-15T11:59:00Z", "not_before": "2026-09-15T12:00:00Z", "expires_at": "2026-09-15T12:15:00Z"},
        "ledger_kms_key": {"arn": KEY, "readback_digest": DIGEST}, "artifact_signing_contract": contract}
    evidence = {"schema_version": 1, "observed_at": "2026-09-15T11:59:00Z", "account_id": "042360977644", "region": "us-east-1",
        "signing_job": {"jobId": JOB, "status": "Succeeded", "jobOwner": "042360977644", "jobInvoker": "042360977644",
            "platformId": "AWSLambda-SHA384-ECDSA", "profileName": "synthetic_gug215", "profileVersion": "abcdefghij",
            "source": {"s3": {"bucketName": unsigned["bucket"], "key": unsigned["key"], "version": unsigned["version_id"]}},
            "signedObject": {"s3": {"bucketName": signed["bucket"], "key": signed["key"]}}, "signatureExpiresAt": "2026-10-01T00:00:00Z"},
        "signing_profile": {"profileName": "synthetic_gug215", "profileVersion": "abcdefghij", "profileVersionArn": PROFILE,
            "platformId": "AWSLambda-SHA384-ECDSA", "status": "Active"}, "bucket_versioning": {"Status": "Enabled"},
        "signed_versions": {"Name": signed["bucket"], "Prefix": signed["key"], "IsTruncated": False,
            "Versions": [{"Key": signed["key"], "VersionId": signed["version_id"], "IsLatest": True, "Size": len(signed_bytes)}]},
        "code_signing_config": {"CodeSigningConfig": {"CodeSigningConfigId": CSC.rsplit(":", 1)[1], "CodeSigningConfigArn": CSC,
            "AllowedPublishers": {"SigningProfileVersionArns": [PROFILE]}, "CodeSigningPolicies": {"UntrustedArtifactOnDeployment": "Enforce"}}}}
    for label, item in [("unsigned", unsigned), ("signed", signed)]:
        evidence[label + "_request"] = {"Bucket": item["bucket"], "Key": item["key"], "VersionId": item["version_id"], "ExpectedBucketOwner": "042360977644"}
        evidence[label + "_head"] = {"VersionId": item["version_id"], "ContentLength": item["archive_size_bytes"],
            "ServerSideEncryption": "aws:kms", "SSEKMSKeyId": KEY, "ChecksumSHA256": item["lambda_code_sha256"]}
    state.update(intent=intent, manifest=manifest, archive=built.archive, signed=signed_bytes, evidence=evidence)
    return state

def build(world, **kwargs):
    args = {"intent": world["intent"], "expected_intent_digest": mat.canonical_digest(world["intent"]),
        "package_manifest": world["manifest"], "package_archive": world["archive"], "signed_archive": world["signed"],
        "signing_readback": world["evidence"], "expected_signing_readback_digest": mat.canonical_digest(world["evidence"]),
        "repo_root": ROOT, "evaluated_at": NOW}
    args.update(kwargs)
    return mat.build_workforce_materialization_plan(**args)

def test_integrated_plan_preserves_signed_bytes_exact_policy_and_pending_identity(world):
    plan = build(world)
    assert plan["status"] == "PREPARED_NOT_AUTHORIZED_NOT_INSTALLED"
    assert plan["deployment_authorized"] is plan["independent_approval_present"] is False
    compiled = plan["compiled"]
    policy, role, function = (compiled[k] for k in ("policy", "role", "function"))
    assert role["permissions_boundary_arn"] == role["attached_policy_arns"][0] == policy["arn"]
    assert role["attached_document_digest"] == role["boundary_document_digest"] == policy["document_digest"]
    assert role["provider_role_id"] is function["runtime_configuration"] is function["numeric_version_arn"] is None
    assert function["create_request"]["Publish"] is False and function["create_request"]["Environment"] == {"Variables": {}}
    assert function["signed_s3_version_id"] == world["intent"]["artifact_signing_contract"]["signed_destination"]["version_id"]
    assert function["expected_signed_code_sha256"] != world["manifest"]["lambda_code_sha256"]
    assert policy["managed_policy_characters"] <= 6144
    assert compiled["ledger"]["retirement_id"] == "gug215#sha256:" + sha256(plan["target"]["change_set_id"].encode()).hexdigest()
    assert all(any(path in call[-1] for call in world["git_calls"] if call[1] == "show") for path in plan["compiler_sources"])

@pytest.mark.parametrize("missing", ["effect_window", "ledger_kms_key"])
def test_no_effect_or_key_prepares_only_identical_deny_all_role(world, missing):
    world["intent"][missing] = None
    compiled = build(world)["compiled"]
    assert compiled["policy"]["document"]["Statement"] == [{"Sid": "DenyEveryProofSessionAction", "Effect": "Deny", "Action": "*", "Resource": "*"}]
    role = compiled["role"]
    assert role["create_request"]["PermissionsBoundary"] == role["attach_request"]["PolicyArn"]
    assert role["boundary_document_digest"] == role["attached_document_digest"]
    assert role["provider_role_id"] is None

@pytest.mark.parametrize("kwargs", [{"expected_intent_digest": DIGEST}, {"expected_signing_readback_digest": DIGEST}])
def test_external_pin_mismatch_rejects_before_source_or_output(world, kwargs):
    with pytest.raises(mat.RetirementEntrypointMaterializationError, match="WORKFORCE_EXTERNAL_PIN_MISMATCH"):
        build(world, **kwargs)
    assert not world["git_calls"]

@pytest.mark.parametrize("key,value", [("authorization_mode", "SINGLE_OPERATOR_NONPROD_EXCEPTION"), ("schema_version", True),
    ("authority_account_id", "905418363887"), ("api_id", "*"), ("function_version", "1"), ("broker_role_id", "AROA" + "9" * 17), ("deployment_authorized", True)])
def test_resealed_invalid_or_premature_intent_cannot_promote(world, key, value):
    world["intent"][key] = value
    with pytest.raises(mat.RetirementEntrypointMaterializationError):
        build(world)

@pytest.mark.parametrize("key,value", [("role_id", "invented"), ("role_arn", "arn:aws:iam::042360977644:role/Admin"),
    ("permission_set_arn", "arn:aws:sso:::permissionSet/ssoins-0000000000000000/ps-1111111111111111"), ("policy_sha256", "")])
def test_role_metadata_syntax_or_scope_fails_even_when_resealed(world, key, value):
    world["intent"]["roles"]["classify"][key] = value
    with pytest.raises(mat.RetirementEntrypointMaterializationError):
        build(world)

@pytest.mark.parametrize("path,value", [
    (("signed_request", "VersionId"), "foreign"), (("unsigned_request", "Key"), "foreign"),
    (("signed_head", "ChecksumSHA256"), "A" * 43 + "="), (("signed_head", "SSEKMSKeyId"), "foreign"),
    (("signing_job", "profileVersion"), "foreign123"), (("signing_profile", "profileVersion"), "foreign123"),
    (("signing_job", "status"), "InProgress"), (("bucket_versioning", "Status"), "Suspended"),
    (("signed_versions", "IsTruncated"), True), (("signed_versions", "NextKeyMarker"), "")])
def test_resealed_cross_artifact_or_partial_readback_rejects(world, path, value):
    world["evidence"][path[0]][path[1]] = value
    with pytest.raises(mat.RetirementEntrypointMaterializationError):
        build(world)

@pytest.mark.parametrize("field", ["archive", "signed"])
def test_archive_bytes_do_not_follow_caller_hashes(world, field):
    world[field] += b"corrupt"
    with pytest.raises(mat.RetirementEntrypointMaterializationError):
        build(world)

@pytest.mark.parametrize("key,value", [("dirty", " M source.py\n"), ("head", "f" * 40), ("tree", "f" * 40)])
def test_clean_source_validator_rejects_dirty_or_wrong_snapshot(world, key, value):
    world[key] = value
    with pytest.raises(mat.RetirementEntrypointMaterializationError):
        build(world)

@pytest.mark.parametrize("path", [p.as_posix() for p in mat.WORKFORCE_MATERIALIZER_PATHS])
def test_changed_compiler_blob_does_not_pass_clean_status(world, path):
    world["blobs"][path] += b"\n# synthetic drift\n"
    with pytest.raises(mat.RetirementEntrypointMaterializationError):
        build(world)

@pytest.mark.parametrize("field,value", [("expires_at", "2026-09-15T12:15:01Z"), ("expires_at", "2026-09-15T12:00:00Z"),
    ("authorized_at", "2026-09-15T12:01:00Z"), ("not_before", "2026-09-14T23:59:00Z")])
def test_effect_window_cannot_inherit_24_hour_reader_interval(world, field, value):
    world["intent"]["effect_window"][field] = value
    with pytest.raises(mat.RetirementEntrypointMaterializationError):
        build(world)

@pytest.mark.parametrize("reader_end,accepted", [("2026-09-15T12:30:00Z", True),
    ("2026-09-15T12:29:59Z", False), ("2026-09-15T12:15:01Z", False)])
def test_effect_window_reserves_fifteen_minutes_for_reader_reconciliation(world, reader_end, accepted):
    world["intent"]["reader"]["not_after"] = reader_end
    if accepted:
        assert build(world)["deployment_authorized"] is False
    else:
        with pytest.raises(mat.RetirementEntrypointMaterializationError, match="WORKFORCE_EFFECT_WINDOW_INVALID"):
            build(world)

def load_cli():
    spec = importlib.util.spec_from_file_location("synthetic_workforce_materializer_cli", CLI)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

def arguments(world, tmp_path):
    tmp_path.chmod(0o700)
    for name, value in {"intent.json": world["intent"], "manifest.json": world["manifest"], "readback.json": world["evidence"]}.items():
        path = tmp_path / name
        path.write_text(json.dumps(value))
        path.chmod(0o600)
    for name, value in [("unsigned.zip", world["archive"]), ("signed.zip", world["signed"])]:
        path = tmp_path / name
        path.write_bytes(value)
        path.chmod(0o600)
    return ["workforce-plan", "--intent", str(tmp_path / "intent.json"),
        "--expected-intent-digest", mat.canonical_digest(world["intent"]),
        "--unsigned-package-manifest", str(tmp_path / "manifest.json"), "--unsigned-package-archive", str(tmp_path / "unsigned.zip"),
        "--signed-package-archive", str(tmp_path / "signed.zip"), "--signing-readback", str(tmp_path / "readback.json"),
        "--expected-signing-readback-digest", mat.canonical_digest(world["evidence"]), "--plan-out", str(tmp_path / "plan.json")]

def test_cli_runs_real_validator_compiler_and_persists_closed_plan(world, tmp_path, monkeypatch, capsys):
    cli = load_cli()
    monkeypatch.setattr(cli, "_now", lambda: NOW)
    argv = arguments(world, tmp_path)
    assert cli.main(argv) == 0
    status = json.loads(capsys.readouterr().out)
    plan = json.loads((tmp_path / "plan.json").read_text())
    assert status["plan_digest"] == plan["plan_digest"] and status["aws_mutation_attempted"] is False
    assert plan["compiled"]["policy"]["document"]["Statement"]
    assert cli.main(argv) == 2
    assert json.loads(capsys.readouterr().err)["reason"] == "WORKFORCE_PLAN_ALREADY_EXISTS"

@pytest.mark.parametrize("flag", ["--apply", "--install", "--allow-create-stack", "--skip-signature", "--profile", "--function-version"])
def test_cli_has_no_workforce_install_identity_or_bypass_flags(world, tmp_path, flag):
    with pytest.raises(SystemExit) as caught:
        load_cli()._parser().parse_args(arguments(world, tmp_path) + [flag, "synthetic"])
    assert caught.value.code == 2

def test_v2_stays_rejected_by_legacy_package_and_signing_contract(world):
    with pytest.raises(package.RetirementPackageError):
        package.validate_retirement_package_manifest(world["manifest"], archive=world["archive"])
    with pytest.raises(mat.RetirementEntrypointMaterializationError, match="UNSIGNED_ARTIFACT_INVALID"):
        mat._validate_artifact_signing_contract(world["intent"]["artifact_signing_contract"])


def iam_decision(document, action, resource, ctx):
    """Only operators in this closed policy; not an AWS IAM simulator."""
    from fnmatch import fnmatchcase
    allowed = False
    for row in document["Statement"]:
        values = lambda item: item if isinstance(item, list) else [item]
        if "Action" in row and not any(fnmatchcase(action, x) for x in values(row["Action"])):
            continue
        if "NotAction" in row and any(fnmatchcase(action, x) for x in values(row["NotAction"])):
            continue
        if "Resource" in row and not any(fnmatchcase(resource, x) for x in values(row["Resource"])):
            continue
        if "NotResource" in row and any(fnmatchcase(resource, x) for x in values(row["NotResource"])):
            continue
        matched = True
        for op, entries in row.get("Condition", {}).items():
            for key, expected in entries.items():
                actual = ctx.get(key)
                if op in ("ArnNotEqualsIfExists", "StringNotEqualsIfExists"):
                    check = actual is None or actual != expected
                elif op == "StringEquals":
                    check = actual == expected
                elif op in ("Bool", "BoolIfExists"):
                    check = ((op == "BoolIfExists" and actual is None)
                             or (type(actual) is bool and actual == (expected == "true")))
                elif op in ("DateGreaterThanEquals", "DateLessThan"):
                    def instant(value):
                        return (datetime.fromtimestamp(int(value), UTC) if value.isdigit()
                                else datetime.fromisoformat(value.replace("Z", "+00:00")))
                    check = actual is not None and (instant(actual) >= instant(expected)
                        if op == "DateGreaterThanEquals" else instant(actual) < instant(expected))
                elif op == "ForAllValues:StringEquals":
                    check = actual is None or all(x in expected for x in actual)
                elif op == "Null":
                    check = (actual is None) == (expected == "true")
                else:
                    raise AssertionError(op)
                matched = matched and check
        if matched and row["Effect"] == "Deny":
            return "DENY"
        if matched:
            allowed = True
    return "ALLOW" if allowed else "IMPLICIT_DENY"

def origin():
    return {"lambda:SourceFunctionArn": "arn:aws:lambda:us-east-1:042360977644:function:scanalyze-platform-authority-gug215-retirement"}

def decrypt_context():
    # Protected provider context, not caller-supplied headers or credentials.
    return {"kms:ViaService": "dynamodb.us-east-1.amazonaws.com",
            "kms:CallerAccount": "042360977644", "aws:ViaAWSService": True}

def test_dynamodb_fas_decrypt_works_without_lambda_source_context(world):
    policy = build(world)["compiled"]["policy"]["document"]
    assert iam_decision(policy, "kms:Decrypt", KEY, decrypt_context()) == "ALLOW"

@pytest.mark.parametrize("key,value", [
    ("key", KEY.replace("000000000001", "000000000009")),
    ("kms:ViaService", None), ("kms:ViaService", "s3.us-east-1.amazonaws.com"),
    ("kms:ViaService", "dynamodb.us-west-2.amazonaws.com"),
    ("kms:CallerAccount", None), ("kms:CallerAccount", "905418363887"),
    ("aws:ViaAWSService", None), ("aws:ViaAWSService", False),
])
def test_decrypt_scope_is_explicit_deny_even_with_external_grant(world, key, value):
    policy = copy.deepcopy(build(world)["compiled"]["policy"]["document"])
    context = decrypt_context()
    resource = KEY
    if key == "key": resource = value
    elif value is None: context.pop(key)
    else: context[key] = value
    # Model a separate resource/session Allow in the union of applicable
    # statements. Explicit Deny must still win; implicit boundary denial is
    # intentionally NOT treated as sufficient in this test.
    policy["Statement"].append({"Effect": "Allow", "Action": "kms:Decrypt", "Resource": "*"})
    assert iam_decision(policy, "kms:Decrypt", resource, context) == "DENY"
    def same_guard(row):
        if row.get("Effect") != "Deny" or row.get("Action") != "kms:Decrypt": return False
        if key == "key": return "NotResource" in row
        return any(key in values for values in row.get("Condition", {}).values())
    removed = [row for row in policy["Statement"] if same_guard(row)]
    assert len(removed) == 1
    policy["Statement"] = [row for row in policy["Statement"] if not same_guard(row)]
    assert iam_decision(policy, "kms:Decrypt", resource, context) == "ALLOW"

@pytest.mark.parametrize("action", ["kms:Encrypt", "kms:CreateGrant", "kms:GenerateDataKey",
                                   "kms:ReEncryptFrom", "kms:ReEncryptTo", "kms:ListGrants"])
def test_broker_never_receives_factory_crypto_or_grant_actions(world, action):
    policy = copy.deepcopy(build(world)["compiled"]["policy"]["document"])
    policy["Statement"].append({"Effect": "Allow", "Action": "kms:*", "Resource": "*"})
    assert iam_decision(policy, action, KEY, {**origin(), **decrypt_context()}) == "DENY"

def test_describe_key_stays_direct_lambda_only(world):
    policy = build(world)["compiled"]["policy"]["document"]
    assert iam_decision(policy, "kms:DescribeKey", KEY, origin()) == "ALLOW"
    assert iam_decision(policy, "kms:DescribeKey", KEY, decrypt_context()) == "DENY"


COMPACT_GROUPS = {
    "ReadExactRetainedStack": "cloudformation", "ReadExactLedgerKmsKey": "kms",
    "ReadExactLedgerControls": "dynamodb", "ReadExactRoles": "iam",
    "ReadBrokerNumericConfiguration": "lambda", "ReadExactDeployedApi": "apigateway",
    "WriteExactBrokerLogStreams": "logs",
}


def expanded_reviewed_policy(world):
    intent = world["intent"]
    change_set = intent["target"]["change_set_id"]
    replacements = {
        "stack_arn": intent["target"]["stack_id"], "change_set_name": change_set,
        "retirement_id": "gug215#sha256:" + sha256(change_set.encode()).hexdigest(),
        "ledger_arn": "arn:aws:dynamodb:us-east-1:042360977644:table/scanalyze-platform-authority-change-set-retirements",
        "broker_function_arn": origin()["lambda:SourceFunctionArn"],
        "reader_arn": intent["reader"]["role_arn"], "reader_start": intent["reader"]["not_before"],
        "reader_end": intent["reader"]["not_after"],
        "broker_role_arn": "arn:aws:iam::042360977644:role/ScanalyzeGug215BrokerExecution",
        "effect_start": intent["effect_window"]["not_before"], "effect_end": intent["effect_window"]["expires_at"],
        "ledger_kms_key_arn": intent["ledger_kms_key"]["arn"],
        "class_role_arn": intent["roles"]["classify"]["role_arn"],
        "approve_role_arn": intent["roles"]["retire"]["role_arn"],
        "boundary_arn": "arn:aws:iam::042360977644:policy/scanalyze/platform-authority/scanalyze-platform-authority-gug365-broker-boundary",
        "code_signing_config_arn": intent["artifact_signing_contract"]["code_signing_config"]["arn"],
        "api_arn": "arn:aws:apigateway:us-east-1::/apis/" + intent["api_id"],
        "log_stream_arn": "arn:aws:logs:us-east-1:042360977644:log-group:/aws/lambda/scanalyze-platform-authority-gug215-retirement:log-stream:*",
    }
    raw = world["blobs"][mat.WORKFORCE_POLICY_PATH.as_posix()].decode()
    for key, value in replacements.items(): raw = raw.replace("${" + key + "}", value)
    assert "${" not in raw
    policy = json.loads(raw)
    policy["Statement"][-1]["NotAction"].sort()
    return policy


@pytest.mark.parametrize("regional_roles", [False, True])
def test_entire_compact_document_preserves_exact_sets_conditions_and_quota(world, regional_roles):
    if regional_roles:
        for role in world["intent"]["roles"].values():
            role["role_arn"] = role["role_arn"].replace("sso.amazonaws.com/", "sso.amazonaws.com/us-east-1/")
    before = expanded_reviewed_policy(world)
    expected = {"Version": "2012-10-17", "Statement": []}
    merged = {"Effect": "Allow", "Action": [], "Resource": []}
    original_pairs = set()
    date_values = []
    values = lambda value: value if isinstance(value, list) else [value]
    for source in before["Statement"]:
        row = copy.deepcopy(source)
        sid = row.pop("Sid")
        if sid in COMPACT_GROUPS:
            namespace = COMPACT_GROUPS[sid]
            assert set(row) == {"Effect", "Action", "Resource"}
            assert row["Effect"] == "Allow"
            for action in values(row["Action"]):
                assert action.split(":", 1)[0] == namespace
                for resource in values(row["Resource"]):
                    assert resource.split(":")[2] == namespace
                    original_pairs.add((action, resource))
            for key in ("Action", "Resource"): merged[key].extend(values(row[key]))
        else:
            for operator, condition in row.get("Condition", {}).items():
                if operator in {"DateGreaterThanEquals", "DateLessThan"}:
                    instant = datetime.fromisoformat(condition["aws:CurrentTime"].replace("Z", "+00:00"))
                    assert instant.microsecond == 0
                    condition["aws:CurrentTime"] = str(int(instant.timestamp()))
                    date_values.append((operator, instant))
            expected["Statement"].append(row)
    expected["Statement"].append(merged)
    # Primary SAR only permits same-service resource ARNs for these exact
    # seven action groups. Cross-namespace syntactic pairs are not valid
    # service authorization requests; no group shares a namespace.
    effective_pairs = {(action, resource) for action in merged["Action"]
                       for resource in merged["Resource"]
                       if action.split(":", 1)[0] == resource.split(":")[2]}
    assert effective_pairs == original_pairs
    assert len(date_values) == 4
    assert len(COMPACT_GROUPS.values()) == len(set(COMPACT_GROUPS.values())) == 7
    plan = build(world)
    policy = plan["compiled"]["policy"]
    assert policy["document"] == expected
    assert json.loads(policy["create_request"]["PolicyDocument"]) == expected
    assert policy["document_digest"] == mat.canonical_digest(expected)
    assert policy["managed_policy_characters"] == (6111 if regional_roles else 6091)
    assert policy["managed_policy_characters"] <= 6144
    assert len(mat.canonical_json(before)) > 6144
    role = plan["compiled"]["role"]
    assert role["boundary_document_digest"] == role["attached_document_digest"] == policy["document_digest"]
    assert not any("Sid" in row for row in expected["Statement"])


@pytest.mark.parametrize("operation,attribute,moment,expected", [
    ("cloudformation:DeleteChangeSet", "effect_window", None, "IMPLICIT_DENY"),
    ("cloudformation:DeleteChangeSet", "effect_window", "2026-09-15T11:59:59.999999Z", "IMPLICIT_DENY"),
    ("cloudformation:DeleteChangeSet", "effect_window", "2026-09-15T12:00:00Z", "ALLOW"),
    ("cloudformation:DeleteChangeSet", "effect_window", "2026-09-15T12:14:59.999999Z", "ALLOW"),
    ("cloudformation:DeleteChangeSet", "effect_window", "2026-09-15T12:15:00Z", "IMPLICIT_DENY"),
    ("sts:AssumeRole", "reader", None, "IMPLICIT_DENY"),
    ("sts:AssumeRole", "reader", "2026-09-14T23:59:59.999999Z", "IMPLICIT_DENY"),
    ("sts:AssumeRole", "reader", "2026-09-15T00:00:00Z", "ALLOW"),
    ("sts:AssumeRole", "reader", "2026-09-15T23:59:59.999999Z", "ALLOW"),
    ("sts:AssumeRole", "reader", "2026-09-16T00:00:00Z", "IMPLICIT_DENY"),
])
def test_epoch_presentation_keeps_precise_exclusive_windows_and_missing_clock(world, operation, attribute, moment, expected):
    source = expanded_reviewed_policy(world)
    emitted = build(world)["compiled"]["policy"]["document"]
    context = {**origin(), "sts:RoleSessionName": "gug215-workforce-reader",
               "cloudformation:ChangeSetName": world["intent"]["target"]["change_set_id"]}
    if moment is not None: context["aws:CurrentTime"] = moment
    resource = (world["intent"]["reader"]["role_arn"] if attribute == "reader"
                else world["intent"]["target"]["stack_id"])
    assert iam_decision(source, operation, resource, context) == expected
    assert iam_decision(emitted, operation, resource, context) == expected


@pytest.mark.parametrize("target,key", [("reader", "not_before"), ("reader", "not_after"),
                                      ("effect_window", "not_before"), ("effect_window", "expires_at")])
def test_input_fractional_windows_are_rejected_not_truncated(world, target, key):
    world["intent"][target][key] = world["intent"][target][key].replace("Z", ".5Z")
    with pytest.raises(mat.RetirementEntrypointMaterializationError): build(world)


@pytest.mark.parametrize("mutation", ["key_deny", "via_deny", "caller_deny", "fas_deny",
    "decrypt_scope", "group_condition", "group_foreign_namespace", "resource_star", "same_namespace"])
def test_resealed_template_cannot_drop_denials_or_enlarge_compaction(world, mutation):
    document = json.loads(world["blobs"][mat.WORKFORCE_POLICY_PATH.as_posix()])
    by_sid = {row["Sid"]: row for row in document["Statement"]}
    denies = {"key_deny": "DenyDecryptOtherKey", "via_deny": "DenyDecryptMissingOrForeignService",
              "caller_deny": "DenyDecryptMissingOrForeignAccount", "fas_deny": "DenyDecryptWithoutForwardAccess"}
    if mutation in denies:
        document["Statement"].remove(by_sid[denies[mutation]])
    elif mutation == "decrypt_scope": by_sid["DecryptExactLedgerKeyThroughDynamoDb"]["Resource"] = "*"
    elif mutation == "group_condition": by_sid["ReadExactLedgerKmsKey"]["Condition"] = {"Bool": {"aws:ViaAWSService": "true"}}
    elif mutation == "group_foreign_namespace": by_sid["ReadExactLedgerKmsKey"]["Resource"] = CSC
    elif mutation == "resource_star": by_sid["ReadExactRoles"]["Resource"] = "*"
    else: by_sid["ReadExactRoles"]["Resource"].append("${boundary_arn}")
    raw = json.dumps(document).encode()
    intent = copy.deepcopy(world["intent"])
    intent["source"]["policy_template_sha256"] = "sha256:" + sha256(raw).hexdigest()
    with pytest.raises(compiler.ServiceRoleMaterializationError, match="WORKFORCE_POLICY_(SCOPE_CHANGED|INVALID)"):
        compiler.compile_workforce_broker_contract(intent=intent, package_manifest=world["manifest"],
                                                   policy_template=raw, evaluated_at=NOW)


def test_expanded_policy_over_quota_still_fails_closed(world):
    intent = copy.deepcopy(world["intent"])
    # Synthetic overlong but syntactically accepted ARN, never provider evidence.
    intent["artifact_signing_contract"]["code_signing_config"]["arn"] = CSC + "1" * 100
    with pytest.raises(compiler.ServiceRoleMaterializationError, match="WORKFORCE_MANAGED_POLICY_TOO_LARGE"):
        compiler.compile_workforce_broker_contract(intent=intent, package_manifest=world["manifest"],
            policy_template=world["blobs"][mat.WORKFORCE_POLICY_PATH.as_posix()], evaluated_at=NOW)

@pytest.mark.parametrize("source", [None, "arn:aws:lambda:us-east-1:042360977644:function:foreign", "arn:aws:lambda:us-east-1:905418363887:function:scanalyze-platform-authority-gug215-retirement"])
def test_global_origin_deny_is_causal_even_with_added_allow(world, source):
    policy = build(world)["compiled"]["policy"]["document"]
    context = {} if source is None else {"lambda:SourceFunctionArn": source}
    action, resource = "lambda:GetCodeSigningConfig", CSC
    expanded = copy.deepcopy(policy)
    expanded["Statement"].append({"Effect": "Allow", "Action": "*", "Resource": "*"})
    assert iam_decision(expanded, action, resource, context) == "DENY"
    expanded["Statement"] = [r for r in expanded["Statement"] if
        r.get("Condition", {}).get("ArnNotEqualsIfExists") != origin()]
    assert iam_decision(expanded, action, resource, context) == "ALLOW"

@pytest.mark.parametrize("action,resource", [
    ("lambda:GetCodeSigningConfig", CSC.replace("042360977644", "905418363887")),
    ("apigateway:GET", "arn:aws:apigateway:us-east-1::/apis/foreignapi"),
    ("apigateway:GET", "arn:aws:apigateway:us-east-1::/apis/testapi123/stages/retirement"),
    ("sts:AssumeRole", "arn:aws:iam::839393571433:role/Admin"),
    ("kms:DescribeKey", KEY.replace("000000000001", "000000000009")),
    ("cloudformation:DeleteStack", "arn:aws:cloudformation:us-east-1:042360977644:stack/scanalyze-platform-authority-state-backend/*"),
])
def test_unrelated_identity_allow_cannot_escape_same_boundary(world, action, resource):
    boundary = build(world)["compiled"]["policy"]["document"]
    identity = copy.deepcopy(boundary)
    identity["Statement"].append({"Effect": "Allow", "Action": "*", "Resource": "*"})
    # IAM needs identity AND boundary permission; adding identity permission
    # does not widen the single exact managed policy used as the boundary.
    assert not (iam_decision(identity, action, resource, origin()) == "ALLOW"
                and iam_decision(boundary, action, resource, origin()) == "ALLOW")

def test_actual_stage_sdk_calls_map_to_only_needed_accountless_resources(world):
    policy = build(world)["compiled"]["policy"]["document"]
    tree = ast.parse((ROOT / "tooling/platform_authority_change_set_retirement_broker.py").read_text())
    cls = next(x for x in tree.body if isinstance(x, ast.ClassDef) and x.name == "WorkforceRetirementBroker")
    method = next(x for x in cls.body if isinstance(x, ast.FunctionDef) and x.name == "_verify_deployed_stage")
    calls = {ast.literal_eval(x.args[0]) for x in ast.walk(method) if isinstance(x, ast.Call)
             and isinstance(x.func, ast.Name) and x.func.id == "read"}
    assert calls == {"get_api", "get_routes", "get_integrations", "get_stages", "export_api"}
    base = "arn:aws:apigateway:us-east-1::/apis/" + world["intent"]["api_id"]
    for suffix in ("", "/routes", "/integrations", "/stages", "/exports/OAS30"):
        assert iam_decision(policy, "apigateway:GET", base + suffix, origin()) == "ALLOW"
    assert iam_decision(policy, "lambda:GetCodeSigningConfig", CSC, origin()) == "ALLOW"
    ctx = {**origin(), "sts:RoleSessionName": "gug215-workforce-reader", "aws:CurrentTime": "2026-09-15T12:30:00Z"}
    assert iam_decision(policy, "sts:AssumeRole", world["intent"]["reader"]["role_arn"], ctx) == "ALLOW"

@pytest.mark.parametrize("moment,expected", [("2026-09-15T11:59:59Z", "IMPLICIT_DENY"), ("2026-09-15T12:00:00Z", "ALLOW"),
    ("2026-09-15T12:15:00Z", "IMPLICIT_DENY"), ("2026-09-15T23:59:59Z", "IMPLICIT_DENY")])
def test_delete_grant_matches_full_request_arn_and_exact_effect_interval(world, moment, expected):
    policy = build(world)["compiled"]["policy"]["document"]
    ctx = {**origin(), "aws:CurrentTime": moment, "cloudformation:ChangeSetName": world["intent"]["target"]["change_set_id"]}
    assert iam_decision(policy, "cloudformation:DeleteChangeSet", world["intent"]["target"]["stack_id"], ctx) == expected
    # This checks the runtime argument contract, not AWS normalization of it.
    ctx["cloudformation:ChangeSetName"] += "foreign"
    assert iam_decision(policy, "cloudformation:DeleteChangeSet", world["intent"]["target"]["stack_id"], ctx) != "ALLOW"

@pytest.mark.parametrize("mutation", ["extra_allow", "missing_source", "foreign_reader", "wide_key", "remove_deny"])
def test_even_rehashed_policy_scope_changes_fail_compiler(world, mutation):
    document = json.loads(world["blobs"][mat.WORKFORCE_POLICY_PATH.as_posix()])
    if mutation == "extra_allow":
        document["Statement"].append({"Sid": "Injected", "Effect": "Allow", "Action": "*", "Resource": "*"})
    elif mutation == "missing_source":
        document["Statement"][0]["Condition"] = {}
    elif mutation == "foreign_reader":
        next(r for r in document["Statement"] if r["Sid"] == "AssumeExactManagementReader")["Resource"] = "arn:aws:iam::839393571433:role/Admin"
    elif mutation == "wide_key":
        next(r for r in document["Statement"] if r["Sid"] == "ReadExactLedgerKmsKey")["Resource"] = "*"
    else:
        document["Statement"].pop()
    raw = json.dumps(document).encode()
    intent = copy.deepcopy(world["intent"])
    intent["source"]["policy_template_sha256"] = "sha256:" + sha256(raw).hexdigest()
    with pytest.raises(compiler.ServiceRoleMaterializationError):
        compiler.compile_workforce_broker_contract(intent=intent, package_manifest=world["manifest"], policy_template=raw, evaluated_at=NOW)

def test_cli_bad_pin_leaves_no_output(world, tmp_path, monkeypatch, capsys):
    cli = load_cli()
    monkeypatch.setattr(cli, "_now", lambda: NOW)
    argv = arguments(world, tmp_path)
    argv[argv.index("--expected-intent-digest") + 1] = DIGEST
    assert cli.main(argv) == 2 and not (tmp_path / "plan.json").exists()
    assert json.loads(capsys.readouterr().err)["reason"] == "WORKFORCE_EXTERNAL_PIN_MISMATCH"


def test_valid_looking_role_identifier_remains_unverified_metadata(world):
    world["intent"]["roles"]["classify"]["role_id"] = "AROA" + "Z" * 17
    plan = build(world)
    assert plan["deployment_authorized"] is False
    assert plan["compiled"]["role"]["provider_role_id"] is None
    assert plan["compiled"]["function"]["runtime_configuration"] is None
    assert "REFRESH_ASSIGNMENTS_AND_SELECT_EFFECT_WINDOW" in plan["pending"]

def test_workforce_plan_does_not_enter_legacy_installer_even_if_resealed(world):
    plan = build(world)
    plan["compiled"]["role"]["attached_policy_arns"] = ["arn:aws:iam::042360977644:policy/foreign"]
    plan["plan_digest"] = mat.canonical_digest({k: v for k, v in plan.items() if k != "plan_digest"})
    with pytest.raises(mat.RetirementEntrypointMaterializationError):
        mat.validate_materialization_plan(plan, repo_root=ROOT)

@pytest.mark.parametrize("value", ["20260915T120000Z", "2026-09-15T12:00:00.000Z", "2026-09-15T12:00:00+00:00"])
def test_effect_dates_are_canonical_not_only_parseable(world, value):
    world["intent"]["effect_window"]["not_before"] = value
    with pytest.raises(mat.RetirementEntrypointMaterializationError):
        build(world)
