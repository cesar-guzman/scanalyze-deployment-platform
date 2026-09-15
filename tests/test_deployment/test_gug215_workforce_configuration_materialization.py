"""Pure finalizer/CLI checks with public synthetic metadata, never AWS evidence.

The existing allowed workforce fixture replaces only Git subprocess I/O. No
credentials, SDK, network, real Git process or downloaded artifact is involved.
"""
from __future__ import annotations

import copy
import importlib.util
import json
from pathlib import Path

import pytest

_spec = importlib.util.spec_from_file_location("gug215_allowed_workforce_fixture", Path(__file__).with_name("test_gug215_workforce_materialization.py"))
_base = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_base)
world, arguments, build, load_cli = _base.world, _base.arguments, _base.build, _base.load_cli
ROOT, NOW, KEY, DIGEST = _base.ROOT, _base.NOW, _base.KEY, _base.DIGEST
from tooling import platform_authority_retirement_entrypoint_materializer as mat
from tooling import platform_authority_retirement_entrypoint_service_role_materializer as compiler
from tooling.platform_authority_change_set_retirement_broker import WorkforceRetirementConfig, WORKFORCE_WRITE_ACTIONS
from tooling.platform_authority_identity_context_pep_runtime import workforce_config_from_environment

BROKER_ID = "AROA" + "B" * 17
TRUST = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"Service": "sso.amazonaws.com"}, "Action": "sts:AssumeRole"}]}
SSO_POLICY = {"Version": "2012-10-17", "Statement": [{"Effect": "Deny", "Action": "*", "Resource": "*"}]}


def role_record(arn, role_id, trust, *, boundary=None, attached=None, inline=None):
    role = {"Arn": arn, "RoleId": role_id, "RoleName": arn.rsplit("/", 1)[1], "Path": "/", "MaxSessionDuration": 3600,
            "AssumeRolePolicyDocument": trust}
    if boundary:
        role["PermissionsBoundary"] = {"PermissionsBoundaryType": "Policy", "PermissionsBoundaryArn": boundary}
    return {"get_role": {"Role": role}, "list_role_policies": {"IsTruncated": False, "PolicyNames": [] if inline is None else ["SyntheticInline"]},
            "list_attached_role_policies": {"IsTruncated": False, "AttachedPolicies": attached or []},
            "get_role_policy": None if inline is None else {"RoleName": role["RoleName"], "PolicyName": "SyntheticInline", "PolicyDocument": inline}}


def policy_record(contract, *, attached):
    entities = {"IsTruncated": False, "PolicyGroups": [], "PolicyUsers": [],
                "PolicyRoles": [{"RoleName": compiler.BROKER_ROLE_NAME, "RoleId": BROKER_ID}] if attached else []}
    return {"get_policy": {"Policy": {"Arn": contract["arn"], "DefaultVersionId": "v1", "IsAttachable": True,
                "AttachmentCount": int(attached), "PermissionsBoundaryUsageCount": int(attached)}},
            "list_policy_versions": {"IsTruncated": False, "Versions": [{"VersionId": "v1", "IsDefaultVersion": True, "CreateDate": "2026-09-15T10:00:00Z"}]},
            "get_policy_version": {"PolicyVersion": {"VersionId": "v1", "IsDefaultVersion": True, "Document": contract["document"]}},
            "identity_entities": copy.deepcopy(entities), "boundary_entities": copy.deepcopy(entities)}


@pytest.fixture
def configured(world):
    for role in world["intent"]["roles"].values():
        role["trust_sha256"] = mat.canonical_digest(TRUST)
        role["policy_sha256"] = mat.canonical_digest(SSO_POLICY)
    key = {"KeyMetadata": {"Arn": KEY, "AWSAccountId": mat.AUTHORITY_ACCOUNT_ID, "Enabled": True,
            "KeyManager": "AWS", "KeyState": "Enabled", "KeyUsage": "ENCRYPT_DECRYPT", "Origin": "AWS_KMS",
            "MultiRegion": False, "KeySpec": "SYMMETRIC_DEFAULT", "EncryptionAlgorithms": ["SYMMETRIC_DEFAULT"]}}
    world["intent"]["ledger_kms_key"]["readback_digest"] = mat.canonical_digest(key)
    plan = build(world)
    inert = compiler._workforce_inert_preparation(world["intent"], world["manifest"])
    compiled, request = plan["compiled"], plan["compiled"]["function"]["create_request"]
    function = {key: copy.deepcopy(request[key]) for key in ("Role", "Runtime", "Handler", "MemorySize", "Timeout", "Architectures", "Environment", "LoggingConfig")}
    function.update({"FunctionName": compiler.BROKER_FUNCTION_NAME, "FunctionArn": compiler._function_arn(), "Version": "$LATEST",
        "CodeSha256": compiled["function"]["expected_signed_code_sha256"], "CodeSize": len(world["signed"]),
        "PackageType": "Zip", "State": "Active", "LastUpdateStatus": "Successful", "RevisionId": "synthetic-current-revision",
        "RuntimeVersionConfig": {"RuntimeVersionArn": world["manifest"]["broker_runtime_version_arn"]}, "EphemeralStorage": {"Size": 512},
        "TracingConfig": {"Mode": "PassThrough"}, "VpcConfig": {"SubnetIds": [], "SecurityGroupIds": [], "VpcId": ""}})
    table = compiler._table_contract({})
    table["resource_policy"]["Statement"][0]["Action"] = sorted(WORKFORCE_WRITE_ACTIONS)
    tags = {tag["Key"]: tag["Value"] for tag in table["tags"]}
    tags.update(environment="production", production="true")
    evidence = {"record_type": compiler.WORKFORCE_CONFIGURATION_READBACK_TYPE, "schema_version": 1,
        "observed_at": "2026-09-15T11:59:00Z", "authority_account_id": mat.AUTHORITY_ACCOUNT_ID, "region": mat.REGION,
        "broker_role": role_record(compiled["role"]["arn"], BROKER_ID, compiled["role"]["trust_document"],
            boundary=inert["policy"]["arn"], attached=[{"PolicyName": compiler.PROOF_BOUNDARY_NAME, "PolicyArn": inert["policy"]["arn"]}]),
        "permission_set_roles": {op: role_record(role["role_arn"], role["role_id"], TRUST, inline=SSO_POLICY) for op, role in world["intent"]["roles"].items()},
        "policies": {"inert": policy_record(inert["policy"], attached=True), "active": policy_record(compiled["policy"], attached=False)},
        "ledger": {"describe_table": {"Table": {"TableName": table["table_name"], "TableArn": table["arn"], "TableStatus": "ACTIVE",
            "AttributeDefinitions": table["attribute_definitions"], "KeySchema": table["key_schema"], "DeletionProtectionEnabled": True,
            "SSEDescription": {"Status": "ENABLED", "SSEType": "KMS", "KMSMasterKeyArn": KEY}, "BillingModeSummary": {"BillingMode": "PAY_PER_REQUEST"},
            "TableClassSummary": {"TableClass": "STANDARD"}}}, "describe_key": key,
            "describe_time_to_live": {"TimeToLiveDescription": {"TimeToLiveStatus": "DISABLED"}},
            "describe_continuous_backups": {"ContinuousBackupsDescription": {"ContinuousBackupsStatus": "ENABLED",
                "PointInTimeRecoveryDescription": {"PointInTimeRecoveryStatus": "ENABLED", "RecoveryPeriodInDays": 35}}},
            "list_tags_of_resource": {"Tags": [{"Key": key, "Value": value} for key, value in tags.items()]},
            "get_resource_policy": {"Policy": json.dumps(table["resource_policy"])},
            "get_item_request": {"TableName": table["table_name"], "Key": {"retirement_id": {"S": compiled["ledger"]["retirement_id"]}},
                                 "ConsistentRead": True, "ProjectionExpression": "document"}, "get_item": {}},
        "function": {"get_function_configuration": function, "get_runtime_management_config": {"FunctionArn": compiler._function_arn(),
            "UpdateRuntimeOn": "Manual", "RuntimeVersionArn": world["manifest"]["broker_runtime_version_arn"]},
            "get_function_concurrency": {"ReservedConcurrentExecutions": 1}, "get_function_code_signing_config": {"CodeSigningConfigArn": request["CodeSigningConfigArn"]},
            "list_versions_by_function": {"Versions": [copy.deepcopy(function)]}, "list_aliases": {"Aliases": []},
            "list_function_url_configs": {"FunctionUrlConfigs": []}, "get_policy_error": {"code": "ResourceNotFoundException", "function_arn": compiler._function_arn()}},
        "api": {"get_api": {"ApiId": plan["api_id"], "ProtocolType": "HTTP", "RouteSelectionExpression": "$request.method $request.path", "DisableExecuteApiEndpoint": False},
            **{method: {"Items": []} for method in ("get_routes", "get_integrations", "get_stages", "get_deployments")}}}
    world["configuration_evidence"] = evidence
    return world


def finalize(world, **overrides):
    args = {"intent": world["intent"], "expected_intent_digest": mat.canonical_digest(world["intent"]),
        "package_manifest": world["manifest"], "package_archive": world["archive"], "signed_archive": world["signed"],
        "signing_readback": world["evidence"], "expected_signing_readback_digest": mat.canonical_digest(world["evidence"]),
        "configuration_readback": world["configuration_evidence"], "expected_configuration_readback_digest": mat.canonical_digest(world["configuration_evidence"]),
        "repo_root": ROOT, "evaluated_at": NOW}
    args.update(overrides)
    return compiler.finalize_workforce_configuration_plan(**args)


def test_actual_schema2_roundtrips_without_fabricating_numeric_version_or_authority(configured):
    plan = finalize(configured)
    runtime = workforce_config_from_environment(plan["environment"])
    assert runtime.schema_version == "2" and "function_version" not in plan["configuration"]
    assert runtime.broker_role_id == BROKER_ID and runtime.expected_code_sha256 != configured["manifest"]["lambda_code_sha256"]
    assert plan["numeric_version_arn"] is plan["publish_request"] is plan["post_publication_binding"] is None
    assert plan["configure_request"]["RevisionId"] == "synthetic-current-revision"
    assert plan["environment_size_bytes"] == sum(len(k.encode()) + len(v.encode()) for k, v in plan["environment"].items()) <= 4096
    assert plan["deployment_authorized"] is plan["aws_mutation_attempted"] is False
    assert plan["source_ci_status"] == "PENDING_CONNECTED_REVALIDATION"
    assert "NOT_CRYPTOGRAPHIC_VERIFICATION" in plan["signature_status"]
    assert "NOT_AUTHENTICATED" in plan["readback_semantics"]
    assert plan["permission_set_policy_status"] == "CAPTURED_ONLY_REBUILD_CONFIG_AND_PINS_AFTER_REVIEWED_OPERATION_GRANTS"


def test_transition_keeps_deny_boundary_until_attached_deny_removed_and_readback(configured):
    plan = finalize(configured)
    steps = plan["activation_transition"]["operations"]
    assert [s["action"] for s in steps] == ["iam:AttachRolePolicy", "iam:DetachRolePolicy", "READBACK_ONLY", "iam:PutRolePermissionsBoundary", "READBACK_ONLY"]
    inert = compiler._policy_arn(compiler.PROOF_BOUNDARY_NAME)
    active = compiler._policy_arn(compiler.BROKER_BOUNDARY_NAME)
    attached, boundary = {inert}, inert
    for i, step in enumerate(steps):
        if step["action"] == "iam:AttachRolePolicy":
            attached.add(step["request"]["PolicyArn"])
        elif step["action"] == "iam:DetachRolePolicy":
            attached.remove(step["request"]["PolicyArn"])
        elif step["action"] == "iam:PutRolePermissionsBoundary":
            assert attached == {active} and steps[i - 1]["action"] == "READBACK_ONLY"
            boundary = step["request"]["PermissionsBoundary"]
        if i < 3:
            assert boundary == inert  # No intermediate permission increase.
    assert boundary == active and attached == {active}
    assert plan["activation_transition"]["rollback_first_request"]["PermissionsBoundary"] == inert


@pytest.mark.parametrize("override", ["expected_intent_digest", "expected_signing_readback_digest", "expected_configuration_readback_digest"])
def test_external_pins_are_not_computed_as_authorization(configured, override):
    with pytest.raises((compiler.ServiceRoleMaterializationError, mat.RetirementEntrypointMaterializationError)):
        finalize(configured, **{override: DIGEST})


@pytest.mark.parametrize("state", ["dirty", "head", "tree"])
def test_finalizer_rebuilds_real_source_gate_instead_of_accepting_a_sealed_plan(configured, state):
    configured[state] = " M tracked.py" if state == "dirty" else "f" * 40
    with pytest.raises(mat.RetirementEntrypointMaterializationError):
        finalize(configured)


@pytest.mark.parametrize("path,value", [
    (("broker_role", "get_role", "Role", "RoleId"), "invented"),
    (("broker_role", "get_role", "Role", "PermissionsBoundary", "PermissionsBoundaryArn"), "foreign"),
    (("broker_role", "list_role_policies", "PolicyNames"), ["injected"]),
    (("permission_set_roles", "classify", "get_role", "Role", "RoleId"), "AROA" + "Z" * 17),
    (("policies", "active", "get_policy", "Policy", "DefaultVersionId"), "v2"),
    (("policies", "active", "get_policy", "Policy", "AttachmentCount"), True),
    (("policies", "inert", "identity_entities", "PolicyRoles", 0, "RoleId"), "AROA" + "Z" * 17),
    (("function", "get_function_configuration", "CodeSha256"), "A" * 43 + "="),
    (("function", "get_function_configuration", "Environment"), {"Variables": {"unexpected": "public"}}),
    (("function", "get_function_configuration", "Layers"), [{"Arn": "foreign"}]),
    (("function", "get_function_configuration", "RevisionId"), ""),
    (("function", "get_function_concurrency", "ReservedConcurrentExecutions"), True),
    (("function", "get_function_code_signing_config", "CodeSigningConfigArn"), "foreign"),
    (("function", "list_versions_by_function", "Versions", 0, "Version"), "1"),
    (("function", "list_versions_by_function", "Versions", 0, "RevisionId"), "changed-between-reads"),
    (("function", "list_aliases", "Aliases"), [{"Name": "live"}]),
    (("api", "get_api", "ApiId"), "foreign123"),
    (("api", "get_routes", "Items"), [{"RouteKey": "ANY /{proxy+}"}]),
    (("api", "get_deployments", "NextToken"), ""),
    (("schema_version",), True), (("authority_account_id",), "905418363887"),
    (("observed_at",), "2026-09-15T12:00:01Z"), (("observed_at",), "2026-09-15T11:54:59Z"),
    (("authority",), "synthetic-claim-not-accepted"),
])
def test_resealed_role_function_policy_api_and_capture_drift_rejects(configured, path, value):
    target = configured["configuration_evidence"]
    for part in path[:-1]:
        target = target[part]
    target[path[-1]] = value
    with pytest.raises((compiler.ServiceRoleMaterializationError, mat.RetirementEntrypointMaterializationError)):
        finalize(configured)


@pytest.mark.parametrize("mutation", ["absent", "tags", "ttl", "pitr", "resource_policy", "key_arn", "billing", "occupied"])
def test_same_ledger_contract_is_certified_without_adoption_reset_or_retag(configured, mutation):
    row = configured["configuration_evidence"]["ledger"]
    if mutation == "absent": row["describe_table"] = {"error": "ResourceNotFoundException"}
    elif mutation == "tags": next(t for t in row["list_tags_of_resource"]["Tags"] if t["Key"] == "production")["Value"] = "false"
    elif mutation == "ttl": row["describe_time_to_live"]["TimeToLiveDescription"]["TimeToLiveStatus"] = "ENABLED"
    elif mutation == "pitr": row["describe_continuous_backups"]["ContinuousBackupsDescription"]["PointInTimeRecoveryDescription"]["RecoveryPeriodInDays"] = 7
    elif mutation == "resource_policy": row["get_resource_policy"]["Policy"] = '{}'
    elif mutation == "key_arn": row["describe_table"]["Table"]["SSEDescription"]["KMSMasterKeyArn"] = "foreign"
    elif mutation == "billing": row["describe_table"]["Table"]["BillingModeSummary"]["BillingMode"] = "PROVISIONED"
    else: row["get_item"] = {"Item": {"document": {"S": '{"state":"ATTEMPTED"}'}}}
    code = "WORKFORCE_LEDGER_SLOT_OCCUPIED" if mutation == "occupied" else "WORKFORCE_LEDGER_NOT_CERTIFIED"
    with pytest.raises(compiler.ServiceRoleMaterializationError, match=code):
        finalize(configured)


def test_key_readback_is_bound_independently_of_envelope_pin(configured):
    configured["configuration_evidence"]["ledger"]["describe_key"]["KeyMetadata"]["KeyManager"] = "CUSTOMER"
    with pytest.raises(compiler.ServiceRoleMaterializationError, match="WORKFORCE_LEDGER_KEY_READBACK_PIN_MISMATCH"):
        finalize(configured)


def test_provider_policy_metadata_and_url_encoded_documents_are_accepted(configured):
    from urllib.parse import quote
    for policy in configured["configuration_evidence"]["policies"].values():
        version = policy["get_policy_version"]["PolicyVersion"]
        version["Document"] = quote(json.dumps(version["Document"]))
    assert finalize(configured)["deployment_authorized"] is False


def test_duplicate_iam_document_is_rejected_even_under_resealed_envelope(configured):
    configured["configuration_evidence"]["policies"]["active"]["get_policy_version"]["PolicyVersion"]["Document"] = '{"Version":"2012-10-17","Version":"2012-10-17","Statement":[]}'
    with pytest.raises(compiler.ServiceRoleMaterializationError): finalize(configured)


def finalizer_args(configured, tmp_path):
    argv = arguments(configured, tmp_path)
    argv[0] = "workforce-finalize-plan"
    path = tmp_path / "configuration-readback.json"
    path.write_text(json.dumps(configured["configuration_evidence"]))
    path.chmod(0o600)
    return argv + ["--configuration-readback", str(path), "--expected-configuration-readback-digest", mat.canonical_digest(configured["configuration_evidence"])]


def test_cli_finalizer_runs_real_builder_runtime_config_and_private_readback(configured, tmp_path, monkeypatch, capsys):
    cli = load_cli()
    monkeypatch.setattr(cli, "_now", lambda: NOW)
    argv = finalizer_args(configured, tmp_path)
    assert cli.main(argv) == 0
    status = json.loads(capsys.readouterr().out)
    plan = json.loads((tmp_path / "plan.json").read_text())
    assert status["plan_digest"] == plan["plan_digest"] and status["configuration_digest"] == plan["configuration_digest"]
    assert workforce_config_from_environment(plan["environment"]).broker_role_id == BROKER_ID
    assert cli.main(argv) == 2
    assert json.loads(capsys.readouterr().err)["reason"] == "WORKFORCE_CONFIGURATION_PLAN_ALREADY_EXISTS"


def test_cli_rejects_pin_before_creating_output(configured, tmp_path, monkeypatch, capsys):
    cli = load_cli()
    monkeypatch.setattr(cli, "_now", lambda: NOW)
    argv = finalizer_args(configured, tmp_path)
    argv[-1] = DIGEST
    assert cli.main(argv) == 2 and not (tmp_path / "plan.json").exists()
    assert json.loads(capsys.readouterr().err)["reason"] == "WORKFORCE_CONFIGURATION_PIN_MISMATCH"


@pytest.mark.parametrize("flag", ["--apply", "--install", "--allow-create-stack", "--profile", "--plan", "--function-version"])
def test_no_writer_or_self_hashed_plan_input(configured, tmp_path, flag):
    with pytest.raises(SystemExit): load_cli()._parser().parse_args(finalizer_args(configured, tmp_path) + [flag, "synthetic"])


def test_final_plan_still_rejects_legacy_installer(configured):
    with pytest.raises(mat.RetirementEntrypointMaterializationError):
        mat.validate_materialization_plan(finalize(configured), repo_root=ROOT)


@pytest.mark.parametrize("value", [False, True, 0, None, "false"])
def test_optional_provider_ipv6_field_allows_only_boolean_false(configured, value):
    configured["configuration_evidence"]["function"]["get_function_configuration"]["VpcConfig"]["Ipv6AllowedForDualStack"] = value
    if value is False:
        assert finalize(configured)["deployment_authorized"] is False
    else:
        with pytest.raises(compiler.ServiceRoleMaterializationError, match="WORKFORCE_CONFIGURATION_FUNCTION_CHANGED"):
            finalize(configured)


@pytest.mark.parametrize("key,value", [("SubnetIds", ["subnet-synthetic"]), ("SecurityGroupIds", ["sg-synthetic"]), ("VpcId", "vpc-synthetic"), ("extra", False)])
def test_provider_vpc_readback_cannot_expand_network(configured, key, value):
    configured["configuration_evidence"]["function"]["get_function_configuration"]["VpcConfig"][key] = value
    with pytest.raises(compiler.ServiceRoleMaterializationError, match="WORKFORCE_CONFIGURATION_FUNCTION_CHANGED"):
        finalize(configured)


def test_missing_iam_pagination_metadata_is_not_complete_evidence(configured):
    del configured["configuration_evidence"]["policies"]["active"]["list_policy_versions"]["IsTruncated"]
    with pytest.raises(compiler.ServiceRoleMaterializationError, match="WORKFORCE_CONFIGURATION_PARTIAL_READBACK"):
        finalize(configured)


def test_finalizer_guards_environment_quota_after_real_config_validation(configured, monkeypatch):
    original = WorkforceRetirementConfig.runtime_environment
    def oversized_serialization(self):
        values = original(self)
        values["GUG215_WORKFORCE_CONFIG_B64Z"] += "A" * 4096
        return values
    # Simulates serializer-size regression only; all source, readback, policy,
    # schema and time checks still execute. No authority predicate is mocked.
    monkeypatch.setattr(WorkforceRetirementConfig, "runtime_environment", oversized_serialization)
    with pytest.raises(compiler.ServiceRoleMaterializationError, match="WORKFORCE_CONFIGURATION_ENV_TOO_LARGE"):
        finalize(configured)


@pytest.mark.parametrize("missing", ["effect_window", "ledger_kms_key"])
def test_inert_preparation_cannot_be_promoted_without_effect_window_and_key(configured, missing):
    configured["intent"][missing] = None
    with pytest.raises(compiler.ServiceRoleMaterializationError, match="WORKFORCE_CONFIGURATION_EFFECT_AND_KEY_REQUIRED"):
        finalize(configured)


@pytest.mark.parametrize("end", ["2026-09-15T12:00:00Z", "2026-09-15T12:15:01Z"])
def test_finalizer_preserves_expiry_and_maximum_effect_duration(configured, end):
    configured["intent"]["effect_window"]["expires_at"] = end
    with pytest.raises(mat.RetirementEntrypointMaterializationError, match="WORKFORCE_EFFECT_WINDOW_INVALID"):
        finalize(configured)


@pytest.mark.parametrize("mutation", ["missing", "key", "table", "nonconsistent", "bool_as_int", "projection"])
def test_empty_item_response_must_bind_the_exact_strong_read(configured, mutation):
    row = configured["configuration_evidence"]["ledger"]
    request = row["get_item_request"]
    if mutation == "missing": del row["get_item_request"]
    elif mutation == "key": request["Key"]["retirement_id"]["S"] = "gug215#foreign"
    elif mutation == "table": request["TableName"] = "synthetic-other-table"
    elif mutation == "nonconsistent": request["ConsistentRead"] = False
    elif mutation == "bool_as_int": request["ConsistentRead"] = 1
    else: request["ProjectionExpression"] = "other_attribute"
    assert row["get_item"] == {}
    with pytest.raises(compiler.ServiceRoleMaterializationError, match="WORKFORCE_LEDGER_NOT_CERTIFIED"):
        finalize(configured)
