"""Public-metadata-only GUG215 entrypoint → collector → durable CAS tests.

No profile, credential object, identity token, network or legacy proof fixture.
The in-memory provider implements conditional writes, not broker decisions.
"""
from __future__ import annotations

import base64
import copy
import hashlib
import io
import json
import threading
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest
from jsonschema import Draft202012Validator

from tooling import platform_authority_change_set_retirement_broker as core
from tooling import platform_authority_identity_context_pep_runtime as entry


START = datetime(2026, 9, 14, 10, tzinfo=UTC)
PUBLIC_USER_FIXTURE = "synthetic-user-fixture-not-a-person"
STACK = "arn:aws:cloudformation:us-east-1:042360977644:stack/scanalyze-platform-authority-state-backend/11111111-1111-4111-8111-111111111111"
CHANGESET = "arn:aws:cloudformation:us-east-1:042360977644:changeSet/scanalyze-platform-authority-bootstrap-20260914090000/22222222-2222-4222-8222-222222222222"
KMS = "arn:aws:kms:us-east-1:042360977644:key/33333333-3333-4333-8333-333333333333"
TEMPLATE = "synthetic original template bytes; never an installation input"
TRUST = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}]}
ROLE_TRUST = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"Federated": "arn:aws:iam::042360977644:saml-provider/SyntheticFixture"}, "Action": "sts:AssumeRoleWithSAML"}]}
POLICY = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "cloudformation:DeleteChangeSet", "Resource": CHANGESET}]}


def timestamp(value):
    return value.isoformat().replace("+00:00", "Z")


def binding_document():
    roles = {}
    for i, (operation, name) in enumerate(core.WORKFORCE_RETIREMENT_ROLES.items(), 1):
        roles[operation] = {
            "role_arn": f"arn:aws:iam::042360977644:role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_{name}_{str(i) * 16}",
            "role_id": "AROA" + str(i) * 17,
            "permission_set_arn": "arn:aws:sso:::permissionSet/ssoins-7223feaee61e2475/ps-" + str(i) * 16,
            "policy_sha256": core.canonical_digest(POLICY), "trust_sha256": core.canonical_digest(ROLE_TRUST),
        }
    evidence = {"resource_changes": [list(item) for item in core.EXPECTED_RESOURCE_CHANGES],
        "tags": core.EXPECTED_TAGS, "parameters": {"AuthorityAccountId": "042360977644",
        "NoncurrentVersionRetentionDays": "365", "StateKey": core.CANONICAL_STATE_KEY}, "capabilities": []}
    return {"schema_version": "1", "authorization_mode": core.WORKFORCE_RETIREMENT_MODE,
        "authority_account_id": "042360977644", "region": "us-east-1", "stack_id": STACK, "change_set_id": CHANGESET,
        "expected_template_sha256": "sha256:" + hashlib.sha256(TEMPLATE.encode()).hexdigest(),
        "expected_evidence_sha256": core.canonical_digest(evidence),
        "expected_code_sha256": base64.b64encode(hashlib.sha256(b"synthetic source fixture").digest()).decode(),
        "expected_broker_policy_sha256": core.canonical_digest(POLICY), "broker_role_id": "AROA" + "3" * 17,
        "broker_trust_policy_sha256": core.canonical_digest(TRUST),
        "broker_runtime_version_arn": "arn:aws:lambda:us-east-1::runtime:" + "a" * 64,
        "code_signing_config_arn": "arn:aws:lambda:us-east-1:042360977644:code-signing-config:csc-" + "a" * 17,
        "signing_profile_version_arn": "arn:aws:signer:us-east-1:042360977644:/signing-profiles/SyntheticFixture/1234567890",
        "function_version": "17", "api_id": "synthetic1", "owner_operator_id": "cesar-guzman",
        "owner_subject_digest": core.workforce_owner_subject_digest(PUBLIC_USER_FIXTURE),
        "authorized_at": timestamp(START), "not_before": timestamp(START), "expires_at": timestamp(START + timedelta(minutes=15)),
        "roles": roles, "management_reader_role_arn": core.WORKFORCE_READER_ARN}


def deployed_export(config):
    # Public synthetic provider response, never installation evidence.
    return {"openapi": "3.0.1", "info": {"title": "synthetic", "version": "1"},
        "paths": {"/" + operation: {"post": {"security": [{"sigv4": []}],
            "x-amazon-apigateway-integration": {"type": "aws_proxy", "httpMethod": "POST",
                "uri": config.version_arn, "payloadFormatVersion": "2.0"}}}
            for operation in core.WORKFORCE_RETIREMENT_OPERATIONS},
        "components": {"securitySchemes": {"sigv4": {"type": "apiKey", "name": "Authorization",
            "in": "header", "x-amazon-apigateway-authtype": "awsSigv4"}}}}


class PublicExportBody(io.BytesIO):
    def __deepcopy__(self, _memo):
        return self


class World:
    def __init__(self, schema_version="1"):
        document = binding_document()
        if schema_version == "2":
            document["schema_version"] = "2"
            del document["function_version"]
        self.config = core.WorkforceRetirementConfig(document, core.canonical_digest(document))
        if schema_version == "2":
            self.config = self.config.bind_lambda_context(SimpleNamespace(function_version="17",
                invoked_function_arn=self.config.function_arn + ":17"))
        self.now = START + timedelta(seconds=1)
        self.calls, self.deletes = [], []
        self.record, self.absent = None, False
        self.lock = threading.Lock()
        self.overrides, self.hooks = {}, {}
        self.history = []
        self.exports = []
        self.clients = SimpleNamespace(**{
            service: self.client(service) for service in ("sts", "iam", "dynamodb", "lambda_client", "cloudformation", "kms", "s3control", "apigatewayv2")})
        self.clients.assignment_reader = self.reader

    def client(self, service):
        world = self
        class Client:
            def __getattr__(self, method):
                return lambda **kw: world.call(service, method, kw)
        return Client()

    @contextmanager
    def reader(self):
        self.calls.append(("reader", "assume_fixed_reader", {}))
        yield self.client("sso")

    def call(self, service, method, kw):
        self.calls.append((service, method, copy.deepcopy(kw)))
        key = service + "." + method
        if key in self.hooks:
            self.hooks[key](kw)
        if key in self.overrides:
            result = self.overrides[key]
            if isinstance(result, BaseException):
                raise result
            return copy.deepcopy(result(kw) if callable(result) else result)
        result = self.respond(service, method, kw)
        return copy.deepcopy(result)

    def respond(self, service, method, kw):
        cfg = self.config
        if service == "apigatewayv2":
            assert kw["ApiId"] == cfg.api_id
            if method == "export_api":
                assert kw == {"ApiId": cfg.api_id, "Specification": "OAS30", "OutputType": "JSON",
                              "IncludeExtensions": True, "StageName": "retirement"}
                stream = PublicExportBody(json.dumps(deployed_export(cfg)).encode())
                self.exports.append(stream)
                return {"body": stream}
            assert kw == {"ApiId": cfg.api_id}
            return {
                "get_api": {"ApiId": cfg.api_id, "ProtocolType": "HTTP", "DisableExecuteApiEndpoint": False,
                    "ApiEndpoint": f"https://{cfg.api_id}.execute-api.us-east-1.amazonaws.com",
                    "RouteSelectionExpression": "$request.method $request.path"},
                "get_routes": {"Items": [{"RouteId": "route" + str(i), "RouteKey": "POST /" + operation,
                    "AuthorizationType": "AWS_IAM", "Target": "integrations/shared001"}
                    for i, operation in enumerate(core.WORKFORCE_RETIREMENT_OPERATIONS)]},
                "get_integrations": {"Items": [{"IntegrationId": "shared001", "IntegrationType": "AWS_PROXY",
                    "IntegrationMethod": "POST", "IntegrationUri": cfg.version_arn, "PayloadFormatVersion": "2.0"}]},
                "get_stages": {"Items": [{"StageName": "retirement", "DeploymentId": "deployed01", "AutoDeploy": False}]},
            }[method]
        if service == "sts":
            assert method == "get_caller_identity" and kw == {}
            return {"Account": "042360977644", "Arn": "arn:aws:sts::042360977644:assumed-role/ScanalyzeGug215BrokerExecution/runtime",
                    "UserId": cfg.broker_role_id + ":runtime"}
        if service == "sso":
            assert kw["InstanceArn"] == core.WORKFORCE_INSTANCE
            role = next(value for value in cfg.roles.values() if value["permission_set_arn"] == kw["PermissionSetArn"])
            name = role["role_arn"].rsplit("/", 1)[1].removeprefix("AWSReservedSSO_").rsplit("_", 1)[0]
            return {
                "describe_permission_set": {"PermissionSet": {"PermissionSetArn": role["permission_set_arn"], "Name": name, "SessionDuration": "PT1H"}},
                "list_account_assignments": {"AccountAssignments": [{"AccountId": "042360977644", "PermissionSetArn": role["permission_set_arn"], "PrincipalType": "USER", "PrincipalId": PUBLIC_USER_FIXTURE}]},
                "list_accounts_for_provisioned_permission_set": {"AccountIds": ["042360977644"]},
                "get_inline_policy_for_permission_set": {"InlinePolicy": json.dumps(POLICY)},
                "list_managed_policies_in_permission_set": {"AttachedManagedPolicies": []},
                "list_customer_managed_policy_references_in_permission_set": {"CustomerManagedPolicyReferences": []},
                "get_permissions_boundary_for_permission_set": {},
            }[method]
        if service == "iam":
            broker = kw.get("RoleName") == cfg.broker_execution_role_name
            role = next((value for value in cfg.roles.values() if value["role_arn"].endswith("/" + kw.get("RoleName", ""))), None)
            if method == "get_role":
                value = {"Arn": cfg.execution_role_arn if broker else role["role_arn"],
                    "RoleId": cfg.broker_role_id if broker else role["role_id"], "AssumeRolePolicyDocument": TRUST if broker else ROLE_TRUST}
                if broker:
                    value["PermissionsBoundary"] = {"PermissionsBoundaryType": "Policy", "PermissionsBoundaryArn": cfg.broker_permissions_boundary_arn}
                return {"Role": value}
            if method == "list_role_policies":
                return {"IsTruncated": False, "PolicyNames": [] if broker else ["SyntheticInline"]}
            if method == "list_attached_role_policies":
                return {"IsTruncated": False, "AttachedPolicies": [{"PolicyName": core.BROKER_BOUNDARY_POLICY_NAME, "PolicyArn": cfg.broker_permissions_boundary_arn}] if broker else []}
            if method == "get_role_policy":
                return {"RoleName": kw["RoleName"], "PolicyName": kw["PolicyName"], "PolicyDocument": POLICY}
            assert kw["PolicyArn"] == cfg.broker_permissions_boundary_arn
            return {
                "get_policy": {"Policy": {"Arn": cfg.broker_permissions_boundary_arn, "DefaultVersionId": "v1", "AttachmentCount": 1, "PermissionsBoundaryUsageCount": 1, "IsAttachable": True}},
                "list_policy_versions": {"IsTruncated": False, "Versions": [{"VersionId": "v1", "IsDefaultVersion": True, "CreateDate": START}]},
                "list_entities_for_policy": {"IsTruncated": False, "PolicyGroups": [], "PolicyUsers": [], "PolicyRoles": [{"RoleName": cfg.broker_execution_role_name, "RoleId": cfg.broker_role_id}]},
                "get_policy_version": {"PolicyVersion": {"VersionId": "v1", "IsDefaultVersion": True, "Document": POLICY}},
            }[method]
        if service == "lambda_client":
            return {
                "get_function_configuration": {"FunctionArn": cfg.version_arn, "Version": cfg.function_version,
                    "CodeSha256": cfg.expected_code_sha256, "Role": cfg.execution_role_arn,
                    "RuntimeVersionConfig": {"RuntimeVersionArn": cfg.broker_runtime_version_arn},
                    "LoggingConfig": {"LogFormat": "JSON", "ApplicationLogLevel": "ERROR", "SystemLogLevel": "WARN", "LogGroup": core.BROKER_LOG_GROUP_NAME},
                    "Architectures": ["x86_64"], "EphemeralStorage": {"Size": 512},
                    "Handler": "tooling.platform_authority_identity_context_pep_runtime.handler", "MemorySize": 256,
                    "PackageType": "Zip", "Runtime": "python3.12", "Timeout": 60, "TracingConfig": {"Mode": "PassThrough"},
                    "VpcConfig": {"SubnetIds": [], "SecurityGroupIds": [], "VpcId": ""}, "Environment": {"Variables": cfg.runtime_environment()}},
                "get_runtime_management_config": {"FunctionArn": cfg.version_arn, "UpdateRuntimeOn": "Manual", "RuntimeVersionArn": cfg.broker_runtime_version_arn},
                "get_function_concurrency": {"ReservedConcurrentExecutions": 1},
                "get_function_code_signing_config": {"CodeSigningConfigArn": cfg.code_signing_config_arn},
                "get_code_signing_config": {"CodeSigningConfig": {"CodeSigningConfigArn": cfg.code_signing_config_arn,
                    "AllowedPublishers": {"SigningProfileVersionArns": [cfg.signing_profile_version_arn]}, "CodeSigningPolicies": {"UntrustedArtifactOnDeployment": "Enforce"}}},
                "get_policy": {"Policy": json.dumps(core.workforce_retirement_resource_policy(cfg))},
            }[method]
        if service == "kms":
            assert method == "describe_key" and kw == {"KeyId": KMS}
            return {"KeyMetadata": {"Arn": KMS, "AWSAccountId": "042360977644", "Enabled": True,
                    "KeyManager": "AWS", "KeyState": "Enabled", "KeyUsage": "ENCRYPT_DECRYPT", "Origin": "AWS_KMS", "MultiRegion": False}}
        if service == "s3control":
            assert kw == {"AccountId": "042360977644"}
            return {"PublicAccessBlockConfiguration": dict.fromkeys(core.PUBLIC_ACCESS_BLOCK_KEYS, True)}
        if service == "dynamodb":
            if method == "get_item":
                assert kw == {"TableName": cfg.ledger_table_name, "Key": {"retirement_id": {"S": cfg.retirement_id}}, "ConsistentRead": True, "ProjectionExpression": "document"}
                with self.lock:
                    return {} if self.record is None else {"Item": {"document": {"S": json.dumps(self.record)}}}
            if method == "put_item":
                assert kw["ConditionExpression"] == "attribute_not_exists(retirement_id)"
                assert kw["Item"]["retirement_id"] == {"S": cfg.retirement_id}
                with self.lock:
                    if self.record is not None:
                        raise RuntimeError("synthetic conditional conflict")
                    self.record = json.loads(kw["Item"]["document"]["S"])
                    self.history.append(copy.deepcopy(self.record))
                return {}
            if method == "update_item":
                assert kw["Key"] == {"retirement_id": {"S": cfg.retirement_id}}
                assert kw["ConditionExpression"] == "#state = :expected_state AND #version = :expected_version AND #attempt_count = :expected_attempt_count AND #ledger_digest = :expected_ledger_digest"
                values = kw["ExpressionAttributeValues"]
                with self.lock:
                    for field, kind in (("state", "S"), ("version", "N"), ("attempt_count", "N"), ("ledger_digest", "S")):
                        if str(self.record[field]) != values[":expected_" + field][kind]:
                            raise RuntimeError("synthetic conditional conflict")
                    self.record = json.loads(values[":document"]["S"])
                    self.history.append(copy.deepcopy(self.record))
                after = self.hooks.get("after_update")
                if after:
                    after()
                return {}
            return {
                "describe_table": {"Table": {"TableStatus": "ACTIVE", "TableName": cfg.ledger_table_name, "TableArn": cfg.table_arn,
                    "KeySchema": [{"AttributeName": "retirement_id", "KeyType": "HASH"}],
                    "AttributeDefinitions": [{"AttributeName": "retirement_id", "AttributeType": "S"}], "DeletionProtectionEnabled": True,
                    "SSEDescription": {"Status": "ENABLED", "SSEType": "KMS", "KMSMasterKeyArn": KMS},
                    "BillingModeSummary": {"BillingMode": "PAY_PER_REQUEST"}, "TableClassSummary": {"TableClass": "STANDARD"}}},
                "describe_time_to_live": {"TimeToLiveDescription": {"TimeToLiveStatus": "DISABLED"}},
                "describe_continuous_backups": {"ContinuousBackupsDescription": {"ContinuousBackupsStatus": "ENABLED", "PointInTimeRecoveryDescription": {"PointInTimeRecoveryStatus": "ENABLED", "RecoveryPeriodInDays": 35}}},
                "list_tags_of_resource": {"Tags": [{"Key": key, "Value": value} for key, value in {**core.EXPECTED_LEDGER_TAGS, "environment": "production", "production": "true", "account_id": "042360977644", "region": "us-east-1"}.items()]},
                "get_resource_policy": {"Policy": json.dumps({"Version": "2012-10-17", "Statement": [{"Effect": "Deny", "Principal": {"AWS": "*"}, "Action": list(core.WORKFORCE_WRITE_ACTIONS), "Resource": cfg.table_arn, "Condition": {"ArnNotEquals": {"aws:PrincipalArn": cfg.execution_role_arn}}}]})},
            }[method]
        if service == "cloudformation":
            if method == "delete_change_set":
                assert kw == {"ChangeSetName": CHANGESET, "StackName": STACK}
                assert self.record["state"] == "ATTEMPTED" and self.record["attempt_count"] == 1
                self.deletes.append(kw)
                self.absent = True
                return {}
            return {
                "describe_stacks": {"Stacks": [{"StackName": cfg.stack_name, "StackId": STACK, "StackStatus": "REVIEW_IN_PROGRESS"}]},
                "list_stack_resources": {"StackResourceSummaries": []},
                "list_change_sets": {"Summaries": [] if self.absent else [{"ChangeSetName": cfg.change_set_name, "ChangeSetId": CHANGESET, "Status": "CREATE_COMPLETE", "ExecutionStatus": "AVAILABLE"}]},
                "describe_change_set": {"ChangeSetName": cfg.change_set_name, "ChangeSetId": CHANGESET, "StackName": cfg.stack_name, "StackId": STACK,
                    "Status": "CREATE_COMPLETE", "ExecutionStatus": "AVAILABLE", "ChangeSetType": "CREATE",
                    "Changes": [{"Type": "Resource", "ResourceChange": {"LogicalResourceId": name, "ResourceType": resource, "Action": action, "Replacement": replacement}} for name, resource, action, replacement in core.EXPECTED_RESOURCE_CHANGES],
                    "Tags": [{"Key": key, "Value": value} for key, value in core.EXPECTED_TAGS.items()],
                    "Parameters": [{"ParameterKey": key, "ParameterValue": value} for key, value in {"AuthorityAccountId": "042360977644", "NoncurrentVersionRetentionDays": "365", "StateKey": core.CANONICAL_STATE_KEY}.items()]},
                "get_template": {"TemplateBody": TEMPLATE},
            }[method]
        raise AssertionError("unexpected public metadata boundary")

    def event(self, operation):
        role = self.config.roles["classify" if operation == "classify" else "retire"]
        route, path = "POST /" + operation, "/retirement/" + operation
        return {"version": "2.0", "routeKey": route, "rawPath": path, "rawQueryString": "", "body": "{}", "isBase64Encoded": False,
            "requestContext": {"accountId": "042360977644", "apiId": self.config.api_id, "stage": "retirement", "routeKey": route,
                "domainName": self.config.api_id + ".execute-api.us-east-1.amazonaws.com", "requestId": "synthetic-" + operation,
                "timeEpoch": int(self.now.timestamp() * 1000), "http": {"method": "POST", "path": path},
                "authorizer": {"iam": {"accountId": "042360977644", "userArn": "arn:aws:sts::042360977644:assumed-role/" + role["role_arn"].rsplit("/", 1)[1] + "/synthetic-session",
                    "userId": role["role_id"] + ":synthetic-session"}}}}

    def invoke(self, operation, event=None):
        return entry.handler(self.event(operation) if event is None else event,
            SimpleNamespace(invoked_function_arn=self.config.version_arn, function_version=self.config.function_version))


@pytest.fixture
def world(monkeypatch):
    value = World()
    # Replaces only the source of public provider metadata, not its validators.
    monkeypatch.setattr(entry.WorkforceBotoClients, "create", lambda config, **_kw: value.clients)
    monkeypatch.setattr(entry, "_workforce_now", lambda: value.now)
    for key, item in value.config.runtime_environment().items():
        monkeypatch.setenv(key, item)
    return value


@pytest.fixture
def world_v2(monkeypatch):
    value = World("2")
    monkeypatch.setattr(entry.WorkforceBotoClients, "create", lambda config, **_kw: value.clients)
    monkeypatch.setattr(entry, "_workforce_now", lambda: value.now)
    for key, item in value.config.runtime_environment().items():
        monkeypatch.setenv(key, item)
    return value


def body(response):
    return json.loads(response["body"])


def test_real_entrypoint_collector_cas_delete_and_post_expiry_reconcile(world):
    assert body(world.invoke("classify"))["status"] == "CLASSIFIED"
    assert body(world.invoke("retire"))["status"] == "RETIREMENT_ATTEMPTED"
    assert len(world.deletes) == 1
    assert body(world.invoke("retire"))["status"] == "RECONCILIATION_REQUIRED"
    world.now = START + timedelta(minutes=20)
    assert body(world.invoke("reconcile"))["status"] == "RETIRED_RECONCILED"
    assert len(world.deletes) == 1
    assert [row["state"] for row in world.history] == ["CLASSIFIED", "EXCEPTION_ACCEPTED", "ATTEMPTED", "RETIRED_RECONCILED"]
    assert world.record["independent_approval_present"] is False
    assert world.record["human_authentication_evidence"] == "API_GATEWAY_IAM_EXCLUSIVE_USER_ASSIGNMENT"
    assert "STS_EVALUATED_IDENTITY_CONTEXT" not in json.dumps(world.record)
    schema = json.loads((Path(__file__).parents[2] / "schemas/platform-authority-change-set-retirement-ledger.v4.schema.json").read_text())
    Draft202012Validator.check_schema(schema)
    for record in world.history:
        Draft202012Validator(schema).validate(record)
    assert body(world.invoke("retire"))["status"] == "DENY"


@pytest.mark.parametrize("fixture_name", ["world", "world_v2"])
def test_provider_iam_metadata_allows_exact_classify_and_single_retirement(request, fixture_name):
    world = request.getfixturevalue(fixture_name)
    # AWS ListPolicyVersions and ListEntitiesForPolicy include these fields.
    assert body(world.invoke("classify"))["status"] == "CLASSIFIED"
    assert body(world.invoke("retire"))["status"] == "RETIREMENT_ATTEMPTED"
    assert len(world.deletes) == 1


@pytest.mark.parametrize("case", [
    "second_version", "wrong_default", "integer_default", "default_pointer_drift",
    "version_marker", "version_truncated", "invalid_date", "unknown_version_field",
    "foreign_role", "duplicate_role", "changed_role_id", "invalid_role_id",
    "unknown_role_field", "entity_marker", "entity_truncated",
])
def test_provider_iam_metadata_does_not_hide_policy_or_identity_drift(world, case):
    kw = {"PolicyArn": world.config.broker_permissions_boundary_arn}
    versions = world.respond("iam", "list_policy_versions", kw)
    entities = world.respond("iam", "list_entities_for_policy", kw)
    policy = world.respond("iam", "get_policy", kw)
    if case == "second_version":
        versions["Versions"].append({"VersionId": "v2", "IsDefaultVersion": False, "CreateDate": START})
    elif case == "wrong_default":
        versions["Versions"][0]["IsDefaultVersion"] = False
    elif case == "integer_default":
        versions["Versions"][0]["IsDefaultVersion"] = 1
    elif case == "default_pointer_drift":
        policy["Policy"]["DefaultVersionId"] = "v2"
    elif case == "version_marker":
        versions["Marker"] = "hidden-page"
    elif case == "version_truncated":
        versions["IsTruncated"] = True
    elif case == "invalid_date":
        versions["Versions"][0]["CreateDate"] = "not-a-timestamp"
    elif case == "unknown_version_field":
        versions["Versions"][0]["Unexpected"] = True
    elif case == "foreign_role":
        entities["PolicyRoles"][0]["RoleName"] = "UnexpectedRole"
    elif case == "duplicate_role":
        entities["PolicyRoles"].append(copy.deepcopy(entities["PolicyRoles"][0]))
    elif case == "changed_role_id":
        entities["PolicyRoles"][0]["RoleId"] = "AROA" + "9" * 17
    elif case == "invalid_role_id":
        entities["PolicyRoles"][0]["RoleId"] = 7
    elif case == "unknown_role_field":
        entities["PolicyRoles"][0]["Unexpected"] = True
    elif case == "entity_marker":
        entities["Marker"] = "hidden-page"
    elif case == "entity_truncated":
        entities["IsTruncated"] = True
    world.overrides.update({"iam.list_policy_versions": versions,
                            "iam.list_entities_for_policy": entities,
                            "iam.get_policy": policy})
    assert body(world.invoke("classify"))["status"] == "DENY"
    assert world.record is None and world.deletes == []


@pytest.mark.parametrize("date_value", [None, "2026-09-14T10:00:00Z"])
def test_optional_iam_metadata_and_serialized_timestamp_remain_compatible(world, date_value):
    kw = {"PolicyArn": world.config.broker_permissions_boundary_arn}
    versions = world.respond("iam", "list_policy_versions", kw)
    if date_value is None:
        versions["Versions"][0].pop("CreateDate")
    else:
        versions["Versions"][0]["CreateDate"] = date_value
    entities = world.respond("iam", "list_entities_for_policy", kw)
    entities["PolicyRoles"][0].pop("RoleId")
    world.overrides.update({"iam.list_policy_versions": versions,
                            "iam.list_entities_for_policy": entities})
    assert body(world.invoke("classify"))["status"] == "CLASSIFIED"


@pytest.mark.parametrize("fixture_name", ["world", "world_v2"])
def test_provider_disabled_ipv6_metadata_preserves_empty_vpc(request, fixture_name):
    world = request.getfixturevalue(fixture_name)
    response = world.respond("lambda_client", "get_function_configuration", {})
    response["VpcConfig"]["Ipv6AllowedForDualStack"] = False
    world.overrides["lambda_client.get_function_configuration"] = response
    assert body(world.invoke("classify"))["status"] == "CLASSIFIED"


@pytest.mark.parametrize("field,value", [
    ("Ipv6AllowedForDualStack", True), ("Ipv6AllowedForDualStack", 0),
    ("Ipv6AllowedForDualStack", None), ("Ipv6AllowedForDualStack", "false"),
    ("SubnetIds", ["subnet-synthetic"]), ("SecurityGroupIds", ["sg-synthetic"]),
    ("VpcId", "vpc-synthetic"), ("Unexpected", False),
])
def test_provider_vpc_metadata_cannot_change_network_boundary(world, field, value):
    response = world.respond("lambda_client", "get_function_configuration", {})
    response["VpcConfig"][field] = value
    world.overrides["lambda_client.get_function_configuration"] = response
    assert body(world.invoke("classify"))["status"] == "DENY"
    assert world.record is None and world.deletes == []


@pytest.mark.parametrize("schema", ["1", "2", "3", "4"])
@pytest.mark.parametrize("state", ["CLASSIFIED", "ATTEMPTED", "RETIRED_RECONCILED"])
def test_occupied_key_never_resets_foreign_version_or_mode(world, schema, state):
    world.record = {"schema_version": schema, "state": state, "authorization_mode": "legacy-or-incompatible", "retirement_id": world.config.retirement_id}
    before = copy.deepcopy(world.record)
    for operation in ("classify", "retire", "reconcile"):
        assert world.invoke(operation)["statusCode"] == 403
    assert world.record == before and world.deletes == []
    assert not any(method in {"put_item", "update_item"} for _, method, _ in world.calls)


def test_same_key_as_legacy_algorithm_and_terminal_v4_blocks(world):
    assert world.config.retirement_id == "gug215#sha256:" + hashlib.sha256(CHANGESET.encode()).hexdigest()
    assert body(world.invoke("classify"))["status"] == "CLASSIFIED"
    assert body(world.invoke("retire"))["status"] == "RETIREMENT_ATTEMPTED"
    assert body(world.invoke("reconcile"))["status"] == "RETIRED_RECONCILED"
    assert world.invoke("retire")["statusCode"] == 403
    assert len(world.deletes) == 1


def test_identical_concurrent_cas_loser_never_deletes(world):
    assert body(world.invoke("classify"))["status"] == "CLASSIFIED"
    barrier = threading.Barrier(2)
    def synchronize(kw):
        if kw["ExpressionAttributeValues"][":expected_state"]["S"] == "CLASSIFIED":
            barrier.wait(timeout=5)
    world.hooks["dynamodb.update_item"] = synchronize
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: world.invoke("retire"), range(2)))
    assert sorted(item["statusCode"] for item in results) == [200, 403]
    assert len(world.deletes) == 1 and world.record["attempt_count"] == 1


def test_committed_cas_with_lost_response_never_authorizes_effect(world):
    world.invoke("classify")
    def uncertain():
        if world.record["state"] == "ATTEMPTED":
            raise RuntimeError("synthetic response loss after write")
    world.hooks["after_update"] = uncertain
    assert world.invoke("retire")["statusCode"] == 403
    assert world.record["state"] == "ATTEMPTED" and world.deletes == []
    assert body(world.invoke("retire"))["status"] == "RECONCILIATION_REQUIRED"
    assert world.deletes == []


@pytest.mark.parametrize("boundary", ["before_approval", "before_attempt", "after_attempt"])
def test_expiry_boundaries_consume_only_a_committed_attempt(world, boundary):
    world.invoke("classify")
    def expire(_kw):
        state = world.record["state"]
        if (boundary == "before_approval" and state == "CLASSIFIED") or (boundary == "before_attempt" and state == "EXCEPTION_ACCEPTED"):
            world.now = START + timedelta(minutes=15)
    world.hooks["sts.get_caller_identity"] = expire
    if boundary == "after_attempt":
        world.hooks["after_update"] = lambda: setattr(world, "now", START + timedelta(minutes=15)) if world.record["state"] == "ATTEMPTED" else None
    assert world.invoke("retire")["statusCode"] == 403
    assert world.deletes == []
    assert world.record["attempt_count"] == int(boundary == "after_attempt")
    if boundary == "after_attempt":
        assert body(world.invoke("reconcile"))["status"] == "RECONCILIATION_REQUIRED"


@pytest.mark.parametrize("method,mutate", [
    ("list_account_assignments", lambda row: row["AccountAssignments"][0].update(PrincipalType="GROUP")),
    ("list_account_assignments", lambda row: row["AccountAssignments"][0].update(PrincipalId="other-synthetic-user")),
    ("list_account_assignments", lambda row: row["AccountAssignments"].append(copy.deepcopy(row["AccountAssignments"][0]))),
    ("list_accounts_for_provisioned_permission_set", lambda row: row["AccountIds"].append("839393571433")),
    ("describe_permission_set", lambda row: row["PermissionSet"].update(SessionDuration="PT2H")),
    ("describe_permission_set", lambda row: row["PermissionSet"].update(Name="AWSAdministratorAccess")),
    ("get_inline_policy_for_permission_set", lambda row: row.update(InlinePolicy="{}")),
    ("list_managed_policies_in_permission_set", lambda row: row["AttachedManagedPolicies"].append({"Name": "SyntheticUnexpected"})),
    ("list_customer_managed_policy_references_in_permission_set", lambda row: row["CustomerManagedPolicyReferences"].append({"Name": "SyntheticUnexpected"})),
    ("get_permissions_boundary_for_permission_set", lambda row: row.update(PermissionsBoundary={"ManagedPolicyArn": "synthetic-unexpected"})),
])
def test_real_assignment_collector_rejects_drift_before_ledger(world, method, mutate):
    def changed(kw):
        row = world.respond("sso", method, kw)
        mutate(row)
        return row
    world.overrides["sso." + method] = changed
    assert world.invoke("classify")["statusCode"] == 403
    assert world.record is None and world.deletes == []


@pytest.mark.parametrize("path,value", [
    (("body",), '{"caller":"synthetic"}'), (("body",), '{"x":1,"x":2}'), (("body",), "NaN"),
    (("isBase64Encoded",), 0), (("version",), "1.0"), (("rawPath",), "/classify"),
    (("requestContext", "apiId"), "foreign001"), (("requestContext", "stage"), "$default"),
    (("requestContext", "http", "method"), "GET"), (("requestContext", "accountId"), "839393571433"),
    (("requestContext", "timeEpoch"), True), (("requestContext", "timeEpoch"), int((START - timedelta(seconds=1)).timestamp() * 1000)),
    (("requestContext", "authorizer", "iam", "userId"), "AROA" + "9" * 17 + ":synthetic-session"),
    (("requestContext", "authorizer", "iam", "userArn"), "arn:aws:sts::042360977644:assumed-role/AWSAdministratorAccess/synthetic-session"),
])
def test_request_validation_rejects_before_sdk_factory(world, monkeypatch, path, value):
    event = world.event("classify")
    cursor = event
    for key in path[:-1]:
        cursor = cursor[key]
    cursor[path[-1]] = value
    monkeypatch.setattr(entry.WorkforceBotoClients, "create", lambda _: pytest.fail("no SDK construction expected"))
    assert world.invoke("classify", event)["statusCode"] == 403


def test_protected_config_pin_cannot_be_substituted(world, monkeypatch):
    monkeypatch.setenv("GUG215_WORKFORCE_CONFIG_DIGEST", "sha256:" + "0" * 64)
    monkeypatch.setattr(entry.WorkforceBotoClients, "create", lambda _: pytest.fail("no SDK construction expected"))
    assert world.invoke("classify")["statusCode"] == 403


@pytest.mark.parametrize("key,value", [("owner_operator_id", "synthetic-other-owner"), ("region", "us-west-2"),
    ("authority_account_id", "839393571433"), ("function_version", "$LATEST"),
    ("management_reader_role_arn", "arn:aws:iam::839393571433:role/Administrator"),
    ("not_before", "2026-09-14T10:00:00"), ("expires_at", "2026-09-14T10:15:01Z")])
def test_reanchoring_does_not_broaden_closed_scope(key, value):
    data = binding_document()
    data[key] = value
    with pytest.raises(core.BrokerError):
        core.WorkforceRetirementConfig(data, core.canonical_digest(data))


def test_no_fallback_to_legacy_when_mode_invalid(world, monkeypatch):
    monkeypatch.setenv("GUG215_IDENTITY_MODE", "unknown")
    monkeypatch.setattr(entry.BotoClients, "create", lambda _: pytest.fail("no legacy SDK fallback"))
    assert body(world.invoke("classify"))["reason_code"] == "WORKFORCE_MODE_INVALID"


def test_assignment_is_rechecked_after_attempt_before_delete(world):
    world.invoke("classify")
    def drift():
        if world.record["state"] == "ATTEMPTED":
            world.overrides["sso.list_account_assignments"] = {"AccountAssignments": []}
    world.hooks["after_update"] = drift
    assert world.invoke("retire")["statusCode"] == 403
    assert world.record["state"] == "ATTEMPTED" and world.deletes == []


def test_provider_details_are_not_returned(world):
    world.overrides["sso.describe_permission_set"] = RuntimeError("synthetic-private-provider-detail")
    response = world.invoke("classify")
    assert response["statusCode"] >= 400
    assert "synthetic-private-provider-detail" not in json.dumps(response)
    assert world.record is None


@pytest.mark.parametrize("field,value", [("Arn", "arn:aws:iam::042360977644:role/Foreign"),
    ("RoleId", "AROA" + "9" * 17), ("AssumeRolePolicyDocument", {}),
    ("PermissionsBoundary", {"PermissionsBoundaryArn": "synthetic-unexpected"})])
def test_current_sso_role_identity_and_trust_are_required(world, field, value):
    def changed(kw):
        response = world.respond("iam", "get_role", kw)
        if kw["RoleName"] != world.config.broker_execution_role_name:
            response["Role"][field] = value
        return response
    world.overrides["iam.get_role"] = changed
    assert world.invoke("classify")["statusCode"] == 403
    assert world.record is None


@pytest.mark.parametrize("field,value", [("Version", "$LATEST"), ("CodeSha256", "0" * 43 + "="),
    ("Role", "arn:aws:iam::042360977644:role/Foreign"), ("Environment", {"Variables": {}}),
    ("RuntimeVersionConfig", {}), ("Layers", [{"Arn": "synthetic-foreign"}]), ("LoggingConfig", {"LogFormat": "Text"})])
def test_current_numeric_version_closure_is_required(world, field, value):
    def changed(kw):
        response = world.respond("lambda_client", "get_function_configuration", kw)
        response[field] = value
        return response
    world.overrides["lambda_client.get_function_configuration"] = changed
    assert world.invoke("classify")["statusCode"] == 403 and world.record is None


@pytest.mark.parametrize("sid", ["DenyDirectInvocation", "DenyForeignAccount", "DenyForeignRoute", "DenyBeforeWindow", "DenyExpiredMutation", "DenyAsync"])
def test_missing_service_only_boundary_cannot_trust_fabricated_context(world, sid):
    policy = core.workforce_retirement_resource_policy(world.config)
    policy["Statement"] = [row for row in policy["Statement"] if row["Sid"] != sid]
    world.overrides["lambda_client.get_policy"] = {"Policy": json.dumps(policy)}
    assert world.invoke("classify")["statusCode"] == 403 and world.record is None


def test_before_window_and_future_request_are_rejected_before_reads(world):
    world.now = START - timedelta(seconds=1)
    assert world.invoke("classify")["statusCode"] == 403 and world.calls == []
    world.now = START + timedelta(seconds=1)
    event = world.event("classify")
    event["requestContext"]["timeEpoch"] += 1000
    assert world.invoke("classify", event)["statusCode"] == 403 and world.calls == []


def test_assignment_pagination_repeated_token_is_rejected(world):
    world.overrides["sso.list_account_assignments"] = {"AccountAssignments": [], "NextToken": "synthetic-repeated"}
    assert world.invoke("classify")["statusCode"] == 403
    assert sum(method == "list_account_assignments" for _, method, _ in world.calls) == 2
    assert world.record is None


def test_hidden_stack_resources_page_is_not_an_empty_stack(world):
    world.overrides["cloudformation.list_stack_resources"] = {"StackResourceSummaries": [], "NextToken": "synthetic-hidden-page"}
    assert world.invoke("classify")["statusCode"] == 403 and world.record is None


def test_target_changed_after_cas_consumes_attempt_and_never_deletes(world):
    world.invoke("classify")
    def change():
        if world.record["state"] == "ATTEMPTED":
            world.overrides["cloudformation.get_template"] = {"TemplateBody": "changed public template"}
    world.hooks["after_update"] = change
    assert world.invoke("retire")["statusCode"] == 403
    assert world.record["state"] == "ATTEMPTED" and world.deletes == []
    assert body(world.invoke("retire"))["status"] == "RECONCILIATION_REQUIRED"


def test_duplicate_ledger_fields_do_not_become_an_absent_or_reset_record(world):
    world.overrides["dynamodb.get_item"] = {"Item": {"document": {"S": '{"state":"ATTEMPTED","state":"CLASSIFIED"}'}}}
    assert world.invoke("classify")["statusCode"] == 403
    assert not any(method in {"put_item", "update_item", "delete_change_set"} for _, method, _ in world.calls)


def test_one_physical_delete_guard_stops_sdk_resend_without_credentials():
    class Events:
        guard = None
        def register(self, event, handler, unique_id):
            assert event == "before-send.cloudformation.DeleteChangeSet"
            self.guard = handler
        def unregister(self, event, unique_id):
            self.guard = None
    class PublicSdkBoundary:
        def __init__(self):
            self.meta = SimpleNamespace(events=Events())
            self.sends = 0
        def delete_change_set(self, **_kw):
            for _ in range(2):
                self.meta.events.guard()
                self.sends += 1
    sdk = PublicSdkBoundary()
    client = entry._OnePhysicalDelete(sdk)
    with pytest.raises(core.BrokerError, match="WORKFORCE_DELETE_ALREADY_SENT"):
        client.delete_change_set(ChangeSetName=CHANGESET, StackName=STACK)
    assert sdk.sends == 1 and sdk.meta.events.guard is None
    with pytest.raises(core.BrokerError, match="WORKFORCE_DELETE_ALREADY_SENT"):
        client.delete_change_set(ChangeSetName=CHANGESET, StackName=STACK)
    assert sdk.sends == 1


def test_write_response_loss_retains_one_attempt_and_reconciliation(world):
    world.invoke("classify")
    def uncertain(kw):
        world.respond("cloudformation", "delete_change_set", kw)
        raise RuntimeError("synthetic transport failure after physical send")
    world.overrides["cloudformation.delete_change_set"] = uncertain
    assert body(world.invoke("retire"))["status"] == "RECONCILIATION_REQUIRED"
    assert len(world.deletes) == 1
    assert body(world.invoke("retire"))["status"] == "RECONCILIATION_REQUIRED"
    assert body(world.invoke("reconcile"))["status"] == "RETIRED_RECONCILED"
    assert len(world.deletes) == 1


@pytest.mark.parametrize("field", ["Tags", "Parameters", "NextToken"])
def test_change_set_partial_or_duplicate_metadata_is_rejected(world, field):
    def changed(kw):
        response = world.respond("cloudformation", "describe_change_set", kw)
        if field == "NextToken":
            response[field] = "synthetic-hidden-page"
        else:
            response[field].append(copy.deepcopy(response[field][0]))
        return response
    world.overrides["cloudformation.describe_change_set"] = changed
    assert world.invoke("classify")["statusCode"] == 403 and world.record is None


@pytest.mark.parametrize("kind", ["window", "budget", "rollback", "request_age", "control"])
def test_expiry_after_cas_during_signing_blocks_first_physical_send(world, monkeypatch, kind):
    clock = [0.0]
    monkeypatch.setattr(core.time, "monotonic", lambda: clock[0])
    class Events:
        guard = None
        def register(self, _event, handler, **_kwargs):
            self.guard = handler
        def unregister(self, _event, **_kwargs):
            self.guard = None
    class DelayedPublicBoundary:
        def __init__(self):
            self.meta = SimpleNamespace(events=Events())
        def __getattr__(self, method):
            return getattr(world.clients.cloudformation, method)
        def delete_change_set(self, **kw):
            assert world.record["state"] == "ATTEMPTED"
            # This models elapsed signing time with no credential objects.
            if kind == "window":
                world.now = START + timedelta(minutes=15)
            elif kind == "budget":
                clock[0] = 25.0
            elif kind == "rollback":
                world.now = START + timedelta(seconds=5)
            elif kind == "request_age":
                world.now += timedelta(seconds=2)
            self.meta.events.guard()
            return world.respond("cloudformation", "delete_change_set", kw)
    def factory(config, *, deadline, operation, request_guard):
        scope = entry.WorkforceBotoClients.__new__(entry.WorkforceBotoClients)
        scope._binding, scope._deadline, scope._operation = config, deadline, operation
        scope._request_guard = request_guard
        values = vars(world.clients).copy()
        values["cloudformation"] = entry._OnePhysicalDelete(DelayedPublicBoundary(), before_send=scope._before_delete_send)
        return SimpleNamespace(**values)
    monkeypatch.setattr(entry.WorkforceBotoClients, "create", factory)
    assert body(world.invoke("classify"))["status"] == "CLASSIFIED"
    world.now = START + timedelta(seconds=300 if kind == "request_age" else 10)
    event = world.event("retire")
    if kind == "request_age":
        event["requestContext"]["timeEpoch"] = int((START + timedelta(seconds=1)).timestamp() * 1000)
    assert world.invoke("retire", event)["statusCode"] == (200 if kind == "control" else 403)
    assert world.record["state"] == "ATTEMPTED" and world.record["attempt_count"] == 1
    assert len(world.deletes) == (1 if kind == "control" else 0)


@pytest.mark.parametrize("boundary", ["metadata", "after_cas", "reconciliation"])
def test_common_25_second_budget_rejects_late_provider_readbacks(world, monkeypatch, boundary):
    clock = [0.0]
    monkeypatch.setattr(core.time, "monotonic", lambda: clock[0])
    if boundary == "metadata":
        world.hooks["sso.get_inline_policy_for_permission_set"] = lambda _kw: clock.__setitem__(0, 25.0)
        assert world.invoke("classify")["statusCode"] == 403
        assert world.record is None
        return
    world.invoke("classify")
    if boundary == "after_cas":
        world.hooks["after_update"] = lambda: clock.__setitem__(0, 25.0) if world.record["state"] == "ATTEMPTED" else None
        assert world.invoke("retire")["statusCode"] == 403
        assert world.deletes == [] and world.record["state"] == "ATTEMPTED"
    else:
        world.invoke("retire")
        world.hooks["s3control.get_public_access_block"] = lambda _kw: clock.__setitem__(0, 25.0)
        assert world.invoke("reconcile")["statusCode"] == 403
        assert len(world.deletes) == 1 and world.record["state"] == "ATTEMPTED"


def test_workforce_requires_explicit_production_table_tags_without_retagging(world):
    world.overrides["dynamodb.list_tags_of_resource"] = {"Tags": [{"Key": key, "Value": value}
        for key, value in {**core.EXPECTED_LEDGER_TAGS, "account_id": "042360977644", "region": "us-east-1"}.items()]}
    assert world.invoke("classify")["statusCode"] == 403 and world.record is None
    assert not any(method in {"tag_resource", "untag_resource", "put_item", "update_item"} for _, method, _ in world.calls)
    assert core.RetirementBroker._ledger_control_tags(None) == core.EXPECTED_LEDGER_TAGS


def test_ingress_observed_time_is_not_reset_before_sdk_construction(world, monkeypatch):
    world.now = START + timedelta(seconds=10)
    event = world.event("classify")
    event["requestContext"]["timeEpoch"] = int((START + timedelta(seconds=1)).timestamp() * 1000)
    readings = iter((START + timedelta(seconds=10), START + timedelta(seconds=5)))
    monkeypatch.setattr(entry, "_workforce_now", lambda: next(readings))
    called = []
    def factory(*_args, **_kwargs):
        called.append(True)
        return world.clients
    monkeypatch.setattr(entry.WorkforceBotoClients, "create", factory)
    response = world.invoke("classify", event)
    assert response["statusCode"] == 403
    assert body(response)["reason_code"] == "WORKFORCE_REQUEST_EXPIRED"
    assert called == [] and world.calls == [] and world.record is None


def test_post_send_response_age_cannot_be_reported_as_success(world):
    world.invoke("classify")
    world.now = START + timedelta(seconds=300)
    event = world.event("retire")
    event["requestContext"]["timeEpoch"] = int((START + timedelta(seconds=1)).timestamp() * 1000)
    def delayed_response(kw):
        result = world.respond("cloudformation", "delete_change_set", kw)
        world.now += timedelta(seconds=2)
        return result
    world.overrides["cloudformation.delete_change_set"] = delayed_response
    response = world.invoke("retire", event)
    assert response["statusCode"] == 403
    assert body(response)["reason_code"] == "WORKFORCE_REQUEST_EXPIRED"
    assert world.record["state"] == "ATTEMPTED" and len(world.deletes) == 1
    assert body(world.invoke("retire"))["status"] == "RECONCILIATION_REQUIRED"
    assert len(world.deletes) == 1


def configuration_v2():
    data = binding_document()
    data["schema_version"] = "2"
    del data["function_version"]
    return core.WorkforceRetirementConfig(data, core.canonical_digest(data))


def test_schema2_configuration_has_no_prepublished_version_or_authority_claim():
    config = configuration_v2()
    before = config.runtime_environment()
    with pytest.raises(core.BrokerError, match="WORKFORCE_VERSION_UNBOUND"):
        _ = config.version_arn
    bound = config.bind_lambda_context(SimpleNamespace(function_version="27",
        invoked_function_arn=config.function_arn + ":27"))
    assert bound.function_version == "27" and bound.version_arn.endswith(":27")
    assert bound.runtime_environment() == before
    assert bound.expected_digest == config.expected_digest
    assert "function_version" not in bound.document
    assert entry.workforce_config_from_environment(before).document == config.document
    assert bound.retirement_id == World().config.retirement_id
    with pytest.raises(core.BrokerError, match="WORKFORCE_VERSION_INVALID"):
        bound.bind_lambda_context(SimpleNamespace(function_version="28", invoked_function_arn=config.function_arn + ":28"))


@pytest.mark.parametrize("field,value", [("function_version", "17"), ("function_version", None),
    ("runtime_function_version", "17"), ("deployment_authorized", True)])
def test_schema2_rejects_persisted_version_and_promotion_even_when_resealed(field, value):
    data = core._workforce_plain(configuration_v2().document)
    data[field] = value
    with pytest.raises(core.BrokerError):
        core.WorkforceRetirementConfig(data, core.canonical_digest(data))


@pytest.mark.parametrize("version,qualifier", [(None, "17"), (17, "17"), (True, "1"),
    ("$LATEST", "$LATEST"), ("0", "0"), ("017", "017"), ("17", "retire"), ("17", "18"),
    ("17", ""), ("100000000", "100000000")])
def test_schema2_requires_two_matching_provider_numeric_context_fields_before_sdk(monkeypatch, version, qualifier):
    config = configuration_v2()
    value = World()
    for key, item in config.runtime_environment().items():
        monkeypatch.setenv(key, item)
    monkeypatch.setattr(entry.WorkforceBotoClients, "create", lambda *_a, **_kw: pytest.fail("must reject before SDK"))
    context = SimpleNamespace(function_version=version, invoked_function_arn=config.function_arn + ":" + qualifier)
    response = entry.handler(value.event("classify"), context)
    assert response["statusCode"] == 403 and body(response)["reason_code"] == "WORKFORCE_VERSION_INVALID"


@pytest.mark.parametrize("replacement", ["us-west-2", "839393571433", "foreign-function"])
def test_schema2_numeric_context_cannot_change_function_scope(replacement):
    config = configuration_v2()
    arn = config.function_arn + ":17"
    if replacement == "us-west-2":
        arn = arn.replace("us-east-1", replacement)
    elif replacement == "839393571433":
        arn = arn.replace("042360977644", replacement)
    else:
        arn = arn.replace(config.function_name, replacement)
    with pytest.raises(core.BrokerError, match="WORKFORCE_VERSION_INVALID"):
        config.bind_lambda_context(SimpleNamespace(function_version="17", invoked_function_arn=arn))


def test_schema2_real_handler_deployed_stage_cas_delete_and_expired_reconcile(world_v2):
    world = world_v2
    assert body(world.invoke("classify"))["status"] == "CLASSIFIED"
    assert body(world.invoke("retire"))["status"] == "RETIREMENT_ATTEMPTED"
    assert len(world.deletes) == 1
    world.now = START + timedelta(minutes=20)
    assert body(world.invoke("reconcile"))["status"] == "RETIRED_RECONCILED"
    assert len(world.deletes) == 1 and all(stream.closed for stream in world.exports)
    # Every write/effect has its own fresh deployed snapshot readback. There
    # is no cached Boolean result reused from the initial preflight.
    since_write = []
    for service, method, _kwargs in world.calls:
        since_write.append((service, method))
        if method in {"put_item", "update_item", "delete_change_set"}:
            assert ("apigatewayv2", "export_api") in since_write
            assert since_write.count(("apigatewayv2", "get_stages")) >= 2
            since_write = []
    assert "function_version" not in world.config.document
    assert world.record["broker_function_version_arn_digest"] == core.canonical_digest({"function_version_arn": world.config.version_arn})


@pytest.mark.parametrize("kind", ["unsigned_code", "old_deployed_version", "deployed_anonymous", "editable_anonymous", "hidden_route", "stage_race"])
def test_schema2_context_and_correct_latest_configuration_are_not_execution_authority(world_v2, kind):
    world = world_v2
    if kind == "unsigned_code":
        def wrong_code(kw):
            row = world.respond("lambda_client", "get_function_configuration", kw)
            row["CodeSha256"] = base64.b64encode(hashlib.sha256(b"unsigned-source-only").digest()).decode()
            return row
        world.overrides["lambda_client.get_function_configuration"] = wrong_code
    elif kind in {"old_deployed_version", "deployed_anonymous"}:
        export = deployed_export(world.config)
        operation = export["paths"]["/retire"]["post"]
        if kind == "old_deployed_version":
            operation["x-amazon-apigateway-integration"]["uri"] = world.config.function_arn + ":16"
        else:
            operation["security"] = []
        world.overrides["apigatewayv2.export_api"] = lambda _kw: {"body": PublicExportBody(json.dumps(export).encode())}
    elif kind in {"editable_anonymous", "hidden_route"}:
        def wrong_routes(kw):
            row = world.respond("apigatewayv2", "get_routes", kw)
            if kind == "editable_anonymous":
                row["Items"][1]["AuthorizationType"] = "NONE"
            else:
                row["NextToken"] = "hidden"
            return row
        world.overrides["apigatewayv2.get_routes"] = wrong_routes
    else:
        count = [0]
        def raced_stages(kw):
            count[0] += 1
            row = world.respond("apigatewayv2", "get_stages", kw)
            if count[0] > 1:
                row["Items"][0]["DeploymentId"] = "deployed02"
            return row
        world.overrides["apigatewayv2.get_stages"] = raced_stages
    assert world.invoke("classify")["statusCode"] == 403
    assert world.record is None and world.deletes == []
    assert not any(method in {"put_item", "update_item"} for _, method, _ in world.calls)


@pytest.mark.parametrize("boundary", ["create", "approval", "attempt", "delete", "reconcile"])
def test_schema2_deployed_stage_is_reread_at_every_cas_and_effect(world_v2, boundary):
    world = world_v2
    def revoke():
        world.overrides["apigatewayv2.get_stages"] = {"Items": []}
    if boundary == "create":
        world.hooks["cloudformation.get_template"] = lambda _kw: revoke()
        assert world.invoke("classify")["statusCode"] == 403 and world.record is None
    else:
        assert body(world.invoke("classify"))["status"] == "CLASSIFIED"
        if boundary == "approval":
            world.hooks["cloudformation.get_template"] = lambda _kw: revoke()
        elif boundary in {"attempt", "delete"}:
            wanted = "EXCEPTION_ACCEPTED" if boundary == "attempt" else "ATTEMPTED"
            world.hooks["after_update"] = lambda: revoke() if world.record["state"] == wanted else None
        if boundary == "reconcile":
            assert body(world.invoke("retire"))["status"] == "RETIREMENT_ATTEMPTED"
            world.now = START + timedelta(minutes=20)
            world.hooks["s3control.get_public_access_block"] = lambda _kw: revoke()
            assert world.invoke("reconcile")["statusCode"] == 403
        else:
            assert world.invoke("retire")["statusCode"] == 403
        expected = {"approval": "CLASSIFIED", "attempt": "EXCEPTION_ACCEPTED", "delete": "ATTEMPTED", "reconcile": "ATTEMPTED"}
        assert world.record["state"] == expected[boundary]
    assert len(world.deletes) == int(boundary == "reconcile")


@pytest.mark.parametrize("kind", ["read_failure", "close_failure", "oversize", "extra_body", "deadline", "utc_rollback", "request_age"])
def test_schema2_stream_and_clock_failures_cannot_reach_a_cas(world_v2, monkeypatch, kind):
    world = world_v2
    clock = [0.0]
    monkeypatch.setattr(core.time, "monotonic", lambda: clock[0])
    world.now = START + timedelta(seconds=10)
    export_bytes = json.dumps(deployed_export(world.config)).encode()
    from tooling.platform_authority_workforce_stage_binding import MAX_EXPORT_BYTES
    class BrokenBody(PublicExportBody):
        def read(self, amount=-1):
            if kind == "read_failure":
                raise RuntimeError("synthetic-provider-sensitive-detail")
            if kind == "deadline":
                clock[0] = 25.0
            elif kind == "utc_rollback":
                world.now = START + timedelta(seconds=5)
            elif kind == "request_age":
                world.now += timedelta(seconds=301)
            elif kind == "extra_body" and amount == 1:
                return b"!"
            return super().read(amount)
        def close(self):
            super().close()
            if kind == "close_failure":
                raise RuntimeError("synthetic-provider-sensitive-detail")
    stream = BrokenBody(b"x" * (MAX_EXPORT_BYTES + 1) if kind == "oversize" else export_bytes)
    world.overrides["apigatewayv2.export_api"] = {"body": stream}
    response = world.invoke("classify")
    assert response["statusCode"] == 403
    assert "synthetic-provider-sensitive-detail" not in json.dumps(response)
    assert world.record is None and world.deletes == [] and stream.closed


@pytest.mark.parametrize("state", ["CLASSIFIED", "ATTEMPTED", "RETIRED_RECONCILED"])
def test_schema2_cannot_reset_schema1_bound_occupied_key(world_v2, state):
    world = world_v2
    world.record = {"schema_version": "4", "state": state, "retirement_id": world.config.retirement_id,
                    "identity_binding_digest": World().config.expected_digest}
    before = copy.deepcopy(world.record)
    for operation in core.WORKFORCE_RETIREMENT_OPERATIONS:
        assert world.invoke(operation)["statusCode"] == 403
    assert world.record == before and world.deletes == []
    assert not any(method in {"put_item", "update_item"} for _, method, _ in world.calls)


class PublicPermissionSetError(Exception):
    def __init__(self, response):
        super().__init__("synthetic-provider-detail-not-for-output")
        self.response = response


def absent_boundary_response(permission_set_arn):
    return {"Error": {"Code": "ResourceNotFoundException",
        "Message": "PermissionsBoundary not present in permission set " + permission_set_arn},
        "ResponseMetadata": {"HTTPStatusCode": 404}}


def test_real_api_absent_boundary_shape_requires_exact_permission_set_reconfirmation(world):
    def missing_boundary(kw):
        raise PublicPermissionSetError(absent_boundary_response(kw["PermissionSetArn"]))
    world.overrides["sso.get_permissions_boundary_for_permission_set"] = missing_boundary
    assert body(world.invoke("classify"))["status"] == "CLASSIFIED"
    calls = world.calls
    checked = 0
    for index, (service, method, kwargs) in enumerate(calls):
        if service == "sso" and method == "get_permissions_boundary_for_permission_set":
            assert calls[index + 1] == ("sso", "describe_permission_set", kwargs)
            checked += 1
    assert checked >= 2


@pytest.mark.parametrize("kind", ["denied", "missing_set", "foreign_set", "generic_404", "wrong_status", "changed_set", "deleted_set", "late_recheck"])
def test_absent_boundary_response_does_not_hide_missing_or_changed_permission_set(world, kind):
    recheck = [False]
    def missing_boundary(kw):
        response = absent_boundary_response(kw["PermissionSetArn"])
        if kind == "denied":
            response["Error"]["Code"] = "AccessDeniedException"
        elif kind == "missing_set":
            response["Error"]["Message"] = "Permission set does not exist"
        elif kind == "foreign_set":
            response["Error"]["Message"] = "PermissionsBoundary not present in permission set foreign"
        elif kind == "generic_404":
            response["Error"]["Message"] = "Not found"
        elif kind == "wrong_status":
            response["ResponseMetadata"]["HTTPStatusCode"] = 403
        recheck[0] = True
        raise PublicPermissionSetError(response)
    def describe(kw):
        row = world.respond("sso", "describe_permission_set", kw)
        if recheck[0]:
            if kind == "changed_set":
                row["PermissionSet"]["Name"] = "AWSAdministratorAccess"
            elif kind == "deleted_set":
                return {}
            elif kind == "late_recheck":
                world.now = START + timedelta(minutes=15)
        return row
    world.overrides["sso.get_permissions_boundary_for_permission_set"] = missing_boundary
    world.overrides["sso.describe_permission_set"] = describe
    response = world.invoke("classify")
    assert response["statusCode"] == 403
    assert "synthetic-provider-detail" not in json.dumps(response)
    assert world.record is None and world.deletes == []
