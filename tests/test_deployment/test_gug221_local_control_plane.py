"""Fail-closed synthetic tests for the GUG-221 local control plane."""

from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
import json
from pathlib import Path
import sys
from typing import Any

import pytest


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tooling"))

from platform_authority_lambda_audit_repair_broker import (  # noqa: E402
    BrokerConfig,
    BrokerContractError,
    canonical_digest,
)
import platform_authority_lambda_audit_repair_broker_runtime as runtime  # noqa: E402


REPAIR = "scanalyze-authority-lambda-audit-repair"
PLAN = "scanalyze-authority-lambda-audit-plan"
RECONCILE = "scanalyze-authority-lambda-audit-reconcile"
REPAIR_ALIAS = (REPAIR, "repair-v1")
PLAN_ALIAS = (PLAN, "plan-v1")
RECONCILE_ALIAS = (RECONCILE, "reconcile-v1")
CODE_SHA = "A" * 43 + "="
CSC_ARN = (
    "arn:aws:lambda:us-east-1:042360977644:"
    "code-signing-config:csc-1234567890abcdef0"
)
SIGNER_ARN = (
    "arn:aws:signer:us-east-1:042360977644:"
    "/signing-profiles/ScanalyzeGug221/ABCDEFGHIJ"
)
KMS_ARN = (
    "arn:aws:kms:us-east-1:042360977644:key/"
    "11111111-2222-3333-4444-555555555555"
)
TABLE_NAME = "scanalyze-platform-authority-gug221-repair-ledger"
TABLE_ARN = f"arn:aws:dynamodb:us-east-1:042360977644:table/{TABLE_NAME}"
PRINCIPAL_ID = "1234567890-11111111-2222-3333-4444-555555555555"
INSTANCE_ARN = "arn:aws:sso:::instance/ssoins-1234567890abcdef"
COLLECTOR_ARN = (
    "arn:aws:sso:::permissionSet/ssoins-1234567890abcdef/"
    "ps-fedcba0987654321"
)
INVOKER_ARN = (
    "arn:aws:sso:::permissionSet/ssoins-1234567890abcdef/"
    "ps-0123456789abcdef"
)
SAML_ARN = (
    "arn:aws:iam::042360977644:saml-provider/"
    "AWSSSO_1234567890abcdef_DO_NOT_DELETE"
)
POLICY_DIGEST = canonical_digest({"Version": "2012-10-17", "Statement": []})
INVOKER_DIGEST = canonical_digest(
    {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Deny", "Action": "*", "Resource": "*"}],
    }
)


def _ledger_policy_statements() -> list[dict[str, Any]]:
    return [
        {
            "Sid": "DenyPlanCreationOutsidePlanExecution",
            "Effect": "Deny",
            "Principal": {"AWS": "*"},
            "Action": list(runtime.PLAN_LEDGER_WRITE_ACTIONS),
            "Resource": TABLE_ARN,
            "Condition": {
                "ArnNotEquals": {
                    "aws:PrincipalArn": runtime.PLAN_EXECUTION_ROLE_ARN,
                }
            },
        },
        {
            "Sid": "DenyPlanConsumptionOutsideRepairExecution",
            "Effect": "Deny",
            "Principal": {"AWS": "*"},
            "Action": list(runtime.REPAIR_LEDGER_WRITE_ACTIONS),
            "Resource": TABLE_ARN,
            "Condition": {
                "ArnNotEquals": {
                    "aws:PrincipalArn": runtime.REPAIR_EXECUTION_ROLE_ARN,
                }
            },
        },
        {
            "Sid": "DenyEveryUnsupportedLedgerMutation",
            "Effect": "Deny",
            "Principal": {"AWS": "*"},
            "Action": list(runtime.UNSUPPORTED_LEDGER_WRITE_ACTIONS),
            "Resource": TABLE_ARN,
        },
    ]


def _weakened_ledger_policy() -> str:
    statements = _ledger_policy_statements()
    statements[0]["Condition"] = {
        "ArnNotEquals": {
            "aws:PrincipalArn": runtime.REPAIR_EXECUTION_ROLE_ARN,
        }
    }
    return json.dumps({"Version": "2012-10-17", "Statement": statements})


def config_for(mode: str = "repair") -> BrokerConfig:
    qualifiers = {"repair": "repair-v1", "plan": "plan-v1", "reconcile": "reconcile-v1"}
    return BrokerConfig.from_env(
        {
            "FUNCTION_MODE": mode,
            "FUNCTION_QUALIFIER": qualifiers[mode],
            "SOURCE_COMMIT": "a" * 40,
            "REPAIR_ID": "gug221-" + "a" * 64,
            "PRINCIPAL_ID": PRINCIPAL_ID,
            "IDENTITY_STORE_ID": "d-1234567890",
            "IDENTITY_CENTER_INSTANCE_ARN": INSTANCE_ARN,
            "COLLECTOR_PERMISSION_SET_ARN": COLLECTOR_ARN,
            "REPAIR_INVOKER_PERMISSION_SET_ARN": INVOKER_ARN,
            "COLLECTOR_POLICY_DIGEST": POLICY_DIGEST,
            "REPAIR_INVOKER_POLICY_DIGEST": INVOKER_DIGEST,
            "ORIGINAL_GUG220_LEDGER_DIGEST": "c" * 64,
            "EXPECTED_PERMISSION_SET_TAGS_JSON": json.dumps(
                {
                    "scanalyze:control": "lambda-audit",
                    "scanalyze:managed-by": "gug-221",
                }
            ),
            "REPAIR_LEDGER_TABLE_NAME": TABLE_NAME,
            "REPAIR_LEDGER_KMS_KEY_ARN": KMS_ARN,
            "EXPECTED_ARTIFACT_CODE_SHA256": CODE_SHA,
            "EXPECTED_CODE_SIGNING_CONFIG_ARN": CSC_ARN,
            "EXPECTED_SIGNING_PROFILE_VERSION_ARN": SIGNER_ARN,
            "REPAIR_NOT_BEFORE": "2026-07-21T19:55:00Z",
            "REPAIR_NOT_AFTER": "2026-07-21T20:10:00Z",
            "AWS_LAMBDA_FUNCTION_VERSION": {
                "repair": "42",
                "plan": "43",
                "reconcile": "44",
            }[mode],
            "REPAIR_FUNCTION_VERSION": "42",
            "PLAN_FUNCTION_VERSION": "43",
            "EXPECTED_BOTO3_VERSION": "1.40.1",
            "EXPECTED_BOTOCORE_VERSION": "1.40.1",
            "COLLECTOR_SAML_PROVIDER_ARN": SAML_ARN,
            "IDENTITY_CENTER_KMS_MODE": "AWS_OWNED_KMS_KEY",
        }
    )


class ProviderError(RuntimeError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.response = {"Error": {"Code": code}}


def _function(
    config: BrokerConfig,
    *,
    function_name: str,
    version: str,
    qualifier: str,
    function_kind: str,
) -> dict[str, Any]:
    base_arn = (
        f"arn:aws:lambda:us-east-1:042360977644:function:{function_name}"
    )
    return {
        "FunctionName": function_name,
        "FunctionArn": base_arn if version == "$LATEST" else f"{base_arn}:{version}",
        "Runtime": "python3.12",
        "Role": {
            "plan": runtime.PLAN_EXECUTION_ROLE_ARN,
            "repair": runtime.REPAIR_EXECUTION_ROLE_ARN,
            "reconcile": runtime.READ_EXECUTION_ROLE_ARN,
        }[function_kind],
        "Handler": {
            "plan": runtime.PLAN_FUNCTION_HANDLER,
            "repair": runtime.REPAIR_FUNCTION_HANDLER,
            "reconcile": runtime.READ_FUNCTION_HANDLER,
        }[function_kind],
        "Description": (
            {
                "plan": "GUG-221 read-only plan proof and create-only ledger gate",
                "repair": "GUG-221 exact one-shot Lambda audit provisioning repair PEP",
                "reconcile": "GUG-221 read-only reconciliation PEP",
            }
            if version == "$LATEST"
            else {
                "plan": "GUG-221 reviewed immutable plan version",
                "repair": "GUG-221 reviewed immutable repair version",
                "reconcile": "GUG-221 reviewed immutable reconcile version",
            }
        )[function_kind],
        "Timeout": runtime.FUNCTION_TIMEOUT_SECONDS[function_kind],
        "MemorySize": runtime.FUNCTION_MEMORY_SIZE_MB,
        "CodeSha256": CODE_SHA,
        "Version": version,
        "State": "Active",
        "LastUpdateStatus": "Successful",
        "PackageType": "Zip",
        "Architectures": ["x86_64"],
        "SigningProfileVersionArn": SIGNER_ARN,
        "Environment": {
            "Variables": runtime.AwsLocalControlPlaneAdapter._expected_environment(
                config, function_kind=function_kind
            )
        },
        "VpcConfig": {
            "SubnetIds": [],
            "SecurityGroupIds": [],
            "VpcId": "",
            "Ipv6AllowedForDualStack": False,
        },
        "DeadLetterConfig": {},
        "KMSKeyArn": "",
        "Layers": [],
        "FileSystemConfigs": [],
        "TracingConfig": {"Mode": "PassThrough"},
        "EphemeralStorage": {"Size": 512},
        "SnapStart": {"ApplyOn": "None", "OptimizationStatus": "Off"},
        "LoggingConfig": {
            "LogFormat": "Text",
            "SystemLogLevel": "INFO",
            "LogGroup": f"/aws/lambda/{function_name}",
        },
        "_qualifier": qualifier,
    }


def provider_state(config: BrokerConfig | None = None) -> dict[str, Any]:
    config = config or config_for()
    aliases = {}
    for function_name, alias, version in (
        (REPAIR, "repair-v1", "42"),
        (PLAN, "plan-v1", "43"),
        (RECONCILE, "reconcile-v1", "44"),
    ):
        aliases[(function_name, alias)] = {
            "AliasArn": (
                "arn:aws:lambda:us-east-1:042360977644:function:"
                f"{function_name}:{alias}"
            ),
            "Name": alias,
            "FunctionVersion": version,
            "Description": "",
            "RoutingConfig": {"AdditionalVersionWeights": {}},
        }
    functions = {
        (REPAIR, None): _function(
            config,
            function_name=REPAIR,
            version="$LATEST",
            qualifier="$LATEST",
            function_kind="repair",
        ),
        REPAIR_ALIAS: _function(
            config,
            function_name=REPAIR,
            version="42",
            qualifier="repair-v1",
            function_kind="repair",
        ),
        (PLAN, None): _function(
            config,
            function_name=PLAN,
            version="$LATEST",
            qualifier="$LATEST",
            function_kind="plan",
        ),
        PLAN_ALIAS: _function(
            config,
            function_name=PLAN,
            version="43",
            qualifier="plan-v1",
            function_kind="plan",
        ),
        (RECONCILE, None): _function(
            config,
            function_name=RECONCILE,
            version="$LATEST",
            qualifier="$LATEST",
            function_kind="reconcile",
        ),
        RECONCILE_ALIAS: _function(
            config,
            function_name=RECONCILE,
            version="44",
            qualifier="reconcile-v1",
            function_kind="reconcile",
        ),
    }
    for item in functions.values():
        item.pop("_qualifier")
    versions = {
        REPAIR: [functions[(REPAIR, None)], functions[REPAIR_ALIAS]],
        PLAN: [functions[(PLAN, None)], functions[PLAN_ALIAS]],
        RECONCILE: [functions[(RECONCILE, None)], functions[RECONCILE_ALIAS]],
    }
    function_inventory = [
        deepcopy(item)
        for function_name in (REPAIR, PLAN, RECONCILE)
        for item in versions[function_name]
    ]
    statements = _ledger_policy_statements()
    return {
        "aliases": aliases,
        "alias_inventory": {
            REPAIR: [aliases[REPAIR_ALIAS]],
            PLAN: [aliases[PLAN_ALIAS]],
            RECONCILE: [aliases[RECONCILE_ALIAS]],
        },
        "functions": functions,
        "versions": versions,
        "function_inventory": function_inventory,
        "associations": {
            REPAIR: {"FunctionName": REPAIR, "CodeSigningConfigArn": CSC_ARN},
            PLAN: {"FunctionName": PLAN, "CodeSigningConfigArn": CSC_ARN},
            RECONCILE: {
                "FunctionName": RECONCILE,
                "CodeSigningConfigArn": CSC_ARN,
            },
        },
        "csc": {
            "CodeSigningConfig": {
                "CodeSigningConfigId": "csc-1234567890abcdef0",
                "CodeSigningConfigArn": CSC_ARN,
                "Description": "GUG-221 enforce-only reviewed signer",
                "AllowedPublishers": {
                    "SigningProfileVersionArns": [SIGNER_ARN]
                },
                "CodeSigningPolicies": {
                    "UntrustedArtifactOnDeployment": "Enforce"
                },
            }
        },
        "concurrency": {
            REPAIR: {"ReservedConcurrentExecutions": 1},
            PLAN: {"ReservedConcurrentExecutions": 1},
            RECONCILE: {"ReservedConcurrentExecutions": 1},
        },
        "events": {
            key: {
                "FunctionArn": aliases[key]["AliasArn"],
                "MaximumRetryAttempts": 0,
                "MaximumEventAgeInSeconds": 60,
                "DestinationConfig": {"OnSuccess": {}, "OnFailure": {}},
            }
            for key in (REPAIR_ALIAS, PLAN_ALIAS, RECONCILE_ALIAS)
        },
        "policy_present": set(),
        "url_present": set(),
        "absence_error": None,
        "event_sources": {REPAIR: [], PLAN: [], RECONCILE: []},
        "table": {
            "Table": {
                "TableName": TABLE_NAME,
                "TableArn": TABLE_ARN,
                "TableStatus": "ACTIVE",
                "BillingModeSummary": {"BillingMode": "PAY_PER_REQUEST"},
                "KeySchema": [{"AttributeName": "repair_id", "KeyType": "HASH"}],
                "AttributeDefinitions": [
                    {"AttributeName": "repair_id", "AttributeType": "S"}
                ],
                "DeletionProtectionEnabled": True,
                "TableClassSummary": {"TableClass": "STANDARD"},
                "SSEDescription": {
                    "Status": "ENABLED",
                    "SSEType": "KMS",
                    "KMSMasterKeyArn": KMS_ARN,
                },
                "LocalSecondaryIndexes": [],
                "GlobalSecondaryIndexes": [],
                "Replicas": [],
                "GlobalTableWitnesses": [],
                "LatestStreamArn": "",
                "LatestStreamLabel": "",
                "StreamSpecification": {"StreamEnabled": False},
            }
        },
        "backups": {
            "ContinuousBackupsDescription": {
                "ContinuousBackupsStatus": "ENABLED",
                "PointInTimeRecoveryDescription": {
                    "PointInTimeRecoveryStatus": "ENABLED",
                    "RecoveryPeriodInDays": 35,
                },
            }
        },
        "ttl": {
            "TimeToLiveDescription": {"TimeToLiveStatus": "DISABLED"}
        },
        "resource_policy": {
            "Policy": json.dumps(
                {"Version": "2012-10-17", "Statement": statements}
            )
        },
        "key": {
            "KeyMetadata": {
                "AWSAccountId": "042360977644",
                "KeyId": "11111111-2222-3333-4444-555555555555",
                "Arn": KMS_ARN,
                "Enabled": True,
                "Description": "GUG-221 retained repair-ledger encryption key",
                "KeyUsage": "ENCRYPT_DECRYPT",
                "KeyState": "Enabled",
                "Origin": "AWS_KMS",
                "KeyManager": "CUSTOMER",
                "CustomerMasterKeySpec": "SYMMETRIC_DEFAULT",
                "KeySpec": "SYMMETRIC_DEFAULT",
                "EncryptionAlgorithms": ["SYMMETRIC_DEFAULT"],
                "MultiRegion": False,
                "ExpirationModel": "KEY_MATERIAL_DOES_NOT_EXPIRE",
            }
        },
        "rotation": {
            "KeyId": "11111111-2222-3333-4444-555555555555",
            "KeyRotationEnabled": True,
            "RotationPeriodInDays": 365,
            "NextRotationDate": datetime(2027, 7, 21, tzinfo=timezone.utc),
        },
        "key_policy": {
            "PolicyName": "default",
            "Policy": json.dumps(runtime._expected_repair_ledger_key_policy()),
        },
        "key_aliases": {
            "Aliases": [
                {
                    "AliasName": runtime.REPAIR_LEDGER_KEY_ALIAS,
                    "AliasArn": (
                        "arn:aws:kms:us-east-1:042360977644:"
                        + runtime.REPAIR_LEDGER_KEY_ALIAS
                    ),
                    "TargetKeyId": "11111111-2222-3333-4444-555555555555",
                    "CreationDate": datetime(2026, 7, 21, tzinfo=timezone.utc),
                    "LastUpdatedDate": datetime(2026, 7, 21, tzinfo=timezone.utc),
                }
            ],
            "Truncated": False,
        },
        "key_tags": {
            "Tags": [
                {"TagKey": key, "TagValue": value}
                for key, value in sorted(runtime.REPAIR_LEDGER_KEY_TAGS.items())
            ],
            "Truncated": False,
        },
    }


class FakeLambda:
    def __init__(self, state: dict[str, Any], calls: list[tuple[str, dict[str, Any]]]) -> None:
        self.state = state
        self.calls = calls

    def _call(self, name: str, kwargs: dict[str, Any]) -> None:
        self.calls.append((name, kwargs))

    @staticmethod
    def _page(
        pages: list[list[dict[str, Any]]], kwargs: dict[str, Any], key: str
    ) -> dict[str, Any]:
        index = int(kwargs.get("Marker", "0"))
        response: dict[str, Any] = {key: deepcopy(pages[index])}
        if index + 1 < len(pages):
            response["NextMarker"] = str(index + 1)
        return response

    def get_alias(self, **kwargs: Any) -> dict[str, Any]:
        self._call("lambda:GetAlias", kwargs)
        return deepcopy(self.state["aliases"][(kwargs["FunctionName"], kwargs["Name"])])

    def list_aliases(self, **kwargs: Any) -> dict[str, Any]:
        self._call("lambda:ListAliases", kwargs)
        function_name = kwargs["FunctionName"]
        pages = self.state.get("alias_inventory_pages", {}).get(function_name)
        if pages is not None:
            return self._page(pages, kwargs, "Aliases")
        return {"Aliases": deepcopy(self.state["alias_inventory"][function_name])}

    def list_functions(self, **kwargs: Any) -> dict[str, Any]:
        self._call("lambda:ListFunctions", kwargs)
        pages = self.state.get("function_inventory_pages")
        if pages is not None:
            return self._page(pages, kwargs, "Functions")
        return {"Functions": deepcopy(self.state["function_inventory"])}

    def list_versions_by_function(self, **kwargs: Any) -> dict[str, Any]:
        self._call("lambda:ListVersionsByFunction", kwargs)
        function_name = kwargs["FunctionName"]
        pages = self.state.get("version_pages", {}).get(function_name)
        if pages is not None:
            return self._page(pages, kwargs, "Versions")
        return {"Versions": deepcopy(self.state["versions"][function_name])}

    def get_function_configuration(self, **kwargs: Any) -> dict[str, Any]:
        self._call("lambda:GetFunctionConfiguration", kwargs)
        return deepcopy(
            self.state["functions"][
                (kwargs["FunctionName"], kwargs.get("Qualifier"))
            ]
        )

    def get_function_code_signing_config(self, **kwargs: Any) -> dict[str, Any]:
        self._call("lambda:GetFunctionCodeSigningConfig", kwargs)
        return deepcopy(self.state["associations"][kwargs["FunctionName"]])

    def get_code_signing_config(self, **kwargs: Any) -> dict[str, Any]:
        self._call("lambda:GetCodeSigningConfig", kwargs)
        return deepcopy(self.state["csc"])

    def get_function_concurrency(self, **kwargs: Any) -> dict[str, Any]:
        self._call("lambda:GetFunctionConcurrency", kwargs)
        return deepcopy(self.state["concurrency"][kwargs["FunctionName"]])

    def get_function_event_invoke_config(self, **kwargs: Any) -> dict[str, Any]:
        self._call("lambda:GetFunctionEventInvokeConfig", kwargs)
        key = (kwargs["FunctionName"], kwargs.get("Qualifier"))
        if key not in self.state["events"]:
            raise ProviderError("ResourceNotFoundException")
        return deepcopy(self.state["events"][key])

    def get_policy(self, **kwargs: Any) -> dict[str, Any]:
        self._call("lambda:GetPolicy", kwargs)
        key = (kwargs["FunctionName"], kwargs.get("Qualifier"))
        if self.state["absence_error"]:
            raise ProviderError(self.state["absence_error"])
        if key in self.state["policy_present"]:
            return {"Policy": "{}"}
        raise ProviderError("ResourceNotFoundException")

    def get_function_url_config(self, **kwargs: Any) -> dict[str, Any]:
        self._call("lambda:GetFunctionUrlConfig", kwargs)
        key = (kwargs["FunctionName"], kwargs.get("Qualifier"))
        if self.state["absence_error"]:
            raise ProviderError(self.state["absence_error"])
        if key in self.state["url_present"]:
            return {"FunctionUrl": "https://example.invalid"}
        raise ProviderError("ResourceNotFoundException")

    def list_event_source_mappings(self, **kwargs: Any) -> dict[str, Any]:
        self._call("lambda:ListEventSourceMappings", kwargs)
        function_name = kwargs["FunctionName"].split(":", 1)[0]
        return {"EventSourceMappings": deepcopy(self.state["event_sources"][function_name])}


class FakeDynamo:
    def __init__(self, state: dict[str, Any], calls: list[tuple[str, dict[str, Any]]]) -> None:
        self.state = state
        self.calls = calls

    def _result(self, action: str, key: str, kwargs: dict[str, Any]) -> dict[str, Any]:
        self.calls.append((action, kwargs))
        return deepcopy(self.state[key])

    def describe_table(self, **kwargs: Any) -> dict[str, Any]:
        return self._result("dynamodb:DescribeTable", "table", kwargs)

    def describe_continuous_backups(self, **kwargs: Any) -> dict[str, Any]:
        return self._result("dynamodb:DescribeContinuousBackups", "backups", kwargs)

    def describe_time_to_live(self, **kwargs: Any) -> dict[str, Any]:
        return self._result("dynamodb:DescribeTimeToLive", "ttl", kwargs)

    def get_resource_policy(self, **kwargs: Any) -> dict[str, Any]:
        return self._result("dynamodb:GetResourcePolicy", "resource_policy", kwargs)


class FakeKms:
    def __init__(self, state: dict[str, Any], calls: list[tuple[str, dict[str, Any]]]) -> None:
        self.state = state
        self.calls = calls

    def describe_key(self, **kwargs: Any) -> dict[str, Any]:
        self.calls.append(("kms:DescribeKey", kwargs))
        return deepcopy(self.state["key"])

    def get_key_rotation_status(self, **kwargs: Any) -> dict[str, Any]:
        self.calls.append(("kms:GetKeyRotationStatus", kwargs))
        return deepcopy(self.state["rotation"])

    def get_key_policy(self, **kwargs: Any) -> dict[str, Any]:
        self.calls.append(("kms:GetKeyPolicy", kwargs))
        return deepcopy(self.state["key_policy"])

    def list_aliases(self, **kwargs: Any) -> dict[str, Any]:
        self.calls.append(("kms:ListAliases", kwargs))
        return deepcopy(self.state["key_aliases"])

    def list_resource_tags(self, **kwargs: Any) -> dict[str, Any]:
        self.calls.append(("kms:ListResourceTags", kwargs))
        return deepcopy(self.state["key_tags"])


def adapter_for(state: dict[str, Any]) -> tuple[runtime.AwsLocalControlPlaneAdapter, list[tuple[str, dict[str, Any]]]]:
    calls: list[tuple[str, dict[str, Any]]] = []
    return (
        runtime.AwsLocalControlPlaneAdapter(
            lambda_client=FakeLambda(state, calls),
            dynamodb=FakeDynamo(state, calls),
            kms=FakeKms(state, calls),
        ),
        calls,
    )


def _set(state: dict[str, Any], path: tuple[Any, ...], value: Any) -> None:
    current: Any = state
    for part in path[:-1]:
        current = current[part]
    current[path[-1]] = value


def test_local_control_plane_consumes_every_granted_read_with_exact_targets() -> None:
    config = config_for()
    adapter, calls = adapter_for(provider_state(config))

    observed = adapter.snapshot(config)

    runtime.validate_local_control_plane_snapshot(config, observed)
    effective_policy = json.loads(
        provider_state(config)["resource_policy"]["Policy"]
    )
    statements_by_sid = {
        statement["Sid"]: statement
        for statement in effective_policy["Statement"]
    }
    assert statements_by_sid["DenyPlanCreationOutsidePlanExecution"][
        "Action"
    ] == ["dynamodb:PutItem"]
    assert statements_by_sid["DenyPlanCreationOutsidePlanExecution"][
        "Condition"
    ]["ArnNotEquals"]["aws:PrincipalArn"] == runtime.PLAN_EXECUTION_ROLE_ARN
    assert statements_by_sid["DenyPlanConsumptionOutsideRepairExecution"][
        "Action"
    ] == ["dynamodb:UpdateItem"]
    assert statements_by_sid["DenyPlanConsumptionOutsideRepairExecution"][
        "Condition"
    ]["ArnNotEquals"]["aws:PrincipalArn"] == runtime.REPAIR_EXECUTION_ROLE_ARN
    assert runtime.READ_EXECUTION_ROLE_ARN not in json.dumps(effective_policy)
    actions = [action for action, _ in calls]
    assert actions.count("lambda:GetAlias") == 3
    assert actions.count("lambda:ListFunctions") == 1
    assert actions.count("lambda:ListVersionsByFunction") == 3
    assert actions.count("lambda:ListAliases") == 3
    assert actions.count("lambda:GetFunctionConfiguration") == 6
    assert actions.count("lambda:GetFunctionCodeSigningConfig") == 3
    assert actions.count("lambda:GetCodeSigningConfig") == 1
    assert actions.count("lambda:GetFunctionConcurrency") == 3
    assert actions.count("lambda:GetFunctionEventInvokeConfig") == 9
    assert actions.count("lambda:GetPolicy") == 12
    assert actions.count("lambda:GetFunctionUrlConfig") == 6
    assert actions.count("lambda:ListEventSourceMappings") == 12
    assert actions.count("dynamodb:DescribeTable") == 1
    assert actions.count("dynamodb:DescribeContinuousBackups") == 1
    assert actions.count("dynamodb:DescribeTimeToLive") == 1
    assert actions.count("dynamodb:GetResourcePolicy") == 1
    assert actions.count("kms:DescribeKey") == 1
    assert actions.count("kms:GetKeyRotationStatus") == 1
    assert actions.count("kms:GetKeyPolicy") == 1
    assert actions.count("kms:ListAliases") == 1
    assert actions.count("kms:ListResourceTags") == 1
    configuration_calls = [
        kwargs for action, kwargs in calls if action == "lambda:GetFunctionConfiguration"
    ]
    assert {item.get("Qualifier") for item in configuration_calls} == {
        None,
        "repair-v1",
        "plan-v1",
        "reconcile-v1",
    }
    list_functions_call = next(
        kwargs for action, kwargs in calls if action == "lambda:ListFunctions"
    )
    assert list_functions_call == {"FunctionVersion": "ALL", "MaxItems": 50}
    for action, kwargs in calls:
        if action.startswith("dynamodb:Describe"):
            assert kwargs["TableName"] == TABLE_ARN
        if action in {
            "kms:DescribeKey",
            "kms:GetKeyRotationStatus",
        }:
            assert kwargs == {"KeyId": KMS_ARN}
        if action == "kms:GetKeyPolicy":
            assert kwargs == {"KeyId": KMS_ARN, "PolicyName": "default"}
        if action == "kms:ListAliases":
            assert kwargs == {"KeyId": KMS_ARN, "Limit": 100}
        if action == "kms:ListResourceTags":
            assert kwargs == {"KeyId": KMS_ARN, "Limit": 50}


def test_lambda_function_version_and_alias_inventories_are_fully_paginated() -> None:
    config = config_for()
    state = provider_state(config)
    state["function_inventory_pages"] = [
        state["function_inventory"][:1],
        state["function_inventory"][1:],
    ]
    state["version_pages"] = {
        function_name: [[items[0]], [items[1]]]
        for function_name, items in state["versions"].items()
    }
    state["alias_inventory_pages"] = {
        REPAIR: [[state["alias_inventory"][REPAIR][0]]],
        PLAN: [[], [state["alias_inventory"][PLAN][0]]],
        RECONCILE: [[state["alias_inventory"][RECONCILE][0]]],
    }
    adapter, calls = adapter_for(state)

    adapter.snapshot(config)

    assert any(
        action == "lambda:ListFunctions" and kwargs.get("Marker") == "1"
        for action, kwargs in calls
    )
    assert sum(
        action == "lambda:ListVersionsByFunction" and kwargs.get("Marker") == "1"
        for action, kwargs in calls
    ) == 3
    assert any(
        action == "lambda:ListAliases"
        and kwargs["FunctionName"] == PLAN
        and kwargs.get("Marker") == "1"
        for action, kwargs in calls
    )


def test_foreign_function_cannot_reuse_repair_execution_role() -> None:
    config = config_for()
    state = provider_state(config)
    foreign = deepcopy(state["function_inventory"][0])
    foreign["FunctionName"] = "foreign-alternate-pep"
    foreign["FunctionArn"] = (
        "arn:aws:lambda:us-east-1:042360977644:function:foreign-alternate-pep"
    )
    state["function_inventory"].append(foreign)
    adapter, _ = adapter_for(state)

    with pytest.raises(BrokerContractError) as captured:
        adapter.snapshot(config)

    assert captured.value.code == "LAMBDA_EXECUTION_ROLE_REUSED"


def test_extra_published_version_is_rejected_before_surface_use() -> None:
    config = config_for()
    state = provider_state(config)
    foreign = deepcopy(state["versions"][REPAIR][1])
    foreign["Version"] = "41"
    foreign["FunctionArn"] = (
        "arn:aws:lambda:us-east-1:042360977644:function:"
        f"{REPAIR}:41"
    )
    state["function_inventory"].append(foreign)
    state["versions"][REPAIR].append(foreign)
    adapter, _ = adapter_for(state)

    with pytest.raises(BrokerContractError) as captured:
        adapter.snapshot(config)

    assert captured.value.code == "LAMBDA_ALTERNATE_PEP_PRESENT"


def test_extra_alias_is_rejected_before_it_can_become_an_invocation_surface() -> None:
    config = config_for()
    state = provider_state(config)
    foreign = deepcopy(state["alias_inventory"][REPAIR][0])
    foreign["Name"] = "foreign-v1"
    foreign["AliasArn"] = (
        "arn:aws:lambda:us-east-1:042360977644:function:"
        f"{REPAIR}:foreign-v1"
    )
    state["alias_inventory"][REPAIR].append(foreign)
    adapter, _ = adapter_for(state)

    with pytest.raises(BrokerContractError) as captured:
        adapter.snapshot(config)

    assert captured.value.code == "LAMBDA_ALTERNATE_PEP_PRESENT"


def test_latest_code_must_equal_the_reviewed_published_artifact() -> None:
    config = config_for()
    state = provider_state(config)
    state["functions"][(REPAIR, None)]["CodeSha256"] = "B" * 43 + "="
    adapter, _ = adapter_for(state)

    with pytest.raises(BrokerContractError) as captured:
        adapter.snapshot(config)

    assert captured.value.code == "LAMBDA_CONFIGURATION_CHANGED"


@pytest.mark.parametrize("qualifier", [None, "42"])
def test_unreviewed_async_configuration_is_rejected(
    qualifier: str | None,
) -> None:
    config = config_for()
    state = provider_state(config)
    state["events"][(REPAIR, qualifier)] = {
        "FunctionArn": (
            f"arn:aws:lambda:us-east-1:042360977644:function:{REPAIR}"
        ),
        "MaximumRetryAttempts": 0,
        "MaximumEventAgeInSeconds": 60,
        "DestinationConfig": {},
    }
    adapter, _ = adapter_for(state)

    with pytest.raises(BrokerContractError) as captured:
        adapter.snapshot(config)

    assert captured.value.code == "LAMBDA_ASYNC_CONFIGURATION_CHANGED"


@pytest.mark.parametrize(
    ("path", "value"),
    [
        (("aliases", REPAIR_ALIAS, "FunctionVersion"), "$LATEST"),
        (("aliases", PLAN_ALIAS, "FunctionVersion"), "44"),
        (("aliases", REPAIR_ALIAS, "AliasArn"), "arn:aws:lambda:foreign"),
        (("aliases", REPAIR_ALIAS, "RoutingConfig"), {"AdditionalVersionWeights": {"41": 0.1}}),
        (("functions", REPAIR_ALIAS, "CodeSha256"), "B" * 43 + "="),
        (("functions", REPAIR_ALIAS, "Runtime"), "python3.13"),
        (("functions", REPAIR_ALIAS, "Role"), "arn:aws:iam::042360977644:role/Admin"),
        (("functions", REPAIR_ALIAS, "Handler"), "foreign.handler"),
        (("functions", REPAIR_ALIAS, "Description"), "foreign"),
        (("functions", REPAIR_ALIAS, "State"), "Pending"),
        (("functions", REPAIR_ALIAS, "LastUpdateStatus"), "InProgress"),
        (("functions", REPAIR_ALIAS, "PackageType"), "Image"),
        (("functions", REPAIR_ALIAS, "Architectures"), ["arm64"]),
        (("functions", REPAIR_ALIAS, "SigningProfileVersionArn"), SIGNER_ARN[:-1] + "Z"),
        (("functions", REPAIR_ALIAS, "Environment", "Error"), {"ErrorCode": "KMSAccessDenied"}),
        (("functions", REPAIR_ALIAS, "Environment", "Variables", "FOREIGN"), "true"),
        (("associations", REPAIR, "CodeSigningConfigArn"), CSC_ARN[:-1] + "1"),
        (("csc", "CodeSigningConfig", "AllowedPublishers", "SigningProfileVersionArns"), []),
        (("csc", "CodeSigningConfig", "AllowedPublishers", "SigningProfileVersionArns"), [SIGNER_ARN, SIGNER_ARN[:-1] + "Z"]),
        (("csc", "CodeSigningConfig", "CodeSigningPolicies", "UntrustedArtifactOnDeployment"), "Warn"),
        (("concurrency", REPAIR, "ReservedConcurrentExecutions"), 0),
        (("concurrency", REPAIR, "ReservedConcurrentExecutions"), True),
        (("events", REPAIR_ALIAS, "MaximumRetryAttempts"), 1),
        (("events", REPAIR_ALIAS, "MaximumEventAgeInSeconds"), 61),
        (("events", REPAIR_ALIAS, "DestinationConfig"), {"OnFailure": {"Destination": "arn:aws:sqs:foreign"}}),
        (("table", "Table", "TableArn"), TABLE_ARN + "-foreign"),
        (("table", "Table", "TableStatus"), "UPDATING"),
        (("table", "Table", "BillingModeSummary", "BillingMode"), "PROVISIONED"),
        (("table", "Table", "KeySchema"), [{"AttributeName": "other", "KeyType": "HASH"}]),
        (("table", "Table", "AttributeDefinitions"), [{"AttributeName": "repair_id", "AttributeType": "N"}]),
        (("table", "Table", "DeletionProtectionEnabled"), False),
        (("table", "Table", "TableClassSummary", "TableClass"), "STANDARD_INFREQUENT_ACCESS"),
        (("table", "Table", "SSEDescription", "KMSMasterKeyArn"), KMS_ARN[:-1] + "6"),
        (("table", "Table", "GlobalSecondaryIndexes"), [{"IndexName": "foreign"}]),
        (("table", "Table", "StreamSpecification"), {"StreamEnabled": True}),
        (("table", "Table", "Replicas"), [{"RegionName": "us-west-2"}]),
        (("backups", "ContinuousBackupsDescription", "ContinuousBackupsStatus"), "DISABLED"),
        (("backups", "ContinuousBackupsDescription", "PointInTimeRecoveryDescription", "PointInTimeRecoveryStatus"), "DISABLED"),
        (("backups", "ContinuousBackupsDescription", "PointInTimeRecoveryDescription", "RecoveryPeriodInDays"), 34),
        (("ttl", "TimeToLiveDescription", "TimeToLiveStatus"), "ENABLED"),
        (("ttl", "TimeToLiveDescription", "AttributeName"), "effects_attempted"),
        (("key", "KeyMetadata", "AWSAccountId"), "999999999999"),
        (("key", "KeyMetadata", "Arn"), KMS_ARN[:-1] + "6"),
        (("key", "KeyMetadata", "Enabled"), False),
        (("key", "KeyMetadata", "KeyState"), "PendingDeletion"),
        (("key", "KeyMetadata", "KeyUsage"), "SIGN_VERIFY"),
        (("key", "KeyMetadata", "Origin"), "EXTERNAL"),
        (("key", "KeyMetadata", "KeyManager"), "AWS"),
        (("key", "KeyMetadata", "KeySpec"), "RSA_2048"),
        (("key", "KeyMetadata", "MultiRegion"), True),
        (("key", "KeyMetadata", "EncryptionAlgorithms"), ["RSAES_OAEP_SHA_256"]),
        (("key", "KeyMetadata", "Description"), "foreign"),
        (("rotation", "KeyRotationEnabled"), False),
        (("rotation", "RotationPeriodInDays"), 90),
        (("rotation", "OnDemandRotationStartDate"), datetime(2026, 7, 21, tzinfo=timezone.utc)),
    ],
)
def test_any_local_control_plane_drift_fails_closed(
    path: tuple[Any, ...], value: Any
) -> None:
    config = config_for()
    state = provider_state(config)
    _set(state, path, value)
    adapter, _ = adapter_for(state)

    with pytest.raises(BrokerContractError):
        adapter.snapshot(config)


@pytest.mark.parametrize(
    "policy",
    [
        "not-json",
        '{"Version":"2012-10-17","Version":"2012-10-17","Statement":[]}',
        json.dumps({"Version": "2012-10-17", "Statement": []}),
        _weakened_ledger_policy(),
    ],
)
def test_malformed_duplicate_extra_or_weakened_ledger_policy_is_rejected(
    policy: str,
) -> None:
    config = config_for()
    state = provider_state(config)
    state["resource_policy"]["Policy"] = policy
    adapter, _ = adapter_for(state)
    with pytest.raises(BrokerContractError) as captured:
        adapter.snapshot(config)
    assert captured.value.code == "LEDGER_RESOURCE_POLICY_CHANGED"


@pytest.mark.parametrize("surface", ["policy_present", "url_present"])
def test_public_lambda_invocation_surface_is_rejected(surface: str) -> None:
    config = config_for()
    state = provider_state(config)
    state[surface].add((PLAN, "plan-v1"))
    adapter, _ = adapter_for(state)
    with pytest.raises(BrokerContractError) as captured:
        adapter.snapshot(config)
    assert captured.value.code == "LAMBDA_INVOCATION_SURFACE_PRESENT"


def test_numeric_version_resource_policy_is_rejected() -> None:
    config = config_for()
    state = provider_state(config)
    state["policy_present"].add((REPAIR, "42"))
    adapter, _ = adapter_for(state)
    with pytest.raises(BrokerContractError) as captured:
        adapter.snapshot(config)
    assert captured.value.code == "LAMBDA_INVOCATION_SURFACE_PRESENT"


def test_lambda_invocation_surface_access_denied_is_not_treated_as_absence() -> None:
    config = config_for()
    state = provider_state(config)
    state["absence_error"] = "AccessDeniedException"
    adapter, _ = adapter_for(state)
    with pytest.raises(BrokerContractError) as captured:
        adapter.snapshot(config)
    assert captured.value.code == "LAMBDA_INVOCATION_SURFACE_READ_FAILED"


def test_event_source_mapping_is_rejected() -> None:
    config = config_for()
    state = provider_state(config)
    state["event_sources"][REPAIR] = [{"UUID": "foreign"}]
    adapter, _ = adapter_for(state)
    with pytest.raises(BrokerContractError) as captured:
        adapter.snapshot(config)
    assert captured.value.code == "LAMBDA_EVENT_SOURCE_PRESENT"
