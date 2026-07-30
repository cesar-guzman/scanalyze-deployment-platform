"""Direct-provider effective-state regressions for GUG-221 Phase B."""

from __future__ import annotations

import ast
from copy import deepcopy
from datetime import UTC, datetime
import json
from pathlib import Path
import sys
from typing import Any, Mapping

from jsonschema import Draft202012Validator, FormatChecker
import pytest


ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import tooling.platform_authority_lambda_audit_repair_effective_state as module  # noqa: E402
import tooling.platform_authority_lambda_audit_repair_change_set as change_set_module  # noqa: E402


FIXTURES = ROOT / "tests/test_deployment/fixtures/gug221_effective_state"
SCHEMA = (
    ROOT / "schemas/"
    "platform-authority-lambda-audit-repair-effective-state.v1.schema.json"
)
KEY_ID = "11111111-2222-4333-8444-555555555555"
KEY_ARN = "arn:aws:kms:us-east-1:042360977644:key/" + KEY_ID
CSC_ID = "csc-1234567890abcdef0"
CSC_ARN = f"arn:aws:lambda:us-east-1:042360977644:code-signing-config:{CSC_ID}"
SIGNER_ARN = (
    "arn:aws:signer:us-east-1:042360977644:/signing-profiles/ScanalyzeGug221/ABCDEFGHIJ"
)
SIGNING_JOB_ARN = (
    "arn:aws:signer:us-east-1:042360977644:/signing-jobs/"
    "11111111-2222-4333-8444-555555555555"
)
TABLE_ARN = "arn:aws:dynamodb:us-east-1:042360977644:table/" + module.TABLE_NAME
VERSIONS = {
    module.PLAN_FUNCTION_NAME: "41",
    module.RECONCILE_FUNCTION_NAME: "42",
    module.REPAIR_FUNCTION_NAME: "43",
}
ALIASES = {
    module.PLAN_FUNCTION_NAME: module.PLAN_ALIAS_NAME,
    module.RECONCILE_FUNCTION_NAME: module.RECONCILE_ALIAS_NAME,
    module.REPAIR_FUNCTION_NAME: module.REPAIR_ALIAS_NAME,
}
ROLES = {
    module.PLAN_FUNCTION_NAME: module.PLAN_ROLE_NAME,
    module.RECONCILE_FUNCTION_NAME: module.RECONCILE_ROLE_NAME,
    module.REPAIR_FUNCTION_NAME: module.REPAIR_ROLE_NAME,
}


def _reviewed_template_bytes() -> bytes:
    return (
        ROOT
        / "bootstrap/cfn-platform-authority-lambda-audit-repair-pep.yaml"
    ).read_bytes()


def _pep_parameter_values() -> dict[str, str]:
    return {
        "AuthorityAccountId": module.AUTHORITY_ACCOUNT_ID,
        "ManagementAccountId": "839393571433",
        "SourceCommit": "1" * 40,
        "RepairId": "gug221-" + ("2" * 64),
        "PrincipalId": "11111111-2222-4333-8444-555555555555",
        "IdentityStoreId": "d-1234567890",
        "IdentityCenterInstanceArn": (
            "arn:aws:sso:::instance/ssoins-1234567890ABCDEF"
        ),
        "CollectorPermissionSetArn": (
            "arn:aws:sso:::permissionSet/"
            "ssoins-1234567890ABCDEF/ps-1234567890ABCDEF"
        ),
        "RepairInvokerPermissionSetArn": (
            "arn:aws:sso:::permissionSet/"
            "ssoins-1234567890ABCDEF/ps-abcdef0123456789"
        ),
        "CollectorPolicyDigest": "3" * 64,
        "RepairInvokerPolicyDigest": "4" * 64,
        "OriginalGug220LedgerDigest": "5" * 64,
        "ExpectedPermissionSetTagsJson": (
            '{"environment":"non-production","work_package":"GUG-221"}'
        ),
        "RepairNotBefore": "2026-07-23T12:30:00Z",
        "RepairNotAfter": "2026-07-23T12:45:00Z",
        "CollectorSamlProviderArn": (
            "arn:aws:iam::042360977644:saml-provider/"
            "AWSSSO_synthetic_DO_NOT_DELETE"
        ),
        "IdentityCenterKmsMode": "AWS_OWNED_KMS_KEY",
        "IdentityCenterKmsKeyArn": "",
        "ExpectedBoto3Version": "1.39.0",
        "ExpectedBotocoreVersion": "1.39.0",
        "RepairArtifactBucket": "scanalyze-gug221-repair-artifacts",
        "RepairArtifactKey": (
            "scanalyze/platform-authority/gug-221/signed/"
            "11111111-2222-4333-8444-555555555555.zip"
        ),
        "RepairArtifactVersion": "repair-version",
        "RepairArtifactCodeSha256": "A" * 43 + "=",
        "ReconcileArtifactBucket": "scanalyze-gug221-reconcile-artifacts",
        "ReconcileArtifactKey": (
            "scanalyze/platform-authority/gug-221/signed/"
            "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee.zip"
        ),
        "ReconcileArtifactVersion": "reconcile-version",
        "ReconcileArtifactCodeSha256": "A" * 43 + "=",
        "SigningProfileVersionArn": SIGNER_ARN,
    }


def _pep_handoff() -> dict[str, Any]:
    template = _reviewed_template_bytes()
    values = _pep_parameter_values()
    return {
        "artifact_type": (
            "scanalyze.platform_authority.lambda_audit_repair_pep_parameters.v1"
        ),
        "schema_version": 1,
        "work_package": module.WORK_PACKAGE,
        "source_commit": values["SourceCommit"],
        "template_sha256": module.sha256(template).hexdigest(),
        "parameters": [
            {"ParameterKey": key, "ParameterValue": values[key]}
            for key in module.TEMPLATE_PARAMETER_KEYS
        ],
    }


class ProviderError(RuntimeError):
    def __init__(self, code: str) -> None:
        super().__init__("redacted provider error")
        self.response = {"Error": {"Code": code}}


def _physical_ids() -> dict[str, str]:
    result: dict[str, str] = {
        **module.ROLE_NAMES,
        **module.FUNCTION_NAMES,
        **module.LOG_GROUP_NAMES,
        "RepairCodeSigningConfig": CSC_ARN,
        "RepairLedger": module.TABLE_NAME,
        "RepairLedgerKey": KEY_ID,
        "RepairLedgerKeyAlias": module.KMS_ALIAS_NAME,
    }
    for logical_id, function_name in module.VERSION_FUNCTIONS.items():
        result[logical_id] = (
            "arn:aws:lambda:us-east-1:042360977644:function:"
            f"{function_name}:{VERSIONS[function_name]}"
        )
    for logical_id, (function_name, alias_name) in module.ALIAS_BINDINGS.items():
        result[logical_id] = (
            "arn:aws:lambda:us-east-1:042360977644:function:"
            f"{function_name}:{alias_name}"
        )
    for logical_id, (_, alias_name) in module.EVENT_INVOKE_BINDINGS.items():
        result[logical_id] = f"opaque-event-config-{alias_name}"
    assert set(result) == set(module.RESOURCE_LOGICAL_IDS)
    assert len(set(result.values())) == 23
    return result


def _phase_b_receipt(
    physical_ids: dict[str, str] | None = None,
) -> dict[str, Any]:
    physical = physical_ids or _physical_ids()
    resources = [
        {
            "logical_resource_id": logical_id,
            "resource_type": module.EXPECTED_RESOURCE_TYPES[logical_id],
            "physical_resource_id_sha256": module._text_digest(physical[logical_id]),
        }
        for logical_id in module.RESOURCE_LOGICAL_IDS
    ]
    return {
        "artifact_type": module.PHASE_B_EXECUTION_ARTIFACT_TYPE,
        "schema_version": 1,
        "work_package": module.WORK_PACKAGE,
        "phase": "B_PEP_EXECUTION_TRACE",
        "source_commit": "1" * 40,
        "stack_resources": resources,
        "stack_resources_sha256": module.canonical_digest(resources),
        "evidence_status": "CLOUDFORMATION_EXECUTION_TRACE_VERIFIED",
        "authority_status": "TRACE_ONLY_NOT_PROVIDER_STATE",
        "production_status": "NO-GO",
    }


def _expected_contract(logical_id: str) -> Mapping[str, Any]:
    return module._expected_resource_contracts(
        reviewed_template_bytes=_reviewed_template_bytes(),
        pep_parameter_handoff=_pep_handoff(),
        physical_ids=_physical_ids(),
    )[logical_id]


def _role_logical_id(role_name: str) -> str:
    matches = [
        logical_id
        for logical_id, expected_name in module.ROLE_NAMES.items()
        if expected_name == role_name
    ]
    assert len(matches) == 1
    return matches[0]


class Calls:
    def __init__(self) -> None:
        self.items: list[tuple[str, dict[str, Any]]] = []

    def add(self, method: str, kwargs: dict[str, Any]) -> None:
        self.items.append((method, deepcopy(kwargs)))


class FakeIam:
    def __init__(
        self,
        calls: Calls,
        *,
        pagination_mode: str | None = None,
        stable_drift: str | None = None,
    ) -> None:
        self.calls = calls
        self.pagination_mode = pagination_mode
        self.stable_drift = stable_drift

    def get_role(self, **kwargs: Any) -> dict[str, Any]:
        self.calls.add("get_role", kwargs)
        role_name = kwargs["RoleName"]
        contract = _expected_contract(_role_logical_id(role_name))
        result = {
            "Role": {
                "Path": contract["path"],
                "RoleName": role_name,
                "RoleId": (
                    "AROA" + module._text_digest(role_name)[:16].upper()
                ),
                "Arn": contract["arn"],
                "MaxSessionDuration": contract["max_session_duration"],
                "AssumeRolePolicyDocument": contract[
                    "assume_role_policy"
                ],
                "RoleLastUsed": {
                    "LastUsedDate": datetime.now(UTC),
                    "Region": "us-east-1",
                },
            }
        }
        if (
            self.stable_drift == "iam_trust"
            and role_name == module.INSPECTOR_ROLE_NAME
        ):
            result["Role"]["AssumeRolePolicyDocument"] = {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"AWS": "*"},
                        "Action": "sts:AssumeRole",
                    }
                ],
            }
        if (
            self.stable_drift == "iam_permission_boundary"
            and role_name == module.PLAN_ROLE_NAME
        ):
            result["Role"]["PermissionsBoundary"] = {
                "PermissionsBoundaryType": "Policy",
                "PermissionsBoundaryArn": (
                    "arn:aws:iam::042360977644:policy/foreign"
                ),
            }
        if (
            self.stable_drift == "iam_role_id_shape"
            and role_name == module.PLAN_ROLE_NAME
        ):
            result["Role"]["RoleId"] = "foreign-role-id"
        return result

    def list_role_policies(self, **kwargs: Any) -> dict[str, Any]:
        self.calls.add("list_role_policies", kwargs)
        mode = self.pagination_mode
        marker = kwargs.get("Marker")
        contract = _expected_contract(_role_logical_id(kwargs["RoleName"]))
        policy_name = contract["inline_policies"][0]["policy_name"]
        if mode == "two_pages":
            if marker is None:
                return {
                    "PolicyNames": [],
                    "IsTruncated": True,
                    "Marker": "next",
                }
            return {
                "PolicyNames": [policy_name],
                "IsTruncated": False,
            }
        if mode == "empty_token":
            return {
                "PolicyNames": [policy_name],
                "IsTruncated": True,
                "Marker": "",
            }
        if mode == "repeat_token":
            return {
                "PolicyNames": [policy_name + ("A" if marker is None else "B")],
                "IsTruncated": True,
                "Marker": "same",
            }
        if mode == "incoherent":
            return {
                "PolicyNames": [policy_name],
                "IsTruncated": False,
                "Marker": "unexpected",
            }
        if mode == "duplicate":
            if marker is None:
                return {
                    "PolicyNames": [policy_name],
                    "IsTruncated": True,
                    "Marker": "next",
                }
            return {
                "PolicyNames": [policy_name],
                "IsTruncated": False,
            }
        if mode == "page_limit":
            index = int(marker or "0")
            return {
                "PolicyNames": [f"Inline{index}"],
                "IsTruncated": True,
                "Marker": str(index + 1),
            }
        return {
            "PolicyNames": [policy_name],
            "IsTruncated": False,
        }

    def get_role_policy(self, **kwargs: Any) -> dict[str, Any]:
        self.calls.add("get_role_policy", kwargs)
        contract = _expected_contract(
            _role_logical_id(kwargs["RoleName"])
        )
        matches = [
            item
            for item in contract["inline_policies"]
            if item["policy_name"] == kwargs["PolicyName"]
        ]
        assert len(matches) == 1
        result = {
            "RoleName": kwargs["RoleName"],
            "PolicyName": kwargs["PolicyName"],
            "PolicyDocument": matches[0]["document"],
        }
        if (
            self.stable_drift == "iam_inline"
            and kwargs["RoleName"] == module.PLAN_ROLE_NAME
        ):
            result["PolicyDocument"] = {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": "iam:*",
                        "Resource": "*",
                    }
                ],
            }
        return result

    def list_attached_role_policies(self, **kwargs: Any) -> dict[str, Any]:
        self.calls.add("list_attached_role_policies", kwargs)
        return {"AttachedPolicies": [], "IsTruncated": False}

    def list_role_tags(self, **kwargs: Any) -> dict[str, Any]:
        self.calls.add("list_role_tags", kwargs)
        contract = _expected_contract(
            _role_logical_id(kwargs["RoleName"])
        )
        return {
            "Tags": [
                {"Key": key, "Value": value}
                for key, value in contract["tags"].items()
            ],
            "IsTruncated": False,
        }

    def list_instance_profiles_for_role(self, **kwargs: Any) -> dict[str, Any]:
        self.calls.add("list_instance_profiles_for_role", kwargs)
        return {"InstanceProfiles": [], "IsTruncated": False}


def _function_configuration(
    function_name: str,
    version: str,
    *,
    memory_size: int | None = None,
) -> dict[str, Any]:
    if version == "$LATEST":
        logical_id = next(
            logical
            for logical, name in module.FUNCTION_NAMES.items()
            if name == function_name
        )
    else:
        logical_id = next(
            logical
            for logical, name in module.VERSION_FUNCTIONS.items()
            if name == function_name
        )
    configuration = _expected_contract(logical_id)["configuration"]
    return {
        "FunctionName": configuration["function_name"],
        "FunctionArn": configuration["function_arn"],
        "Runtime": configuration["runtime"],
        "Role": configuration["role"],
        "Handler": configuration["handler"],
        "Description": configuration["description"],
        "Timeout": configuration["timeout"],
        "MemorySize": (
            configuration["memory_size"]
            if memory_size is None
            else memory_size
        ),
        "CodeSha256": configuration["code_sha256"],
        "Version": configuration["version"],
        "State": configuration["state"],
        "LastUpdateStatus": configuration["last_update_status"],
        "PackageType": configuration["package_type"],
        "Architectures": configuration["architectures"],
        "Environment": configuration["environment"],
        "VpcConfig": {
            "SubnetIds": [],
            "SecurityGroupIds": [],
            "VpcId": "",
        },
        "DeadLetterConfig": {},
        "TracingConfig": {"Mode": "PassThrough"},
        "Layers": [],
        "FileSystemConfigs": [],
        "EphemeralStorage": {"Size": 512},
        "SnapStart": {
            "ApplyOn": "None",
            "OptimizationStatus": "Off",
        },
        "LoggingConfig": {
            "LogFormat": "Text",
            "LogGroup": f"/aws/lambda/{function_name}",
        },
        "SigningProfileVersionArn": SIGNER_ARN,
        "SigningJobArn": SIGNING_JOB_ARN,
    }


class FakeLambda:
    def __init__(
        self,
        calls: Calls,
        *,
        absence_error: str = "ResourceNotFoundException",
        missing_error: str | None = None,
        malformed: bool = False,
        drift: bool = False,
        stable_drift: str | None = None,
    ) -> None:
        self.calls = calls
        self.absence_error = absence_error
        self.missing_error = missing_error
        self.malformed = malformed
        self.drift = drift
        self.stable_drift = stable_drift
        self.configuration_calls = 0

    def get_alias(self, **kwargs: Any) -> dict[str, Any]:
        self.calls.add("get_alias", kwargs)
        name = kwargs["Name"]
        function_name = kwargs["FunctionName"]
        result = {
            "AliasArn": (
                f"arn:aws:lambda:us-east-1:042360977644:function:{function_name}:{name}"
            ),
            "Name": name,
            "FunctionVersion": VERSIONS[function_name],
            "Description": "",
            "RoutingConfig": {"AdditionalVersionWeights": {}},
            "RevisionId": "alias-revision",
        }
        if (
            self.stable_drift == "lambda_alias"
            and function_name == module.PLAN_FUNCTION_NAME
        ):
            result["FunctionVersion"] = "99"
        return result

    def list_aliases(self, **kwargs: Any) -> dict[str, Any]:
        self.calls.add("list_aliases", kwargs)
        aliases = [
            self.get_alias(
                FunctionName=kwargs["FunctionName"],
                Name=ALIASES[kwargs["FunctionName"]],
            )
        ]
        if (
            self.stable_drift == "lambda_extra_alias"
            and kwargs["FunctionName"] == module.PLAN_FUNCTION_NAME
        ):
            aliases.append(
                {
                    "AliasArn": (
                        "arn:aws:lambda:us-east-1:042360977644:function:"
                        f"{kwargs['FunctionName']}:foreign"
                    ),
                    "Name": "foreign",
                    "FunctionVersion": VERSIONS[kwargs["FunctionName"]],
                    "Description": "",
                    "RoutingConfig": {"AdditionalVersionWeights": {}},
                    "RevisionId": "foreign-revision",
                }
            )
        return {"Aliases": aliases}

    def get_policy(self, **kwargs: Any) -> dict[str, Any]:
        self.calls.add("get_policy", kwargs)
        raise ProviderError(self.absence_error)

    def get_function_event_invoke_config(self, **kwargs: Any) -> dict[str, Any]:
        self.calls.add("get_function_event_invoke_config", kwargs)
        return {
            "FunctionArn": (
                "arn:aws:lambda:us-east-1:042360977644:function:"
                f"{kwargs['FunctionName']}:{kwargs['Qualifier']}"
            ),
            "MaximumRetryAttempts": 0,
            "MaximumEventAgeInSeconds": 60,
            "DestinationConfig": {
                "OnSuccess": {},
                "OnFailure": {},
            },
        }

    def list_function_event_invoke_configs(self, **kwargs: Any) -> dict[str, Any]:
        self.calls.add("list_function_event_invoke_configs", kwargs)
        function_name = kwargs["FunctionName"]
        configs = [
            self.get_function_event_invoke_config(
                FunctionName=function_name,
                Qualifier=ALIASES[function_name],
            )
        ]
        if (
            self.stable_drift == "lambda_extra_event_invoke"
            and function_name == module.PLAN_FUNCTION_NAME
        ):
            configs.append(
                {
                    "FunctionArn": (
                        "arn:aws:lambda:us-east-1:042360977644:function:"
                        f"{function_name}:foreign"
                    ),
                    "MaximumRetryAttempts": 2,
                    "MaximumEventAgeInSeconds": 3600,
                    "DestinationConfig": {},
                }
            )
        return {"FunctionEventInvokeConfigs": configs}

    def get_function_configuration(self, **kwargs: Any) -> dict[str, Any]:
        self.calls.add("get_function_configuration", kwargs)
        if self.missing_error is not None:
            raise ProviderError(self.missing_error)
        self.configuration_calls += 1
        memory_size = (
            4096
            if self.drift and self.configuration_calls > 3
            else None
        )
        result = _function_configuration(
            kwargs["FunctionName"],
            "$LATEST",
            memory_size=memory_size,
        )
        if kwargs["FunctionName"] == module.PLAN_FUNCTION_NAME:
            field_by_drift = {
                "lambda_role": ("Role", "arn:aws:iam::042360977644:role/Foreign"),
                "lambda_runtime": ("Runtime", "python3.11"),
                "lambda_memory": ("MemorySize", 4096),
                "lambda_timeout": ("Timeout", 900),
            }
            mutation = field_by_drift.get(str(self.stable_drift))
            if mutation is not None:
                result[mutation[0]] = mutation[1]
            if self.stable_drift == "lambda_vpc":
                result["VpcConfig"] = {
                    "SubnetIds": ["subnet-0123456789abcdef0"],
                    "SecurityGroupIds": ["sg-0123456789abcdef0"],
                    "VpcId": "vpc-0123456789abcdef0",
                    "Ipv6AllowedForDualStack": False,
                }
            elif self.stable_drift == "lambda_dead_letter":
                result["DeadLetterConfig"] = {
                    "TargetArn": (
                        "arn:aws:sqs:us-east-1:042360977644:"
                        "foreign-dead-letter"
                    )
                }
            elif self.stable_drift == "lambda_kms":
                result["KMSKeyArn"] = (
                    "arn:aws:kms:us-east-1:042360977644:key/"
                    "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
                )
            elif self.stable_drift == "lambda_tracing":
                result["TracingConfig"] = {"Mode": "Active"}
            elif self.stable_drift == "lambda_layers":
                result["Layers"] = [
                    {
                        "Arn": (
                            "arn:aws:lambda:us-east-1:042360977644:"
                            "layer:foreign:1"
                        ),
                        "CodeSize": 1,
                    }
                ]
            elif self.stable_drift == "lambda_file_system":
                result["FileSystemConfigs"] = [
                    {
                        "Arn": (
                            "arn:aws:elasticfilesystem:us-east-1:"
                            "042360977644:access-point/fsap-0123456789abcdef0"
                        ),
                        "LocalMountPath": "/mnt/foreign",
                    }
                ]
            elif self.stable_drift == "lambda_image_config":
                result["ImageConfigResponse"] = {
                    "ImageConfig": {
                        "Command": ["foreign"],
                        "EntryPoint": [],
                        "WorkingDirectory": "/",
                    }
                }
            elif self.stable_drift == "lambda_ephemeral_storage":
                result["EphemeralStorage"] = {"Size": 10240}
            elif self.stable_drift == "lambda_snap_start":
                result["SnapStart"] = {
                    "ApplyOn": "PublishedVersions",
                    "OptimizationStatus": "On",
                }
            elif self.stable_drift == "lambda_runtime_version":
                result["RuntimeVersionConfig"] = {
                    "Error": {
                        "ErrorCode": "RuntimeVersionError",
                        "Message": "redacted",
                    }
                }
            elif self.stable_drift == "lambda_signing_profile":
                result["SigningProfileVersionArn"] = (
                    "arn:aws:signer:us-east-1:042360977644:"
                    "/signing-profiles/Foreign/ABCDEFGHIJ"
                )
            elif self.stable_drift == "lambda_master_arn":
                result["MasterArn"] = (
                    "arn:aws:lambda:us-east-1:042360977644:function:"
                    "foreign-master"
                )
            elif self.stable_drift == "lambda_signing_job_foreign":
                result["SigningJobArn"] = SIGNING_JOB_ARN.replace(
                    "042360977644", "999999999999"
                )
            elif self.stable_drift == "lambda_signing_job_missing":
                result.pop("SigningJobArn")
            elif self.stable_drift == "lambda_logging":
                result["LoggingConfig"] = {
                    "LogFormat": "JSON",
                    "ApplicationLogLevel": "DEBUG",
                    "SystemLogLevel": "DEBUG",
                    "LogGroup": "/aws/lambda/foreign",
                }
        if self.malformed:
            result.pop("State")
        return result

    def get_function_code_signing_config(self, **kwargs: Any) -> dict[str, Any]:
        self.calls.add("get_function_code_signing_config", kwargs)
        return {
            "FunctionName": kwargs["FunctionName"],
            "CodeSigningConfigArn": CSC_ARN,
        }

    def get_function_concurrency(self, **kwargs: Any) -> dict[str, Any]:
        self.calls.add("get_function_concurrency", kwargs)
        value = (
            2
            if self.stable_drift == "lambda_concurrency"
            and kwargs["FunctionName"] == module.PLAN_FUNCTION_NAME
            else 1
        )
        return {"ReservedConcurrentExecutions": value}

    def list_event_source_mappings(self, **kwargs: Any) -> dict[str, Any]:
        self.calls.add("list_event_source_mappings", kwargs)
        return {"EventSourceMappings": []}

    def list_versions_by_function(self, **kwargs: Any) -> dict[str, Any]:
        self.calls.add("list_versions_by_function", kwargs)
        function_name = kwargs["FunctionName"]
        version_configuration = _function_configuration(
            function_name, VERSIONS[function_name]
        )
        if (
            self.stable_drift == "lambda_version"
            and function_name == module.PLAN_FUNCTION_NAME
        ):
            version_configuration["CodeSha256"] = "B" * 43 + "="
        versions = [
            _function_configuration(function_name, "$LATEST"),
            version_configuration,
        ]
        if (
            self.stable_drift == "lambda_extra_version"
            and function_name == module.PLAN_FUNCTION_NAME
        ):
            foreign = _function_configuration(
                function_name, VERSIONS[function_name]
            )
            foreign["Version"] = "99"
            foreign["FunctionArn"] = (
                "arn:aws:lambda:us-east-1:042360977644:function:"
                f"{function_name}:99"
            )
            versions.append(foreign)
        return {"Versions": versions}

    def get_code_signing_config(self, **kwargs: Any) -> dict[str, Any]:
        self.calls.add("get_code_signing_config", kwargs)
        assert kwargs == {"CodeSigningConfigArn": CSC_ARN}
        contract = _expected_contract("RepairCodeSigningConfig")
        result = {
            "CodeSigningConfig": {
                "CodeSigningConfigId": CSC_ID,
                "CodeSigningConfigArn": CSC_ARN,
                "Description": contract["description"],
                "AllowedPublishers": contract["allowed_publishers"],
                "CodeSigningPolicies": contract["code_signing_policies"],
            }
        }
        if self.stable_drift == "lambda_code_signing":
            result["CodeSigningConfig"]["CodeSigningPolicies"] = {
                "UntrustedArtifactOnDeployment": "Warn"
            }
        return result

    def list_tags(self, **kwargs: Any) -> dict[str, Any]:
        self.calls.add("list_tags", kwargs)
        resource = kwargs["Resource"]
        if resource == CSC_ARN:
            logical_id = "RepairCodeSigningConfig"
        else:
            logical_id = next(
                logical
                for logical, function_name in module.FUNCTION_NAMES.items()
                if resource.endswith(":" + function_name)
            )
        return {"Tags": dict(_expected_contract(logical_id)["tags"])}


class FakeDynamo:
    def __init__(
        self,
        calls: Calls,
        *,
        stable_drift: str | None = None,
    ) -> None:
        self.calls = calls
        self.stable_drift = stable_drift

    def describe_table(self, **kwargs: Any) -> dict[str, Any]:
        self.calls.add("describe_table", kwargs)
        result = {
            "Table": {
                "TableName": module.TABLE_NAME,
                "TableArn": TABLE_ARN,
                "TableStatus": "ACTIVE",
                "AttributeDefinitions": [
                    {
                        "AttributeName": "repair_id",
                        "AttributeType": "S",
                    }
                ],
                "KeySchema": [
                    {
                        "AttributeName": "repair_id",
                        "KeyType": "HASH",
                    }
                ],
                "BillingModeSummary": {"BillingMode": "PAY_PER_REQUEST"},
                "ProvisionedThroughput": {
                    "ReadCapacityUnits": 0,
                    "WriteCapacityUnits": 0,
                },
                "DeletionProtectionEnabled": True,
                "SSEDescription": {
                    "Status": "ENABLED",
                    "SSEType": "KMS",
                    "KMSMasterKeyArn": KEY_ARN,
                },
                "TableClassSummary": {"TableClass": "STANDARD"},
                "ItemCount": 17,
                "TableSizeBytes": 4096,
            }
        }
        if self.stable_drift == "dynamodb_sse":
            result["Table"]["SSEDescription"]["KMSMasterKeyArn"] = (
                "arn:aws:kms:us-east-1:042360977644:key/"
                "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
            )
        if self.stable_drift == "dynamodb_deletion_protection":
            result["Table"]["DeletionProtectionEnabled"] = False
        if self.stable_drift == "dynamodb_replicas":
            result["Table"]["Replicas"] = [
                {
                    "RegionName": "us-west-2",
                    "ReplicaStatus": "ACTIVE",
                }
            ]
        if self.stable_drift == "dynamodb_multi_region":
            result["Table"]["MultiRegionConsistency"] = "EVENTUAL"
        if self.stable_drift == "dynamodb_witnesses":
            result["Table"]["GlobalTableWitnesses"] = [
                {"RegionName": "us-west-2"}
            ]
        if self.stable_drift == "dynamodb_restore":
            result["Table"]["RestoreSummary"] = {
                "SourceTableArn": TABLE_ARN + "-foreign",
                "SourceBackupArn": TABLE_ARN + "/backup/foreign",
                "RestoreDateTime": datetime.now(UTC),
                "RestoreInProgress": False,
            }
        if self.stable_drift == "dynamodb_stream":
            result["Table"]["StreamSpecification"] = {
                "StreamEnabled": True,
                "StreamViewType": "NEW_AND_OLD_IMAGES",
            }
            result["Table"]["LatestStreamLabel"] = "foreign-stream"
            result["Table"]["LatestStreamArn"] = (
                TABLE_ARN + "/stream/foreign"
            )
        if self.stable_drift == "dynamodb_provisioned_throughput":
            result["Table"]["ProvisionedThroughput"] = {
                "ReadCapacityUnits": 1,
                "WriteCapacityUnits": 1,
            }
        if self.stable_drift == "dynamodb_on_demand_throughput":
            result["Table"]["OnDemandThroughput"] = {
                "MaxReadRequestUnits": 100,
                "MaxWriteRequestUnits": 100,
            }
        if self.stable_drift == "dynamodb_warm_throughput":
            result["Table"]["WarmThroughput"] = {
                "ReadUnitsPerSecond": 100,
                "WriteUnitsPerSecond": 100,
                "Status": "ACTIVE",
            }
        return result

    def describe_continuous_backups(self, **kwargs: Any) -> dict[str, Any]:
        self.calls.add("describe_continuous_backups", kwargs)
        result = {
            "ContinuousBackupsDescription": {
                "ContinuousBackupsStatus": "ENABLED",
                "PointInTimeRecoveryDescription": {
                    "PointInTimeRecoveryStatus": "ENABLED",
                    "RecoveryPeriodInDays": 35,
                },
            }
        }
        if self.stable_drift == "dynamodb_pitr":
            result["ContinuousBackupsDescription"][
                "PointInTimeRecoveryDescription"
            ]["PointInTimeRecoveryStatus"] = "DISABLED"
        return result

    def describe_time_to_live(self, **kwargs: Any) -> dict[str, Any]:
        self.calls.add("describe_time_to_live", kwargs)
        return {"TimeToLiveDescription": {"TimeToLiveStatus": "DISABLED"}}

    def get_resource_policy(self, **kwargs: Any) -> dict[str, Any]:
        self.calls.add("get_resource_policy", kwargs)
        contract = _expected_contract("RepairLedger")
        policy = contract["resource_policy"]["policy"]
        if self.stable_drift == "dynamodb_resource_policy":
            policy = {
                "Version": "2012-10-17",
                "Statement": [],
            }
        return {
            "Policy": json.dumps(policy),
            "RevisionId": "policy-revision",
        }

    def list_tags_of_resource(self, **kwargs: Any) -> dict[str, Any]:
        self.calls.add("list_tags_of_resource", kwargs)
        contract = _expected_contract("RepairLedger")
        return {
            "Tags": [
                {"Key": key, "Value": value}
                for key, value in contract["tags"].items()
            ]
        }


class FakeKms:
    def __init__(
        self,
        calls: Calls,
        *,
        stable_drift: str | None = None,
    ) -> None:
        self.calls = calls
        self.stable_drift = stable_drift

    def describe_key(self, **kwargs: Any) -> dict[str, Any]:
        self.calls.add("describe_key", kwargs)
        contract = _expected_contract("RepairLedgerKey")
        result = {
            "KeyMetadata": {
                "AWSAccountId": module.AUTHORITY_ACCOUNT_ID,
                "KeyId": KEY_ID,
                "Arn": KEY_ARN,
                "Enabled": True,
                "Description": contract["description"],
                "KeyUsage": "ENCRYPT_DECRYPT",
                "KeyState": "Enabled",
                "Origin": "AWS_KMS",
                "KeyManager": "CUSTOMER",
                "CustomerMasterKeySpec": "SYMMETRIC_DEFAULT",
                "KeySpec": "SYMMETRIC_DEFAULT",
                "EncryptionAlgorithms": ["SYMMETRIC_DEFAULT"],
                "MultiRegion": False,
            }
        }
        if self.stable_drift == "kms":
            result["KeyMetadata"]["Description"] = "stable foreign drift"
        if self.stable_drift == "kms_encryption_algorithms":
            result["KeyMetadata"]["EncryptionAlgorithms"] = ["RSAES_OAEP_SHA_256"]
        if self.stable_drift == "kms_multi_region_configuration":
            result["KeyMetadata"]["MultiRegionConfiguration"] = {
                "MultiRegionKeyType": "PRIMARY",
                "PrimaryKey": {
                    "Arn": KEY_ARN,
                    "Region": "us-east-1",
                },
                "ReplicaKeys": [
                    {
                        "Arn": KEY_ARN.replace("us-east-1", "us-west-2"),
                        "Region": "us-west-2",
                    }
                ],
            }
        return result

    def get_key_rotation_status(self, **kwargs: Any) -> dict[str, Any]:
        self.calls.add("get_key_rotation_status", kwargs)
        return {
            "KeyId": KEY_ID,
            "KeyRotationEnabled": True,
            "RotationPeriodInDays": 365,
        }

    def get_key_policy(self, **kwargs: Any) -> dict[str, Any]:
        self.calls.add("get_key_policy", kwargs)
        contract = _expected_contract("RepairLedgerKey")
        return {
            "PolicyName": "default",
            "Policy": json.dumps(contract["key_policy"]),
        }

    def list_resource_tags(self, **kwargs: Any) -> dict[str, Any]:
        self.calls.add("list_resource_tags", kwargs)
        contract = _expected_contract("RepairLedgerKey")
        return {
            "Tags": [
                {"TagKey": key, "TagValue": value}
                for key, value in contract["tags"].items()
            ],
            "Truncated": False,
        }

    def list_aliases(self, **kwargs: Any) -> dict[str, Any]:
        self.calls.add("list_aliases", kwargs)
        aliases = [
            {
                "AliasName": module.KMS_ALIAS_NAME,
                "AliasArn": (
                    "arn:aws:kms:us-east-1:042360977644:"
                    + module.KMS_ALIAS_NAME
                ),
                "TargetKeyId": KEY_ID,
            }
        ]
        if self.stable_drift == "kms_extra_alias":
            aliases.append(
                {
                    "AliasName": "alias/scanalyze/foreign",
                    "AliasArn": (
                        "arn:aws:kms:us-east-1:042360977644:"
                        "alias/scanalyze/foreign"
                    ),
                    "TargetKeyId": KEY_ID,
                }
            )
        return {"Aliases": aliases, "Truncated": False}


class FakeLogs:
    def __init__(
        self,
        calls: Calls,
        *,
        stable_drift: str | None = None,
    ) -> None:
        self.calls = calls
        self.stable_drift = stable_drift

    def describe_log_groups(self, **kwargs: Any) -> dict[str, Any]:
        self.calls.add("describe_log_groups", kwargs)
        name = kwargs["logGroupNamePrefix"]
        result = {
            "logGroups": [
                {
                    "logGroupName": name,
                    "arn": (f"arn:aws:logs:us-east-1:042360977644:log-group:{name}:*"),
                    "logGroupArn": (
                        f"arn:aws:logs:us-east-1:042360977644:log-group:{name}"
                    ),
                    "retentionInDays": 365,
                    "logGroupClass": "STANDARD",
                    "storedBytes": 999999,
                }
            ]
        }
        if (
            self.stable_drift == "logs_retention"
            and name == module.PLAN_LOG_GROUP_NAME
        ):
            result["logGroups"][0]["retentionInDays"] = 7
        if (
            self.stable_drift == "logs_data_protection"
            and name == module.PLAN_LOG_GROUP_NAME
        ):
            result["logGroups"][0]["dataProtectionStatus"] = "ACTIVATED"
        if (
            self.stable_drift == "logs_inherited_data_protection"
            and name == module.PLAN_LOG_GROUP_NAME
        ):
            result["logGroups"][0]["inheritedProperties"] = [
                "ACCOUNT_DATA_PROTECTION"
            ]
        return result

    def list_tags_log_group(self, **kwargs: Any) -> dict[str, Any]:
        self.calls.add("list_tags_log_group", kwargs)
        name = kwargs["logGroupName"]
        logical_id = next(
            logical
            for logical, log_group_name in module.LOG_GROUP_NAMES.items()
            if name == log_group_name
        )
        return {
            "tags": dict(_expected_contract(logical_id)["tags"])
        }

    def list_tags_for_resource(self, **kwargs: Any) -> dict[str, Any]:
        self.calls.add("list_tags_for_resource", kwargs)
        arn = kwargs["resourceArn"]
        logical_id = next(
            logical
            for logical, log_group_name in module.LOG_GROUP_NAMES.items()
            if arn.endswith(":log-group:" + log_group_name)
        )
        return {"tags": dict(_expected_contract(logical_id)["tags"])}


def _clients(
    *,
    iam_pagination_mode: str | None = None,
    absence_error: str = "ResourceNotFoundException",
    missing_error: str | None = None,
    malformed: bool = False,
    drift: bool = False,
    stable_drift: str | None = None,
) -> tuple[dict[str, Any], Calls]:
    calls = Calls()
    return (
        {
            "iam_client": FakeIam(
                calls,
                pagination_mode=iam_pagination_mode,
                stable_drift=stable_drift,
            ),
            "lambda_client": FakeLambda(
                calls,
                absence_error=absence_error,
                missing_error=missing_error,
                malformed=malformed,
                drift=drift,
                stable_drift=stable_drift,
            ),
            "dynamodb_client": FakeDynamo(
                calls, stable_drift=stable_drift
            ),
            "kms_client": FakeKms(calls, stable_drift=stable_drift),
            "logs_client": FakeLogs(calls, stable_drift=stable_drift),
        },
        calls,
    )


def _collect(
    *,
    physical_ids: dict[str, str] | None = None,
    receipt: dict[str, Any] | None = None,
    reviewed_template_bytes: bytes | None = None,
    pep_parameter_handoff: dict[str, Any] | None = None,
    **client_options: Any,
) -> tuple[dict[str, Any], Calls]:
    physical = physical_ids or _physical_ids()
    clients, calls = _clients(**client_options)
    result = module.collect_effective_state_read_only(
        phase_b_execution_receipt=receipt or _phase_b_receipt(physical),
        physical_resource_ids=physical,
        reviewed_template_bytes=(
            reviewed_template_bytes or _reviewed_template_bytes()
        ),
        pep_parameter_handoff=pep_parameter_handoff or _pep_handoff(),
        evaluated_at=datetime(2026, 7, 23, 12, 45, tzinfo=UTC),
        **clients,
    )
    return result, calls


def _error_code(
    *,
    physical_ids: dict[str, str] | None = None,
    receipt: dict[str, Any] | None = None,
    reviewed_template_bytes: bytes | None = None,
    pep_parameter_handoff: dict[str, Any] | None = None,
    **client_options: Any,
) -> tuple[str, Calls]:
    physical = physical_ids or _physical_ids()
    clients, calls = _clients(**client_options)
    with pytest.raises(module.EffectiveStateReadbackError) as captured:
        module.collect_effective_state_read_only(
            phase_b_execution_receipt=receipt or _phase_b_receipt(physical),
            physical_resource_ids=physical,
            reviewed_template_bytes=(
                reviewed_template_bytes or _reviewed_template_bytes()
            ),
            pep_parameter_handoff=pep_parameter_handoff or _pep_handoff(),
            evaluated_at=datetime(2026, 7, 23, 12, 45, tzinfo=UTC),
            **clients,
        )
    return captured.value.code, calls


def test_collects_exact_23_sorted_sanitized_resources_twice() -> None:
    physical = _physical_ids()
    result, calls = _collect(physical_ids=physical)

    assert result["resource_count"] == 23
    assert [item["logical_resource_id"] for item in result["resources"]] == list(
        module.RESOURCE_LOGICAL_IDS
    )
    assert all(
        set(item)
        == {
            "logical_resource_id",
            "resource_type",
            "physical_resource_id_sha256",
            "expected_state_sha256",
            "observed_state_sha256",
            "provider_state_sha256",
            "conformance_status",
        }
        for item in result["resources"]
    )
    assert result["conformance_status"] == "EXACT_TEMPLATE_MATCH"
    assert (
        result["expected_resources_sha256"]
        == result["observed_resources_sha256"]
    )
    assert result["reviewed_template_sha256"] == module.sha256(
        _reviewed_template_bytes()
    ).hexdigest()
    assert result["pep_parameter_handoff_sha256"] == module.canonical_digest(
        _pep_handoff()
    )
    assert all(
        item["expected_state_sha256"]
        == item["observed_state_sha256"]
        == item["provider_state_sha256"]
        and item["conformance_status"] == "EXACT_TEMPLATE_MATCH"
        for item in result["resources"]
    )
    assert (
        result["first_snapshot_sha256"]
        == result["second_snapshot_sha256"]
        == result["resources_sha256"]
    )
    module.validate_effective_state_receipt(result)

    serialized = json.dumps(result, sort_keys=True)
    assert "super-secret-never-emit" not in serialized
    assert SIGNER_ARN not in serialized
    assert KEY_ARN not in serialized
    assert TABLE_ARN not in serialized
    for private_id in physical.values():
        assert private_id not in serialized

    methods = [method for method, _ in calls.items]
    assert methods
    assert "get_function" not in methods
    assert all(method.startswith(("get_", "list_", "describe_")) for method in methods)
    assert methods.count("get_role") == 8
    assert methods.count("get_function_configuration") == 6
    assert methods.count("describe_table") == 2
    assert methods.count("describe_key") == 2
    assert methods.count("describe_log_groups") == 6


def test_physical_id_hash_mismatch_blocks_before_provider_calls() -> None:
    original = _physical_ids()
    forged = deepcopy(original)
    forged["PlanFunction"] = "foreign-function"
    code, calls = _error_code(
        physical_ids=forged,
        receipt=_phase_b_receipt(original),
    )
    assert code == "PHYSICAL_RESOURCE_BINDING_INVALID"
    assert calls.items == []


def test_template_digest_mismatch_blocks_before_provider_calls() -> None:
    code, calls = _error_code(
        reviewed_template_bytes=_reviewed_template_bytes() + b"\n"
    )
    assert code == "PEP_PARAMETER_HANDOFF_INVALID"
    assert calls.items == []


def test_handoff_parameter_drift_changes_expected_provider_contract() -> None:
    handoff = deepcopy(_pep_handoff())
    parameter = next(
        item
        for item in handoff["parameters"]
        if item["ParameterKey"] == "ReconcileArtifactCodeSha256"
    )
    parameter["ParameterValue"] = "B" * 43 + "="
    code, calls = _error_code(pep_parameter_handoff=handoff)
    assert code == "EFFECTIVE_STATE_CONFORMANCE_DRIFT"
    assert calls.items


def test_two_consecutive_snapshots_must_be_identical() -> None:
    code, _ = _error_code(drift=True)
    assert code == "EFFECTIVE_STATE_CONFORMANCE_DRIFT"


@pytest.mark.parametrize(
    "stable_drift",
    [
        "iam_trust",
        "iam_inline",
        "iam_permission_boundary",
        "lambda_role",
        "lambda_runtime",
        "lambda_memory",
        "lambda_timeout",
        "lambda_code_signing",
        "lambda_alias",
        "lambda_extra_alias",
        "lambda_extra_event_invoke",
        "lambda_extra_version",
        "lambda_version",
        "lambda_concurrency",
        "lambda_vpc",
        "lambda_dead_letter",
        "lambda_kms",
        "lambda_tracing",
        "lambda_layers",
        "lambda_file_system",
        "lambda_image_config",
        "lambda_ephemeral_storage",
        "lambda_snap_start",
        "lambda_runtime_version",
        "lambda_signing_profile",
        "lambda_master_arn",
        "lambda_logging",
        "dynamodb_sse",
        "dynamodb_pitr",
        "dynamodb_deletion_protection",
        "dynamodb_resource_policy",
        "dynamodb_replicas",
        "dynamodb_multi_region",
        "dynamodb_witnesses",
        "dynamodb_restore",
        "dynamodb_stream",
        "dynamodb_provisioned_throughput",
        "dynamodb_on_demand_throughput",
        "dynamodb_warm_throughput",
        "kms",
        "kms_encryption_algorithms",
        "kms_multi_region_configuration",
        "kms_extra_alias",
        "logs_retention",
        "logs_data_protection",
        "logs_inherited_data_protection",
    ],
)
def test_stable_provider_drift_never_proves_template_conformance(
    stable_drift: str,
) -> None:
    code, calls = _error_code(stable_drift=stable_drift)
    assert code == "EFFECTIVE_STATE_CONFORMANCE_DRIFT"
    assert calls.items


def test_provider_assigned_iam_role_id_is_shape_checked_and_classified() -> None:
    code, calls = _error_code(stable_drift="iam_role_id_shape")
    assert code == "PROVIDER_RESPONSE_MALFORMED"
    assert calls.items

    expected = _expected_contract("PlanExecutionRole")
    assert expected["role_id_classification"] == {
        "authority": "AWS_ASSIGNED",
        "format": "IAM_ROLE_UNIQUE_ID",
        "conformance": "FORMAT_AND_TWO_SNAPSHOT_STABILITY",
    }


@pytest.mark.parametrize(
    "stable_drift",
    ["lambda_signing_job_foreign", "lambda_signing_job_missing"],
)
def test_provider_assigned_signing_job_is_context_checked_and_classified(
    stable_drift: str,
) -> None:
    code, calls = _error_code(stable_drift=stable_drift)
    assert code == "PROVIDER_RESPONSE_MALFORMED"
    assert calls.items

    expected = _expected_contract("PlanFunction")
    assert expected["configuration"]["signing_job_classification"] == {
        "authority": "AWS_SIGNER_ASSIGNED",
        "binding": "ACCOUNT_REGION_FORMAT_AND_TWO_SNAPSHOT_STABILITY",
        "exact_job_provenance": False,
    }


@pytest.mark.parametrize(
    "error_code",
    ["AccessDeniedException", "ThrottlingException", "SlowDown"],
)
def test_access_denied_and_throttle_never_prove_absence(
    error_code: str,
) -> None:
    code, _ = _error_code(absence_error=error_code)
    assert code == "PROVIDER_CALL_FAILED"


def test_only_exact_resource_not_found_proves_expected_absence() -> None:
    exact, _ = _error_code(missing_error="ResourceNotFoundException")
    assert exact == "EFFECTIVE_STATE_RESOURCE_ABSENT"

    foreign, _ = _error_code(missing_error="NoSuchEntity")
    assert foreign == "PROVIDER_CALL_FAILED"


def test_exact_resource_not_found_is_accepted_for_optional_absence() -> None:
    result, calls = _collect(absence_error="ResourceNotFoundException")
    assert result["evidence_status"] == ("DIRECT_PROVIDER_EFFECTIVE_STATE_VERIFIED")
    assert any(method == "get_policy" for method, _ in calls.items)


def test_iam_two_page_inventory_is_bounded_and_complete() -> None:
    result, calls = _collect(iam_pagination_mode="two_pages")
    assert result["resource_count"] == 23
    assert any(
        method == "list_role_policies" and kwargs.get("Marker") == "next"
        for method, kwargs in calls.items
    )
    for method, kwargs in calls.items:
        if "MaxItems" in kwargs:
            assert 1 <= kwargs["MaxItems"] <= 100
        if "Limit" in kwargs:
            assert 1 <= kwargs["Limit"] <= 100
        if "limit" in kwargs:
            assert 1 <= kwargs["limit"] <= 100


@pytest.mark.parametrize(
    "mode, expected",
    [
        ("empty_token", "PROVIDER_PAGINATION_MALFORMED"),
        ("repeat_token", "PROVIDER_PAGINATION_MALFORMED"),
        ("incoherent", "PROVIDER_PAGINATION_MALFORMED"),
        ("duplicate", "PROVIDER_PAGINATION_MALFORMED"),
        ("page_limit", "PROVIDER_PAGINATION_LIMIT_EXCEEDED"),
    ],
)
def test_pagination_tokens_duplicates_and_bounds_fail_closed(
    mode: str,
    expected: str,
) -> None:
    code, _ = _error_code(iam_pagination_mode=mode)
    assert code == expected


def test_malformed_provider_response_blocks_evidence() -> None:
    code, _ = _error_code(malformed=True)
    assert code == "PROVIDER_RESPONSE_MALFORMED"


def test_receipt_validator_rejects_digest_and_order_tamper() -> None:
    result, _ = _collect()

    digest_tamper = deepcopy(result)
    digest_tamper["resources"][0]["provider_state_sha256"] = "9" * 64
    with pytest.raises(
        module.EffectiveStateReadbackError,
        match="EFFECTIVE_STATE_RECEIPT_INVALID",
    ):
        module.validate_effective_state_receipt(digest_tamper)

    order_tamper = deepcopy(result)
    order_tamper["resources"][0:2] = reversed(order_tamper["resources"][0:2])
    order_tamper["resources_sha256"] = module.canonical_digest(
        order_tamper["resources"]
    )
    order_tamper["first_snapshot_sha256"] = order_tamper["resources_sha256"]
    order_tamper["second_snapshot_sha256"] = order_tamper["resources_sha256"]
    order_tamper["provider_state_sha256"] = module.canonical_digest(
        {
            "resource_count": 23,
            "resources_sha256": order_tamper["resources_sha256"],
        }
    )
    with pytest.raises(
        module.EffectiveStateReadbackError,
        match="EFFECTIVE_STATE_RECEIPT_INVALID",
    ):
        module.validate_effective_state_receipt(order_tamper)


def test_schema_and_new_fixtures_enforce_exact_resource_order() -> None:
    schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    validator = Draft202012Validator(schema, format_checker=FormatChecker())
    valid = json.loads((FIXTURES / "valid-receipt.json").read_text(encoding="utf-8"))
    mutation = json.loads(
        (FIXTURES / "invalid-unsorted.mutation.json").read_text(encoding="utf-8")
    )
    assert mutation["fixture"] == "valid-receipt.json"
    assert not list(validator.iter_errors(valid))
    module.validate_effective_state_receipt(valid)

    invalid = deepcopy(valid)
    invalid["resources"][0:2] = reversed(invalid["resources"][0:2])
    assert list(validator.iter_errors(invalid))
    with pytest.raises(
        module.EffectiveStateReadbackError,
        match=mutation["expected_error"],
    ):
        module.validate_effective_state_receipt(invalid)


def test_source_contains_no_lambda_get_function_or_mutating_api_calls() -> None:
    source = Path(module.__file__).read_text(encoding="utf-8")
    tree = ast.parse(source)
    method_names = {
        node.args[1].value
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "_provider_call"
        and len(node.args) >= 2
        and isinstance(node.args[1], ast.Constant)
        and isinstance(node.args[1].value, str)
    }
    assert "get_function" not in method_names
    assert "get_function_url_config" not in method_names
    assert method_names
    assert all(name.startswith(("get_", "list_", "describe_")) for name in method_names)
    assert not any(
        name.startswith(
            (
                "create_",
                "put_",
                "update_",
                "delete_",
                "invoke_",
                "tag_",
                "untag_",
            )
        )
        for name in method_names
    )
    assert "cloudformation_client" not in source
    assert "sts_client" not in source


def test_change_set_chain_passes_reviewed_contract_to_provider_readback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    physical = _physical_ids()
    trace = _phase_b_receipt(physical)
    captured: dict[str, Any] = {}
    sentinel_client = object()

    monkeypatch.setattr(
        change_set_module,
        "_readback_pep_execution_trace_and_private_ids",
        lambda **_: (trace, physical),
    )

    def collect(**kwargs: Any) -> dict[str, str]:
        captured.update(kwargs)
        return {"evidence_status": "synthetic"}

    monkeypatch.setattr(module, "collect_effective_state_read_only", collect)
    template = _reviewed_template_bytes()
    handoff = _pep_handoff()
    result = (
        change_set_module.readback_pep_execution_with_effective_state_read_only(
            source_root=ROOT,
            profile_name=change_set_module.EXPECTED_PROFILE,
            region=change_set_module.REGION,
            signed_receipt={},
            deployment_contract={},
            gug220_intent={},
            gug220_ledger={},
            gug220_receipt={},
                gug220_evidence={},
                delegation_live_receipt={},
                phase_b_identity_materialization_receipt={},
                pep_handoff=handoff,
                pep_change_set_receipt={},
                phase_b_precondition_parameter_handoff={},
                phase_b_precondition_change_set_receipt={},
                broker_effect_receipt={},
                reviewed_template_bytes=template,
                reviewed_phase_b_precondition_template_bytes=b"synthetic",
            sts_client=sentinel_client,
            cloudformation_client=sentinel_client,
            cloudtrail_client=sentinel_client,
            iam_client=sentinel_client,
            lambda_client=sentinel_client,
            dynamodb_client=sentinel_client,
            kms_client=sentinel_client,
            logs_client=sentinel_client,
        )
    )
    assert result["cloudformation_trace_receipt"] is trace
    assert result["effective_state_receipt"]["evidence_status"] == "synthetic"
    assert captured["phase_b_execution_receipt"] is trace
    assert captured["physical_resource_ids"] is physical
    assert captured["reviewed_template_bytes"] is template
    assert captured["pep_parameter_handoff"] is handoff
    assert captured["dynamodb_client"] is sentinel_client
