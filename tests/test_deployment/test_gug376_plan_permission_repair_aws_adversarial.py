from __future__ import annotations

from datetime import UTC, datetime
import json
from pathlib import Path
from typing import Any, Mapping

import pytest

from tooling import platform_authority_plan_permission_repair_aws as runtime
from tooling.platform_authority_plan_permission_repair import (
    PlanPermissionRepairError,
    ProviderResponseAmbiguous,
    canonical_json,
    render_target_policy,
)
from tests.test_deployment.test_gug376_plan_permission_repair_aws import (
    _environment as _valid_runtime_environment,
)


REPO_ROOT = Path(__file__).resolve().parents[2]
LEDGER_FIXTURE = (
    REPO_ROOT
    / "fixtures/valid/"
    "platform-authority-plan-permission-repair-ledger-v1-synthetic.json"
)


class _PageClient:
    def __init__(self, pages: list[Mapping[str, Any]]) -> None:
        self.pages = pages
        self.calls: list[dict[str, Any]] = []

    def list_values(self, **kwargs: Any) -> Mapping[str, Any]:
        self.calls.append(kwargs)
        index = min(len(self.calls) - 1, len(self.pages) - 1)
        return self.pages[index]


def test_token_pagination_rejects_a_cycle_and_preserves_request_order() -> None:
    client = _PageClient(
        [
            {"Values": [], "NextToken": "token-a"},
            {"Values": [], "NextToken": "token-b"},
            {"Values": [], "NextToken": "token-a"},
        ]
    )

    with pytest.raises(PlanPermissionRepairError) as captured:
        runtime._paginate_token(client, "list_values", "Values", Scope="exact")

    assert captured.value.code == "PAGINATION_INVALID"
    assert client.calls == [
        {"Scope": "exact"},
        {"Scope": "exact", "NextToken": "token-a"},
        {"Scope": "exact", "NextToken": "token-b"},
    ]


def test_marker_pagination_rejects_terminal_marker_and_cycle() -> None:
    terminal = _PageClient(
        [{"Values": [], "IsTruncated": False, "Marker": "stale"}]
    )
    with pytest.raises(PlanPermissionRepairError) as captured:
        runtime._paginate_marker(terminal, "list_values", "Values")
    assert captured.value.code == "PAGINATION_INVALID"

    cycle = _PageClient(
        [
            {"Values": [], "IsTruncated": True, "Marker": "marker-a"},
            {"Values": [], "IsTruncated": True, "Marker": "marker-a"},
        ]
    )
    with pytest.raises(PlanPermissionRepairError) as captured:
        runtime._paginate_marker(cycle, "list_values", "Values")
    assert captured.value.code == "PAGINATION_INVALID"


def test_pagination_enforces_closed_page_and_item_caps(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(runtime, "MAX_PROVIDER_PAGES", 2)
    pages = _PageClient(
        [
            {"Values": [], "NextToken": "a"},
            {"Values": [], "NextToken": "b"},
        ]
    )
    with pytest.raises(PlanPermissionRepairError) as captured:
        runtime._paginate_token(pages, "list_values", "Values")
    assert captured.value.code == "PAGINATION_LIMIT"
    assert len(pages.calls) == 2

    monkeypatch.setattr(runtime, "MAX_PROVIDER_ITEMS", 1)
    oversized = _PageClient([{"Values": [1, 2]}])
    with pytest.raises(PlanPermissionRepairError) as captured:
        runtime._paginate_token(oversized, "list_values", "Values")
    assert captured.value.code == "PROVIDER_RESPONSE_OVERSIZED"


def test_checked_page_accepts_aware_datetime_and_rejects_naive_datetime() -> None:
    aware = {"ObservedAt": datetime(2026, 8, 30, 1, 2, 3, tzinfo=UTC)}
    assert runtime._checked_page(aware, "synthetic") is aware

    with pytest.raises(PlanPermissionRepairError) as captured:
        runtime._checked_page(
            {"ObservedAt": datetime(2026, 8, 30, 1, 2, 3)},
            "synthetic",
        )
    assert captured.value.code == "PROVIDER_RESPONSE_MALFORMED"


@pytest.mark.parametrize("number", [float("nan"), float("inf"), float("-inf")])
def test_checked_page_rejects_nonfinite_numbers(number: float) -> None:
    with pytest.raises(PlanPermissionRepairError) as captured:
        runtime._checked_page({"NonFinite": number}, "synthetic")

    assert captured.value.code == "PROVIDER_RESPONSE_MALFORMED"


class _RawCall:
    def __init__(self, *, fail: bool = False) -> None:
        self.calls = 0
        self.fail = fail

    def operation(self) -> str:
        self.calls += 1
        if self.fail:
            raise RuntimeError("provider secret must not trigger a retry")
        return "ok"


@pytest.mark.parametrize(
    "remaining",
    [True, runtime.MIN_READ_CALL_REMAINING_MS - 1, runtime.MIN_READ_CALL_REMAINING_MS],
)
def test_budget_client_blocks_without_calling_provider(remaining: Any) -> None:
    raw = _RawCall()
    client = runtime._BudgetClient(raw, lambda: remaining)

    with pytest.raises(PlanPermissionRepairError) as captured:
        client.operation()

    assert captured.value.code == "FUNCTION_BUDGET_INSUFFICIENT"
    assert raw.calls == 0


def test_budget_client_makes_exactly_one_attempt() -> None:
    raw = _RawCall(fail=True)
    client = runtime._BudgetClient(
        raw, lambda: runtime.MIN_READ_CALL_REMAINING_MS + 1
    )

    with pytest.raises(RuntimeError):
        client.operation()

    assert raw.calls == 1


class _ConfigCapture:
    def __init__(self, **kwargs: Any) -> None:
        self.kwargs = kwargs


class _UnusedBoto:
    def client(self, *_args: Any, **_kwargs: Any) -> Any:
        raise AssertionError("client creation is not part of this assertion")


def test_sdk_config_disables_sdk_retries_and_has_closed_timeouts() -> None:
    factory = runtime.BotoSessionFactory(
        boto3_module=_UnusedBoto(),
        config_type=_ConfigCapture,
        remaining_time_ms=lambda: 600_000,
    )

    assert factory.client_config.kwargs == {
        "region_name": runtime.REGION,
        "retries": {"mode": "standard", "total_max_attempts": 1},
        "connect_timeout": runtime.SDK_CONNECT_TIMEOUT_SECONDS,
        "read_timeout": runtime.SDK_READ_TIMEOUT_SECONDS,
    }


class _MutationClient:
    def __init__(self) -> None:
        self.calls = 0

    def put_inline_policy_to_permission_set(self, **_kwargs: Any) -> None:
        self.calls += 1


def _identity_center_adapter(
    client: Any, remaining_time_ms: Any = 600_000
) -> runtime.AwsIdentityCenterAdapter:
    return runtime.AwsIdentityCenterAdapter(
        sso_admin=client,
        identitystore=object(),
        authority_iam=object(),
        graph_supplier=lambda _arn, _policy: "sha256:" + "0" * 64,
        expected_description="synthetic",
        expected_plan_tags={"managed_by": "existing-plan"},
        source_commit="a" * 40,
        remaining_time_ms=lambda: remaining_time_ms,
    )


def test_plan_and_invoker_tag_contracts_are_independent_and_closed() -> None:
    adapter = _identity_center_adapter(object())

    assert adapter._expected_plan_tags == {"managed_by": "existing-plan"}
    assert adapter._expected_invoker_tags == {
        "component": "plan-repair-delegation",
        "environment": "non-production",
        "managed_by": "cloudformation",
        "production": "false",
        "service": "scanalyze-platform-authority",
        "source_commit": "a" * 40,
        "work_package": "GUG-376",
    }
    assert adapter._expected_plan_tags != adapter._expected_invoker_tags


@pytest.mark.parametrize(
    ("plan_tags", "source_commit", "code"),
    [
        ({}, "a" * 40, "PLAN_TAG_BINDING_MALFORMED"),
        ({"managed_by": 1}, "a" * 40, "PLAN_TAG_BINDING_MALFORMED"),
        (
            {"managed_by": "existing-plan"},
            "A" * 40,
            "INVOKER_TAG_BINDING_MALFORMED",
        ),
    ],
)
def test_adapter_rejects_malformed_tag_bindings(
    plan_tags: Mapping[str, Any], source_commit: str, code: str
) -> None:
    with pytest.raises(PlanPermissionRepairError) as captured:
        runtime.AwsIdentityCenterAdapter(
            sso_admin=object(),
            identitystore=object(),
            authority_iam=object(),
            graph_supplier=lambda _arn, _policy: "sha256:" + "0" * 64,
            expected_description="synthetic",
            expected_plan_tags=plan_tags,
            source_commit=source_commit,
            remaining_time_ms=lambda: 600_000,
        )

    assert captured.value.code == code


def test_mutation_budget_is_checked_before_put_inline_policy() -> None:
    client = _MutationClient()
    adapter = _identity_center_adapter(
        client, runtime.MIN_MUTATION_CALL_REMAINING_MS
    )
    intent = {
        "instance_arn": "arn:aws:sso:::instance/ssoins-synthetic",
        "permission_set_arn": "arn:aws:sso:::permissionSet/synthetic",
        "change_set_name": "scanalyze-platform-authority-bootstrap-20300101000000",
    }
    policy = canonical_json(render_target_policy(intent["change_set_name"]))

    with pytest.raises(PlanPermissionRepairError) as captured:
        adapter.put_inline_policy(intent, policy)

    assert captured.value.code == "FUNCTION_BUDGET_INSUFFICIENT"
    assert client.calls == 0


@pytest.mark.parametrize("number", ["-0", "01", "-01", "+1", "1.0", "1e0", " 1"])
def test_dynamo_decode_rejects_noncanonical_integer(number: str) -> None:
    with pytest.raises(PlanPermissionRepairError) as captured:
        runtime.DynamoLedger._decode({"counter": {"N": number}})

    assert captured.value.code == "LEDGER_MALFORMED"
    assert captured.value.__cause__ is None


@pytest.mark.parametrize(
    ("number", "expected"), [("0", 0), ("1", 1), ("-1", -1), ("123", 123)]
)
def test_dynamo_decode_accepts_only_canonical_integer(
    number: str, expected: int
) -> None:
    assert runtime.DynamoLedger._decode({"counter": {"N": number}}) == {
        "counter": expected
    }


def _ledger_fixture() -> dict[str, Any]:
    return json.loads(LEDGER_FIXTURE.read_text(encoding="utf-8"))


def test_successful_cas_with_malformed_all_new_is_ambiguous() -> None:
    ledger = _ledger_fixture()

    class Client:
        calls = 0

        def update_item(self, **_kwargs: Any) -> Mapping[str, Any]:
            self.calls += 1
            attributes = runtime.DynamoLedger._encode(ledger)
            attributes["schema_version"] = {"N": "01"}
            return {"Attributes": attributes}

    client = Client()
    with pytest.raises(ProviderResponseAmbiguous) as captured:
        runtime.DynamoLedger(client, "exact-ledger").compare_and_swap(
            repair_id=str(ledger["repair_id"]),
            expected_ledger_digest=str(ledger["ledger_digest"]),
            expected_ledger=ledger,
            replacement=ledger,
        )

    assert client.calls == 1
    assert captured.value.__cause__ is None
    assert captured.value.__suppress_context__ is True


class _OperationClient:
    def __init__(self, coordinates: Mapping[str, Any] | None = None) -> None:
        self.coordinates = dict(coordinates or {})

    def _status(self) -> dict[str, Any]:
        return {
            "RequestId": "request-123",
            "Status": "SUCCEEDED",
            **self.coordinates,
        }

    def provision_permission_set(self, **_kwargs: Any) -> Mapping[str, Any]:
        return {"PermissionSetProvisioningStatus": self._status()}

    def describe_permission_set_provisioning_status(
        self, **_kwargs: Any
    ) -> Mapping[str, Any]:
        return {"PermissionSetProvisioningStatus": self._status()}


def _operation_intent() -> dict[str, str]:
    return {
        "instance_arn": "arn:aws:sso:::instance/ssoins-synthetic",
        "permission_set_arn": "arn:aws:sso:::permissionSet/synthetic",
    }


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("PermissionSetArn", "arn:aws:sso:::permissionSet/foreign"),
        ("TargetId", "000000000000"),
        ("TargetType", "FOREIGN"),
    ],
)
@pytest.mark.parametrize("operation", ["provision", "describe"])
def test_provisioning_response_rejects_mismatched_optional_coordinates(
    operation: str, field: str, value: str
) -> None:
    adapter = _identity_center_adapter(_OperationClient({field: value}))
    intent = _operation_intent()

    with pytest.raises(ProviderResponseAmbiguous) as captured:
        if operation == "provision":
            adapter.provision_permission_set(intent)
        else:
            adapter.describe_provisioning(intent, "request-123")

    assert captured.value.__cause__ is None


def test_provisioning_response_allows_omitted_optional_coordinates() -> None:
    adapter = _identity_center_adapter(_OperationClient())
    intent = _operation_intent()

    result = adapter.provision_permission_set(intent)
    assert (result.request_id, result.status) == ("request-123", "SUCCEEDED")
    assert adapter.describe_provisioning(intent, "request-123") == "SUCCEEDED"


class _AssumeSts:
    def __init__(self, source_identity: str | None) -> None:
        self.source_identity = source_identity
        self.calls: list[dict[str, Any]] = []
        self.expected_arn = ""

    def assume_role(self, **kwargs: Any) -> Mapping[str, Any]:
        self.calls.append(kwargs)
        role_name = str(kwargs["RoleArn"]).rsplit("/", 1)[-1]
        account = str(kwargs["RoleArn"]).split(":", 5)[4]
        self.expected_arn = (
            f"arn:aws:sts::{account}:assumed-role/{role_name}/"
            f"{kwargs['RoleSessionName']}"
        )
        response: dict[str, Any] = {
            "Credentials": {
                "AccessKeyId": "synthetic-access",
                "SecretAccessKey": "synthetic-secret",
                "SessionToken": "synthetic-token",
            },
            "AssumedRoleUser": {
                "Arn": self.expected_arn,
                "AssumedRoleId": "AROASYNTHETIC:" + kwargs["RoleSessionName"],
            },
        }
        if self.source_identity is not None:
            response["SourceIdentity"] = (
                kwargs["SourceIdentity"]
                if self.source_identity == "exact"
                else self.source_identity
            )
        return response


class _CallerSts:
    def __init__(self, assume: _AssumeSts, arn_suffix: str = "") -> None:
        self.assume = assume
        self.arn_suffix = arn_suffix

    def get_caller_identity(self) -> Mapping[str, Any]:
        return {
            "Account": runtime.AUTHORITY_ACCOUNT_ID,
            "Arn": self.assume.expected_arn + self.arn_suffix,
            "UserId": "AROASYNTHETIC:session",
        }


class _AssumeBoto:
    def __init__(self, source_identity: str | None, arn_suffix: str = "") -> None:
        self.assume = _AssumeSts(source_identity)
        self.caller = _CallerSts(self.assume, arn_suffix)

    def client(self, service: str, **kwargs: Any) -> Any:
        assert service == "sts"
        if "aws_access_key_id" in kwargs:
            return self.caller
        return self.assume


@pytest.mark.parametrize("source_identity", [None, "foreign-source"])
def test_assume_role_requires_exact_source_identity(
    source_identity: str | None,
) -> None:
    factory = runtime.BotoSessionFactory(
        boto3_module=_AssumeBoto(source_identity),
        config_type=_ConfigCapture,
        remaining_time_ms=lambda: 600_000,
    )

    with pytest.raises(PlanPermissionRepairError) as captured:
        factory._assume(
            runtime.READBACK_ROLE_ARN,
            "gug376-plan-permission-repair-" + "b" * 64,
            "readback",
        )

    assert captured.value.code == "ASSUME_ROLE_IDENTITY_MISMATCH"


def test_assumed_caller_identity_rejects_an_arn_suffix() -> None:
    factory = runtime.BotoSessionFactory(
        boto3_module=_AssumeBoto("exact", "/extra"),
        config_type=_ConfigCapture,
        remaining_time_ms=lambda: 600_000,
    )

    with pytest.raises(PlanPermissionRepairError) as captured:
        factory.assumed_clients(
            role_arn=runtime.READBACK_ROLE_ARN,
            repair_id="gug376-plan-permission-repair-" + "b" * 64,
            purpose="readback",
            services=(),
        )

    assert captured.value.code == "ASSUME_ROLE_IDENTITY_MISMATCH"


def test_local_execution_identity_requires_one_exact_session_segment() -> None:
    prefix = (
        f"arn:aws:sts::{runtime.AUTHORITY_ACCOUNT_ID}:assumed-role/"
        f"{runtime.EXECUTION_ROLE_NAMES['plan']}/"
    )
    runtime._validate_local_execution_identity(
        {"Account": runtime.AUTHORITY_ACCOUNT_ID, "Arn": prefix + "session"},
        "plan",
    )

    for arn in (prefix, prefix + "session/extra"):
        with pytest.raises(PlanPermissionRepairError) as captured:
            runtime._validate_local_execution_identity(
                {"Account": runtime.AUTHORITY_ACCOUNT_ID, "Arn": arn},
                "plan",
            )
        assert captured.value.code == "LOCAL_IDENTITY_MISMATCH"


class _NotFound(Exception):
    def __init__(self) -> None:
        self.response = {"Error": {"Code": "ResourceNotFoundException"}}
        super().__init__("private provider message")


def _lambda_environment() -> dict[str, str]:
    env = {
        key: f"synthetic-{key.lower()}"
        for key in runtime.COMMON_FUNCTION_ENVIRONMENT_KEYS
    }
    env["EXPECTED_ARTIFACT_CODE_SHA256"] = "A" * 44
    env["EXPECTED_CODE_SIGNING_CONFIG_ARN"] = (
        f"arn:aws:lambda:{runtime.REGION}:{runtime.AUTHORITY_ACCOUNT_ID}:"
        "code-signing-config:csc-synthetic"
    )
    env["EXPECTED_SIGNING_PROFILE_VERSION_ARN"] = (
        f"arn:aws:signer:{runtime.REGION}:{runtime.AUTHORITY_ACCOUNT_ID}:"
        "/signing-profiles/synthetic/1"
    )
    return env


class _LambdaClient:
    versions = {"plan": "11", "repair": "12", "reconcile": "13"}

    def __init__(self, env: Mapping[str, str], fault: str | None = None) -> None:
        self.env = dict(env)
        self.fault = fault

    @staticmethod
    def _mode(function_name: str) -> str:
        return next(
            mode
            for mode, expected in runtime.FUNCTION_NAMES.items()
            if expected == function_name
        )

    def get_alias(self, *, FunctionName: str, Name: str) -> Mapping[str, Any]:
        mode = self._mode(FunctionName)
        routing: Mapping[str, Any] = {"AdditionalVersionWeights": {}}
        if self.fault == "alias-routing" and mode == "plan":
            routing = {"AdditionalVersionWeights": {"99": 0.1}}
        return {
            "AliasArn": (
                f"arn:aws:lambda:{runtime.REGION}:"
                f"{runtime.AUTHORITY_ACCOUNT_ID}:function:{FunctionName}:{Name}"
            ),
            "Name": Name,
            "FunctionVersion": self.versions[mode],
            "Description": "",
            "RoutingConfig": routing,
        }

    def get_function_configuration(
        self, *, FunctionName: str, Qualifier: str
    ) -> Mapping[str, Any]:
        mode = self._mode(FunctionName)
        assert Qualifier == self.versions[mode]
        variables = {
            key: self.env[key]
            for key in runtime.COMMON_FUNCTION_ENVIRONMENT_KEYS
        }
        if mode in {"repair", "reconcile"}:
            variables["PLAN_FUNCTION_VERSION"] = self.versions["plan"]
        if mode == "reconcile":
            variables["REPAIR_FUNCTION_VERSION"] = self.versions["repair"]
        configuration: dict[str, Any] = {
            "FunctionName": FunctionName,
            "FunctionArn": (
                f"arn:aws:lambda:{runtime.REGION}:"
                f"{runtime.AUTHORITY_ACCOUNT_ID}:function:"
                f"{FunctionName}:{Qualifier}"
            ),
            "Version": Qualifier,
            "Runtime": "python3.12",
            "Handler": runtime.EXPECTED_HANDLERS[mode],
            "Role": (
                f"arn:aws:iam::{runtime.AUTHORITY_ACCOUNT_ID}:role/"
                f"{runtime.EXECUTION_ROLE_NAMES[mode]}"
            ),
            "MemorySize": 1024,
            "Timeout": runtime.EXPECTED_TIMEOUTS[mode],
            "PackageType": "Zip",
            "CodeSha256": self.env["EXPECTED_ARTIFACT_CODE_SHA256"],
            "Description": (
                runtime.EXPECTED_VERSION_DESCRIPTION_PREFIXES[mode]
                + self.env["IMMU_CONFIG_DIGEST"]
            ),
            "State": "Active",
            "LastUpdateStatus": "Successful",
            "RuntimeVersionConfig": {
                "RuntimeVersionArn": (
                    "arn:aws:lambda:us-east-1::runtime:python3.12-synthetic"
                )
            },
            "Environment": {"Variables": variables},
            "Architectures": ["x86_64"],
            "VpcConfig": {
                "SubnetIds": [],
                "SecurityGroupIds": [],
                "VpcId": "",
                "Ipv6AllowedForDualStack": False,
            },
            "LoggingConfig": {
                "LogFormat": "Text",
                "LogGroup": f"/aws/lambda/{FunctionName}",
                "ApplicationLogLevel": "",
                "SystemLogLevel": "INFO",
            },
            "SnapStart": {"ApplyOn": "None", "OptimizationStatus": "Off"},
            "DeadLetterConfig": {},
            "KMSKeyArn": "",
            "Layers": [],
            "FileSystemConfigs": [],
            "MasterArn": "",
            "ImageConfigResponse": {},
            "TracingConfig": {"Mode": "PassThrough"},
            "EphemeralStorage": {"Size": 512},
            "SigningProfileVersionArn": self.env[
                "EXPECTED_SIGNING_PROFILE_VERSION_ARN"
            ],
        }
        if mode == "plan":
            if self.fault == "environment-shape":
                configuration["Environment"]["Unexpected"] = "opaque"
            elif self.fault == "environment-variable":
                configuration["Environment"]["Variables"][
                    "UNREVIEWED"
                ] = "opaque"
            elif self.fault == "vpc-shape":
                configuration["VpcConfig"]["Unexpected"] = "opaque"
            elif self.fault == "logging-shape":
                configuration["LoggingConfig"]["Unexpected"] = "opaque"
            elif self.fault == "dead-letter":
                configuration["DeadLetterConfig"] = {
                    "TargetArn": "arn:aws:sqs:us-east-1:000000000000:foreign"
                }
            elif self.fault == "tracing":
                configuration["TracingConfig"] = {"Mode": "Active"}
            elif self.fault == "snap-start":
                configuration["SnapStart"] = {
                    "ApplyOn": "PublishedVersions",
                    "OptimizationStatus": "On",
                }
        return configuration

    def get_runtime_management_config(
        self, *, FunctionName: str, Qualifier: str
    ) -> Mapping[str, Any]:
        mode = self._mode(FunctionName)
        assert Qualifier == self.versions[mode]
        update_mode = (
            "Auto"
            if self.fault == "runtime-management" and mode == "plan"
            else "FunctionUpdate"
        )
        return {
            "FunctionArn": (
                f"arn:aws:lambda:{runtime.REGION}:"
                f"{runtime.AUTHORITY_ACCOUNT_ID}:function:"
                f"{FunctionName}:{Qualifier}"
            ),
            "RuntimeVersionArn": (
                "arn:aws:lambda:us-east-1::runtime:python3.12-synthetic"
            ),
            "UpdateRuntimeOn": update_mode,
        }

    def get_function_code_signing_config(
        self, **_kwargs: Any
    ) -> Mapping[str, Any]:
        return {
            "CodeSigningConfigArn": self.env[
                "EXPECTED_CODE_SIGNING_CONFIG_ARN"
            ]
        }

    def get_function_concurrency(self, **_kwargs: Any) -> Mapping[str, Any]:
        return {"ReservedConcurrentExecutions": 1}

    def get_function_event_invoke_config(
        self, *, FunctionName: str, **_kwargs: Any
    ) -> Mapping[str, Any]:
        destination: Mapping[str, Any] = {
            "OnSuccess": {},
            "OnFailure": {},
        }
        if self.fault == "destination" and self._mode(FunctionName) == "plan":
            destination = {
                "OnSuccess": {},
                "OnFailure": {
                    "Destination": "arn:aws:sqs:us-east-1:000000000000:foreign"
                },
            }
        return {
            "MaximumRetryAttempts": 0,
            "MaximumEventAgeInSeconds": 60,
            "DestinationConfig": destination,
        }

    def get_policy(self, **_kwargs: Any) -> Mapping[str, Any]:
        raise _NotFound()

    def get_function_url_config(self, **_kwargs: Any) -> Mapping[str, Any]:
        raise _NotFound()

    def get_code_signing_config(self, **_kwargs: Any) -> Mapping[str, Any]:
        allowed: dict[str, Any] = {
            "SigningProfileVersionArns": [
                self.env["EXPECTED_SIGNING_PROFILE_VERSION_ARN"]
            ]
        }
        policies: dict[str, Any] = {
            "UntrustedArtifactOnDeployment": "Enforce"
        }
        if self.fault == "signing-publishers-shape":
            allowed["Unexpected"] = "opaque"
        elif self.fault == "signing-policies-shape":
            policies["Unexpected"] = "opaque"
        return {
            "CodeSigningConfig": {
                "CodeSigningConfigArn": self.env[
                    "EXPECTED_CODE_SIGNING_CONFIG_ARN"
                ],
                "AllowedPublishers": allowed,
                "CodeSigningPolicies": policies,
            }
        }


def test_lambda_control_plane_accepts_only_the_exact_closed_shapes() -> None:
    env = _lambda_environment()
    assert runtime._verify_lambda_control_plane(
        client=_LambdaClient(env), env=env
    ) == _LambdaClient.versions


@pytest.mark.parametrize(
    ("fault", "code"),
    [
        ("alias-routing", "LAMBDA_ALIAS_MISMATCH"),
        ("environment-shape", "LAMBDA_ENVIRONMENT_MISMATCH"),
        ("environment-variable", "LAMBDA_ENVIRONMENT_MISMATCH"),
        ("vpc-shape", "LAMBDA_CONFIGURATION_MISMATCH"),
        ("logging-shape", "LAMBDA_CONFIGURATION_MISMATCH"),
        ("dead-letter", "LAMBDA_CONFIGURATION_MISMATCH"),
        ("tracing", "LAMBDA_CONFIGURATION_MISMATCH"),
        ("snap-start", "LAMBDA_CONFIGURATION_MISMATCH"),
        (
            "runtime-management",
            "LAMBDA_RUNTIME_MANAGEMENT_MISMATCH",
        ),
        ("destination", "LAMBDA_RETRY_CONFIGURATION_MISMATCH"),
        ("signing-publishers-shape", "LAMBDA_SIGNING_MISMATCH"),
        ("signing-policies-shape", "LAMBDA_SIGNING_MISMATCH"),
    ],
)
def test_lambda_control_plane_rejects_alias_environment_and_side_channels(
    fault: str, code: str
) -> None:
    env = _lambda_environment()

    with pytest.raises(PlanPermissionRepairError) as captured:
        runtime._verify_lambda_control_plane(
            client=_LambdaClient(env, fault), env=env
        )

    assert captured.value.code == code


class _HandlerContext:
    invoked_function_arn = (
        f"arn:aws:lambda:{runtime.REGION}:{runtime.AUTHORITY_ACCOUNT_ID}:"
        f"function:{runtime.FUNCTION_NAMES['plan']}:"
        f"{runtime.FUNCTION_QUALIFIERS['plan']}"
    )

    @staticmethod
    def get_remaining_time_in_millis() -> int:
        return 600_000


def test_public_handler_removes_provider_payload_and_exception_chain(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from tooling import platform_authority_plan_permission_repair as core

    secret = "customer-secret-provider-payload"

    def fail(*_args: Any, **_kwargs: Any) -> Any:
        raise RuntimeError(secret)

    monkeypatch.setattr(runtime, "_runtime_factory", fail)
    environment, _ = _valid_runtime_environment()
    for key, value in environment.items():
        monkeypatch.setenv(key, value)
    monkeypatch.setenv("AWS_LAMBDA_FUNCTION_VERSION", "1")
    core.install_runtime_factory(None)
    try:
        with pytest.raises(runtime.PublicPlanRepairFailure) as captured:
            runtime.plan_handler({}, _HandlerContext())
    finally:
        core.install_runtime_factory(None)

    assert str(captured.value) == "GUG376_PLAN_REPAIR_BLOCKED:PROVIDER_FAILURE"
    assert secret not in str(captured.value)
    assert secret not in repr(captured.value)
    assert captured.value.__cause__ is None
    assert captured.value.__context__ is None
