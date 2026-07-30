"""GUG-214 authority recovery preflight security contracts."""
from __future__ import annotations

import copy
import importlib.util
import inspect
import json
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

from tooling.founder_bootstrap_pep import (
    AUTHORITY_ACCOUNT_ID,
    AUTHORITY_REGION,
    PEP_TABLE_NAME,
    AwsCliFounderPepStore,
    FounderPepAuthorizationError,
)
from tooling.platform_authority_bootstrap import (
    BootstrapAuthorizationError,
    BootstrapBinding,
    render_bootstrap_iam_policy,
)


REPO_ROOT = Path(__file__).resolve().parents[2]
BOOTSTRAP_SCRIPT = REPO_ROOT / "scripts/deployment/platform-authority-bootstrap.py"
NORMAL_PLAN_POLICY = REPO_ROOT / "policies/iam/platform-authority-bootstrap-plan-role.json"
FOUNDER_PLAN_POLICY = REPO_ROOT / "policies/iam/platform-authority-founder-live-plan-role.json"
FOUNDER_APPLY_POLICY = REPO_ROOT / "policies/iam/platform-authority-founder-live-apply-role.json"
STACK_NAME = "scanalyze-platform-authority-state-backend"
SYNTHETIC_AUTHORITY = "111122223333"
SYNTHETIC_ROLE = (
    "arn:aws:sts::111122223333:assumed-role/"
    "AWSReservedSSO_ScanalyzeAuthorityBootstrapPlan_0123456789abcdef/synthetic.user"
)
STACK_ARN_TEMPLATE = (
    "arn:${aws_partition}:cloudformation:${region}:${authority_account_id}:"
    f"stack/{STACK_NAME}/*"
)


def _actions(statement: dict[str, Any]) -> set[str]:
    value = statement.get("Action", [])
    return {value} if isinstance(value, str) else set(value)


def _binding() -> BootstrapBinding:
    return BootstrapBinding(
        authority_account_id=SYNTHETIC_AUTHORITY,
        region="us-east-1",
        stack_name=STACK_NAME,
        state_bucket_name=(
            f"scanalyze-platform-authority-{SYNTHETIC_AUTHORITY}-us-east-1-state"
        ),
        state_key="platform-authority/terraform.tfstate",
        destination_account_ids=("444455556666", "777788889999"),
    )


@pytest.fixture
def bootstrap_module(monkeypatch: pytest.MonkeyPatch) -> ModuleType:
    spec = importlib.util.spec_from_file_location("gug214_bootstrap_cli", BOOTSTRAP_SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    monkeypatch.setenv("AWS_PROFILE", "synthetic-authority-plan")
    monkeypatch.setenv("AWS_REGION", "us-east-1")
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")
    for name in module.FORBIDDEN_CREDENTIAL_ENV:
        monkeypatch.delenv(name, raising=False)
    return module


@pytest.fixture
def founder_module() -> ModuleType:
    script = REPO_ROOT / "scripts/deployment/founder-bootstrap-pep.py"
    spec = importlib.util.spec_from_file_location("gug214_founder_cli", script)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class RecoveryClient:
    """In-memory AWS adapter that records the exact read-only boundary."""

    def __init__(
        self,
        *,
        region: str = "us-east-1",
        account_id: str = SYNTHETIC_AUTHORITY,
        caller_arn: str = SYNTHETIC_ROLE,
        stack_response: dict[str, Any] | None = None,
        resources_response: dict[str, Any] | None = None,
        change_set_pages: dict[str | None, dict[str, Any]] | None = None,
        account_public_access_block: dict[str, Any] | None = None,
    ) -> None:
        self.region = region
        self.account_id = account_id
        self.caller_arn = caller_arn
        self.stack_response = stack_response or {
            "Stacks": [
                {
                    "StackName": STACK_NAME,
                    "StackId": (
                        "arn:aws:cloudformation:us-east-1:111122223333:stack/"
                        f"{STACK_NAME}/00000000-0000-4000-8000-000000000000"
                    ),
                    "StackStatus": "REVIEW_IN_PROGRESS",
                }
            ]
        }
        self.resources_response = (
            {"StackResourceSummaries": []}
            if resources_response is None
            else resources_response
        )
        self.change_set_pages = change_set_pages or {None: {"Summaries": []}}
        self.account_public_access_block = account_public_access_block
        self.calls: list[tuple[str, str, tuple[str, ...]]] = []

    def run(self, service: str, operation: str, *args: str) -> dict[str, Any]:
        self.calls.append((service, operation, args))
        if (service, operation) == ("sts", "get-caller-identity"):
            return {"Account": self.account_id, "Arn": self.caller_arn}
        if (service, operation) == ("cloudformation", "list-stack-resources"):
            assert args == ("--stack-name", STACK_NAME)
            return self.resources_response
        if (service, operation) == ("cloudformation", "list-change-sets"):
            assert args[:2] == ("--stack-name", STACK_NAME)
            assert args[2:4] == ("--max-items", "100")
            if len(args) == 4:
                token = None
            else:
                assert args[4] == "--starting-token" and len(args) == 6
                token = args[5]
            return self.change_set_pages[token]
        raise AssertionError(f"unexpected AWS call: {service} {operation} {args}")

    def run_allow_missing(
        self,
        service: str,
        operation: str,
        *args: str,
        missing_markers: tuple[str, ...],
    ) -> dict[str, Any] | None:
        del missing_markers
        self.calls.append((service, operation, args))
        if (service, operation) == ("cloudformation", "describe-stacks"):
            assert args == ("--stack-name", STACK_NAME)
            return self.stack_response
        if (service, operation) == ("s3control", "get-public-access-block"):
            assert args == ("--account-id", SYNTHETIC_AUTHORITY)
            return self.account_public_access_block
        raise AssertionError(f"unexpected AWS call: {service} {operation} {args}")


def test_normal_plan_lists_change_sets_only_on_the_canonical_stack() -> None:
    policy = json.loads(NORMAL_PLAN_POLICY.read_text(encoding="utf-8"))
    statements = [
        statement
        for statement in policy["Statement"]
        if "cloudformation:ListChangeSets" in _actions(statement)
    ]

    assert len(statements) == 1
    assert statements[0]["Effect"] == "Allow"
    assert statements[0]["Resource"] == STACK_ARN_TEMPLATE
    assert "Condition" not in statements[0]


@pytest.mark.parametrize("mutation", ["wildcard", "condition", "mixed", "duplicate"])
def test_normal_plan_renderer_rejects_ambiguous_change_set_inventory_scope(
    mutation: str,
) -> None:
    policy = json.loads(NORMAL_PLAN_POLICY.read_text(encoding="utf-8"))
    inventory = next(
        statement
        for statement in policy["Statement"]
        if "cloudformation:ListChangeSets" in _actions(statement)
    )
    if mutation == "wildcard":
        inventory["Resource"] = "*"
    elif mutation == "condition":
        inventory["Condition"] = {"StringEquals": {"aws:RequestedRegion": "us-east-1"}}
    elif mutation == "mixed":
        inventory["Action"] = [
            "cloudformation:DescribeStacks",
            "cloudformation:ListChangeSets",
        ]
    else:
        policy["Statement"].append(copy.deepcopy(inventory))

    with pytest.raises(BootstrapAuthorizationError):
        render_bootstrap_iam_policy(
            policy_template=policy,
            binding=_binding(),
            change_set_name="scanalyze-platform-authority-bootstrap-20300101000000",
        )


def test_founder_plan_lists_change_sets_only_on_the_canonical_stack() -> None:
    policy = json.loads(FOUNDER_PLAN_POLICY.read_text(encoding="utf-8"))
    statements = [
        statement
        for statement in policy["Statement"]
        if "cloudformation:ListChangeSets" in _actions(statement)
    ]

    assert len(statements) == 1
    assert statements[0]["Effect"] == "Allow"
    assert statements[0]["Resource"] == (
        "arn:aws:cloudformation:${region}:${authority_account_id}:"
        f"stack/{STACK_NAME}/*"
    )
    assert "Condition" not in statements[0]


def test_recovery_preflight_accepts_only_exact_empty_shell_and_sanitizes_receipt(
    bootstrap_module: ModuleType,
) -> None:
    client = RecoveryClient()

    receipt = bootstrap_module._recovery_preflight(client, _binding())

    assert receipt["stack_status"] == "REVIEW_IN_PROGRESS"
    assert receipt["resource_count"] == 0
    assert receipt["active_change_set_count"] == 0
    assert receipt["account_public_access_blocked"] is False
    serialized = json.dumps(receipt, sort_keys=True)
    assert SYNTHETIC_ROLE not in serialized
    assert "synthetic.user" not in serialized
    assert {call[:2] for call in client.calls} == {
        ("sts", "get-caller-identity"),
        ("cloudformation", "describe-stacks"),
        ("cloudformation", "list-stack-resources"),
        ("cloudformation", "list-change-sets"),
        ("s3control", "get-public-access-block"),
    }


def test_recovery_preflight_paginates_to_prove_global_change_set_absence(
    bootstrap_module: ModuleType,
) -> None:
    client = RecoveryClient(
        change_set_pages={
            None: {"Summaries": [], "NextToken": "second-page"},
            "second-page": {"Summaries": []},
        }
    )

    receipt = bootstrap_module._recovery_preflight(client, _binding())

    assert receipt["active_change_set_count"] == 0
    change_set_calls = [call for call in client.calls if call[:2] == ("cloudformation", "list-change-sets")]
    assert change_set_calls == [
        (
            "cloudformation",
            "list-change-sets",
            ("--stack-name", STACK_NAME, "--max-items", "100"),
        ),
        (
            "cloudformation",
            "list-change-sets",
            (
                "--stack-name",
                STACK_NAME,
                "--max-items",
                "100",
                "--starting-token",
                "second-page",
            ),
        ),
    ]


def test_normal_plan_rechecks_recovery_inventory_before_change_set_creation(
    bootstrap_module: ModuleType,
) -> None:
    source = inspect.getsource(bootstrap_module._cmd_plan)

    inventory_index = source.index(
        "_require_no_active_change_sets(client, binding.stack_name)"
    )
    create_index = source.index('"create-change-set"')
    assert inventory_index < create_index
    assert "client.run(" not in source[inventory_index:source.index("response = client.run(")]


@pytest.mark.parametrize(
    "client",
    [
        RecoveryClient(account_id="999900001111"),
        RecoveryClient(
            caller_arn=(
                "arn:aws:sts::111122223333:assumed-role/"
                "AWSReservedSSO_AWSAdministratorAccess_0123456789abcdef/synthetic.user"
            )
        ),
        RecoveryClient(region="us-west-2"),
    ],
    ids=("wrong-account", "wrong-permission-set", "wrong-region"),
)
def test_recovery_preflight_rejects_wrong_authority_identity(
    bootstrap_module: ModuleType,
    client: RecoveryClient,
) -> None:
    with pytest.raises(BootstrapAuthorizationError):
        bootstrap_module._recovery_preflight(client, _binding())


@pytest.mark.parametrize("status", ["CREATE_COMPLETE", "ROLLBACK_COMPLETE", None])
def test_recovery_preflight_requires_exact_review_status(
    bootstrap_module: ModuleType,
    status: str | None,
) -> None:
    client = RecoveryClient(
        stack_response={
            "Stacks": [
                {
                    "StackName": STACK_NAME,
                    "StackStatus": status,
                }
            ]
        }
    )

    with pytest.raises(BootstrapAuthorizationError, match="review"):
        bootstrap_module._recovery_preflight(client, _binding())


@pytest.mark.parametrize(
    "stack",
    [
        {
            "StackName": "foreign-stack",
            "StackId": (
                "arn:aws:cloudformation:us-east-1:111122223333:stack/"
                "foreign-stack/00000000-0000-4000-8000-000000000000"
            ),
            "StackStatus": "REVIEW_IN_PROGRESS",
        },
        {
            "StackName": STACK_NAME,
            "StackId": (
                "arn:aws:cloudformation:us-east-1:999900001111:stack/"
                f"{STACK_NAME}/00000000-0000-4000-8000-000000000000"
            ),
            "StackStatus": "REVIEW_IN_PROGRESS",
        },
    ],
    ids=("foreign-name", "foreign-stack-account"),
)
def test_recovery_preflight_rejects_foreign_stack_identity(
    bootstrap_module: ModuleType,
    stack: dict[str, Any],
) -> None:
    client = RecoveryClient(stack_response={"Stacks": [stack]})

    with pytest.raises(BootstrapAuthorizationError, match="identity"):
        bootstrap_module._recovery_preflight(client, _binding())


@pytest.mark.parametrize(
    ("field", "value"),
    [
        (
            "RoleARN",
            "arn:aws:iam::111122223333:role/ForeignCloudFormationAdmin",
        ),
        (
            "NotificationARNs",
            ["arn:aws:sns:us-east-1:111122223333:foreign-notifications"],
        ),
        (
            "ParentId",
            (
                "arn:aws:cloudformation:us-east-1:111122223333:stack/"
                "foreign-parent/00000000-0000-4000-8000-000000000001"
            ),
        ),
        (
            "RootId",
            (
                "arn:aws:cloudformation:us-east-1:111122223333:stack/"
                "foreign-root/00000000-0000-4000-8000-000000000002"
            ),
        ),
    ],
    ids=("service-role", "notifications", "nested-parent", "nested-root"),
)
def test_recovery_preflight_rejects_inherited_or_nested_stack_authority(
    bootstrap_module: ModuleType,
    field: str,
    value: object,
) -> None:
    stack = copy.deepcopy(RecoveryClient().stack_response["Stacks"][0])
    stack[field] = value
    client = RecoveryClient(stack_response={"Stacks": [stack]})

    with pytest.raises(BootstrapAuthorizationError, match="authority|metadata"):
        bootstrap_module._recovery_preflight(client, _binding())


@pytest.mark.parametrize("value", [None, "", "not-a-list"])
def test_recovery_preflight_rejects_ambiguous_notification_metadata(
    bootstrap_module: ModuleType,
    value: object,
) -> None:
    stack = copy.deepcopy(RecoveryClient().stack_response["Stacks"][0])
    stack["NotificationARNs"] = value
    client = RecoveryClient(stack_response={"Stacks": [stack]})

    with pytest.raises(BootstrapAuthorizationError, match="metadata"):
        bootstrap_module._recovery_preflight(client, _binding())


def test_normal_apply_rechecks_exact_shell_immediately_before_execute(
    bootstrap_module: ModuleType,
) -> None:
    source = inspect.getsource(bootstrap_module._cmd_apply)
    execute_index = source.index('"execute-change-set"')
    execute_call_index = source.rfind("client.run(", 0, execute_index)
    rechecks = [
        index
        for index in range(len(source))
        if source.startswith("_require_exact_empty_review_stack", index)
    ]

    assert len(rechecks) == 2
    assert rechecks[-1] < execute_call_index
    assert "client.run(" not in source[rechecks[-1] : execute_call_index]


@pytest.mark.parametrize("command", ["_cmd_plan", "_cmd_apply"])
def test_founder_effect_rechecks_exact_shell_before_protected_cloudformation_effect(
    founder_module: ModuleType,
    command: str,
) -> None:
    source = inspect.getsource(getattr(founder_module, command))
    effect_source = source[source.index("    def effect()") :]
    recheck_index = effect_source.index("_require_exact_founder_review_stack")
    protected_operation = "create-change-set" if command == "_cmd_plan" else "execute-change-set"
    effect_index = effect_source.index(protected_operation)

    assert recheck_index < effect_index


def test_founder_review_shell_uses_the_shared_authority_metadata_contract(
    founder_module: ModuleType,
) -> None:
    stack = copy.deepcopy(RecoveryClient().stack_response["Stacks"][0])
    stack["StackId"] = (
        f"arn:aws:cloudformation:{AUTHORITY_REGION}:{AUTHORITY_ACCOUNT_ID}:stack/"
        f"{STACK_NAME}/00000000-0000-4000-8000-000000000000"
    )
    stack["RoleARN"] = (
        f"arn:aws:iam::{AUTHORITY_ACCOUNT_ID}:role/ForeignCloudFormationAdmin"
    )

    with pytest.raises(BootstrapAuthorizationError, match="authority"):
        founder_module._require_exact_founder_review_stack(stack, [])


@pytest.mark.parametrize(
    "resources",
    [
        {"StackResourceSummaries": [{"LogicalResourceId": "ForeignResource"}]},
        {"StackResourceSummaries": None},
        {},
    ],
    ids=("foreign-resource", "non-list", "missing-list"),
)
def test_recovery_preflight_rejects_nonempty_or_ambiguous_resources(
    bootstrap_module: ModuleType,
    resources: dict[str, Any],
) -> None:
    client = RecoveryClient(resources_response=resources)

    with pytest.raises(BootstrapAuthorizationError, match="resource"):
        bootstrap_module._recovery_preflight(client, _binding())


@pytest.mark.parametrize(
    "pages",
    [
        {None: {"Summaries": [{"ChangeSetName": "foreign", "Status": "CREATE_COMPLETE"}]}},
        {None: {"Summaries": None}},
        {None: {}},
        {None: {"Summaries": [], "NextToken": ""}},
        {None: {"Summaries": [], "NextToken": 7}},
        {
            None: {"Summaries": [], "NextToken": "repeat"},
            "repeat": {"Summaries": [], "NextToken": "repeat"},
        },
    ],
    ids=(
        "foreign-change-set",
        "non-list",
        "missing-list",
        "empty-token",
        "non-string-token",
        "repeated-token",
    ),
)
def test_recovery_preflight_rejects_any_change_set_or_ambiguous_pagination(
    bootstrap_module: ModuleType,
    pages: dict[str | None, dict[str, Any]],
) -> None:
    client = RecoveryClient(change_set_pages=pages)

    with pytest.raises(BootstrapAuthorizationError, match="Change Set|pagination"):
        bootstrap_module._recovery_preflight(client, _binding())


def test_founder_plan_change_set_inventory_is_paginated_and_fail_closed(
    founder_module: ModuleType,
) -> None:
    class Client:
        def __init__(self, pages: dict[str | None, dict[str, Any]]) -> None:
            self.pages = pages
            self.calls: list[tuple[str, str, tuple[str, ...]]] = []

        def run(self, service: str, operation: str, *args: str) -> dict[str, Any]:
            self.calls.append((service, operation, args))
            assert (service, operation) == ("cloudformation", "list-change-sets")
            assert args[:4] == ("--stack-name", STACK_NAME, "--max-items", "100")
            token = None if len(args) == 4 else args[5]
            if len(args) != 4:
                assert args[4] == "--starting-token" and len(args) == 6
            return self.pages[token]

    clean = Client(
        {
            None: {"Summaries": [], "NextToken": "second-page"},
            "second-page": {"Summaries": []},
        }
    )
    founder_module._require_no_active_change_sets(clean)
    assert len(clean.calls) == 2

    foreign = Client(
        {
            None: {
                "Summaries": [
                    {
                        "ChangeSetName": "foreign",
                        "Status": "CREATE_COMPLETE",
                        "ExecutionStatus": "AVAILABLE",
                    }
                ]
            }
        }
    )
    with pytest.raises(FounderPepAuthorizationError, match="Change Set"):
        founder_module._require_no_active_change_sets(foreign)


def test_founder_plan_rechecks_change_sets_immediately_before_creation(
    founder_module: ModuleType,
) -> None:
    source = inspect.getsource(founder_module._cmd_plan)
    effect_source = source[source.index("    def effect()") :]

    inventory_index = effect_source.index("_require_no_active_change_sets(client)")
    create_index = effect_source.index('"cloudformation", "create-change-set"')
    assert inventory_index < create_index
    between = effect_source[inventory_index:create_index]
    assert "client.run(" not in between


@pytest.mark.parametrize("policy_path", [FOUNDER_PLAN_POLICY, FOUNDER_APPLY_POLICY])
def test_founder_roles_can_read_exact_table_and_continuous_backups_without_wildcard(
    policy_path: Path,
) -> None:
    policy = json.loads(policy_path.read_text(encoding="utf-8"))
    metadata = [
        statement
        for statement in policy["Statement"]
        if {
            "dynamodb:DescribeTable",
            "dynamodb:DescribeContinuousBackups",
        }.intersection(_actions(statement))
    ]

    assert len(metadata) == 1
    assert _actions(metadata[0]) == {
        "dynamodb:DescribeTable",
        "dynamodb:DescribeContinuousBackups",
    }
    assert metadata[0]["Resource"] == (
        "arn:aws:dynamodb:${region}:${authority_account_id}:table/${pep_table_name}"
    )
    assert "*" not in metadata[0]["Resource"]
    assert "Condition" not in metadata[0]


def test_founder_table_control_readback_proves_exact_table_and_pitr() -> None:
    commands: list[tuple[str, ...]] = []
    table_arn = (
        f"arn:aws:dynamodb:{AUTHORITY_REGION}:{AUTHORITY_ACCOUNT_ID}:table/{PEP_TABLE_NAME}"
    )

    def runner(command: list[str] | tuple[str, ...]) -> str:
        parts = tuple(command)
        commands.append(parts)
        if "describe-table" in parts:
            return json.dumps(
                {
                    "Table": {
                        "TableStatus": "ACTIVE",
                        "TableArn": table_arn,
                        "KeySchema": [
                            {"AttributeName": "exception_id", "KeyType": "HASH"}
                        ],
                        "DeletionProtectionEnabled": True,
                        "SSEDescription": {"Status": "ENABLED"},
                    }
                }
            )
        assert "describe-continuous-backups" in parts
        return json.dumps(
            {
                "ContinuousBackupsDescription": {
                    "ContinuousBackupsStatus": "ENABLED",
                    "PointInTimeRecoveryDescription": {
                        "PointInTimeRecoveryStatus": "ENABLED"
                    },
                }
            }
        )

    store = AwsCliFounderPepStore(
        region=AUTHORITY_REGION,
        authority_account_id=AUTHORITY_ACCOUNT_ID,
        table_name=PEP_TABLE_NAME,
        runner=runner,
    )

    assert store.verify_table_controls() == {
        "active": True,
        "exact_arn": True,
        "exact_key": True,
        "deletion_protected": True,
        "sse_enabled": True,
        "pitr_enabled": True,
    }
    assert [parts[1:3] for parts in commands] == [
        ("dynamodb", "describe-table"),
        ("dynamodb", "describe-continuous-backups"),
    ]
    assert all(("--table-name", PEP_TABLE_NAME) == parts[5:7] for parts in commands)


def test_founder_table_control_readback_fails_closed_when_pitr_is_not_enabled() -> None:
    table_arn = (
        f"arn:aws:dynamodb:{AUTHORITY_REGION}:{AUTHORITY_ACCOUNT_ID}:table/{PEP_TABLE_NAME}"
    )

    def runner(command: list[str] | tuple[str, ...]) -> str:
        parts = tuple(command)
        if "describe-table" in parts:
            return json.dumps(
                {
                    "Table": {
                        "TableStatus": "ACTIVE",
                        "TableArn": table_arn,
                        "KeySchema": [
                            {"AttributeName": "exception_id", "KeyType": "HASH"}
                        ],
                        "DeletionProtectionEnabled": True,
                        "SSEDescription": {"Status": "ENABLED"},
                    }
                }
            )
        return json.dumps(
            {
                "ContinuousBackupsDescription": {
                    "ContinuousBackupsStatus": "ENABLED",
                    "PointInTimeRecoveryDescription": {
                        "PointInTimeRecoveryStatus": "DISABLED"
                    },
                }
            }
        )

    store = AwsCliFounderPepStore(
        region=AUTHORITY_REGION,
        authority_account_id=AUTHORITY_ACCOUNT_ID,
        table_name=PEP_TABLE_NAME,
        runner=runner,
    )

    with pytest.raises(FounderPepAuthorizationError, match="controls are incomplete"):
        store.verify_table_controls()
