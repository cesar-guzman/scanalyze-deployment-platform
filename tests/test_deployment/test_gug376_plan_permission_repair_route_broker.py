from __future__ import annotations

import ast
import base64
from copy import deepcopy
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from hashlib import sha256
import inspect
import json
from pathlib import Path
import sys
import types
from typing import Any, Callable, Mapping, Sequence
import zlib

import pytest


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tooling"))

import platform_authority_plan_permission_repair_route_broker as broker  # noqa: E402
from tooling import (  # noqa: E402
    platform_authority_gug376_collision_admission as collision_contract,
)


NOW = datetime(2026, 8, 30, 19, 0, tzinfo=timezone.utc)
SOURCE_COMMIT = "a" * 40
REPAIR_ID = "gug376-plan-permission-repair-" + ("b" * 64)
INTENT_DIGEST = "sha256:" + ("c" * 64)
BINDING_DIGEST = "sha256:" + ("d" * 64)
FOUNDATION_PUBLISH_BINDING_DIGEST = "sha256:" + ("e" * 64)
SOURCE_TREE_SHA = "f" * 40
BOOTSTRAP_INTENT_DIGEST = "sha256:" + ("0" * 64)
INSTANCE_ARN = "arn:aws:sso:::instance/ssoins-1234567890abcdef"
ROUTE_CREATOR_PS = (
    "arn:aws:sso:::permissionSet/ssoins-1234567890abcdef/ps-1111111111111111"
)
ROUTE_EXECUTOR_PS = (
    "arn:aws:sso:::permissionSet/ssoins-1234567890abcdef/ps-2222222222222222"
)
ROUTE_INVOKER_PS = (
    "arn:aws:sso:::permissionSet/ssoins-1234567890abcdef/ps-3333333333333333"
)
DELEGATION_PS = (
    "arn:aws:sso:::permissionSet/ssoins-1234567890abcdef/ps-4444444444444444"
)
NORMAL_PLAN_ROLE_NAME = (
    "AWSReservedSSO_ScanalyzeAuthorityBootstrapPlan_0123456789ABCDEF"
)
NORMAL_PLAN_ROLE_ARN = (
    "arn:aws:iam::042360977644:role/aws-reserved/sso.amazonaws.com/"
    + NORMAL_PLAN_ROLE_NAME
)
NORMAL_PLAN_CALLER = (
    "arn:aws:sts::042360977644:assumed-role/"
    + NORMAL_PLAN_ROLE_NAME
    + "/cesar-gug376"
)
NORMAL_PLAN_CALLER_DIGEST = broker.digest_value(
    {"caller_arn": NORMAL_PLAN_CALLER}
)


def _collision_manifest(
    cfg: broker.BrokerConfig,
    *,
    phase: str,
    operation: str,
    effect_request: Mapping[str, Any],
) -> dict[str, Any]:
    return broker.seal(
        {
            "schema_version": 1,
            "record_type": "synthetic.route_collision_admission.v1",
            "phase": phase,
            "operation": operation,
            "effect_request_digest": broker.digest_value(effect_request),
            "source_commit_sha": cfg.source_commit,
            "source_tree_sha": cfg.source_tree_sha,
            "bootstrap_intent_digest": cfg.bootstrap_intent_digest,
        },
        "manifest_digest",
    )


def _attempt_collision_manifest(
    cfg: broker.BrokerConfig,
    *,
    operation: str,
    effect_request: Mapping[str, Any],
) -> dict[str, Any]:
    return _collision_manifest(
        cfg,
        phase=collision_contract.route_collision_operation_phase(operation),
        operation=operation,
        effect_request=effect_request,
    )


class _SyntheticCollisionAdmission:
    """Exact sealed one-shot admission used only by this broker test."""

    def __init__(
        self,
        cfg: broker.BrokerConfig,
        *,
        timeline: list[str] | None = None,
    ) -> None:
        self.cfg = cfg
        self.timeline = timeline if timeline is not None else []
        self.calls: list[tuple[str, str]] = []
        self._capabilities: dict[int, dict[str, Any]] = {}
        self._grants: dict[int, dict[str, Any]] = {}

    def admit(
        self,
        *,
        phase: str,
        operation: str,
        effect_request: Mapping[str, Any],
        before_call: Callable[[], None],
    ) -> object:
        before_call()
        manifest = _collision_manifest(
            self.cfg,
            phase=phase,
            operation=operation,
            effect_request=effect_request,
        )
        capability = object()
        self._capabilities[id(capability)] = {
            "capability": capability,
            "manifest": manifest,
            "consumed": False,
        }
        self.calls.append(("admit", operation))
        self.timeline.append(f"admission:admit:{operation}")
        return capability

    def manifest(self, capability: object) -> Mapping[str, Any]:
        state = self._capabilities.get(id(capability))
        if state is None or state["capability"] is not capability:
            raise broker.RouteBrokerError("SYNTHETIC_CAPABILITY_INVALID")
        return deepcopy(state["manifest"])

    def consume(
        self,
        capability: object,
        *,
        operation: str,
        effect_request_digest: str,
        expected_manifest_digest: str,
        now: datetime,
    ) -> object:
        state = self._capabilities.get(id(capability))
        if (
            state is None
            or state["capability"] is not capability
            or state["consumed"] is not False
            or state["manifest"]["operation"] != operation
            or state["manifest"]["effect_request_digest"]
            != effect_request_digest
            or state["manifest"]["manifest_digest"]
            != expected_manifest_digest
            or not self.cfg.route_not_before <= now < self.cfg.route_not_after
        ):
            raise broker.RouteBrokerError("SYNTHETIC_CAPABILITY_INVALID")
        state["consumed"] = True
        grant = object()
        self._grants[id(grant)] = {
            "grant": grant,
            "manifest": state["manifest"],
            "revalidated": False,
        }
        self.calls.append(("consume", operation))
        self.timeline.append(f"admission:consume:{operation}")
        return grant

    def revalidate(self, grant: object, *, now: datetime) -> str:
        state = self._grants.get(id(grant))
        if (
            state is None
            or state["grant"] is not grant
            or state["revalidated"] is not False
            or not self.cfg.route_not_before <= now < self.cfg.route_not_after
        ):
            raise broker.RouteBrokerError("SYNTHETIC_GRANT_INVALID")
        state["revalidated"] = True
        operation = str(state["manifest"]["operation"])
        self.calls.append(("revalidate", operation))
        self.timeline.append(f"admission:revalidate:{operation}")
        return str(state["manifest"]["manifest_digest"])

STACKS = {
    "seed-revoke-execute-v1": (
        broker.MANAGEMENT_ACCOUNT_ID,
        "scanalyze-platform-authority-gug376-temporary-change-set-route",
    ),
    "delegation-execute-v1": (
        broker.MANAGEMENT_ACCOUNT_ID,
        "scanalyze-platform-authority-bootstrap-plan-repair-delegation",
    ),
    "pep-execute-v1": (
        broker.AUTHORITY_ACCOUNT_ID,
        "scanalyze-platform-authority-bootstrap-plan-repair-pep",
    ),
    "pep-protection-execute-v1": (
        broker.AUTHORITY_ACCOUNT_ID,
        "scanalyze-platform-authority-bootstrap-plan-repair-pep",
    ),
    "delegation-revoke-execute-v1": (
        broker.MANAGEMENT_ACCOUNT_ID,
        "scanalyze-platform-authority-bootstrap-plan-repair-delegation",
    ),
    "route-revoke-execute-v1": (
        broker.MANAGEMENT_ACCOUNT_ID,
        "scanalyze-platform-authority-gug376-temporary-change-set-route",
    ),
}


class _ContractHarnessRouteBroker(broker.RouteBroker):
    """Exercise future broker state transitions while product effects close."""

    def __init__(self, **kwargs: Any) -> None:
        if kwargs.get("collision_admission") is None:
            ledger = kwargs.get("ledger")
            kwargs["collision_admission"] = _SyntheticCollisionAdmission(
                kwargs["config"],
                timeline=getattr(ledger, "timeline", None),
            )
        super().__init__(**kwargs)

CREATE_TO_EXECUTE = {
    "seed-revoke-create-v1": "seed-revoke-execute-v1",
    "delegation-create-v1": "delegation-execute-v1",
    "pep-create-v1": "pep-execute-v1",
    "pep-protection-create-v1": "pep-protection-execute-v1",
    "delegation-revoke-create-v1": "delegation-revoke-execute-v1",
    "route-revoke-create-v1": "route-revoke-execute-v1",
}
PEP_SETUP_ALIASES = (
    "seed-revoke-create-v1",
    "seed-revoke-execute-v1",
    "delegation-create-v1",
    "delegation-execute-v1",
    "pep-create-v1",
    "pep-execute-v1",
    "pep-protection-create-v1",
    "pep-protection-execute-v1",
)


def _change(alias: str) -> dict[str, Any]:
    if alias == "pep-protection-create-v1":
        return {
            "action": "Modify",
            "logical_resource_id": "RepairLedger",
            "resource_type": "AWS::DynamoDB::Table",
            "replacement": "False",
            "scope": [
                "DeletionPolicy",
                "Properties",
                "UpdateReplacePolicy",
            ],
            "details": [
                {
                    "target_attribute": "DeletionPolicy",
                    "target_name": None,
                    "requires_recreation": None,
                    "evaluation": "Static",
                    "change_source": "DirectModification",
                    "causing_entity": None,
                },
                {
                    "target_attribute": "Properties",
                    "target_name": "DeletionProtectionEnabled",
                    "requires_recreation": "Never",
                    "evaluation": "Static",
                    "change_source": "DirectModification",
                    "causing_entity": None,
                },
                {
                    "target_attribute": "UpdateReplacePolicy",
                    "target_name": None,
                    "requires_recreation": None,
                    "evaluation": "Static",
                    "change_source": "DirectModification",
                    "causing_entity": None,
                },
            ],
        }
    logical_id = "Change" + "".join(part.title() for part in alias.split("-"))
    return {
        "action": "Remove" if "revoke" in alias else "Add",
        "logical_resource_id": logical_id,
        "resource_type": "AWS::CloudFormation::Stack",
        "replacement": None,
        "scope": [],
        "details": [],
    }


def _provider_details(change: Mapping[str, Any]) -> list[dict[str, Any]]:
    details: list[dict[str, Any]] = []
    for item in change["details"]:
        target = {"Attribute": item["target_attribute"]}
        if item["target_name"] is not None:
            target["Name"] = item["target_name"]
        if item["requires_recreation"] is not None:
            target["RequiresRecreation"] = item["requires_recreation"]
        detail = {
            "Target": target,
            "Evaluation": item["evaluation"],
            "ChangeSource": item["change_source"],
        }
        if item["causing_entity"] is not None:
            detail["CausingEntity"] = item["causing_entity"]
        details.append(detail)
    return details


def _terminal_outputs(alias: str) -> tuple[list[str], dict[str, str]]:
    if alias == "seed-revoke-execute-v1":
        static = {
            "BrokerInvokerAssignmentMode": "true",
            "ProductionAuthorized": "false",
            "SeedAssignmentMode": "false",
        }
        dynamic = [
            "BrokerInvokerPermissionSetArn",
            "BrokerSeedCreatorPermissionSetArn",
            "BrokerSeedExecutorPermissionSetArn",
        ]
    elif alias == "route-revoke-execute-v1":
        static = {
            "BrokerInvokerAssignmentMode": "false",
            "ProductionAuthorized": "false",
            "SeedAssignmentMode": "false",
        }
        dynamic = [
            "BrokerInvokerPermissionSetArn",
            "BrokerSeedCreatorPermissionSetArn",
            "BrokerSeedExecutorPermissionSetArn",
        ]
    elif alias == "delegation-execute-v1":
        static = {
            "ProductionAuthorized": "false",
            "RepairInvokerAssignmentMode": "true",
        }
        dynamic = ["RepairInvokerPermissionSetArn"]
    elif alias == "delegation-revoke-execute-v1":
        static = {
            "ProductionAuthorized": "false",
            "RepairInvokerAssignmentMode": "false",
        }
        dynamic = ["RepairInvokerPermissionSetArn"]
    elif alias == "pep-execute-v1":
        static = {
            "LedgerDeletionProtectionMode": "false",
            "ProductionAuthorized": "false",
        }
        dynamic = []
    elif alias == "pep-protection-execute-v1":
        static = {
            "LedgerDeletionProtectionMode": "true",
            "ProductionAuthorized": "false",
        }
        dynamic = []
    else:
        static = {"ProductionAuthorized": "false"}
        dynamic = []
    return sorted([*static, *dynamic]), static


def _config_value(**changes: Any) -> dict[str, Any]:
    requests: dict[str, dict[str, Any]] = {}
    creator_contracts: dict[str, dict[str, Any]] = {}
    expectations: dict[str, dict[str, Any]] = {}
    for index, (creator, executor) in enumerate(CREATE_TO_EXECUTE.items(), start=1):
        account, stack = STACKS[executor]
        stem = creator.removesuffix("-create-v1")
        parameters: list[dict[str, str]] = []
        if creator in {"pep-create-v1", "pep-protection-create-v1"}:
            pep_values = {
                "AuthorityAccountId": broker.AUTHORITY_ACCOUNT_ID,
                "ManagementAccountId": broker.MANAGEMENT_ACCOUNT_ID,
                "SourceCommit": SOURCE_COMMIT,
                "SourceBundleDigest": "sha256:" + "5" * 64,
                "RepairId": REPAIR_ID,
                "PrincipalId": "12345678-1234-4123-8123-123456789012",
                "IdentityStoreId": "d-1234567890",
                "IdentityCenterInstanceArn": INSTANCE_ARN,
                "PlanPermissionSetArn": ROUTE_CREATOR_PS,
                "ExpectedPermissionSetDescription": "Exact Plan permission set",
                "RepairInvokerPermissionSetArn": (
                    broker.REPAIR_INVOKER_PERMISSION_SET_SENTINEL
                ),
                "CurrentPolicyDigest": "sha256:" + "6" * 64,
                "DesiredPolicyDigest": "sha256:" + "7" * 64,
                "ExpectedPlanPermissionSetTagsJson": '{"managed_by":"terraform"}',
                "BootstrapChangeSetName": (
                    "scanalyze-platform-authority-bootstrap-20260830190000"
                ),
                "RepairNotBefore": "2026-08-30T19:00:00Z",
                "RepairNotAfter": "2026-08-30T19:15:00Z",
                "PlanSamlProviderArn": (
                    "arn:aws:iam::042360977644:saml-provider/"
                    "AWSSSO_scanalyze_DO_NOT_DELETE"
                ),
                "IdentityCenterKmsMode": "AWS_OWNED_KMS_KEY",
                "IdentityCenterKmsKeyArn": "",
                "ExpectedBoto3Version": "1.42.57",
                "ExpectedBotocoreVersion": "1.42.97",
                "ArtifactBucket": "scanalyze-artifacts",
                "ArtifactKey": (
                    "scanalyze/platform-authority/gug-376/plan-policy-repair/"
                    "signed/12345678-1234-4123-8123-123456789012.zip"
                ),
                "ArtifactVersion": "synthetic-version",
                "ArtifactCodeSha256": "A" * 43 + "=",
                "SigningProfileVersionArn": (
                    "arn:aws:signer:us-east-1:042360977644:/signing-profiles/"
                    "ScanalyzeGug376/ABCDEFGHIJ"
                ),
                "ImmutableConfigurationDigest": "sha256:" + "8" * 64,
                "LedgerDeletionProtectionEnabled": "false",
            }
            if creator == "pep-create-v1":
                parameters = [
                    {"ParameterKey": key, "ParameterValue": value}
                    for key, value in pep_values.items()
                ]
            else:
                parameters = [
                    (
                        {"ParameterKey": key, "ParameterValue": "true"}
                        if key == "LedgerDeletionProtectionEnabled"
                        else {"ParameterKey": key, "UsePreviousValue": True}
                    )
                    for key in pep_values
                ]
        change_set_names = {
            "seed-revoke-create-v1": "gug376-temporary-route-seed-revoke",
            "delegation-create-v1": "gug376-plan-repair-delegation-create",
            "pep-create-v1": "gug376-plan-repair-pep-create",
            "pep-protection-create-v1": "gug376-plan-repair-pep-protection-enable",
            "delegation-revoke-create-v1": "gug376-plan-repair-delegation-revoke",
            "route-revoke-create-v1": "gug376-temporary-route-invoker-revoke",
        }
        requests[creator] = {
            "StackName": stack,
            "ChangeSetName": change_set_names[creator],
            "ChangeSetType": (
                "UPDATE"
                if "revoke" in creator or creator == "pep-protection-create-v1"
                else "CREATE"
            ),
            "Description": "GUG-376 exact synthetic route command",
            "Parameters": parameters,
            "Capabilities": ["CAPABILITY_NAMED_IAM"],
            "Tags": [],
            "IncludeNestedStacks": False,
            "ResourcesToImport": [],
            "NotificationARNs": [],
            "RollbackConfiguration": {
                "MonitoringTimeInMinutes": 0,
                "RollbackTriggers": [],
            },
            "TemplateURL": (
                "https://scanalyze-artifacts.s3.us-east-1.amazonaws.com/"
                f"gug376/{stem}.yaml?versionId=synthetic-{index}"
            ),
            "ClientToken": "gug376-" + broker.digest_value(creator)[7:55],
        }
        if requests[creator]["ChangeSetType"] == "CREATE":
            requests[creator]["OnStackFailure"] = "DELETE"
        requests[executor] = {
            "StackName": stack,
            "ChangeSetName": change_set_names[creator],
            "ClientRequestToken": "gug376-" + broker.digest_value(executor)[7:55],
        }
        if requests[creator]["ChangeSetType"] == "UPDATE":
            requests[executor]["DisableRollback"] = False
        template_digest = "sha256:" + (format(index, "x") * 64)
        creator_contracts[creator] = {
            "template_digest": template_digest,
            "expected_changes": [_change(creator)],
        }
        output_keys, static_outputs = _terminal_outputs(executor)
        expectations[executor] = {
            "account_id": account,
            "stack_name": stack,
            "terminal_statuses": [
                (
                    "UPDATE_COMPLETE"
                    if "revoke" in executor
                    or executor == "pep-protection-execute-v1"
                    else "CREATE_COMPLETE"
                )
            ],
            "template_digest": template_digest,
            "expected_resources": [
                {
                    "logical_resource_id": "SyntheticResource",
                    "resource_type": "AWS::CloudFormation::Stack",
                }
            ],
            "expected_output_keys": output_keys,
            "expected_static_outputs": static_outputs,
            "expected_tags": [],
        }

    output_contracts = {
        "route": {
            "account_id": broker.MANAGEMENT_ACCOUNT_ID,
            "stack_name": STACKS["seed-revoke-execute-v1"][1],
            "permission_set_output_keys": [
                "BrokerInvokerPermissionSetArn",
                "BrokerSeedCreatorPermissionSetArn",
                "BrokerSeedExecutorPermissionSetArn",
            ],
            "required_mode_outputs": {
                "BrokerInvokerAssignmentMode": "true",
                "SeedAssignmentMode": "true",
            },
        },
        "delegation": {
            "account_id": broker.MANAGEMENT_ACCOUNT_ID,
            "stack_name": STACKS["delegation-execute-v1"][1],
            "permission_set_output_keys": ["RepairInvokerPermissionSetArn"],
            "required_mode_outputs": {"RepairInvokerAssignmentMode": "true"},
        },
    }
    revocations = {
        "seed-revoke-execute-v1": {
            "account_id": broker.AUTHORITY_ACCOUNT_ID,
            "instance_arn": INSTANCE_ARN,
            "permission_set_sources": [
                {"source": "route", "output_key": "BrokerSeedCreatorPermissionSetArn"},
                {"source": "route", "output_key": "BrokerSeedExecutorPermissionSetArn"},
            ],
        },
        "delegation-revoke-execute-v1": {
            "account_id": broker.AUTHORITY_ACCOUNT_ID,
            "instance_arn": INSTANCE_ARN,
            "permission_set_sources": [
                {"source": "delegation", "output_key": "RepairInvokerPermissionSetArn"}
            ],
        },
        "route-revoke-execute-v1": {
            "account_id": broker.AUTHORITY_ACCOUNT_ID,
            "instance_arn": INSTANCE_ARN,
            "permission_set_sources": [
                {"source": "route", "output_key": "BrokerInvokerPermissionSetArn"}
            ],
        },
    }
    ledger_id = "gug376-route-broker"
    initialization_digest = broker.digest_value(
        {
            "record_type": broker.LEDGER_RECORD_TYPE,
            "ledger_id": ledger_id,
            "source_commit": SOURCE_COMMIT,
            "binding_digest": BINDING_DIGEST,
            "initial_state": "READY",
            "initial_version": 0,
            "retry_permitted": False,
        }
    )
    value = {
        "schema_version": 1,
        "record_type": broker.CONFIG_RECORD_TYPE,
        "source_commit": SOURCE_COMMIT,
        "ledger_id": ledger_id,
        "ledger_binding_digest": BINDING_DIGEST,
        "initialization_digest": initialization_digest,
        "foundation_publish_binding_digest": (
            FOUNDATION_PUBLISH_BINDING_DIGEST
        ),
        "source_tree_sha": SOURCE_TREE_SHA,
        "bootstrap_intent_digest": BOOTSTRAP_INTENT_DIGEST,
        "repair_id": REPAIR_ID,
        "bootstrap_change_set_name": "scanalyze-bootstrap-plan-20260830",
        "identity_center_instance_arn": INSTANCE_ARN,
        "bootstrap_principal_id": "12345678-1234-4123-8123-123456789012",
        "route_not_before": "2026-08-30T18:00:00Z",
        "route_not_after": "2026-08-30T20:00:00Z",
        "recovery_not_after": "2026-08-31T20:00:00Z",
        "normal_plan_generated_role_arn": NORMAL_PLAN_ROLE_ARN,
        "normal_plan_generated_role_name": NORMAL_PLAN_ROLE_NAME,
        "requests": requests,
        "creator_contracts": creator_contracts,
        "permission_set_output_contracts": output_contracts,
        "terminal_expectations": expectations,
        "revocation_assignment_scopes": revocations,
        "retry_permitted": False,
        "production_authorized": False,
        "production_status": "NO-GO",
    }
    value.update(changes)
    value.pop("config_digest", None)
    return broker.seal(value, "config_digest")


def config(**changes: Any) -> broker.BrokerConfig:
    return broker.BrokerConfig.from_mapping(_config_value(**changes))


class Context:
    def __init__(
        self,
        function: str,
        alias: str,
        *,
        remaining_time_ms: int = 900_000,
    ) -> None:
        self.invoked_function_arn = (
            f"arn:aws:lambda:{broker.REGION}:{broker.AUTHORITY_ACCOUNT_ID}:"
            f"function:{function}:{alias}"
        )
        configured_aliases = broker.CREATOR_ALIASES + broker.EXECUTOR_ALIASES
        self.function_version = str(
            11 + configured_aliases.index(alias)
            if alias in configured_aliases
            else (
                101
                if function == broker.CREATE_RECOVERY_FUNCTION_NAME
                else 102
            )
        )
        self.remaining_time_ms = remaining_time_ms

    def get_remaining_time_in_millis(self) -> int:
        return self.remaining_time_ms


def creator_context(alias: str) -> Context:
    return Context(broker.CREATOR_FUNCTION_NAME, alias)


def executor_context(alias: str) -> Context:
    return Context(broker.EXECUTOR_FUNCTION_NAME, alias)


def create_recovery_context() -> Context:
    return Context(broker.CREATE_RECOVERY_FUNCTION_NAME, broker.RECOVERY_ALIAS)


def execute_recovery_context() -> Context:
    return Context(broker.EXECUTE_RECOVERY_FUNCTION_NAME, broker.RECOVERY_ALIAS)


class FakeLedger:
    def __init__(
        self,
        cfg: broker.BrokerConfig,
        *,
        state: str = "READY",
        receipt: str | None = None,
        dispatch: Mapping[str, Any] | None = None,
        bindings: Mapping[str, str] | None = None,
        fail_cas_at: int | None = None,
        protected: bool = True,
        timeline: list[str] | None = None,
    ) -> None:
        self.cfg = cfg
        self.snapshot = broker.LedgerSnapshot(
            state=state,
            version=0,
            binding_digest=cfg.ledger_binding_digest,
            last_receipt_digest=receipt,
            last_receipt_json=None,
            attempt_claim_json=None,
            dispatch_coordinates_json=(
                broker.canonical_json(dispatch) if dispatch is not None else None
            ),
            derived_bindings_json=(
                broker.canonical_json(bindings) if bindings is not None else None
            ),
        )
        self.fail_cas_at = fail_cas_at
        self.protected = protected
        self.cas_count = 0
        self.timeline = timeline if timeline is not None else []

    def verify_control_plane(self) -> str:
        self.timeline.append("ledger:control-plane")
        if not self.protected:
            raise broker.RouteBrokerError("LEDGER_CONTROL_PLANE_INVALID")
        return broker.digest_value(
            {
                "table": broker.ROUTE_LEDGER_TABLE_NAME,
                "status": "ACTIVE",
                "deletion_protection_enabled": True,
                "sse": "KMS",
            }
        )

    def initialize(self, *, ledger_id: str) -> broker.LedgerSnapshot:
        assert ledger_id == self.cfg.ledger_id
        self.timeline.append("ledger:initialize")
        return self.snapshot

    def read(self, *, ledger_id: str) -> broker.LedgerSnapshot:
        assert ledger_id == self.cfg.ledger_id
        self.timeline.append("ledger:read:" + self.snapshot.state)
        return self.snapshot

    def compare_and_swap(self, **kwargs: Any) -> broker.LedgerSnapshot:
        self.cas_count += 1
        self.timeline.append("ledger:cas:" + kwargs["new_state"])
        if self.fail_cas_at == self.cas_count:
            raise RuntimeError("synthetic CAS failure")
        assert kwargs["expected_state"] == self.snapshot.state
        assert kwargs["expected_version"] == self.snapshot.version
        self.snapshot = broker.LedgerSnapshot(
            state=kwargs["new_state"],
            version=self.snapshot.version + 1,
            binding_digest=self.cfg.ledger_binding_digest,
            last_receipt_digest=kwargs["receipt_digest"],
            last_receipt_json=(
                kwargs.get("receipt_json")
                if kwargs.get("receipt_json") is not None
                else None
            ),
            attempt_claim_json=(
                kwargs.get("attempt_claim_json")
                if kwargs.get("attempt_claim_json") is not None
                else self.snapshot.attempt_claim_json
            ),
            dispatch_coordinates_json=(
                kwargs.get("dispatch_coordinates_json")
                if kwargs.get("dispatch_coordinates_json") is not None
                else self.snapshot.dispatch_coordinates_json
            ),
            derived_bindings_json=(
                kwargs.get("derived_bindings_json")
                if kwargs.get("derived_bindings_json") is not None
                else self.snapshot.derived_bindings_json
            ),
        )
        return self.snapshot


class FakeEffects:
    def __init__(
        self,
        *,
        timeline: list[str] | None = None,
        fail_create: bool = False,
        fail_execute: bool = False,
    ) -> None:
        self.timeline = timeline if timeline is not None else []
        self.fail_create = fail_create
        self.fail_execute = fail_execute
        self.calls: list[tuple[str, str, dict[str, Any]]] = []

    def create_change_set(
        self,
        *,
        operation: str,
        request: Mapping[str, Any],
        permit: object,
    ) -> Mapping[str, Any]:
        broker._consume_effect_permit(
            permit,
            operation=operation,
            request=request,
        )
        self.timeline.append("provider:create")
        self.calls.append(("create", operation, deepcopy(dict(request))))
        if self.fail_create:
            raise TimeoutError("synthetic timeout")
        account = broker.operation_account(operation)
        return {
            "change_set_arn": (
                f"arn:aws:cloudformation:{broker.REGION}:{account}:changeSet/"
                f"{request['ChangeSetName']}/11111111-1111-4111-8111-111111111111"
            ),
            "stack_id": (
                f"arn:aws:cloudformation:{broker.REGION}:{account}:stack/"
                f"{request['StackName']}/22222222-2222-4222-8222-222222222222"
            ),
            "request_id": "33333333-3333-4333-8333-333333333333",
        }

    def execute_change_set(
        self,
        *,
        operation: str,
        request: Mapping[str, Any],
        permit: object,
    ) -> Mapping[str, Any]:
        broker._consume_effect_permit(
            permit,
            operation=operation,
            request=request,
        )
        self.timeline.append("provider:execute")
        self.calls.append(("execute", operation, deepcopy(dict(request))))
        if self.fail_execute:
            raise TimeoutError("synthetic timeout")
        return {"request_id": "44444444-4444-4444-8444-444444444444"}


def _repair_ledger(**changes: Any) -> dict[str, Any]:
    value = {
        "schema_version": 1,
        "record_type": broker.REPAIR_LEDGER_RECORD_TYPE,
        "repair_id": REPAIR_ID,
        "intent_digest": INTENT_DIGEST,
        "source_commit": SOURCE_COMMIT,
        "status": "REPAIR_VERIFIED",
        "stage": "FINAL_READBACK_VERIFIED",
        "effects_attempted": 2,
        "effects_completed": 2,
        "planned_state_digest": "sha256:" + ("1" * 64),
        "state_digest": "sha256:" + ("2" * 64),
        "planned_at": "2026-08-30T18:10:00Z",
        "provider_immutable": True,
        "claim_condition": "attribute_not_exists(repair_id)",
        "mutation_retry_attempted": False,
        "retry_permitted": False,
        "production_authorized": False,
        "claimed_at": "2026-08-30T18:20:00Z",
        "updated_at": "2026-08-30T18:30:00Z",
    }
    value.update(changes)
    return broker.seal(value, "ledger_digest")


def _attestation(repair: Mapping[str, Any], **changes: Any) -> dict[str, Any]:
    value = {
        "schema_version": 1,
        "record_type": broker.RECONCILE_ATTESTATION_RECORD_TYPE,
        "repair_id": REPAIR_ID + "#reconcile-v1",
        "base_repair_id": REPAIR_ID,
        "source_commit": SOURCE_COMMIT,
        "intent_digest": INTENT_DIGEST,
        "repair_ledger_digest": repair["ledger_digest"],
        "observed_state_digest": repair["state_digest"],
        "invocation_authority_graph_digest": "sha256:" + ("3" * 64),
        "function_version": "19",
        "function_qualifier": "reconcile-v1",
        "status": "RECONCILE_VERIFIED",
        "reconciled_at": "2026-08-30T18:50:00Z",
        "claim_condition": "attribute_not_exists(repair_id)",
        "retry_permitted": False,
        "production_authorized": False,
    }
    value.update(changes)
    return broker.seal(value, "attestation_digest")


def _plan_event(**changes: Any) -> dict[str, Any]:
    value = {
        "schema_version": 1,
        "record_type": broker.PLAN_EVENT_RECORD_TYPE,
        "event_id": "55555555-5555-4555-8555-555555555555",
        "event_source": "cloudformation.amazonaws.com",
        "event_name": "ListChangeSets",
        "event_time": "2026-08-30T18:55:00Z",
        "aws_region": broker.REGION,
        "recipient_account_id": broker.AUTHORITY_ACCOUNT_ID,
        "read_only": True,
        "success": True,
        "caller_arn": NORMAL_PLAN_CALLER,
        "identity_type": "AssumedRole",
        "identity_account_id": broker.AUTHORITY_ACCOUNT_ID,
        "session_issuer_type": "Role",
        "session_issuer_arn": NORMAL_PLAN_ROLE_ARN,
        "session_issuer_account_id": broker.AUTHORITY_ACCOUNT_ID,
        "session_issuer_user_name": NORMAL_PLAN_ROLE_NAME,
        "stack_name": broker.PLAN_STACK_NAME,
    }
    value.update(changes)
    return broker.seal(value, "event_digest")


class FakeEvidence:
    def __init__(self, cfg: broker.BrokerConfig) -> None:
        self.cfg = cfg
        self.change_ready = True
        self.terminal = True
        self.assignment_count = 0
        self.id_drift = False
        self.repair = _repair_ledger()
        self.attestation = _attestation(self.repair)
        self.events: list[Mapping[str, Any]] = [_plan_event()]
        self.preflight_read_at = "2026-08-30T19:00:00Z"
        self.preflight_changes = 0
        self.preflight_resources = 0
        self.preflight_complete = True
        self.calls: list[str] = []
        self.creation_time = "2026-08-30T19:00:00Z"
        self.stack_last_updated_time = "2026-08-30T19:00:00Z"
        self.stack_terminal_event_time = "2026-08-30T19:00:00Z"
        self.read_at = "2026-08-30T19:00:00Z"

    def recover_create_dispatch(
        self,
        *,
        operation: str,
        request: Mapping[str, Any],
        claim: Mapping[str, Any],
        contract: Mapping[str, Any],
    ) -> Mapping[str, Any]:
        account = broker.operation_account(operation)
        dispatch = {
            "kind": "CREATE",
            "operation": operation,
            "change_set_arn": (
                f"arn:aws:cloudformation:{broker.REGION}:{account}:changeSet/"
                f"{request['ChangeSetName']}/11111111-1111-4111-8111-111111111111"
            ),
            "stack_arn": (
                f"arn:aws:cloudformation:{broker.REGION}:{account}:stack/"
                f"{request['StackName']}/22222222-2222-4222-8222-222222222222"
            ),
            "create_request_id": "33333333-3333-4333-8333-333333333333",
            "create_request_digest": broker.digest_value(request),
            "dispatched_at": claim["claimed_at"],
        }
        readback = self.read_change_set_ready(
            operation=operation,
            request=request,
            dispatch=dispatch,
            contract=contract,
            parent_receipt_digest=claim["claim_digest"],
        )
        return broker.seal(
            {
                "schema_version": 1,
                "record_type": broker.CREATE_RECOVERY_RECORD_TYPE,
                "source_commit": SOURCE_COMMIT,
                "account_id": account,
                "region": broker.REGION,
                "operation": operation,
                "claim_digest": claim["claim_digest"],
                "request_digest": broker.digest_value(request),
                "dispatch": dispatch,
                "change_set_readback": readback,
                "recovered_at": self.read_at,
            },
            "recovery_digest",
        )

    def recover_execute_dispatch(
        self,
        *,
        operation: str,
        request: Mapping[str, Any],
        claim: Mapping[str, Any],
        create_dispatch: Mapping[str, Any],
        terminal_parameters_digest: str,
        creator_request: Mapping[str, Any],
        contract: Mapping[str, Any],
    ) -> Mapping[str, Any]:
        dispatch = dict(create_dispatch)
        dispatch.update(
            {
                "execute_operation": operation,
                "execute_request_id": "44444444-4444-4444-8444-444444444444",
                "execute_request_digest": broker.digest_value(request),
                "terminal_parameters_digest": terminal_parameters_digest,
                "executed_at": claim["claimed_at"],
            }
        )
        snapshot = {
            "stack_arn": create_dispatch["stack_arn"],
            "change_set_arn": create_dispatch["change_set_arn"],
            "status": "CREATE_COMPLETE",
            "execution_status": "EXECUTE_IN_PROGRESS",
            "creator_request_digest": broker.digest_value(creator_request),
            "execute_request_digest": broker.digest_value(request),
            "template_digest": contract["template_digest"],
            "changes_digest": broker.digest_value(contract["expected_changes"]),
            "parameters_digest": broker.digest_value(creator_request["Parameters"]),
            "tags_digest": broker.digest_value(creator_request["Tags"]),
            "role_arn_absent": True,
            "resources_to_import_absent": True,
            "cloudtrail_event_digest": "sha256:" + ("8" * 64),
            "read_at": self.read_at,
        }
        return broker.seal(
            {
                "schema_version": 1,
                "record_type": broker.EXECUTE_RECOVERY_RECORD_TYPE,
                "source_commit": SOURCE_COMMIT,
                "account_id": broker.operation_account(operation),
                "region": broker.REGION,
                "operation": operation,
                "claim_digest": claim["claim_digest"],
                "request_digest": broker.digest_value(request),
                "dispatch": dispatch,
                "change_set_snapshot": snapshot,
                "recovered_at": self.read_at,
            },
            "recovery_digest",
        )

    def read_change_set_ready(
        self,
        *,
        operation: str,
        request: Mapping[str, Any],
        dispatch: Mapping[str, Any],
        contract: Mapping[str, Any],
        parent_receipt_digest: str,
    ) -> Mapping[str, Any]:
        self.calls.append("change:" + operation)
        derived = {}
        source_digest = None
        if operation == "seed-revoke-create-v1":
            derived = {
                "BrokerInvokerPermissionSetArn": ROUTE_INVOKER_PS,
                "BrokerSeedCreatorPermissionSetArn": ROUTE_CREATOR_PS,
                "BrokerSeedExecutorPermissionSetArn": ROUTE_EXECUTOR_PS,
            }
            source_digest = "sha256:" + ("6" * 64)
        return broker.seal(
            {
                "schema_version": 1,
                "record_type": broker.CHANGE_SET_READBACK_RECORD_TYPE,
                "operation": operation,
                "source_commit": SOURCE_COMMIT,
                "account_id": broker.operation_account(operation),
                "region": broker.REGION,
                "stack_name": request["StackName"],
                "change_set_name": request["ChangeSetName"],
                "stack_arn": dispatch["stack_arn"],
                "change_set_arn": (
                    dispatch["change_set_arn"] + "-drift"
                    if self.id_drift
                    else dispatch["change_set_arn"]
                ),
                "create_request_id": dispatch["create_request_id"],
                "creation_time": self.creation_time,
                "status": "CREATE_COMPLETE" if self.change_ready else "CREATE_IN_PROGRESS",
                "execution_status": "AVAILABLE" if self.change_ready else "UNAVAILABLE",
                "role_arn_absent": True,
                "resources_to_import_absent": True,
                "request_contract_digest": broker.digest_value(request),
                "template_digest": contract["template_digest"],
                "changes_digest": broker.digest_value(contract["expected_changes"]),
                "terminal_parameters_digest": broker.digest_value(
                    {"operation": operation, "parameters": request["Parameters"]}
                ),
                "cloudtrail_event_digest": "sha256:" + ("7" * 64),
                "derived_permission_set_arns": derived,
                "source_stack_digest": source_digest,
                "parent_receipt_digest": parent_receipt_digest,
                "read_at": self.read_at,
            },
            "readback_digest",
        )

    def read_terminal_stack(
        self,
        *,
        operation: str,
        expectation: Mapping[str, Any],
        dispatch: Mapping[str, Any],
        parent_receipt_digest: str,
    ) -> Mapping[str, Any]:
        self.calls.append("terminal:" + operation)
        derived = {}
        source_digest = None
        live_control: dict[str, Any] = {}
        if operation == "delegation-execute-v1":
            derived = {"RepairInvokerPermissionSetArn": DELEGATION_PS}
            source_digest = "sha256:" + ("8" * 64)
        elif operation == "pep-protection-execute-v1":
            live_control = {
                "table_name": broker.REPAIR_LEDGER_TABLE_NAME,
                "table_arn": (
                    f"arn:aws:dynamodb:{broker.REGION}:"
                    f"{broker.AUTHORITY_ACCOUNT_ID}:table/"
                    f"{broker.REPAIR_LEDGER_TABLE_NAME}"
                ),
                "table_status": "ACTIVE",
                "deletion_protection_enabled": True,
                "sse_status": "ENABLED",
                "sse_type": "KMS",
                "kms_key_arn": (
                    f"arn:aws:kms:{broker.REGION}:{broker.AUTHORITY_ACCOUNT_ID}:"
                    "key/11111111-1111-4111-8111-111111111111"
                ),
            }
        return broker.seal(
            {
                "schema_version": 1,
                "record_type": broker.TERMINAL_READBACK_RECORD_TYPE,
                "operation": operation,
                "source_commit": SOURCE_COMMIT,
                "account_id": expectation["account_id"],
                "region": broker.REGION,
                "stack_name": expectation["stack_name"],
                "stack_arn": dispatch["stack_arn"],
                "execute_request_id": dispatch["execute_request_id"],
                "execute_cloudtrail_event_digest": "sha256:" + ("a" * 64),
                "stack_terminal_event_time": self.stack_terminal_event_time,
                "stack_terminal_event_digest": "sha256:" + ("b" * 64),
                "stack_last_updated_time": self.stack_last_updated_time,
                "role_arn_absent": True,
                "parent_id_absent": True,
                "root_id_absent": True,
                "notification_arns": [],
                "template_digest": expectation["template_digest"],
                "stack_resources_digest": broker.digest_value(
                    expectation["expected_resources"]
                ),
                "stack_resource_count": len(expectation["expected_resources"]),
                "stack_outputs_digest": broker.digest_value(
                    {
                        "keys": expectation["expected_output_keys"],
                        "static": expectation["expected_static_outputs"],
                    }
                ),
                "stack_tags_digest": broker.digest_value(expectation["expected_tags"]),
                "stack_parameters_digest": dispatch[
                    "terminal_parameters_digest"
                ],
                "live_control": live_control,
                "live_control_digest": broker.digest_value(live_control),
                "derived_permission_set_arns": derived,
                "source_stack_digest": source_digest,
                "stack_status": (
                    expectation["terminal_statuses"][0]
                    if self.terminal
                    else "UPDATE_IN_PROGRESS"
                ),
                "terminal": self.terminal,
                "parent_receipt_digest": parent_receipt_digest,
                "read_at": self.read_at,
            },
            "readback_digest",
        )

    def read_assignments(
        self,
        *,
        operation: str,
        scope: Mapping[str, Any],
        terminal_readback_digest: str,
    ) -> Mapping[str, Any]:
        self.calls.append("assignment:" + scope["permission_set_arn"])
        return broker.seal(
            {
                "schema_version": 1,
                "record_type": broker.ASSIGNMENT_READBACK_RECORD_TYPE,
                "operation": operation,
                "source_commit": SOURCE_COMMIT,
                "account_id": scope["account_id"],
                "region": broker.REGION,
                "instance_arn": scope["instance_arn"],
                "permission_set_arn": scope["permission_set_arn"],
                "assignment_count": self.assignment_count,
                "terminal": True,
                "terminal_readback_digest": terminal_readback_digest,
                "read_at": self.read_at,
            },
            "readback_digest",
        )

    def read_repair_ledger(self, *, repair_id: str) -> Mapping[str, Any]:
        assert repair_id == REPAIR_ID
        return self.repair

    def read_reconcile_attestation(self, *, attestation_id: str) -> Mapping[str, Any]:
        assert attestation_id == REPAIR_ID + "#reconcile-v1"
        return self.attestation

    def read_plan_list_change_sets_events(self, **kwargs: Any) -> Sequence[Mapping[str, Any]]:
        assert kwargs["start_time"] == "2026-08-30T18:50:00Z"
        assert kwargs["end_time"] == "2026-08-30T19:00:00Z"
        return self.events

    def read_plan_recovery_preflight(
        self,
        *,
        normal_plan_caller_arn_digest: str,
        parent_events_digest: str,
    ) -> Mapping[str, Any]:
        pab = {
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True,
        }
        return broker.seal(
            {
                "schema_version": 1,
                "record_type": broker.PLAN_PREFLIGHT_RECORD_TYPE,
                "source_commit": SOURCE_COMMIT,
                "account_id": broker.AUTHORITY_ACCOUNT_ID,
                "region": broker.REGION,
                "stack_name": broker.PLAN_STACK_NAME,
                "stack_id": (
                    f"arn:aws:cloudformation:{broker.REGION}:"
                    f"{broker.AUTHORITY_ACCOUNT_ID}:stack/{broker.PLAN_STACK_NAME}/"
                    "99999999-9999-4999-8999-999999999999"
                ),
                "stack_status": "REVIEW_IN_PROGRESS",
                "role_arn_absent": True,
                "parent_id_absent": True,
                "root_id_absent": True,
                "notification_arns": [],
                "stack_resource_count": self.preflight_resources,
                "stack_resources_digest": broker.digest_value(
                    [] if self.preflight_resources == 0 else [{"resource": "drift"}]
                ),
                "active_change_set_count": self.preflight_changes,
                "active_change_sets_digest": broker.digest_value(
                    [] if self.preflight_changes == 0 else [{"change": "drift"}]
                ),
                "change_set_page_count": 2,
                "pagination_complete": self.preflight_complete,
                "public_access_block_configuration": pab,
                "public_access_block_digest": broker.digest_value(pab),
                "complete": self.preflight_complete,
                "normal_plan_caller_arn_digest": (
                    normal_plan_caller_arn_digest
                ),
                "parent_events_digest": parent_events_digest,
                "read_at": self.preflight_read_at,
            },
            "readback_digest",
        )


def runtime(
    cfg: broker.BrokerConfig,
    *,
    ledger: FakeLedger | None = None,
    effects: FakeEffects | None = None,
    evidence: FakeEvidence | None = None,
    clock: Callable[[], datetime] | None = None,
    collision_admission: _SyntheticCollisionAdmission | None = None,
) -> tuple[broker.RouteBroker, FakeLedger, FakeEffects, FakeEvidence]:
    actual_ledger = ledger or FakeLedger(cfg)
    actual_effects = effects or FakeEffects()
    actual_evidence = evidence or FakeEvidence(cfg)
    actual_admission = collision_admission or _SyntheticCollisionAdmission(
        cfg,
        timeline=actual_ledger.timeline,
    )
    return (
        _ContractHarnessRouteBroker(
            config=cfg,
            ledger=actual_ledger,
            effects=actual_effects,
            evidence=actual_evidence,
            clock=clock or (lambda: NOW),
            collision_admission=actual_admission,
        ),
        actual_ledger,
        actual_effects,
        actual_evidence,
    )


@pytest.mark.parametrize(
    ("handler_name", "alias", "setup_aliases", "expected_state"),
    [
        (
            "creator_handler",
            "delegation-create-v1",
            ("seed-revoke-create-v1", "seed-revoke-execute-v1"),
            "SEED_REVOKED",
        ),
        (
            "executor_handler",
            "delegation-execute-v1",
            (
                "seed-revoke-create-v1",
                "seed-revoke-execute-v1",
                "delegation-create-v1",
            ),
            "DELEGATION_CREATED",
        ),
    ],
)
def test_product_broker_requires_adapter_after_exact_request_before_cas(
    handler_name: str,
    alias: str,
    setup_aliases: tuple[str, ...],
    expected_state: str,
) -> None:
    cfg = config()
    timeline: list[str] = []
    ledger = FakeLedger(cfg, timeline=timeline)
    effects = FakeEffects(timeline=timeline)
    evidence = FakeEvidence(cfg)
    harness = _ContractHarnessRouteBroker(
        config=cfg,
        ledger=ledger,
        effects=effects,
        evidence=evidence,
        clock=lambda: NOW,
    )
    for setup_alias in setup_aliases:
        _run_effect(harness, cfg, setup_alias)
    timeline.clear()
    effects.calls.clear()
    ledger.cas_count = 0
    route = broker.RouteBroker(
        config=cfg,
        ledger=ledger,
        effects=effects,
        evidence=evidence,
        clock=lambda: NOW,
    )
    with pytest.raises(
        broker.RouteBrokerError,
        match="COLLISION_ADMISSION_ADAPTER_MISSING",
    ):
        context = (
            creator_context(alias)
            if handler_name == "creator_handler"
            else executor_context(alias)
        )
        getattr(route, handler_name)({}, context)
    assert timeline == [
        "ledger:control-plane",
        f"ledger:read:{expected_state}",
    ]
    assert effects.calls == []
    assert ledger.cas_count == 0


@pytest.mark.parametrize("method", ["create_change_set", "execute_change_set"])
def test_aws_effect_adapter_forwards_core_authorized_expansive_effect(
    method: str,
) -> None:
    calls: list[tuple[str, dict[str, Any]]] = []

    class CloudFormation:
        def create_change_set(self, **request: Any) -> Mapping[str, Any]:
            calls.append(("create_change_set", request))
            return {
                "Id": "change-set",
                "StackId": "stack",
                "ResponseMetadata": {"RequestId": "request"},
            }

        def execute_change_set(self, **request: Any) -> Mapping[str, Any]:
            calls.append(("execute_change_set", request))
            return {"ResponseMetadata": {"RequestId": "request"}}

    effects = broker._AwsEffects(
        {
            broker.AUTHORITY_ACCOUNT_ID: CloudFormation(),
            broker.MANAGEMENT_ACCOUNT_ID: CloudFormation(),
        }
    )
    operation = (
        "delegation-create-v1"
        if method == "create_change_set"
        else "delegation-execute-v1"
    )
    request = {"exact": operation}
    permit_checks: list[str] = []
    permit = broker._new_effect_permit(
        operation=operation,
        request=request,
        revalidate=lambda: permit_checks.append(operation),
    )
    result = getattr(effects, method)(
        operation=operation,
        request=request,
        permit=permit,
    )
    assert calls == [(method, {"exact": operation})]
    assert permit_checks == [operation]
    assert result["request_id"] == "request"

    with pytest.raises(broker.RouteBrokerError, match="EFFECT_PERMIT_REUSED"):
        getattr(effects, method)(
            operation=operation,
            request=request,
            permit=permit,
        )
    assert calls == [(method, {"exact": operation})]


@pytest.mark.parametrize("failure", ["missing", "stale", "mismatch"])
def test_aws_effect_adapter_rejects_invalid_permit_before_sdk(
    failure: str,
) -> None:
    calls: list[dict[str, Any]] = []

    class CloudFormation:
        def create_change_set(self, **request: Any) -> Mapping[str, Any]:
            calls.append(request)
            return {
                "Id": "change-set",
                "StackId": "stack",
                "ResponseMetadata": {"RequestId": "request"},
            }

    effects = broker._AwsEffects(
        {
            broker.AUTHORITY_ACCOUNT_ID: CloudFormation(),
            broker.MANAGEMENT_ACCOUNT_ID: CloudFormation(),
        }
    )
    operation = "delegation-create-v1"
    request = {"exact": operation}
    if failure == "missing":
        permit: object = object()
        expected = "EFFECT_PERMIT_INVALID"
    elif failure == "stale":
        permit = broker._new_effect_permit(
            operation=operation,
            request=request,
            revalidate=lambda: (_ for _ in ()).throw(
                broker.RouteBrokerError("COLLISION_ADMISSION_NOT_ACTIVE")
            ),
        )
        expected = "COLLISION_ADMISSION_NOT_ACTIVE"
    else:
        permit = broker._new_effect_permit(
            operation=operation,
            request={"exact": "different"},
            revalidate=lambda: None,
        )
        expected = "EFFECT_PERMIT_BINDING_MISMATCH"

    with pytest.raises(broker.RouteBrokerError, match=expected):
        effects.create_change_set(
            operation=operation,
            request=request,
            permit=permit,
        )
    assert calls == []


def test_expired_effect_permit_after_attempt_cas_is_fail_closed_uncertain(
) -> None:
    cfg = config()
    ledger = FakeLedger(cfg)
    effects = FakeEffects()

    class ExpiredGrantAdmission(_SyntheticCollisionAdmission):
        def revalidate(self, grant: object, *, now: datetime) -> str:
            del grant, now
            raise broker.RouteBrokerError("COLLISION_ADMISSION_NOT_ACTIVE")

    route = broker.RouteBroker(
        config=cfg,
        ledger=ledger,
        effects=effects,
        evidence=FakeEvidence(cfg),
        clock=lambda: NOW,
        collision_admission=ExpiredGrantAdmission(cfg),
    )
    for alias in ("seed-revoke-create-v1", "seed-revoke-execute-v1"):
        _run_effect(route, cfg, alias)
    before_calls = list(effects.calls)

    with pytest.raises(broker.RouteBrokerError) as caught:
        route.creator_handler({}, creator_context("delegation-create-v1"))

    # The capability has already been consumed and the durable attempt CAS is
    # visible, so resetting to the predecessor would authorize a second
    # admission/effect.  Preserve fail-closed uncertainty for read-only causal
    # recovery, while proving the SDK was never invoked.
    assert caught.value.code == "CREATE_CHANGE_SET_UNCERTAIN"
    assert ledger.snapshot.state == "DELEGATION_CREATE_UNCERTAIN"
    assert effects.calls == before_calls


def test_expansive_admission_is_claimed_consumed_once_and_receipted() -> None:
    cfg = config()
    timeline: list[str] = []
    ledger = FakeLedger(cfg, timeline=timeline)
    effects = FakeEffects(timeline=timeline)
    admission = _SyntheticCollisionAdmission(cfg, timeline=timeline)
    route = broker.RouteBroker(
        config=cfg,
        ledger=ledger,
        effects=effects,
        evidence=FakeEvidence(cfg),
        clock=lambda: NOW,
        collision_admission=admission,
    )
    for alias in ("seed-revoke-create-v1", "seed-revoke-execute-v1"):
        _run_effect(route, cfg, alias)
    timeline.clear()

    dispatched = route.creator_handler(
        {}, creator_context("delegation-create-v1")
    )
    assert dispatched["collision_admission_digest"].startswith("sha256:")
    claim = json.loads(ledger.snapshot.attempt_claim_json or "{}")
    manifest = claim["collision_admission_manifest"]
    assert manifest["operation"] == "delegation-create-v1"
    assert claim["collision_admission_manifest_digest"] == manifest[
        "manifest_digest"
    ]
    assert timeline.index("admission:admit:delegation-create-v1") < (
        timeline.index("ledger:cas:DELEGATION_CREATE_ATTEMPTING")
    )
    assert timeline.index("ledger:cas:DELEGATION_CREATE_ATTEMPTING") < (
        timeline.index("admission:consume:delegation-create-v1")
    )
    assert timeline.index("admission:revalidate:delegation-create-v1") < (
        timeline.index("provider:create")
    )

    capability_state = next(
        state
        for state in admission._capabilities.values()
        if state["manifest"]["operation"] == "delegation-create-v1"
    )
    with pytest.raises(
        broker.RouteBrokerError,
        match="SYNTHETIC_CAPABILITY_INVALID",
    ):
        admission.consume(
            capability_state["capability"],
            operation="delegation-create-v1",
            effect_request_digest=manifest["effect_request_digest"],
            expected_manifest_digest=manifest["manifest_digest"],
            now=NOW,
        )
    admission_calls = list(admission.calls)
    completed = route.creator_handler(
        {}, creator_context("delegation-create-v1")
    )
    assert completed["aws_mutations"] == 0
    assert completed["collision_admission_digest"] is None
    assert admission.calls == admission_calls


def test_dispatched_receipt_must_match_attempt_admission_manifest() -> None:
    cfg = config()
    ledger = FakeLedger(cfg)
    route = broker.RouteBroker(
        config=cfg,
        ledger=ledger,
        effects=FakeEffects(),
        evidence=FakeEvidence(cfg),
        clock=lambda: NOW,
        collision_admission=_SyntheticCollisionAdmission(cfg),
    )
    for alias in ("seed-revoke-create-v1", "seed-revoke-execute-v1"):
        _run_effect(route, cfg, alias)
    route.creator_handler({}, creator_context("delegation-create-v1"))
    receipt = json.loads(ledger.snapshot.last_receipt_json or "{}")
    receipt["collision_admission_digest"] = "sha256:" + "9" * 64
    receipt.pop("receipt_digest")
    receipt = broker.seal(receipt, "receipt_digest")
    tampered = replace(
        ledger.snapshot,
        last_receipt_digest=receipt["receipt_digest"],
        last_receipt_json=broker.canonical_json(receipt),
    )

    with pytest.raises(
        broker.RouteBrokerError,
        match="LEDGER_ADMISSION_BINDING_INVALID",
    ):
        broker._validate_ledger_snapshot(tampered, config=cfg)


def test_route_broker_source_has_no_dead_collision_config_symbols() -> None:
    source = (ROOT / "tooling" / broker.__file__.split("/")[-1]).read_text()
    names = {
        node.id
        for node in ast.walk(ast.parse(source))
        if isinstance(node, ast.Name)
    }
    assert "_COLLISION_CONFIG_FIELDS" not in names
    assert "_COLLISION_IDENTITY_FIELDS" not in names
    assert not hasattr(broker, "_validate_collision_config")


@pytest.mark.parametrize(
    ("method", "operation", "expected_call"),
    [
        ("create_change_set", "seed-revoke-create-v1", "create_change_set"),
        (
            "create_change_set",
            "delegation-revoke-create-v1",
            "create_change_set",
        ),
        ("create_change_set", "route-revoke-create-v1", "create_change_set"),
        ("execute_change_set", "seed-revoke-execute-v1", "execute_change_set"),
        (
            "execute_change_set",
            "delegation-revoke-execute-v1",
            "execute_change_set",
        ),
        ("execute_change_set", "route-revoke-execute-v1", "execute_change_set"),
    ],
)
def test_aws_effect_adapter_opens_only_exact_reducing_aliases(
    method: str, operation: str, expected_call: str
) -> None:
    calls: list[str] = []

    class CloudFormation:
        def create_change_set(self, **_request: Any) -> Mapping[str, Any]:
            calls.append("create_change_set")
            return {
                "Id": "change-set",
                "StackId": "stack",
                "ResponseMetadata": {"RequestId": "request"},
            }

        def execute_change_set(self, **_request: Any) -> Mapping[str, Any]:
            calls.append("execute_change_set")
            return {"ResponseMetadata": {"RequestId": "request"}}

    cloudformation = CloudFormation()
    effects = broker._AwsEffects(
        {
            broker.AUTHORITY_ACCOUNT_ID: cloudformation,
            broker.MANAGEMENT_ACCOUNT_ID: cloudformation,
        },
        allowed_reducing_alias=operation,
    )
    request: dict[str, Any] = {}
    permit = broker._new_effect_permit(
        operation=operation,
        request=request,
        revalidate=lambda: None,
    )
    result = getattr(effects, method)(
        operation=operation,
        request=request,
        permit=permit,
    )
    assert calls == [expected_call]
    assert result["request_id"] == "request"

    same_kind_aliases = (
        broker._REDUCING_CREATOR_ALIASES
        if method == "create_change_set"
        else broker._REDUCING_EXECUTOR_ALIASES
    )
    wrong_alias = next(alias for alias in same_kind_aliases if alias != operation)
    with pytest.raises(
        broker.RouteBrokerError,
        match="REDUCING_OPERATION_STATE_INVALID",
    ):
        getattr(effects, method)(
            operation=wrong_alias,
            request={},
            permit=permit,
        )
    assert calls == [expected_call]


def _run_effect(
    route: broker.RouteBroker, cfg: broker.BrokerConfig, alias: str
) -> tuple[Mapping[str, Any], Mapping[str, Any]]:
    del cfg
    handler = route.creator_handler if alias in broker.CREATOR_ALIASES else route.executor_handler
    context = creator_context(alias) if alias in broker.CREATOR_ALIASES else executor_context(alias)
    dispatched = handler({}, context)
    completed = handler({}, context)
    return dispatched, completed


def test_exact_names_and_closed_config_contract() -> None:
    cfg = config()
    assert broker.ROUTE_BROKER_STACK_NAME == "scanalyze-platform-authority-gug376-route-broker"
    assert broker.REPAIR_LEDGER_TABLE_NAME == "scanalyze-platform-authority-plan-policy-repair-ledger"
    configured_pep = {
        item["ParameterKey"]: item["ParameterValue"]
        for item in cfg.request("pep-create-v1")["Parameters"]
    }
    assert configured_pep["RepairInvokerPermissionSetArn"] == (
        broker.REPAIR_INVOKER_PERMISSION_SET_SENTINEL
    )
    with pytest.raises(broker.RouteBrokerError) as extra:
        value = _config_value()
        value["forged"] = True
        broker.BrokerConfig.from_mapping(value)
    assert extra.value.code == "CONFIG_FIELDS_INVALID"
    for changes in (
        {
            "normal_plan_generated_role_name": (
                "AWSReservedSSO_ScanalyzeAuthorityBootstrapPlan_"
                "0123456789FEDCBA"
            )
        },
        {
            "normal_plan_generated_role_arn": NORMAL_PLAN_ROLE_ARN.replace(
                broker.AUTHORITY_ACCOUNT_ID, "000000000000"
            )
        },
        {
            "normal_plan_generated_role_arn": (
                "arn:aws:iam::042360977644:role/" + NORMAL_PLAN_ROLE_NAME
            )
        },
    ):
        with pytest.raises(broker.RouteBrokerError) as role:
            broker.BrokerConfig.from_mapping(_config_value(**changes))
        assert role.value.code == "NORMAL_PLAN_ROLE_INVALID"


def _config_with_identity_center_kms_key(key_arn: str) -> broker.BrokerConfig:
    value = _config_value()
    for parameter in value["requests"]["pep-create-v1"]["Parameters"]:
        if parameter["ParameterKey"] == "IdentityCenterKmsMode":
            parameter["ParameterValue"] = "CUSTOMER_MANAGED_KEY"
        elif parameter["ParameterKey"] == "IdentityCenterKmsKeyArn":
            parameter["ParameterValue"] = key_arn
        elif parameter["ParameterKey"] == "ArtifactBucket":
            parameter["ParameterValue"] = (
                "scanalyze-g376-art-aaaaaaaaaaaa-"
                "042360977644-us-east-1-an"
            )
    value.pop("config_digest")
    return broker.BrokerConfig.from_mapping(
        broker.seal(value, "config_digest")
    )


@pytest.mark.parametrize(
    "key_arn",
    (
        "arn:aws:kms:us-east-1:839393571433:key/"
        "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
        "arn:aws:kms:us-east-1:839393571433:key/"
        "mrk-0123456789abcdef0123456789abcdef",
    ),
)
def test_collision_bindings_accept_only_canonical_key_forms(
    key_arn: str,
) -> None:
    bindings = broker._collision_parameter_bindings(  # noqa: SLF001
        _config_with_identity_center_kms_key(key_arn)
    )
    assert bindings["identity_center_kms_mode"] == "CUSTOMER_MANAGED_KEY"
    assert bindings["identity_center_kms_key_arn"] == key_arn


@pytest.mark.parametrize(
    "key_arn",
    (
        "arn:aws:kms:us-east-1:839393571433:alias/identity-center",
        "arn:aws-cn:kms:us-east-1:839393571433:key/"
        "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
        "arn:aws:kms:us-west-2:839393571433:key/"
        "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
        "arn:aws:kms:us-east-1:000000000000:key/"
        "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
        "arn:aws:kms:us-east-1:839393571433:key/"
        "AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE",
        "arn:aws:kms:us-east-1:839393571433:key/"
        "mrk-0123456789abcdef0123456789abcdeF",
    ),
)
def test_collision_bindings_reject_noncanonical_key_forms(
    key_arn: str,
) -> None:
    with pytest.raises(broker.RouteBrokerError) as exc_info:
        broker._collision_parameter_bindings(  # noqa: SLF001
            _config_with_identity_center_kms_key(key_arn)
        )
    assert exc_info.value.code == "COLLISION_CONFIG_INVALID"


def test_broker_parameter_attestation_rejects_masks_substitution_and_duplicates() -> None:
    pep_parameters = deepcopy(config().request("pep-create-v1")["Parameters"])
    delegation_parameters = [
        {
            "ParameterKey": "RepairPrincipalId",
            "ParameterValue": "12345678-1234-4123-8123-123456789012",
        },
        {
            "ParameterKey": "RepairPrincipalUserArn",
            "ParameterValue": (
                "arn:aws:identitystore:::user/"
                "12345678-1234-4123-8123-123456789012"
            ),
        },
    ]

    assert broker._change_set_parameters_match(
        deepcopy(pep_parameters), pep_parameters
    )
    assert broker._change_set_parameters_match(
        deepcopy(delegation_parameters), delegation_parameters
    )
    assert broker._change_set_parameters_match(
        list(reversed(deepcopy(pep_parameters))), pep_parameters
    )
    update_parameters = [
        {"ParameterKey": "Explicit", "ParameterValue": "value"},
        {"ParameterKey": "Previous", "UsePreviousValue": True},
    ]
    assert broker._change_set_parameters_match(
        list(reversed(deepcopy(update_parameters))), update_parameters
    )
    terminal_parameters_digest = broker.digest_value(
        {"Explicit": "value", "Previous": "previous"}
    )
    normalized_update_parameters = [
        {"ParameterKey": "Previous", "ParameterValue": "previous"},
        {"ParameterKey": "Explicit", "ParameterValue": "value"},
    ]
    assert broker._change_set_parameters_match(
        normalized_update_parameters,
        update_parameters,
        expected_terminal_parameters_digest=terminal_parameters_digest,
    )
    assert not broker._change_set_parameters_match(
        normalized_update_parameters, update_parameters
    )
    wrong_normalized = deepcopy(normalized_update_parameters)
    wrong_normalized[0]["ParameterValue"] = "wrong"
    assert not broker._change_set_parameters_match(
        wrong_normalized,
        update_parameters,
        expected_terminal_parameters_digest=terminal_parameters_digest,
    )
    masked_normalized = deepcopy(normalized_update_parameters)
    masked_normalized[0]["ParameterValue"] = "****"
    assert not broker._change_set_parameters_match(
        masked_normalized,
        update_parameters,
        expected_terminal_parameters_digest=terminal_parameters_digest,
    )
    ambiguous_previous = deepcopy(normalized_update_parameters)
    ambiguous_previous[0]["UsePreviousValue"] = True
    assert not broker._change_set_parameters_match(
        ambiguous_previous,
        update_parameters,
        expected_terminal_parameters_digest=terminal_parameters_digest,
    )
    two_previous_request = [
        {"ParameterKey": "First", "UsePreviousValue": True},
        {"ParameterKey": "Second", "UsePreviousValue": True},
    ]
    mixed_previous_response = [
        {"ParameterKey": "First", "UsePreviousValue": True},
        {"ParameterKey": "Second", "ParameterValue": "second"},
    ]
    assert not broker._change_set_parameters_match(
        mixed_previous_response,
        two_previous_request,
        expected_terminal_parameters_digest=broker.digest_value(
            {"First": "first", "Second": "second"}
        ),
    )
    resolved_previous = list(reversed(deepcopy(update_parameters)))
    resolved_previous[0]["ResolvedValue"] = "forbidden"
    assert not broker._change_set_parameters_match(
        resolved_previous, update_parameters
    )

    for parameter_key, mask in (
        ("PrincipalId", "****"),
        ("ExpectedPermissionSetDescription", "*****"),
        ("ExpectedPlanPermissionSetTagsJson", "****"),
        ("ArtifactVersion", "*****"),
    ):
        observed = deepcopy(pep_parameters)
        next(
            item for item in observed if item["ParameterKey"] == parameter_key
        )["ParameterValue"] = mask
        assert not broker._change_set_parameters_match(
            observed, pep_parameters
        )

    for parameter_key, mask in (
        ("RepairPrincipalId", "****"),
        ("RepairPrincipalUserArn", "*****"),
    ):
        observed = deepcopy(delegation_parameters)
        next(
            item for item in observed if item["ParameterKey"] == parameter_key
        )["ParameterValue"] = mask
        assert not broker._change_set_parameters_match(
            observed, delegation_parameters
        )

    for requested in (pep_parameters, delegation_parameters):
        substituted = deepcopy(requested)
        substituted[0]["ParameterValue"] = "substituted"
        assert not broker._change_set_parameters_match(substituted, requested)

        duplicate = deepcopy(requested)
        duplicate[-1] = deepcopy(duplicate[0])
        assert not broker._change_set_parameters_match(duplicate, requested)

        extra_duplicate = deepcopy(requested)
        extra_duplicate.append(deepcopy(extra_duplicate[0]))
        assert not broker._change_set_parameters_match(
            extra_duplicate, requested
        )

        resolved = deepcopy(requested)
        resolved[0]["ResolvedValue"] = resolved[0]["ParameterValue"]
        assert not broker._change_set_parameters_match(resolved, requested)

        extra_field = deepcopy(requested)
        extra_field[0]["Unexpected"] = "value"
        assert not broker._change_set_parameters_match(extra_field, requested)


def test_terminal_parameter_helpers_resolve_previous_values_and_reject_ambiguity() -> None:
    stack_parameters = [
        {"ParameterKey": "Zulu", "ParameterValue": "previous"},
        {"ParameterKey": "Alpha", "ParameterValue": ""},
    ]
    assert broker._stack_parameter_values(
        stack_parameters, error_code="TEST_INVALID"
    ) == {"Alpha": "", "Zulu": "previous"}
    assert broker._expected_terminal_parameter_values(
        [
            {"ParameterKey": "Zulu", "UsePreviousValue": True},
            {"ParameterKey": "Alpha", "ParameterValue": "replacement"},
        ],
        current_values={"Alpha": "", "Zulu": "previous"},
        error_code="TEST_INVALID",
    ) == {"Alpha": "replacement", "Zulu": "previous"}

    invalid_stack_parameters = (
        [
            {"ParameterKey": "Alpha", "ParameterValue": "value"},
            {"ParameterKey": "Alpha", "ParameterValue": "value"},
        ],
        [{"ParameterKey": "Alpha", "ParameterValue": "****"}],
        [
            {
                "ParameterKey": "Alpha",
                "ParameterValue": "value",
                "ResolvedValue": "value",
            }
        ],
        [
            {
                "ParameterKey": "Alpha",
                "ParameterValue": "value",
                "UsePreviousValue": True,
            }
        ],
    )
    for value in invalid_stack_parameters:
        with pytest.raises(broker.RouteBrokerError, match="TEST_INVALID"):
            broker._stack_parameter_values(value, error_code="TEST_INVALID")

    with pytest.raises(broker.RouteBrokerError, match="TEST_INVALID"):
        broker._expected_terminal_parameter_values(
            [{"ParameterKey": "Zulu", "UsePreviousValue": True}],
            current_values={"Alpha": "", "Zulu": "previous"},
            error_code="TEST_INVALID",
        )


def test_legacy_execute_dispatch_without_terminal_parameter_binding_fails_closed() -> None:
    legacy_dispatch = {
        "kind": "CREATE",
        "operation": "seed-revoke-create-v1",
        "change_set_arn": (
            f"arn:aws:cloudformation:{broker.REGION}:{broker.MANAGEMENT_ACCOUNT_ID}:"
            "changeSet/gug376-route-seed-revoke/"
            "11111111-1111-4111-8111-111111111111"
        ),
        "stack_arn": (
            f"arn:aws:cloudformation:{broker.REGION}:{broker.MANAGEMENT_ACCOUNT_ID}:"
            "stack/scanalyze-platform-authority-gug376-temporary-change-set-route/"
            "22222222-2222-4222-8222-222222222222"
        ),
        "create_request_id": "33333333-3333-4333-8333-333333333333",
        "create_request_digest": "sha256:" + ("3" * 64),
        "dispatched_at": "2026-08-30T18:59:00Z",
        "execute_operation": "seed-revoke-execute-v1",
        "execute_request_id": "44444444-4444-4444-8444-444444444444",
        "execute_request_digest": "sha256:" + ("4" * 64),
        "executed_at": "2026-08-30T19:00:00Z",
    }
    snapshot = broker.LedgerSnapshot(
        state="SEED_REVOKE_EXECUTE_DISPATCHED",
        version=1,
        binding_digest=config().ledger_binding_digest,
        last_receipt_digest=None,
        last_receipt_json=None,
        attempt_claim_json=None,
        dispatch_coordinates_json=broker.canonical_json(legacy_dispatch),
        derived_bindings_json=None,
    )
    with pytest.raises(broker.RouteBrokerError) as caught:
        broker._dispatch_coordinates(snapshot)
    assert caught.value.code == "DISPATCH_COORDINATES_INVALID"


@pytest.mark.parametrize(
    "mutate",
    [
        lambda change: change.pop("details"),
        lambda change: change["details"][0].update(
            {"causing_entity": "forged-parameter"}
        ),
        lambda change: change["details"][0].update(
            {"change_source": "ParameterReference"}
        ),
        lambda change: change.update({"scope": ["Properties"]}),
        lambda change: change["details"][1].update(
            {"requires_recreation": "Always"}
        ),
        lambda change: change.update({"logical_resource_id": "ForeignLedger"}),
    ],
)
def test_creator_contract_rejects_resealed_detail_drift(
    mutate: Callable[[dict[str, Any]], Any],
) -> None:
    value = _config_value()
    change = value["creator_contracts"]["pep-protection-create-v1"][
        "expected_changes"
    ][0]
    mutate(change)
    value.pop("config_digest")
    with pytest.raises(
        broker.RouteBrokerError, match="CREATOR_CONTRACT_INVALID"
    ):
        broker.BrokerConfig.from_mapping(broker.seal(value, "config_digest"))


def test_change_projection_preserves_exact_lifecycle_details() -> None:
    expected = _change("pep-protection-create-v1")
    response = {
        "Changes": [
            {
                "Type": "Resource",
                "ResourceChange": {
                    "Action": expected["action"],
                    "LogicalResourceId": expected["logical_resource_id"],
                    "ResourceType": expected["resource_type"],
                    "Replacement": expected["replacement"],
                    "Scope": list(reversed(expected["scope"])),
                    "Details": list(reversed(_provider_details(expected))),
                },
            }
        ]
    }
    assert broker._AwsEvidence._change_projection(response) == [expected]
    drifted = deepcopy(response)
    drifted["Changes"][0]["ResourceChange"]["Details"][0][
        "CausingEntity"
    ] = "forged"
    assert broker._AwsEvidence._change_projection(drifted) != [expected]


def test_happy_path_uses_exact_cas_chain_dynamic_arns_and_assignment_counts() -> None:
    cfg = config()
    route, ledger, effects, evidence = runtime(cfg)
    terminal_receipts: dict[str, Mapping[str, Any]] = {}
    for alias in PEP_SETUP_ALIASES:
        dispatched, completed = _run_effect(route, cfg, alias)
        assert dispatched["aws_mutations"] == 1
        assert dispatched["state"].endswith("_DISPATCHED")
        assert completed["aws_mutations"] == 0
        terminal_receipts[alias] = completed
        if alias in broker.EXECUTOR_ALIASES:
            dispatch = json.loads(ledger.snapshot.dispatch_coordinates_json or "{}")
            assert broker._DIGEST_RE.fullmatch(
                dispatch["terminal_parameters_digest"]
            )
    closeout = route.creator_handler({}, creator_context("closeout-gate-v1"))
    assert closeout["state"] == "CLOSEOUT_PREREQUISITES_VERIFIED"
    assert closeout["normal_plan_caller_arn_digest"] == (
        NORMAL_PLAN_CALLER_DIGEST
    )
    assert NORMAL_PLAN_CALLER not in broker.canonical_json(closeout)
    for alias in (
        "delegation-revoke-create-v1",
        "delegation-revoke-execute-v1",
        "route-revoke-create-v1",
        "route-revoke-execute-v1",
    ):
        _dispatch, completed = _run_effect(route, cfg, alias)
        terminal_receipts[alias] = completed
    assert ledger.snapshot.state == "ROUTE_REVOKED"
    assert len(effects.calls) == 12
    for kind, _operation, request in effects.calls:
        assert "RoleARN" not in request
        if kind == "execute":
            assert broker._CHANGE_SET_ARN_RE.fullmatch(request["ChangeSetName"])
            assert broker._STACK_ARN_RE.fullmatch(request["StackName"])
    pep_create = next(
        request
        for kind, operation, request in effects.calls
        if kind == "create" and operation == "pep-create-v1"
    )
    pep_parameters = {
        item["ParameterKey"]: item["ParameterValue"]
        for item in pep_create["Parameters"]
    }
    assert pep_parameters["RepairInvokerPermissionSetArn"] == DELEGATION_PS
    from tooling.platform_authority_plan_permission_repair import (
        IMMUTABLE_CONFIGURATION_PARAMETER_KEYS,
        immutable_configuration_digest_from_parameters,
    )

    expected_immutable_digest = immutable_configuration_digest_from_parameters(
        {
            key: pep_parameters[key]
            for key in IMMUTABLE_CONFIGURATION_PARAMETER_KEYS
        }
    )
    assert pep_parameters["ImmutableConfigurationDigest"] == (
        expected_immutable_digest
    )
    assert terminal_receipts["seed-revoke-execute-v1"]["assignment_readback_count"] == 2
    assert terminal_receipts["delegation-revoke-execute-v1"]["assignment_readback_count"] == 1
    assert terminal_receipts["route-revoke-execute-v1"]["assignment_readback_count"] == 1
    bindings = json.loads(ledger.snapshot.derived_bindings_json or "{}")
    assert bindings["route.BrokerInvokerPermissionSetArn"] == ROUTE_INVOKER_PS
    assert bindings["delegation.RepairInvokerPermissionSetArn"] == DELEGATION_PS
    assert bindings[broker.NORMAL_PLAN_CALLER_BINDING_KEY] == (
        NORMAL_PLAN_CALLER_DIGEST
    )
    assert {
        broker.TERMINAL_PARAMETERS_BINDING_PREFIX + alias
        for alias in broker.MUTATING_CREATOR_ALIASES
    }.issubset(bindings)
    assert evidence.calls.count("assignment:" + ROUTE_CREATOR_PS) == 1
    assert evidence.calls.count("assignment:" + ROUTE_EXECUTOR_PS) == 1


def test_product_reducing_aliases_traverse_only_the_exact_state_chain() -> None:
    cfg = config()
    ledger = FakeLedger(cfg)
    effects = FakeEffects()
    evidence = FakeEvidence(cfg)
    product = broker.RouteBroker(
        config=cfg,
        ledger=ledger,
        effects=effects,
        evidence=evidence,
        clock=lambda: NOW,
    )
    harness = _ContractHarnessRouteBroker(
        config=cfg,
        ledger=ledger,
        effects=effects,
        evidence=evidence,
        clock=lambda: NOW,
    )

    for alias in ("seed-revoke-create-v1", "seed-revoke-execute-v1"):
        _run_effect(product, cfg, alias)
    for alias in PEP_SETUP_ALIASES[2:]:
        _run_effect(harness, cfg, alias)
    harness.creator_handler({}, creator_context("closeout-gate-v1"))
    for alias in (
        "delegation-revoke-create-v1",
        "delegation-revoke-execute-v1",
        "route-revoke-create-v1",
        "route-revoke-execute-v1",
    ):
        dispatched, completed = _run_effect(product, cfg, alias)
        assert dispatched["aws_mutations"] == 1
        assert completed["aws_mutations"] == 0

    assert ledger.snapshot.state == "ROUTE_REVOKED"
    reducing_effects = {
        operation
        for _kind, operation, _request in effects.calls
        if operation in broker._REDUCING_ALIASES
    }
    assert reducing_effects == broker._REDUCING_ALIASES


@pytest.mark.parametrize(
    ("handler_name", "context"),
    [
        ("creator_handler", creator_context("seed-revoke-create-v1")),
        (
            "creator_handler",
            creator_context("delegation-revoke-create-v1"),
        ),
        ("creator_handler", creator_context("route-revoke-create-v1")),
        ("executor_handler", executor_context("seed-revoke-execute-v1")),
        (
            "executor_handler",
            executor_context("delegation-revoke-execute-v1"),
        ),
        ("executor_handler", executor_context("route-revoke-execute-v1")),
    ],
)
def test_product_reducing_aliases_reject_every_wrong_state_before_effect(
    handler_name: str, context: Any
) -> None:
    cfg = config()
    ledger = FakeLedger(cfg)
    if context.invoked_function_arn.endswith("seed-revoke-create-v1"):
        snapshot = ledger.snapshot
        ledger.snapshot = broker.LedgerSnapshot(
            state="DELEGATION_CREATED",
            version=snapshot.version,
            binding_digest=snapshot.binding_digest,
        )
    effects = FakeEffects()
    product = broker.RouteBroker(
        config=cfg,
        ledger=ledger,
        effects=effects,
        evidence=FakeEvidence(cfg),
        clock=lambda: NOW,
    )
    with pytest.raises(broker.RouteBrokerError) as rejected:
        getattr(product, handler_name)({}, context)
    assert rejected.value.code in {"LEDGER_STATE_MISMATCH", "REPLAY_REJECTED"}
    assert effects.calls == []
    assert ledger.cas_count == 0


def test_product_handlers_finish_recovered_dispatched_reads_without_admission() -> None:
    cfg = config()
    harness, ledger, effects, evidence = runtime(cfg)
    for alias in ("seed-revoke-create-v1", "seed-revoke-execute-v1"):
        _run_effect(harness, cfg, alias)
    product = broker.RouteBroker(
        config=cfg,
        ledger=ledger,
        effects=effects,
        evidence=evidence,
        clock=lambda: NOW,
    )

    harness.creator_handler({}, creator_context("delegation-create-v1"))
    effect_count = len(effects.calls)
    created = product.creator_handler(
        {}, creator_context("delegation-create-v1")
    )
    assert created["state"] == "DELEGATION_CREATED"
    assert created["aws_mutations"] == 0
    assert len(effects.calls) == effect_count

    harness.executor_handler({}, executor_context("delegation-execute-v1"))
    effect_count = len(effects.calls)
    executed = product.executor_handler(
        {}, executor_context("delegation-execute-v1")
    )
    assert executed["state"] == "DELEGATION_TERMINAL"
    assert executed["aws_mutations"] == 0
    assert len(effects.calls) == effect_count


def test_execute_requires_terminal_parameter_binding_before_claim_or_effect() -> None:
    cfg = config()
    route, ledger, effects, _evidence = runtime(cfg)
    creator_alias = "seed-revoke-create-v1"
    route.creator_handler({}, creator_context(creator_alias))
    route.creator_handler({}, creator_context(creator_alias))
    bindings = json.loads(ledger.snapshot.derived_bindings_json or "{}")
    bindings.pop(broker.TERMINAL_PARAMETERS_BINDING_PREFIX + creator_alias)
    snapshot = ledger.snapshot
    ledger.snapshot = broker.LedgerSnapshot(
        state=snapshot.state,
        version=snapshot.version,
        binding_digest=snapshot.binding_digest,
        last_receipt_digest=snapshot.last_receipt_digest,
        last_receipt_json=snapshot.last_receipt_json,
        attempt_claim_json=snapshot.attempt_claim_json,
        dispatch_coordinates_json=snapshot.dispatch_coordinates_json,
        derived_bindings_json=broker.canonical_json(bindings),
    )
    cas_count = ledger.cas_count
    effect_count = len(effects.calls)

    with pytest.raises(broker.RouteBrokerError) as caught:
        route.executor_handler(
            {}, executor_context("seed-revoke-execute-v1")
        )
    assert caught.value.code == "TERMINAL_PARAMETERS_BINDING_INVALID"
    assert ledger.cas_count == cas_count
    assert len(effects.calls) == effect_count


def test_closeout_response_loss_returns_exact_durable_receipt_without_new_reads_or_cas() -> None:
    cfg = config()
    current = [NOW]
    route, ledger, effects, evidence = runtime(cfg, clock=lambda: current[0])
    for alias in PEP_SETUP_ALIASES:
        _run_effect(route, cfg, alias)
    first = route.creator_handler({}, creator_context("closeout-gate-v1"))
    first_cas_count = ledger.cas_count
    first_evidence_calls = list(evidence.calls)
    first_effect_count = len(effects.calls)
    assert ledger.snapshot.last_receipt_json == broker.canonical_json(first)

    current[0] = datetime(2026, 8, 30, 21, 0, tzinfo=timezone.utc)
    recovered = route.creator_handler({}, creator_context("closeout-gate-v1"))
    assert recovered == first
    assert ledger.cas_count == first_cas_count
    assert evidence.calls == first_evidence_calls
    assert len(effects.calls) == first_effect_count


def test_attempting_is_durable_before_mutation_and_timeout_is_terminal() -> None:
    cfg = config()
    timeline: list[str] = []
    ledger = FakeLedger(cfg, timeline=timeline)
    effects = FakeEffects(timeline=timeline, fail_create=True)
    route, _ledger, _effects, _evidence = runtime(cfg, ledger=ledger, effects=effects)
    with pytest.raises(broker.RouteBrokerError) as caught:
        route.creator_handler({}, creator_context("seed-revoke-create-v1"))
    assert caught.value.code == "CREATE_CHANGE_SET_UNCERTAIN"
    assert timeline.index("ledger:cas:SEED_REVOKE_CREATE_ATTEMPTING") < timeline.index(
        "provider:create"
    )
    assert ledger.snapshot.state == "SEED_REVOKE_CREATE_UNCERTAIN"
    with pytest.raises(broker.RouteBrokerError) as replay:
        route.creator_handler({}, creator_context("seed-revoke-create-v1"))
    assert replay.value.code == "REPLAY_REJECTED"
    assert len(effects.calls) == 1


def test_create_response_loss_recovers_causally_without_second_effect() -> None:
    cfg = config()
    ledger = FakeLedger(cfg, fail_cas_at=2)
    effects = FakeEffects()
    route, _ledger, _effects, _evidence = runtime(
        cfg, ledger=ledger, effects=effects
    )
    with pytest.raises(broker.RouteBrokerError) as uncertain:
        route.creator_handler({}, creator_context("seed-revoke-create-v1"))
    assert uncertain.value.code == "CREATE_CHANGE_SET_UNCERTAIN"
    assert ledger.snapshot.state == "SEED_REVOKE_CREATE_UNCERTAIN"
    assert ledger.snapshot.attempt_claim_json is not None
    assert len(effects.calls) == 1

    recovered = route.create_dispatch_recovery_handler(
        {}, create_recovery_context()
    )
    assert recovered["state"] == "SEED_REVOKE_CREATE_DISPATCHED"
    assert recovered["aws_mutations"] == 0
    assert len(effects.calls) == 1
    completed = route.create_dispatch_recovery_handler(
        {}, create_recovery_context()
    )
    assert completed["state"] == "SEED_REVOKE_CREATED"
    assert completed["aws_mutations"] == 0
    assert len(effects.calls) == 1


def test_execute_response_loss_recovers_causally_without_second_effect() -> None:
    cfg = config()
    route, ledger, effects, _evidence = runtime(cfg)
    _run_effect(route, cfg, "seed-revoke-create-v1")
    ledger.fail_cas_at = ledger.cas_count + 2
    with pytest.raises(broker.RouteBrokerError) as uncertain:
        route.executor_handler({}, executor_context("seed-revoke-execute-v1"))
    assert uncertain.value.code == "EXECUTE_CHANGE_SET_UNCERTAIN"
    assert ledger.snapshot.state == "SEED_REVOKE_EXECUTE_UNCERTAIN"
    assert len(effects.calls) == 2

    recovered = route.execute_dispatch_recovery_handler(
        {}, execute_recovery_context()
    )
    assert recovered["state"] == "SEED_REVOKE_EXECUTE_DISPATCHED"
    assert recovered["aws_mutations"] == 0
    assert len(effects.calls) == 2
    completed = route.execute_dispatch_recovery_handler(
        {}, execute_recovery_context()
    )
    assert completed["state"] == "SEED_REVOKED"
    assert completed["aws_mutations"] == 0
    assert len(effects.calls) == 2


def test_product_recovery_handlers_complete_dispatched_attempts_without_replay() -> None:
    cfg = config()
    harness, ledger, effects, evidence = runtime(cfg)
    harness.creator_handler({}, creator_context("seed-revoke-create-v1"))
    product = broker.RouteBroker(
        config=cfg,
        ledger=ledger,
        effects=effects,
        evidence=evidence,
        clock=lambda: NOW,
    )
    evidence.change_ready = False
    with pytest.raises(broker.RouteBrokerError) as create_pending:
        product.create_dispatch_recovery_handler(
            {}, create_recovery_context()
        )
    assert create_pending.value.retryable_read_only is True
    assert ledger.snapshot.state == "SEED_REVOKE_CREATE_DISPATCHED"
    assert len(effects.calls) == 1
    evidence.change_ready = True
    created = product.create_dispatch_recovery_handler(
        {}, create_recovery_context()
    )
    assert created["state"] == "SEED_REVOKE_CREATED"
    assert created["alias"] == broker.RECOVERY_RECEIPT_ALIASES[0]
    assert created["function_version"] == create_recovery_context().function_version
    assert created["aws_mutations"] == 0
    assert len(effects.calls) == 1

    harness.executor_handler({}, executor_context("seed-revoke-execute-v1"))
    evidence.terminal = False
    with pytest.raises(broker.RouteBrokerError) as execute_pending:
        product.execute_dispatch_recovery_handler(
            {}, execute_recovery_context()
        )
    assert execute_pending.value.retryable_read_only is True
    assert ledger.snapshot.state == "SEED_REVOKE_EXECUTE_DISPATCHED"
    assert len(effects.calls) == 2
    evidence.terminal = True
    executed = product.execute_dispatch_recovery_handler(
        {}, execute_recovery_context()
    )
    assert executed["state"] == "SEED_REVOKED"
    assert executed["alias"] == broker.RECOVERY_RECEIPT_ALIASES[1]
    assert executed["function_version"] == execute_recovery_context().function_version
    assert executed["aws_mutations"] == 0
    assert len(effects.calls) == 2


@pytest.mark.parametrize(
    ("handler_kind", "alias"),
    [
        ("creator", "seed-revoke-create-v1"),
        ("executor", "seed-revoke-execute-v1"),
    ],
)
def test_low_time_budget_never_creates_attempt_or_calls_provider(
    handler_kind: str,
    alias: str,
) -> None:
    cfg = config()
    route, ledger, effects, _evidence = runtime(cfg)
    if handler_kind == "executor":
        _run_effect(route, cfg, "seed-revoke-create-v1")
        before_state = ledger.snapshot.state
        before_cas = ledger.cas_count
        before_calls = len(effects.calls)
        context = Context(
            broker.EXECUTOR_FUNCTION_NAME,
            alias,
            remaining_time_ms=broker.MUTATION_DISPATCH_MIN_REMAINING_MS - 1,
        )
        handler = route.executor_handler
    else:
        before_state = ledger.snapshot.state
        before_cas = ledger.cas_count
        before_calls = len(effects.calls)
        context = Context(
            broker.CREATOR_FUNCTION_NAME,
            alias,
            remaining_time_ms=broker.MUTATION_DISPATCH_MIN_REMAINING_MS - 1,
        )
        handler = route.creator_handler
    with pytest.raises(broker.RouteBrokerError) as caught:
        handler({}, context)
    assert caught.value.code == "TIME_BUDGET_INSUFFICIENT"
    assert caught.value.retryable_read_only is False
    assert ledger.snapshot.state == before_state
    assert ledger.cas_count == before_cas
    assert len(effects.calls) == before_calls


def test_dispatched_continuation_low_budget_is_typed_and_never_replays() -> None:
    cfg = config()
    route, ledger, effects, _evidence = runtime(cfg)
    route.creator_handler({}, creator_context("seed-revoke-create-v1"))
    low = Context(
        broker.CREATOR_FUNCTION_NAME,
        "seed-revoke-create-v1",
        remaining_time_ms=broker.READ_CONTINUATION_MIN_REMAINING_MS - 1,
    )
    with pytest.raises(broker.RouteBrokerError) as caught:
        route.creator_handler({}, low)
    assert caught.value.code == "TIME_BUDGET_PENDING"
    assert caught.value.retryable_read_only is True
    assert ledger.snapshot.state == "SEED_REVOKE_CREATE_DISPATCHED"
    assert len(effects.calls) == 1


def test_read_only_change_set_pending_then_success_never_replays_mutation() -> None:
    cfg = config()
    route, ledger, effects, evidence = runtime(cfg)
    route.creator_handler({}, creator_context("seed-revoke-create-v1"))
    evidence.change_ready = False
    with pytest.raises(broker.RouteBrokerError) as pending:
        route.creator_handler({}, creator_context("seed-revoke-create-v1"))
    assert pending.value.retryable_read_only is True
    assert ledger.snapshot.state == "SEED_REVOKE_CREATE_DISPATCHED"
    assert len(effects.calls) == 1
    evidence.change_ready = True
    completed = route.creator_handler({}, creator_context("seed-revoke-create-v1"))
    assert completed["state"] == "SEED_REVOKE_CREATED"
    assert len(effects.calls) == 1


def test_read_only_terminal_pending_then_success_never_replays_execute() -> None:
    cfg = config()
    route, ledger, effects, evidence = runtime(cfg)
    _run_effect(route, cfg, "seed-revoke-create-v1")
    route.executor_handler({}, executor_context("seed-revoke-execute-v1"))
    evidence.terminal = False
    with pytest.raises(broker.RouteBrokerError) as pending:
        route.executor_handler({}, executor_context("seed-revoke-execute-v1"))
    assert pending.value.retryable_read_only is True
    assert ledger.snapshot.state == "SEED_REVOKE_EXECUTE_DISPATCHED"
    assert len(effects.calls) == 2
    evidence.terminal = True
    completed = route.executor_handler({}, executor_context("seed-revoke-execute-v1"))
    assert completed["state"] == "SEED_REVOKED"


@pytest.mark.parametrize(
    ("handler_name", "context"),
    [
        ("creator_handler", creator_context("seed-revoke-create-v1")),
        ("executor_handler", executor_context("seed-revoke-execute-v1")),
    ],
)
def test_top_level_handler_exposes_only_retryable_readback_as_distinct_error(
    monkeypatch: pytest.MonkeyPatch,
    handler_name: str,
    context: Context,
) -> None:
    class PendingRuntime:
        def creator_handler(self, _event: Any, _context: Any) -> Mapping[str, Any]:
            raise broker.RouteBrokerError(
                "CHANGE_SET_NOT_READY", retryable_read_only=True
            )

        def executor_handler(self, _event: Any, _context: Any) -> Mapping[str, Any]:
            raise broker.RouteBrokerError(
                "TERMINAL_READBACK_PENDING", retryable_read_only=True
            )

    monkeypatch.setattr(broker, "_runtime_factory", lambda: PendingRuntime())
    handler = getattr(broker, handler_name)
    with pytest.raises(broker.RouteBrokerReadOnlyPending) as pending:
        handler({}, context)
    assert pending.value.code in {
        "CHANGE_SET_NOT_READY",
        "TERMINAL_READBACK_PENDING",
    }
    assert str(pending.value).startswith(
        "GUG376_ROUTE_BROKER_READ_ONLY_PENDING:"
    )


def test_top_level_handler_never_relabels_nonretryable_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class BlockedRuntime:
        def creator_handler(self, _event: Any, _context: Any) -> Mapping[str, Any]:
            raise broker.RouteBrokerError("CHANGE_SET_NOT_READY")

    monkeypatch.setattr(broker, "_runtime_factory", lambda: BlockedRuntime())
    with pytest.raises(broker.RouteBrokerError) as blocked:
        broker.creator_handler({}, creator_context("seed-revoke-create-v1"))
    assert type(blocked.value) is broker.RouteBrokerError
    assert blocked.value.retryable_read_only is False


def test_post_window_dispatched_create_completes_but_new_execute_is_blocked() -> None:
    cfg = config()
    current = [NOW]
    route, ledger, effects, evidence = runtime(cfg, clock=lambda: current[0])
    dispatched = route.creator_handler(
        {}, creator_context("seed-revoke-create-v1")
    )
    assert dispatched["state"] == "SEED_REVOKE_CREATE_DISPATCHED"

    current[0] = cfg.route_not_after + timedelta(seconds=1)
    evidence.read_at = broker._timestamp(current[0])
    completed = route.creator_handler(
        {}, creator_context("seed-revoke-create-v1")
    )
    assert completed["state"] == "SEED_REVOKE_CREATED"
    assert completed["aws_mutations"] == 0
    assert len(effects.calls) == 1

    with pytest.raises(broker.RouteBrokerError) as blocked:
        route.executor_handler({}, executor_context("seed-revoke-execute-v1"))
    assert blocked.value.code == "ROUTE_WINDOW_CLOSED"
    assert ledger.snapshot.state == "SEED_REVOKE_CREATED"
    assert len(effects.calls) == 1


def test_post_window_dispatched_execute_completes_without_provider_replay() -> None:
    cfg = config()
    current = [NOW]
    route, ledger, effects, evidence = runtime(cfg, clock=lambda: current[0])
    _run_effect(route, cfg, "seed-revoke-create-v1")
    dispatched = route.executor_handler(
        {}, executor_context("seed-revoke-execute-v1")
    )
    assert dispatched["state"] == "SEED_REVOKE_EXECUTE_DISPATCHED"

    current[0] = cfg.route_not_after + timedelta(seconds=1)
    evidence.stack_last_updated_time = broker._timestamp(current[0])
    evidence.read_at = broker._timestamp(current[0])
    completed = route.executor_handler(
        {}, executor_context("seed-revoke-execute-v1")
    )
    assert completed["state"] == "SEED_REVOKED"
    assert completed["aws_mutations"] == 0
    assert ledger.snapshot.state == "SEED_REVOKED"
    assert len(effects.calls) == 2


def test_recovery_horizon_is_exclusive_and_ledger_is_read_first() -> None:
    cfg = config()
    current = [NOW]
    timeline: list[str] = []
    ledger = FakeLedger(cfg, timeline=timeline)
    route, _ledger, effects, evidence = runtime(
        cfg,
        ledger=ledger,
        evidence=FakeEvidence(cfg),
        clock=lambda: current[0],
    )
    route.creator_handler({}, creator_context("seed-revoke-create-v1"))
    timeline.clear()
    evidence.calls.clear()
    current[0] = cfg.recovery_not_after

    with pytest.raises(broker.RouteBrokerError) as closed:
        route.creator_handler({}, creator_context("seed-revoke-create-v1"))
    assert closed.value.code == "ROUTE_WINDOW_CLOSED"
    assert timeline == [
        "ledger:control-plane",
        "ledger:read:SEED_REVOKE_CREATE_DISPATCHED",
    ]
    assert evidence.calls == []
    assert ledger.snapshot.state == "SEED_REVOKE_CREATE_DISPATCHED"
    assert len(effects.calls) == 1


def test_runtime_preflight_allows_only_matching_dispatched_state_post_window() -> None:
    cfg = config()
    timeline: list[str] = []
    ledger = FakeLedger(cfg, timeline=timeline)
    route, _ledger, _effects, _evidence = runtime(cfg, ledger=ledger)
    route.creator_handler({}, creator_context("seed-revoke-create-v1"))
    timeline.clear()

    broker._runtime_ledger_preflight(
        config=cfg,
        ledger=ledger,
        handler_kind="creator",
        alias="seed-revoke-create-v1",
        now=cfg.route_not_after + timedelta(seconds=1),
    )
    assert timeline == [
        "ledger:control-plane",
        "ledger:read:SEED_REVOKE_CREATE_DISPATCHED",
    ]

    for handler_kind, alias in (
        ("creator", "closeout-gate-v1"),
        ("executor", "seed-revoke-execute-v1"),
    ):
        timeline.clear()
        with pytest.raises(broker.RouteBrokerError) as blocked:
            broker._runtime_ledger_preflight(
                config=cfg,
                ledger=ledger,
                handler_kind=handler_kind,
                alias=alias,
                now=cfg.route_not_after + timedelta(seconds=1),
            )
        assert blocked.value.code == "ROUTE_WINDOW_CLOSED"
        assert timeline == [
            "ledger:control-plane",
            "ledger:read:SEED_REVOKE_CREATE_DISPATCHED",
        ]


def test_runtime_orders_authority_identity_ledger_preflight_before_assume_role(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cfg = config()
    timeline: list[str] = []
    expected_preflight = {
        "alias": "seed-revoke-execute-v1",
        "state": "SEED_REVOKE_CREATED",
    }

    class Session:
        def __init__(self, **kwargs: Any) -> None:
            self.management = "aws_access_key_id" in kwargs

    class Config:
        def __init__(self, **_kwargs: Any) -> None:
            pass

    class TypeDeserializer:
        pass

    class AuthoritySts:
        def get_caller_identity(self) -> Mapping[str, str]:
            timeline.append("authority:get-caller-identity")
            return {
                "Account": broker.AUTHORITY_ACCOUNT_ID,
                "Arn": (
                    f"arn:aws:sts::{broker.AUTHORITY_ACCOUNT_ID}:assumed-role/"
                    f"{broker.AUTHORITY_EXECUTOR_ROLE_NAME}/executor-session"
                ),
                "UserId": "AROATEST:executor-session",
            }

        def assume_role(self, **request: Any) -> Mapping[str, Any]:
            timeline.append("authority:assume-role")
            session_name = f"gug376-executor-{cfg.source_commit}"
            assert request["RoleSessionName"] == session_name
            assert request["SourceIdentity"] == session_name
            return {
                "Credentials": {
                    "AccessKeyId": "synthetic-access-key",
                    "SecretAccessKey": "synthetic-secret-key",
                    "SessionToken": "synthetic-session-token",
                },
                "AssumedRoleUser": {
                    "Arn": (
                        f"arn:aws:sts::{broker.MANAGEMENT_ACCOUNT_ID}:assumed-role/"
                        f"{broker.MANAGEMENT_EXECUTOR_ROLE_NAME}/{session_name}"
                    ),
                    "AssumedRoleId": "AROATEST:" + session_name,
                },
            }

    class ManagementSts:
        def get_caller_identity(self) -> Mapping[str, str]:
            timeline.append("management:get-caller-identity")
            session_name = f"gug376-executor-{cfg.source_commit}"
            return {
                "Account": broker.MANAGEMENT_ACCOUNT_ID,
                "Arn": (
                    f"arn:aws:sts::{broker.MANAGEMENT_ACCOUNT_ID}:assumed-role/"
                    f"{broker.MANAGEMENT_EXECUTOR_ROLE_NAME}/{session_name}"
                ),
                "UserId": "AROATEST:" + session_name,
            }

    authority_sts = AuthoritySts()
    management_sts = ManagementSts()

    def client(session: Session, service: str, _config: Any) -> Any:
        if service == "sts":
            return management_sts if session.management else authority_sts
        if service == "dynamodb" and not session.management:
            timeline.append("authority:dynamodb-client")
        return object()

    def preflight(**kwargs: Any) -> str:
        timeline.append("authority:ledger-preflight")
        assert kwargs["config"] == cfg
        assert kwargs["handler_kind"] == "executor"
        assert kwargs["alias"] == expected_preflight["alias"]
        return expected_preflight["state"]

    boto3_module = types.ModuleType("boto3")
    boto3_module.session = types.SimpleNamespace(Session=Session)  # type: ignore[attr-defined]
    boto3_dynamodb = types.ModuleType("boto3.dynamodb")
    boto3_dynamodb.__path__ = []  # type: ignore[attr-defined]
    boto3_types = types.ModuleType("boto3.dynamodb.types")
    boto3_types.TypeDeserializer = TypeDeserializer  # type: ignore[attr-defined]
    botocore = types.ModuleType("botocore")
    botocore.__path__ = []  # type: ignore[attr-defined]
    botocore_config = types.ModuleType("botocore.config")
    botocore_config.Config = Config  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "boto3", boto3_module)
    monkeypatch.setitem(sys.modules, "boto3.dynamodb", boto3_dynamodb)
    monkeypatch.setitem(sys.modules, "boto3.dynamodb.types", boto3_types)
    monkeypatch.setitem(sys.modules, "botocore", botocore)
    monkeypatch.setitem(sys.modules, "botocore.config", botocore_config)
    monkeypatch.setattr(broker, "_client", client)
    monkeypatch.setattr(broker, "_runtime_ledger_preflight", preflight)
    monkeypatch.setattr(broker, "_runtime_factory", None)
    monkeypatch.setenv(
        "BROKER_CONFIG_JSON",
        broker.canonical_json(broker.encode_runtime_config(_config_value())),
    )
    monkeypatch.setenv("LEDGER_TABLE_NAME", broker.ROUTE_LEDGER_TABLE_NAME)
    monkeypatch.setenv(
        "BROKER_LEDGER_KEY_ARN",
        (
            "arn:aws:kms:us-east-1:042360977644:key/"
            "12345678-1234-4234-8234-1234567890ab"
        ),
    )
    monkeypatch.setenv("AWS_REGION", broker.REGION)
    monkeypatch.delenv("AWS_DEFAULT_REGION", raising=False)
    monkeypatch.delenv("AWS_ENDPOINT_URL", raising=False)

    runtime_value = broker._runtime_from_environment(
        "executor", executor_context("seed-revoke-execute-v1")
    )
    assert isinstance(runtime_value, broker.RouteBroker)
    assert runtime_value._effects._allowed_reducing_alias == (
        "seed-revoke-execute-v1"
    )
    assert timeline[:4] == [
        "authority:get-caller-identity",
        "authority:dynamodb-client",
        "authority:ledger-preflight",
        "authority:assume-role",
    ]
    assert timeline[4] == "management:get-caller-identity"

    inline_adapter = object()

    def build_inline_adapter(**kwargs: Any) -> object:
        assert kwargs["config"] == cfg
        assert isinstance(kwargs["authority_session"], Session)
        assert kwargs["boto3_module"] is boto3_module
        assert callable(kwargs["clock"])
        return inline_adapter

    monkeypatch.setattr(
        broker,
        "_build_inline_collision_admission_adapter",
        build_inline_adapter,
    )
    expected_preflight.update(
        alias="delegation-execute-v1",
        state="DELEGATION_CREATED",
    )
    timeline.clear()
    expansive_runtime = broker._runtime_from_environment(
        "executor", executor_context("delegation-execute-v1")
    )
    assert expansive_runtime._collision_admission is inline_adapter
    assert expansive_runtime._effects._allowed_reducing_alias is None
    assert timeline[:4] == [
        "authority:get-caller-identity",
        "authority:dynamodb-client",
        "authority:ledger-preflight",
        "authority:assume-role",
    ]
    assert timeline[4] == "management:get-caller-identity"


def test_terminal_readback_contradiction_marks_executor_uncertain_without_replay() -> None:
    cfg = config()

    class ContradictionEvidence(FakeEvidence):
        def read_terminal_stack(self, **_kwargs: Any) -> Mapping[str, Any]:
            self.calls.append("terminal:seed-revoke-execute-v1")
            raise broker.RouteBrokerError(
                "TERMINAL_READBACK_INVALID", uncertain=True
            )

    evidence = ContradictionEvidence(cfg)
    harness, ledger, effects, _evidence = runtime(cfg, evidence=evidence)
    _run_effect(harness, cfg, "seed-revoke-create-v1")
    harness.executor_handler({}, executor_context("seed-revoke-execute-v1"))
    product = broker.RouteBroker(
        config=cfg,
        ledger=ledger,
        effects=effects,
        evidence=evidence,
        clock=lambda: NOW,
    )
    mutation_count = len(effects.calls)

    with pytest.raises(broker.RouteBrokerError) as contradiction:
        product.execute_dispatch_recovery_handler(
            {}, execute_recovery_context()
        )
    assert contradiction.value.code == "TERMINAL_READBACK_INVALID"
    assert ledger.snapshot.state == "SEED_REVOKE_EXECUTE_UNCERTAIN"
    assert len(effects.calls) == mutation_count
    assert ledger.snapshot.last_receipt_digest == broker.digest_value(
        {
            "alias": "seed-revoke-execute-v1",
            "dispatched_state": "SEED_REVOKE_EXECUTE_DISPATCHED",
            "config_digest": cfg.config_digest,
            "error_code": "TERMINAL_READBACK_INVALID",
            "outcome": "TERMINAL_READBACK_CONTRADICTION",
            "aws_mutations": 0,
        }
    )

    with pytest.raises(broker.RouteBrokerError) as replay:
        product.executor_handler(
            {}, executor_context("seed-revoke-execute-v1")
        )
    assert replay.value.code == "REPLAY_REJECTED"
    assert len(effects.calls) == mutation_count


def test_executor_terminal_order_uses_pre_call_attempt_boundary() -> None:
    cfg = config()
    current = [NOW]

    class AdvancingEffects(FakeEffects):
        def execute_change_set(
            self,
            *,
            operation: str,
            request: Mapping[str, Any],
            permit: object,
        ) -> Mapping[str, Any]:
            response = super().execute_change_set(
                operation=operation,
                request=request,
                permit=permit,
            )
            current[0] = NOW.replace(minute=1)
            return response

    ledger = FakeLedger(cfg)
    effects = AdvancingEffects()
    evidence = FakeEvidence(cfg)
    route = _ContractHarnessRouteBroker(
        config=cfg,
        ledger=ledger,
        effects=effects,
        evidence=evidence,
        clock=lambda: current[0],
    )
    _run_effect(route, cfg, "seed-revoke-create-v1")
    dispatched = route.executor_handler(
        {}, executor_context("seed-revoke-execute-v1")
    )
    assert dispatched["state"] == "SEED_REVOKE_EXECUTE_DISPATCHED"
    completed = route.executor_handler(
        {}, executor_context("seed-revoke-execute-v1")
    )
    assert completed["state"] == "SEED_REVOKED"
    assert len(effects.calls) == 2


def test_closeout_cloudtrail_delay_leaves_pep_terminal_then_succeeds() -> None:
    cfg = config()
    route, ledger, effects, evidence = runtime(cfg)
    for alias in PEP_SETUP_ALIASES:
        _run_effect(route, cfg, alias)
    evidence.events = []
    with pytest.raises(broker.RouteBrokerError) as pending:
        route.creator_handler({}, creator_context("closeout-gate-v1"))
    assert pending.value.code == "NORMAL_PLAN_PROOF_PENDING"
    assert pending.value.retryable_read_only is True
    assert ledger.snapshot.state == "PEP_PROTECTED"
    mutation_count = len(effects.calls)
    evidence.events = [_plan_event()]
    receipt = route.creator_handler({}, creator_context("closeout-gate-v1"))
    assert receipt["state"] == "CLOSEOUT_PREREQUISITES_VERIFIED"
    assert receipt["normal_plan_caller_arn_digest"] == (
        NORMAL_PLAN_CALLER_DIGEST
    )
    assert len(effects.calls) == mutation_count


@pytest.mark.parametrize(
    ("stage", "effects_completed"),
    [
        ("UNCERTAIN_PROVISION_PERMISSION_SET", 1),
        ("UNCERTAIN_PROVISION_PERMISSION_SET_LEDGER_COMMIT", 2),
        ("UNCERTAIN_FINAL_READBACK", 2),
    ],
)
def test_closeout_rejects_attestation_from_uncertain_repair_ledger(
    stage: str,
    effects_completed: int,
) -> None:
    cfg = config()
    route, ledger, _effects, evidence = runtime(cfg)
    for alias in PEP_SETUP_ALIASES:
        _run_effect(route, cfg, alias)
    repair = _repair_ledger(
        status="UNCERTAIN_RECONCILE_ONLY",
        stage=stage,
        effects_attempted=2,
        effects_completed=effects_completed,
    )
    evidence.repair = repair
    evidence.attestation = _attestation(repair)
    cas_count = ledger.cas_count

    with pytest.raises(broker.RouteBrokerError) as blocked:
        route.creator_handler({}, creator_context("closeout-gate-v1"))

    assert blocked.value.code == "REPAIR_NOT_VERIFIED"
    assert ledger.snapshot.state == "PEP_PROTECTED"
    assert ledger.cas_count == cas_count


def test_closeout_rechecks_normal_plan_freshness_immediately_before_cas() -> None:
    cfg = config()
    route, ledger, effects, evidence = runtime(cfg)
    for alias in PEP_SETUP_ALIASES:
        _run_effect(route, cfg, alias)

    times = iter((NOW, NOW + timedelta(seconds=601)))
    delayed = _ContractHarnessRouteBroker(
        config=cfg,
        ledger=ledger,
        effects=effects,
        evidence=evidence,
        clock=lambda: next(times),
    )
    cas_count = ledger.cas_count
    mutation_count = len(effects.calls)
    with pytest.raises(broker.RouteBrokerError) as stale:
        delayed.creator_handler({}, creator_context("closeout-gate-v1"))
    assert stale.value.code == "NORMAL_PLAN_PROOF_MISSING"
    assert stale.value.retryable_read_only is False
    assert ledger.snapshot.state == "PEP_PROTECTED"
    assert ledger.cas_count == cas_count
    assert len(effects.calls) == mutation_count


@pytest.mark.parametrize(
    "changes",
    [
        {
            "caller_arn": (
                "arn:aws:sts::042360977644:assumed-role/"
                "ScanalyzeBootstrapPlanRepairPlan/lambda"
            )
        },
        {
            "caller_arn": NORMAL_PLAN_CALLER.replace(
                "042360977644", "000000000000"
            )
        },
        {
            "caller_arn": NORMAL_PLAN_CALLER.replace(
                "0123456789ABCDEF", "0123456789FEDCBA"
            )
        },
        {"caller_arn": NORMAL_PLAN_CALLER + "/nested"},
        {"identity_type": "AWSService"},
        {"identity_account_id": "000000000000"},
        {"session_issuer_type": "User"},
        {"session_issuer_arn": NORMAL_PLAN_ROLE_ARN + "-drift"},
        {"session_issuer_account_id": "000000000000"},
        {"session_issuer_user_name": NORMAL_PLAN_ROLE_NAME + "_drift"},
    ],
)
def test_normal_plan_event_rejects_non_exact_session_and_issuer(
    changes: Mapping[str, Any],
) -> None:
    with pytest.raises(broker.RouteBrokerError) as rejected:
        broker._validate_plan_event(
            _plan_event(**changes),
            config=config(),
            repaired_at=datetime(
                2026, 8, 30, 18, 50, tzinfo=timezone.utc
            ),
            reconciled_at=NOW,
        )
    assert rejected.value.code == "NORMAL_PLAN_PROOF_MISSING"


@pytest.mark.parametrize(
    "mode",
    [
        "multiple_sessions",
        "stale",
        "preflight_before_event",
        "preflight_after_closeout",
        "preflight_at_route_expiry",
    ],
)
def test_normal_plan_closeout_rejects_ambiguous_or_stale_proof(
    mode: str,
) -> None:
    cfg = config()
    route, ledger, effects, evidence = runtime(cfg)
    for alias in PEP_SETUP_ALIASES:
        _run_effect(route, cfg, alias)
    if mode == "multiple_sessions":
        evidence.events = [
            _plan_event(),
            _plan_event(
                event_id="66666666-6666-4666-8666-666666666666",
                event_time="2026-08-30T18:56:00Z",
                caller_arn=NORMAL_PLAN_CALLER.replace(
                    "/cesar-gug376", "/second-session"
                ),
            ),
        ]
    elif mode == "stale":
        evidence.attestation = _attestation(
            evidence.repair, reconciled_at="2026-08-30T18:35:00Z"
        )
        evidence.events = [_plan_event(event_time="2026-08-30T18:40:00Z")]
    elif mode == "preflight_before_event":
        evidence.preflight_read_at = "2026-08-30T18:54:59Z"
    elif mode == "preflight_after_closeout":
        evidence.preflight_read_at = "2026-08-30T19:00:01Z"
    else:
        evidence.preflight_read_at = "2026-08-30T20:00:00Z"
    mutation_count = len(effects.calls)
    with pytest.raises(broker.RouteBrokerError):
        route.creator_handler({}, creator_context("closeout-gate-v1"))
    assert ledger.snapshot.state == "PEP_PROTECTED"
    assert len(effects.calls) == mutation_count


def test_normal_plan_closeout_accepts_multiple_events_from_one_exact_session() -> None:
    cfg = config()
    route, _ledger, _effects, evidence = runtime(cfg)
    for alias in PEP_SETUP_ALIASES:
        _run_effect(route, cfg, alias)
    evidence.events = [
        _plan_event(),
        _plan_event(
            event_id="66666666-6666-4666-8666-666666666666",
            event_time="2026-08-30T18:56:00Z",
        ),
    ]
    receipt = route.creator_handler({}, creator_context("closeout-gate-v1"))
    assert receipt["normal_plan_caller_arn_digest"] == (
        NORMAL_PLAN_CALLER_DIGEST
    )


@pytest.mark.parametrize("fault", ["id", "assignment", "pab", "resources", "changes"])
def test_bound_readbacks_fail_closed_without_effect_replay(fault: str) -> None:
    cfg = config()
    route, ledger, effects, evidence = runtime(cfg)
    if fault == "id":
        route.creator_handler({}, creator_context("seed-revoke-create-v1"))
        evidence.id_drift = True
        with pytest.raises(broker.RouteBrokerError):
            route.creator_handler({}, creator_context("seed-revoke-create-v1"))
        assert ledger.snapshot.state == "SEED_REVOKE_CREATE_UNCERTAIN"
        assert len(effects.calls) == 1
        return
    for alias in PEP_SETUP_ALIASES:
        _run_effect(route, cfg, alias)
    if fault == "assignment":
        route.creator_handler({}, creator_context("closeout-gate-v1"))
        _run_effect(route, cfg, "delegation-revoke-create-v1")
        route.executor_handler({}, executor_context("delegation-revoke-execute-v1"))
        evidence.assignment_count = 1
        with pytest.raises(broker.RouteBrokerError) as caught:
            route.executor_handler({}, executor_context("delegation-revoke-execute-v1"))
        assert caught.value.code == "ASSIGNMENTS_REMAIN"
        assert ledger.snapshot.state == "DELEGATION_REVOKE_EXECUTE_DISPATCHED"
        return
    preflight = evidence.read_plan_recovery_preflight

    def forged(
        *,
        normal_plan_caller_arn_digest: str,
        parent_events_digest: str,
    ) -> Mapping[str, Any]:
        result = dict(
            preflight(
                normal_plan_caller_arn_digest=(
                    normal_plan_caller_arn_digest
                ),
                parent_events_digest=parent_events_digest,
            )
        )
        result.pop("readback_digest")
        if fault == "pab":
            result["public_access_block_configuration"] = {
                **result["public_access_block_configuration"],
                "BlockPublicPolicy": False,
            }
        elif fault == "resources":
            result["stack_resource_count"] = 1
        else:
            result["active_change_set_count"] = 1
        return broker.seal(result, "readback_digest")

    evidence.read_plan_recovery_preflight = forged  # type: ignore[method-assign]
    with pytest.raises(broker.RouteBrokerError):
        route.creator_handler({}, creator_context("closeout-gate-v1"))
    assert ledger.snapshot.state == "PEP_PROTECTED"


def test_event_and_resealed_config_cannot_control_role_or_dynamic_arn() -> None:
    cfg = config()
    route, _ledger, effects, _evidence = runtime(cfg)
    with pytest.raises(broker.RouteBrokerError) as event:
        route.creator_handler(
            {"RoleARN": "arn:aws:iam::000000000000:role/Admin"},
            creator_context("seed-revoke-create-v1"),
        )
    assert event.value.code == "NON_EMPTY_EVENT"
    assert effects.calls == []

    for field, value in (
        ("production_authorized", True),
        ("production_status", "GO"),
    ):
        forged = _config_value()
        forged[field] = value
        forged = broker.seal(
            {key: item for key, item in forged.items() if key != "config_digest"},
            "config_digest",
        )
        with pytest.raises(broker.RouteBrokerError) as overclaim:
            broker.BrokerConfig.from_mapping(forged)
        assert overclaim.value.code == "CONFIG_PRODUCTION_OVERCLAIM"

    forged = _config_value()
    forged["revocation_assignment_scopes"]["route-revoke-execute-v1"][
        "permission_set_arn"
    ] = ROUTE_INVOKER_PS
    forged = broker.seal(
        {key: item for key, item in forged.items() if key != "config_digest"},
        "config_digest",
    )
    with pytest.raises(broker.RouteBrokerError) as operator_arn:
        broker.BrokerConfig.from_mapping(forged)
    assert operator_arn.value.code == "ASSIGNMENT_CONFIG_INVALID"


def test_distinct_route_update_names_and_full_arn_identity_binding() -> None:
    cfg = config()
    seed = cfg.request("seed-revoke-create-v1")
    route = cfg.request("route-revoke-create-v1")
    assert seed["ChangeSetName"] != route["ChangeSetName"]
    route_runtime, _ledger, effects, _evidence = runtime(cfg)
    _run_effect(route_runtime, cfg, "seed-revoke-create-v1")
    route_runtime.executor_handler({}, executor_context("seed-revoke-execute-v1"))
    execute = effects.calls[-1][2]
    assert execute["ChangeSetName"].startswith(
        f"arn:aws:cloudformation:{broker.REGION}:{broker.MANAGEMENT_ACCOUNT_ID}:changeSet/"
    )
    assert execute["StackName"].startswith(
        f"arn:aws:cloudformation:{broker.REGION}:{broker.MANAGEMENT_ACCOUNT_ID}:stack/"
    )


def test_sdk_transport_source_identity_and_sts_exactness() -> None:
    class FakeConfig:
        def __init__(self, **kwargs: Any) -> None:
            self.kwargs = kwargs

    configured = broker._sdk_client_config(FakeConfig)
    assert configured.kwargs == {
        "connect_timeout": 3,
        "read_timeout": 8,
        "retries": {"total_max_attempts": 1, "mode": "standard"},
        "s3": {"us_east_1_regional_endpoint": "regional"},
    }
    source = inspect.getsource(broker._runtime_from_environment)
    assert source.count("_client(") == 9
    assert 'session_binding = f"gug376-{handler_kind}-{config.source_commit}"' in source
    assert "SourceIdentity=session_binding" in source
    assert "AWS_SDK_VERSION_MISMATCH" not in source
    assert "expected_boto3_version" not in source
    assert "expected_botocore_version" not in source
    session = "gug376-creator-" + SOURCE_COMMIT
    identity = {
        "Account": broker.MANAGEMENT_ACCOUNT_ID,
        "Arn": (
            f"arn:aws:sts::{broker.MANAGEMENT_ACCOUNT_ID}:assumed-role/"
            f"{broker.MANAGEMENT_CREATOR_ROLE_NAME}/{session}"
        ),
        "UserId": "AROATEST:" + session,
    }
    broker._verify_sts_identity(
        identity,
        account_id=broker.MANAGEMENT_ACCOUNT_ID,
        role_name=broker.MANAGEMENT_CREATOR_ROLE_NAME,
        session_name=session,
    )
    with pytest.raises(broker.RouteBrokerError):
        broker._verify_sts_identity(
            {**identity, "Arn": identity["Arn"] + "-drift"},
            account_id=broker.MANAGEMENT_ACCOUNT_ID,
            role_name=broker.MANAGEMENT_CREATOR_ROLE_NAME,
            session_name=session,
        )


def test_plan_preflight_adapter_paginates_and_proves_account_pab() -> None:
    cfg = config()

    class CloudFormation:
        def __init__(self) -> None:
            self.pages = 0

        def describe_stacks(self, **_request: Any) -> Mapping[str, Any]:
            return {
                "Stacks": [
                    {
                        "StackName": broker.PLAN_STACK_NAME,
                        "StackId": (
                            f"arn:aws:cloudformation:{broker.REGION}:"
                            f"{broker.AUTHORITY_ACCOUNT_ID}:stack/{broker.PLAN_STACK_NAME}/"
                            "99999999-9999-4999-8999-999999999999"
                        ),
                        "StackStatus": "REVIEW_IN_PROGRESS",
                        "NotificationARNs": [],
                    }
                ]
            }

        def list_stack_resources(self, **_request: Any) -> Mapping[str, Any]:
            return {"StackResourceSummaries": []}

        def list_change_sets(self, **request: Any) -> Mapping[str, Any]:
            self.pages += 1
            if self.pages == 1:
                assert "NextToken" not in request
                return {"Summaries": [], "NextToken": "page-2"}
            assert request["NextToken"] == "page-2"
            return {"Summaries": []}

    class S3Control:
        def get_public_access_block(self, **request: Any) -> Mapping[str, Any]:
            assert request == {"AccountId": broker.AUTHORITY_ACCOUNT_ID}
            return {
                "PublicAccessBlockConfiguration": {
                    "BlockPublicAcls": True,
                    "IgnorePublicAcls": True,
                    "BlockPublicPolicy": True,
                    "RestrictPublicBuckets": True,
                }
            }

    authority = CloudFormation()
    evidence = broker._AwsEvidence(
        cloudformation_by_account={
            broker.AUTHORITY_ACCOUNT_ID: authority,
            broker.MANAGEMENT_ACCOUNT_ID: object(),
        },
        sso_admin=object(),
        dynamodb=object(),
        cloudtrail_by_account={
            broker.AUTHORITY_ACCOUNT_ID: object(),
            broker.MANAGEMENT_ACCOUNT_ID: object(),
        },
        s3control=S3Control(),
        repair_table_name=broker.REPAIR_LEDGER_TABLE_NAME,
        deserializer=object(),
        config=cfg,
    )
    evidence.set_budget(
        broker._InvocationBudget(creator_context("closeout-gate-v1"))
    )
    receipt = evidence.read_plan_recovery_preflight(
        normal_plan_caller_arn_digest=NORMAL_PLAN_CALLER_DIGEST,
        parent_events_digest="sha256:" + ("9" * 64),
    )
    assert receipt["change_set_page_count"] == 2
    assert receipt["active_change_set_count"] == 0
    assert receipt["stack_resource_count"] == 0
    assert receipt["public_access_block_configuration"]["RestrictPublicBuckets"] is True


def test_plan_event_adapter_ignores_foreign_roles_but_keeps_malformed_candidate() -> None:
    cfg = config()

    def raw_event(
        *, caller_arn: str, issuer_arn: str, event_id: str
    ) -> dict[str, Any]:
        return {
            "eventID": event_id,
            "eventTime": "2026-08-30T18:55:00Z",
            "eventSource": "cloudformation.amazonaws.com",
            "eventName": "ListChangeSets",
            "awsRegion": broker.REGION,
            "recipientAccountId": broker.AUTHORITY_ACCOUNT_ID,
            "readOnly": True,
            "userIdentity": {
                "type": "AssumedRole",
                "accountId": broker.AUTHORITY_ACCOUNT_ID,
                "arn": caller_arn,
                "sessionContext": {
                    "sessionIssuer": {
                        "type": "Role",
                        "arn": issuer_arn,
                        "accountId": broker.AUTHORITY_ACCOUNT_ID,
                        "userName": NORMAL_PLAN_ROLE_NAME,
                    }
                },
            },
            "requestParameters": {"stackName": broker.PLAN_STACK_NAME},
        }

    events = [
        raw_event(
            caller_arn=(
                "arn:aws:sts::042360977644:assumed-role/"
                "ScanalyzeGug376RouteBrokerInvoker/broker"
            ),
            issuer_arn=(
                "arn:aws:iam::042360977644:role/"
                "ScanalyzeGug376RouteBrokerInvoker"
            ),
            event_id="44444444-4444-4444-8444-444444444444",
        ),
        raw_event(
            caller_arn=NORMAL_PLAN_CALLER,
            issuer_arn=NORMAL_PLAN_ROLE_ARN,
            event_id="55555555-5555-4555-8555-555555555555",
        ),
        raw_event(
            caller_arn=NORMAL_PLAN_CALLER,
            issuer_arn=NORMAL_PLAN_ROLE_ARN + "-drift",
            event_id="66666666-6666-4666-8666-666666666666",
        ),
    ]

    class CloudTrail:
        def lookup_events(self, **_request: Any) -> Mapping[str, Any]:
            return {
                "Events": [
                    {"CloudTrailEvent": json.dumps(event)}
                    for event in events
                ]
            }

    evidence = broker._AwsEvidence(
        cloudformation_by_account={
            broker.AUTHORITY_ACCOUNT_ID: object(),
            broker.MANAGEMENT_ACCOUNT_ID: object(),
        },
        sso_admin=object(),
        dynamodb=object(),
        cloudtrail_by_account={
            broker.AUTHORITY_ACCOUNT_ID: CloudTrail(),
            broker.MANAGEMENT_ACCOUNT_ID: object(),
        },
        s3control=object(),
        repair_table_name=broker.REPAIR_LEDGER_TABLE_NAME,
        deserializer=object(),
        config=cfg,
    )
    evidence.set_budget(
        broker._InvocationBudget(creator_context("closeout-gate-v1"))
    )
    projected = evidence.read_plan_list_change_sets_events(
        stack_name=broker.PLAN_STACK_NAME,
        start_time="2026-08-30T18:50:00Z",
        end_time="2026-08-30T19:00:00Z",
    )
    assert len(projected) == 2
    assert all(item["caller_arn"] == NORMAL_PLAN_CALLER for item in projected)
    broker._validate_plan_event(
        projected[0],
        config=cfg,
        repaired_at=datetime(2026, 8, 30, 18, 50, tzinfo=timezone.utc),
        reconciled_at=NOW,
    )
    with pytest.raises(broker.RouteBrokerError) as malformed:
        broker._validate_plan_event(
            projected[1],
            config=cfg,
            repaired_at=datetime(2026, 8, 30, 18, 50, tzinfo=timezone.utc),
            reconciled_at=NOW,
        )
    assert malformed.value.code == "NORMAL_PLAN_PROOF_MISSING"


@pytest.mark.parametrize(
    ("stack_status", "error_code", "retryable", "uncertain"),
    [
        ("UPDATE_IN_PROGRESS", "TERMINAL_READBACK_PENDING", True, False),
        ("UPDATE_ROLLBACK_COMPLETE", "TERMINAL_READBACK_INVALID", False, True),
    ],
)
def test_terminal_stack_adapter_classifies_pending_and_terminal_contradiction(
    stack_status: str,
    error_code: str,
    retryable: bool,
    uncertain: bool,
) -> None:
    cfg = config()
    operation = "pep-execute-v1"
    expectation = cfg.terminal_expectation(operation)
    stack_arn = (
        f"arn:aws:cloudformation:{broker.REGION}:{broker.AUTHORITY_ACCOUNT_ID}:"
        f"stack/{expectation['stack_name']}/11111111-1111-4111-8111-111111111111"
    )

    class CloudFormation:
        def describe_stacks(self, **request: Any) -> Mapping[str, Any]:
            assert request == {"StackName": stack_arn}
            return {
                "Stacks": [
                    {
                        "StackName": expectation["stack_name"],
                        "StackId": stack_arn,
                        "StackStatus": stack_status,
                    }
                ]
            }

    provider = CloudFormation()
    evidence = broker._AwsEvidence(
        cloudformation_by_account={
            broker.AUTHORITY_ACCOUNT_ID: provider,
            broker.MANAGEMENT_ACCOUNT_ID: object(),
        },
        sso_admin=object(),
        dynamodb=object(),
        cloudtrail_by_account={
            broker.AUTHORITY_ACCOUNT_ID: object(),
            broker.MANAGEMENT_ACCOUNT_ID: object(),
        },
        s3control=object(),
        repair_table_name=broker.REPAIR_LEDGER_TABLE_NAME,
        deserializer=object(),
        config=cfg,
    )
    evidence.set_budget(
        broker._InvocationBudget(executor_context(operation))
    )
    with pytest.raises(broker.RouteBrokerError) as caught:
        evidence.read_terminal_stack(
            operation=operation,
            expectation=expectation,
            dispatch={"stack_arn": stack_arn},
            parent_receipt_digest="sha256:" + ("f" * 64),
        )
    assert caught.value.code == error_code
    assert caught.value.retryable_read_only is retryable
    assert caught.value.uncertain is uncertain


def test_terminal_stack_adapter_rechecks_budget_before_each_provider_read(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cfg = config()
    operation = "pep-execute-v1"
    expectation = cfg.terminal_expectation(operation)
    stack_arn = (
        f"arn:aws:cloudformation:{broker.REGION}:{broker.AUTHORITY_ACCOUNT_ID}:"
        f"stack/{expectation['stack_name']}/"
        "11111111-1111-4111-8111-111111111111"
    )
    change_set_arn = (
        f"arn:aws:cloudformation:{broker.REGION}:{broker.AUTHORITY_ACCOUNT_ID}:"
        "changeSet/gug376-pep-create/"
        "22222222-2222-4222-8222-222222222222"
    )
    parameters = {"Bound": "value"}
    dispatch = {
        "stack_arn": stack_arn,
        "change_set_arn": change_set_arn,
        "terminal_parameters_digest": broker.digest_value(parameters),
    }
    projection = {
        "stack_id": stack_arn,
        "stack_name": expectation["stack_name"],
        "change_set_id": change_set_arn,
        "stack_status": expectation["terminal_statuses"][0],
        "last_updated_time": "2026-08-30T19:00:00Z",
        "role_arn_absent": True,
        "parent_id_absent": True,
        "root_id_absent": True,
        "notification_arns": [],
        "parameters": parameters,
        "outputs": {},
        "tags": [],
    }
    monkeypatch.setattr(
        broker,
        "_stable_stack_projection",
        lambda _stack, *, error_code: projection,
    )
    calls: list[str] = []

    class CloudFormation:
        def describe_stacks(self, **actual: Any) -> Mapping[str, Any]:
            assert actual == {"StackName": stack_arn}
            calls.append("describe_stacks")
            return {
                "Stacks": [
                    {"StackStatus": expectation["terminal_statuses"][0]}
                ]
            }

        def list_stack_resources(self, **_actual: Any) -> Mapping[str, Any]:
            calls.append("list_stack_resources")
            return {"StackResourceSummaries": []}

    class DecrementingContext:
        def __init__(self) -> None:
            self.remaining = [
                broker.READ_CONTINUATION_MIN_REMAINING_MS,
                broker.READ_CONTINUATION_MIN_REMAINING_MS - 1,
            ]

        def get_remaining_time_in_millis(self) -> int:
            return self.remaining.pop(0)

    evidence = broker._AwsEvidence(
        cloudformation_by_account={
            broker.AUTHORITY_ACCOUNT_ID: CloudFormation(),
            broker.MANAGEMENT_ACCOUNT_ID: object(),
        },
        sso_admin=object(),
        dynamodb=object(),
        cloudtrail_by_account={
            broker.AUTHORITY_ACCOUNT_ID: object(),
            broker.MANAGEMENT_ACCOUNT_ID: object(),
        },
        s3control=object(),
        repair_table_name=broker.REPAIR_LEDGER_TABLE_NAME,
        deserializer=object(),
        config=cfg,
    )
    evidence.set_budget(broker._InvocationBudget(DecrementingContext()))
    with pytest.raises(broker.RouteBrokerError) as caught:
        evidence.read_terminal_stack(
            operation=operation,
            expectation=expectation,
            dispatch=dispatch,
            parent_receipt_digest="sha256:" + ("9" * 64),
        )
    assert caught.value.code == "TIME_BUDGET_PENDING"
    assert caught.value.retryable_read_only is True
    assert calls == ["describe_stacks"]


def test_assignment_pagination_rechecks_budget_before_every_page() -> None:
    calls: list[Mapping[str, Any]] = []

    class Sso:
        def list_account_assignments(self, **request: Any) -> Mapping[str, Any]:
            calls.append(request)
            return {"AccountAssignments": [], "NextToken": "page-2"}

    class DecrementingContext:
        def __init__(self) -> None:
            self.remaining = [
                broker.READ_CONTINUATION_MIN_REMAINING_MS,
                broker.READ_CONTINUATION_MIN_REMAINING_MS - 1,
            ]

        def get_remaining_time_in_millis(self) -> int:
            return self.remaining.pop(0)

    evidence = broker._AwsEvidence(
        cloudformation_by_account={
            broker.AUTHORITY_ACCOUNT_ID: object(),
            broker.MANAGEMENT_ACCOUNT_ID: object(),
        },
        sso_admin=Sso(),
        dynamodb=object(),
        cloudtrail_by_account={
            broker.AUTHORITY_ACCOUNT_ID: object(),
            broker.MANAGEMENT_ACCOUNT_ID: object(),
        },
        s3control=object(),
        repair_table_name=broker.REPAIR_LEDGER_TABLE_NAME,
        deserializer=object(),
        config=config(),
    )
    evidence.set_budget(broker._InvocationBudget(DecrementingContext()))
    with pytest.raises(broker.RouteBrokerError) as caught:
        evidence.read_assignments(
            operation="seed-revoke-execute-v1",
            scope={
                "instance_arn": INSTANCE_ARN,
                "account_id": broker.MANAGEMENT_ACCOUNT_ID,
                "permission_set_arn": ROUTE_INVOKER_PS,
            },
            terminal_readback_digest="sha256:" + ("8" * 64),
        )
    assert caught.value.code == "TIME_BUDGET_PENDING"
    assert caught.value.retryable_read_only is True
    assert len(calls) == 1


class DelegationCloudFormation:
    def describe_stacks(self, **request: Any) -> Mapping[str, Any]:
        assert request == {
            "StackName": "scanalyze-platform-authority-bootstrap-plan-repair-delegation"
        }
        return {
            "Stacks": [
                {
                    "StackName": request["StackName"],
                    "StackId": (
                        f"arn:aws:cloudformation:{broker.REGION}:"
                        f"{broker.MANAGEMENT_ACCOUNT_ID}:stack/{request['StackName']}/"
                        "11111111-1111-4111-8111-111111111111"
                    ),
                    "StackStatus": "CREATE_COMPLETE",
                    "NotificationARNs": [],
                    "Outputs": [
                        {
                            "OutputKey": "RepairInvokerPermissionSetArn",
                            "OutputValue": DELEGATION_PS,
                        },
                        {
                            "OutputKey": "RepairInvokerAssignmentMode",
                            "OutputValue": "true",
                        },
                    ],
                }
            ]
        }


class DelegationSso:
    def __init__(
        self,
        *,
        inline_drift: bool = False,
        assignment_drift: bool = False,
        boundary_drift: bool = False,
        managed_drift: bool = False,
        pending: bool = False,
    ) -> None:
        self.inline_drift = inline_drift
        self.assignment_drift = assignment_drift
        self.boundary_drift = boundary_drift
        self.managed_drift = managed_drift
        self.pending = pending
        self.calls: list[tuple[str, dict[str, Any]]] = []

    @staticmethod
    def _exact() -> dict[str, str]:
        return {"InstanceArn": INSTANCE_ARN, "PermissionSetArn": DELEGATION_PS}

    def describe_permission_set(self, **request: Any) -> Mapping[str, Any]:
        self.calls.append(("describe_permission_set", request))
        assert request == self._exact()
        return {
            "PermissionSet": {
                "PermissionSetArn": DELEGATION_PS,
                "Name": "ScanalyzeBootstrapPlanRepair",
                "Description": "GUG-376 invoke-only bootstrap Plan policy repair PEP",
                "SessionDuration": "PT1H",
                "CreatedDate": NOW,
            }
        }

    def get_inline_policy_for_permission_set(
        self, **request: Any
    ) -> Mapping[str, Any]:
        self.calls.append(("get_inline_policy_for_permission_set", request))
        assert request == self._exact()
        policy = broker._AwsEvidence._repair_invoker_inline_policy()
        if self.inline_drift:
            policy = deepcopy(policy)
            policy["Statement"][0]["Resource"] = policy["Statement"][0][
                "Resource"
            ][:-1]
        return {"InlinePolicy": broker.canonical_json(policy)}

    def get_permissions_boundary_for_permission_set(
        self, **request: Any
    ) -> Mapping[str, Any]:
        self.calls.append(("get_permissions_boundary_for_permission_set", request))
        assert request == self._exact()
        if self.boundary_drift:
            return {
                "PermissionsBoundary": {
                    "ManagedPolicyArn": "arn:aws:iam::aws:policy/ReadOnlyAccess"
                }
            }
        return {}

    def list_managed_policies_in_permission_set(
        self, **request: Any
    ) -> Mapping[str, Any]:
        self.calls.append(("list_managed_policies_in_permission_set", request))
        assert request == {**self._exact(), "MaxResults": 100}
        return {
            "AttachedManagedPolicies": (
                [
                    {
                        "Arn": "arn:aws:iam::aws:policy/ReadOnlyAccess",
                        "Name": "ReadOnlyAccess",
                    }
                ]
                if self.managed_drift
                else []
            )
        }

    def list_customer_managed_policy_references_in_permission_set(
        self, **request: Any
    ) -> Mapping[str, Any]:
        self.calls.append(
            ("list_customer_managed_policy_references_in_permission_set", request)
        )
        assert request == {**self._exact(), "MaxResults": 100}
        return {"CustomerManagedPolicyReferences": []}

    def list_tags_for_resource(self, **request: Any) -> Mapping[str, Any]:
        self.calls.append(("list_tags_for_resource", request))
        expected = {"InstanceArn": INSTANCE_ARN, "ResourceArn": DELEGATION_PS}
        tags = [
            {"Key": "component", "Value": "plan-repair-delegation"},
            {"Key": "environment", "Value": "non-production"},
            {"Key": "managed_by", "Value": "cloudformation"},
            {"Key": "production", "Value": "false"},
            {"Key": "service", "Value": "scanalyze-platform-authority"},
            {"Key": "source_commit", "Value": SOURCE_COMMIT},
            {"Key": "work_package", "Value": "GUG-376"},
        ]
        if "NextToken" not in request:
            assert request == expected
            return {"Tags": tags[:3], "NextToken": "tags-page-2"}
        assert request == {**expected, "NextToken": "tags-page-2"}
        return {"Tags": tags[3:]}

    def list_accounts_for_provisioned_permission_set(
        self, **request: Any
    ) -> Mapping[str, Any]:
        self.calls.append(("list_accounts_for_provisioned_permission_set", request))
        assert request == {
            **self._exact(),
            "ProvisioningStatus": "LATEST_PERMISSION_SET_PROVISIONED",
            "MaxResults": 100,
        }
        return {"AccountIds": [broker.AUTHORITY_ACCOUNT_ID]}

    def list_account_assignments(self, **request: Any) -> Mapping[str, Any]:
        self.calls.append(("list_account_assignments", request))
        assert request == {
            **self._exact(),
            "AccountId": broker.AUTHORITY_ACCOUNT_ID,
            "MaxResults": 100,
        }
        assignment = {
            "AccountId": broker.AUTHORITY_ACCOUNT_ID,
            "PermissionSetArn": DELEGATION_PS,
            "PrincipalId": "12345678-1234-4123-8123-123456789012",
            "PrincipalType": "USER",
        }
        return {"AccountAssignments": [] if self.assignment_drift else [assignment]}

    def list_permission_set_provisioning_status(
        self, **request: Any
    ) -> Mapping[str, Any]:
        self.calls.append(("list_permission_set_provisioning_status", request))
        assert request == {
            "InstanceArn": INSTANCE_ARN,
            "Filter": {"Status": "IN_PROGRESS"},
            "MaxResults": 100,
        }
        return {
            "PermissionSetsProvisioningStatus": (
                [
                    {
                        "RequestId": "22222222-2222-4222-8222-222222222222",
                        "Status": "IN_PROGRESS",
                    }
                ]
                if self.pending
                else []
            )
        }

    def describe_permission_set_provisioning_status(
        self, **request: Any
    ) -> Mapping[str, Any]:
        self.calls.append(("describe_permission_set_provisioning_status", request))
        assert request == {
            "InstanceArn": INSTANCE_ARN,
            "ProvisionPermissionSetRequestId": (
                "22222222-2222-4222-8222-222222222222"
            ),
        }
        return {
            "PermissionSetProvisioningStatus": {
                "RequestId": "22222222-2222-4222-8222-222222222222",
                "Status": "IN_PROGRESS",
                "PermissionSetArn": DELEGATION_PS,
            }
        }


def _delegation_evidence(sso: Any) -> broker._AwsEvidence:
    evidence = broker._AwsEvidence(
        cloudformation_by_account={
            broker.AUTHORITY_ACCOUNT_ID: object(),
            broker.MANAGEMENT_ACCOUNT_ID: DelegationCloudFormation(),
        },
        sso_admin=sso,
        dynamodb=object(),
        cloudtrail_by_account={
            broker.AUTHORITY_ACCOUNT_ID: object(),
            broker.MANAGEMENT_ACCOUNT_ID: object(),
        },
        s3control=object(),
        repair_table_name=broker.REPAIR_LEDGER_TABLE_NAME,
        deserializer=object(),
        config=config(),
    )
    evidence.set_budget(
        broker._InvocationBudget(executor_context("delegation-execute-v1"))
    )
    return evidence


def test_delegation_output_readback_binds_exact_live_identity_center_state() -> None:
    sso = DelegationSso()
    outputs, source_digest = _delegation_evidence(sso)._permission_set_outputs(
        source="delegation"
    )
    assert outputs == {"RepairInvokerPermissionSetArn": DELEGATION_PS}
    assert source_digest.startswith("sha256:")
    assert len([name for name, _request in sso.calls if name == "list_tags_for_resource"]) == 2
    assert "list_accounts_for_provisioned_permission_set" in {
        name for name, _request in sso.calls
    }


@pytest.mark.parametrize(
    "change",
    [
        {"inline_drift": True},
        {"assignment_drift": True},
        {"boundary_drift": True},
        {"managed_drift": True},
    ],
)
def test_delegation_output_readback_rejects_live_property_drift(
    change: Mapping[str, bool],
) -> None:
    with pytest.raises(
        broker.RouteBrokerError,
        match="DELEGATION_PERMISSION_SET_READBACK_INVALID",
    ):
        _delegation_evidence(DelegationSso(**change))._permission_set_outputs(
            source="delegation"
        )


def test_delegation_output_readback_blocks_while_provisioning_is_pending() -> None:
    with pytest.raises(
        broker.RouteBrokerError, match="DELEGATION_PROVISIONING_PENDING"
    ) as caught:
        _delegation_evidence(DelegationSso(pending=True))._permission_set_outputs(
            source="delegation"
        )
    assert caught.value.retryable_read_only is True


def test_aws_evidence_reads_real_describe_shape_and_all_change_set_helpers() -> None:
    template_body = "AWSTemplateFormatVersion: '2010-09-09'\nResources: {}\n"
    value = _config_value()
    value["creator_contracts"]["seed-revoke-create-v1"][
        "template_digest"
    ] = "sha256:" + sha256(template_body.encode("utf-8")).hexdigest()
    value.pop("config_digest")
    cfg = broker.BrokerConfig.from_mapping(broker.seal(value, "config_digest"))
    operation = "seed-revoke-create-v1"
    request = cfg.request(operation)
    contract = cfg.creator_contract(operation)
    account_id = broker.operation_account(operation)
    stack_arn = (
        f"arn:aws:cloudformation:{broker.REGION}:{account_id}:stack/"
        f"{request['StackName']}/22222222-2222-4222-8222-222222222222"
    )
    change_set_arn = (
        f"arn:aws:cloudformation:{broker.REGION}:{account_id}:changeSet/"
        f"{request['ChangeSetName']}/11111111-1111-4111-8111-111111111111"
    )
    dispatch = {
        "stack_arn": stack_arn,
        "change_set_arn": change_set_arn,
        "create_request_id": "33333333-3333-4333-8333-333333333333",
    }
    output_contract = cfg.output_contract("route")
    permission_sets = {
        "BrokerInvokerPermissionSetArn": ROUTE_INVOKER_PS,
        "BrokerSeedCreatorPermissionSetArn": ROUTE_CREATOR_PS,
        "BrokerSeedExecutorPermissionSetArn": ROUTE_EXECUTOR_PS,
    }

    class CloudFormation:
        def describe_change_set(self, **actual: Any) -> Mapping[str, Any]:
            assert actual == {
                "StackName": stack_arn,
                "ChangeSetName": change_set_arn,
            }
            return {
                "ChangeSetId": change_set_arn,
                "StackId": stack_arn,
                "StackName": request["StackName"],
                "ChangeSetName": request["ChangeSetName"],
                "Description": request["Description"],
                "ChangeSetType": request["ChangeSetType"],
                "Parameters": [
                    {
                        "ParameterKey": item["ParameterKey"],
                        "ParameterValue": (
                            "previous-" + item["ParameterKey"]
                            if item.get("UsePreviousValue") is True
                            else item["ParameterValue"]
                        ),
                    }
                    for item in request["Parameters"]
                ],
                "Capabilities": request["Capabilities"],
                "Tags": request["Tags"],
                "IncludeNestedStacks": request["IncludeNestedStacks"],
                "NotificationARNs": request["NotificationARNs"],
                "RollbackConfiguration": request["RollbackConfiguration"],
                "Status": "CREATE_COMPLETE",
                "ExecutionStatus": "AVAILABLE",
                "CreationTime": NOW,
                "Changes": [
                    {
                        "Type": "Resource",
                        "ResourceChange": {
                            "Action": item["action"],
                            "LogicalResourceId": item["logical_resource_id"],
                            "ResourceType": item["resource_type"],
                            "Replacement": item["replacement"],
                            "Scope": item["scope"],
                            "Details": _provider_details(item),
                        },
                    }
                    for item in contract["expected_changes"]
                ],
            }

        def get_template(self, **actual: Any) -> Mapping[str, Any]:
            assert actual == {
                "ChangeSetName": change_set_arn,
                "TemplateStage": "Original",
            }
            return {"TemplateBody": template_body}

        def describe_stacks(self, **actual: Any) -> Mapping[str, Any]:
            assert actual in (
                {"StackName": stack_arn},
                {"StackName": output_contract["stack_name"]},
            )
            outputs = {
                **permission_sets,
                **output_contract["required_mode_outputs"],
            }
            parameters = [
                {
                    "ParameterKey": item["ParameterKey"],
                    "ParameterValue": (
                        "previous-" + item["ParameterKey"]
                        if item.get("UsePreviousValue") is True
                        else item["ParameterValue"]
                    ),
                }
                for item in request["Parameters"]
            ]
            return {
                "Stacks": [
                    {
                        "StackName": output_contract["stack_name"],
                        "StackId": stack_arn,
                        "StackStatus": "CREATE_COMPLETE",
                        "CreationTime": NOW - timedelta(minutes=1),
                        "NotificationARNs": [],
                        "Parameters": parameters,
                        "Outputs": [
                            {"OutputKey": key, "OutputValue": output}
                            for key, output in outputs.items()
                        ],
                    }
                ]
            }

    caller_arn = (
        f"arn:aws:sts::{account_id}:assumed-role/"
        f"{broker.MANAGEMENT_CREATOR_ROLE_NAME}/gug376-creator-{SOURCE_COMMIT}"
    )
    event = {
        "eventID": "55555555-5555-4555-8555-555555555555",
        "eventTime": "2026-08-30T18:59:00Z",
        "requestID": dispatch["create_request_id"],
        "eventSource": "cloudformation.amazonaws.com",
        "eventName": "CreateChangeSet",
        "awsRegion": broker.REGION,
        "recipientAccountId": account_id,
        "readOnly": False,
        "userIdentity": {"arn": caller_arn},
        "requestParameters": {
            "stackName": request["StackName"],
            "changeSetName": request["ChangeSetName"],
            "changeSetType": request["ChangeSetType"],
            "description": request["Description"],
            "templateURL": request["TemplateURL"],
            "parameters": [
                {"parameterKey": item["ParameterKey"]}
                for item in request["Parameters"]
            ],
            "capabilities": request["Capabilities"],
            "tags": [
                {"key": item["Key"], "value": item["Value"]}
                for item in request["Tags"]
            ],
            "includeNestedStacks": False,
            "notificationARNs": [],
            "rollbackConfiguration": {
                "rollbackTriggers": [],
                "monitoringTimeInMinutes": 0,
            },
            "clientToken": request["ClientToken"],
        },
        "responseElements": {"id": change_set_arn, "stackId": stack_arn},
    }

    class CloudTrail:
        def lookup_events(self, **_actual: Any) -> Mapping[str, Any]:
            return {"Events": [{"CloudTrailEvent": json.dumps(event)}]}

    client = CloudFormation()
    evidence = broker._AwsEvidence(
        cloudformation_by_account={
            broker.AUTHORITY_ACCOUNT_ID: object(),
            broker.MANAGEMENT_ACCOUNT_ID: client,
        },
        sso_admin=object(),
        dynamodb=object(),
        cloudtrail_by_account={
            broker.AUTHORITY_ACCOUNT_ID: object(),
            broker.MANAGEMENT_ACCOUNT_ID: CloudTrail(),
        },
        s3control=object(),
        repair_table_name=broker.REPAIR_LEDGER_TABLE_NAME,
        deserializer=object(),
        config=cfg,
    )
    evidence.set_budget(
        broker._InvocationBudget(creator_context(operation))
    )
    readback = evidence.read_change_set_ready(
        operation=operation,
        request=request,
        dispatch=dispatch,
        contract=contract,
        parent_receipt_digest="sha256:" + ("9" * 64),
    )
    assert readback["change_set_arn"] == change_set_arn
    assert readback["derived_permission_set_arns"] == permission_sets
    expected_terminal_parameters = {
        item["ParameterKey"]: (
            "previous-" + item["ParameterKey"]
            if item.get("UsePreviousValue") is True
            else item["ParameterValue"]
        )
        for item in request["Parameters"]
    }
    assert readback["terminal_parameters_digest"] == broker.digest_value(
        dict(sorted(expected_terminal_parameters.items()))
    )


def test_update_parameter_baseline_rejects_stack_newer_than_change_set() -> None:
    cfg = config()
    operation = "seed-revoke-create-v1"
    account_id = broker.operation_account(operation)
    stack_name = cfg.request(operation)["StackName"]
    stack_arn = (
        f"arn:aws:cloudformation:{broker.REGION}:{account_id}:stack/"
        f"{stack_name}/22222222-2222-4222-8222-222222222222"
    )

    class CloudFormation:
        def describe_stacks(self, **actual: Any) -> Mapping[str, Any]:
            assert actual == {"StackName": stack_arn}
            return {
                "Stacks": [
                    {
                        "StackName": stack_name,
                        "StackId": stack_arn,
                        "StackStatus": "UPDATE_COMPLETE",
                        "CreationTime": NOW - timedelta(hours=1),
                        "LastUpdatedTime": NOW + timedelta(seconds=1),
                        "NotificationARNs": [],
                        "Parameters": [],
                    }
                ]
            }

    evidence = broker._AwsEvidence(
        cloudformation_by_account={
            broker.AUTHORITY_ACCOUNT_ID: object(),
            broker.MANAGEMENT_ACCOUNT_ID: CloudFormation(),
        },
        sso_admin=object(),
        dynamodb=object(),
        cloudtrail_by_account={
            broker.AUTHORITY_ACCOUNT_ID: object(),
            broker.MANAGEMENT_ACCOUNT_ID: object(),
        },
        s3control=object(),
        repair_table_name=broker.REPAIR_LEDGER_TABLE_NAME,
        deserializer=object(),
        config=cfg,
    )
    evidence.set_budget(broker._InvocationBudget(creator_context(operation)))
    with pytest.raises(broker.RouteBrokerError) as caught:
        evidence._current_stack_parameter_values(
            account_id=account_id,
            stack_arn=stack_arn,
            stack_name=stack_name,
            change_set_creation_time=NOW,
        )
    assert caught.value.code == "CHANGE_SET_PARAMETER_BASELINE_INVALID"


def _recovery_aws_fixture(
    *,
    operation: str,
    events: list[Mapping[str, Any]],
    execution_status: str = "AVAILABLE",
    response_change: Mapping[str, Any] | None = None,
) -> tuple[
    broker.BrokerConfig,
    broker._AwsEvidence,
    dict[str, Any],
    dict[str, Any],
    dict[str, Any],
    list[dict[str, Any]],
]:
    creator_operation = (
        operation
        if operation in broker.CREATOR_ALIASES
        else CREATE_TO_EXECUTE_INV[operation]
    )
    template_body = "AWSTemplateFormatVersion: '2010-09-09'\nResources: {}\n"
    raw = _config_value()
    raw["creator_contracts"][creator_operation]["template_digest"] = (
        "sha256:" + sha256(template_body.encode("utf-8")).hexdigest()
    )
    raw.pop("config_digest")
    cfg = broker.BrokerConfig.from_mapping(broker.seal(raw, "config_digest"))
    creator_request = cfg.request(creator_operation)
    contract = cfg.creator_contract(creator_operation)
    account_id = broker.operation_account(operation)
    stack_arn = (
        f"arn:aws:cloudformation:{broker.REGION}:{account_id}:stack/"
        f"{creator_request['StackName']}/22222222-2222-4222-8222-222222222222"
    )
    change_set_arn = (
        f"arn:aws:cloudformation:{broker.REGION}:{account_id}:changeSet/"
        f"{creator_request['ChangeSetName']}/11111111-1111-4111-8111-111111111111"
    )
    response = {
        "ChangeSetId": change_set_arn,
        "StackId": stack_arn,
        "StackName": creator_request["StackName"],
        "ChangeSetName": creator_request["ChangeSetName"],
        "Description": creator_request["Description"],
        "ChangeSetType": creator_request["ChangeSetType"],
        "Parameters": creator_request["Parameters"],
        "Capabilities": creator_request["Capabilities"],
        "Tags": creator_request["Tags"],
        "IncludeNestedStacks": creator_request["IncludeNestedStacks"],
        "NotificationARNs": creator_request["NotificationARNs"],
        "RollbackConfiguration": creator_request["RollbackConfiguration"],
        "OnStackFailure": creator_request.get("OnStackFailure"),
        "Status": "CREATE_COMPLETE",
        "ExecutionStatus": execution_status,
        "CreationTime": NOW,
        "Changes": [
            {
                "Type": "Resource",
                "ResourceChange": {
                    "Action": item["action"],
                    "LogicalResourceId": item["logical_resource_id"],
                    "ResourceType": item["resource_type"],
                    "Replacement": item["replacement"],
                    "Scope": item["scope"],
                    "Details": _provider_details(item),
                },
            }
            for item in contract["expected_changes"]
        ],
    }
    if response_change:
        response.update(response_change)

    class CloudFormation:
        def __init__(self) -> None:
            self.calls: list[dict[str, Any]] = []

        def describe_change_set(self, **actual: Any) -> Mapping[str, Any]:
            self.calls.append({"method": "describe_change_set", **actual})
            return deepcopy(response)

        def get_template(self, **actual: Any) -> Mapping[str, Any]:
            self.calls.append({"method": "get_template", **actual})
            return {"TemplateBody": template_body}

    class CloudTrail:
        def lookup_events(self, **actual: Any) -> Mapping[str, Any]:
            trail_calls.append(deepcopy(actual))
            return {"Events": deepcopy(events)}

    trail_calls: list[dict[str, Any]] = []
    cloudformation = CloudFormation()
    evidence = broker._AwsEvidence(
        cloudformation_by_account={
            broker.AUTHORITY_ACCOUNT_ID: (
                cloudformation
                if account_id == broker.AUTHORITY_ACCOUNT_ID
                else object()
            ),
            broker.MANAGEMENT_ACCOUNT_ID: (
                cloudformation
                if account_id == broker.MANAGEMENT_ACCOUNT_ID
                else object()
            ),
        },
        sso_admin=object(),
        dynamodb=object(),
        cloudtrail_by_account={
            broker.AUTHORITY_ACCOUNT_ID: (
                CloudTrail()
                if account_id == broker.AUTHORITY_ACCOUNT_ID
                else object()
            ),
            broker.MANAGEMENT_ACCOUNT_ID: (
                CloudTrail()
                if account_id == broker.MANAGEMENT_ACCOUNT_ID
                else object()
            ),
        },
        s3control=object(),
        repair_table_name=broker.REPAIR_LEDGER_TABLE_NAME,
        deserializer=object(),
        config=cfg,
        clock=lambda: NOW + timedelta(minutes=5),
    )
    evidence.set_budget(broker._InvocationBudget(creator_context(creator_operation)))
    coordinates = {
        "stack_arn": stack_arn,
        "change_set_arn": change_set_arn,
    }
    return (
        cfg,
        evidence,
        creator_request,
        contract,
        coordinates,
        cloudformation.calls,
    )


CREATE_TO_EXECUTE_INV = {executor: creator for creator, executor in CREATE_TO_EXECUTE.items()}


def _recovery_event(
    *,
    operation: str,
    request: Mapping[str, Any],
    coordinates: Mapping[str, str],
    event_time: str,
    event_id: str,
    request_id: str,
) -> dict[str, Any]:
    account_id = broker.operation_account(operation)
    is_create = operation in broker.CREATOR_ALIASES
    role_name = (
        (
            broker.AUTHORITY_CREATOR_ROLE_NAME
            if account_id == broker.AUTHORITY_ACCOUNT_ID
            else broker.MANAGEMENT_CREATOR_ROLE_NAME
        )
        if is_create
        else (
            broker.AUTHORITY_EXECUTOR_ROLE_NAME
            if account_id == broker.AUTHORITY_ACCOUNT_ID
            else broker.MANAGEMENT_EXECUTOR_ROLE_NAME
        )
    )
    parameters = (
        broker._AwsEvidence._create_cloudtrail_parameters(request)
        if is_create
        else broker._AwsEvidence._execute_cloudtrail_parameters(request)
    )
    event = {
        "eventID": event_id,
        "eventTime": event_time,
        "requestID": request_id,
        "eventSource": "cloudformation.amazonaws.com",
        "eventName": "CreateChangeSet" if is_create else "ExecuteChangeSet",
        "awsRegion": broker.REGION,
        "recipientAccountId": account_id,
        "readOnly": False,
        "userIdentity": {
            "arn": (
                f"arn:aws:sts::{account_id}:assumed-role/{role_name}/"
                f"gug376-original-{SOURCE_COMMIT}"
            )
        },
        "requestParameters": parameters,
        "responseElements": (
            {
                "id": coordinates["change_set_arn"],
                "stackId": coordinates["stack_arn"],
            }
            if is_create
            else None
        ),
    }
    return {"CloudTrailEvent": json.dumps(event)}


def _mutate_recovery_event(
    envelope: Mapping[str, Any], mutate: Callable[[dict[str, Any]], None]
) -> dict[str, Any]:
    event = json.loads(str(envelope["CloudTrailEvent"]))
    mutate(event)
    return {"CloudTrailEvent": json.dumps(event)}


@pytest.mark.parametrize(
    ("mode", "error_code"),
    [
        ("ok", None),
        ("substitution", "TERMINAL_PARAMETERS_INVALID"),
        ("mask", "TERMINAL_READBACK_INVALID"),
        ("duplicate", "TERMINAL_READBACK_INVALID"),
        ("resolved", "TERMINAL_READBACK_INVALID"),
        ("foreign_change_set", "TERMINAL_READBACK_INVALID"),
        ("concurrent_second_read", "TERMINAL_SNAPSHOT_CHANGED"),
        ("missing_event", "TERMINAL_STACK_EVENT_PENDING"),
        ("wrong_event_token", "TERMINAL_STACK_EVENT_PENDING"),
        ("duplicate_event", "TERMINAL_STACK_EVENT_INVALID"),
        ("event_before_execute", "TERMINAL_STACK_EVENT_INVALID"),
    ],
)
def test_terminal_stack_adapter_binds_parameters_change_set_and_stable_snapshot(
    mode: str, error_code: str | None
) -> None:
    template_body = "AWSTemplateFormatVersion: '2010-09-09'\nResources: {}\n"
    template_digest = "sha256:" + sha256(template_body.encode("utf-8")).hexdigest()
    value = _config_value()
    value["creator_contracts"]["pep-create-v1"][
        "template_digest"
    ] = template_digest
    value["terminal_expectations"]["pep-execute-v1"][
        "template_digest"
    ] = template_digest
    value.pop("config_digest")
    cfg = broker.BrokerConfig.from_mapping(broker.seal(value, "config_digest"))
    operation = "pep-execute-v1"
    creator_operation = "pep-create-v1"
    expectation = cfg.terminal_expectation(operation)
    creator_request = cfg.request(creator_operation)
    account_id = broker.operation_account(operation)
    stack_arn = (
        f"arn:aws:cloudformation:{broker.REGION}:{account_id}:stack/"
        f"{expectation['stack_name']}/22222222-2222-4222-8222-222222222222"
    )
    change_set_arn = (
        f"arn:aws:cloudformation:{broker.REGION}:{account_id}:changeSet/"
        f"{creator_request['ChangeSetName']}/11111111-1111-4111-8111-111111111111"
    )
    parameter_values = {
        item["ParameterKey"]: item["ParameterValue"]
        for item in creator_request["Parameters"]
    }
    terminal_parameters_digest = broker.digest_value(
        dict(sorted(parameter_values.items()))
    )
    execute_request = cfg.request(operation)
    execute_request["StackName"] = stack_arn
    execute_request["ChangeSetName"] = change_set_arn
    execute_request_id = "44444444-4444-4444-8444-444444444444"
    dispatch = {
        "kind": "CREATE",
        "operation": creator_operation,
        "change_set_arn": change_set_arn,
        "stack_arn": stack_arn,
        "create_request_id": "33333333-3333-4333-8333-333333333333",
        "create_request_digest": broker.digest_value(creator_request),
        "dispatched_at": "2026-08-30T18:59:00Z",
        "execute_operation": operation,
        "execute_request_id": execute_request_id,
        "execute_request_digest": broker.digest_value(execute_request),
        "terminal_parameters_digest": terminal_parameters_digest,
        "executed_at": "2026-08-30T19:00:00Z",
    }
    outputs = {
        key: expectation["expected_static_outputs"].get(key, "synthetic-value")
        for key in expectation["expected_output_keys"]
    }
    base_stack: dict[str, Any] = {
        "StackName": expectation["stack_name"],
        "StackId": stack_arn,
        "ChangeSetId": change_set_arn,
        "StackStatus": expectation["terminal_statuses"][0],
        "CreationTime": NOW - timedelta(minutes=1),
        "NotificationARNs": [],
        "Parameters": [
            {"ParameterKey": key, "ParameterValue": item}
            for key, item in parameter_values.items()
        ],
        "Outputs": [
            {"OutputKey": key, "OutputValue": item}
            for key, item in outputs.items()
        ],
        "Tags": deepcopy(expectation["expected_tags"]),
    }
    if mode == "substitution":
        base_stack["Parameters"][0]["ParameterValue"] = "substituted"
    elif mode == "mask":
        base_stack["Parameters"][0]["ParameterValue"] = "****"
    elif mode == "duplicate":
        base_stack["Parameters"].append(deepcopy(base_stack["Parameters"][0]))
    elif mode == "resolved":
        base_stack["Parameters"][0]["ResolvedValue"] = "resolved"
    elif mode == "foreign_change_set":
        base_stack["ChangeSetId"] = change_set_arn + "-foreign"
    stack_reads = 0
    stack_event: dict[str, Any] = {
        "EventId": "synthetic-terminal-stack-event",
        "StackId": stack_arn,
        "StackName": expectation["stack_name"],
        "LogicalResourceId": expectation["stack_name"],
        "PhysicalResourceId": stack_arn,
        "ResourceType": "AWS::CloudFormation::Stack",
        "ResourceStatus": expectation["terminal_statuses"][0],
        "ClientRequestToken": execute_request["ClientRequestToken"],
        "Timestamp": NOW,
    }
    if mode == "wrong_event_token":
        stack_event["ClientRequestToken"] = "gug376-foreign-token"
    elif mode == "event_before_execute":
        stack_event["Timestamp"] = NOW - timedelta(seconds=1)

    class CloudFormation:
        def describe_stacks(self, **actual: Any) -> Mapping[str, Any]:
            nonlocal stack_reads
            assert actual == {"StackName": stack_arn}
            stack_reads += 1
            response_stack = deepcopy(base_stack)
            if mode == "concurrent_second_read" and stack_reads == 2:
                response_stack["Outputs"][0]["OutputValue"] = "concurrent"
                response_stack["LastUpdatedTime"] = NOW + timedelta(seconds=1)
            return {"Stacks": [response_stack]}

        def list_stack_resources(self, **actual: Any) -> Mapping[str, Any]:
            assert actual == {"StackName": stack_arn}
            return {
                "StackResourceSummaries": [
                    {
                        "LogicalResourceId": item["logical_resource_id"],
                        "ResourceType": item["resource_type"],
                    }
                    for item in expectation["expected_resources"]
                ]
            }

        def get_template(self, **actual: Any) -> Mapping[str, Any]:
            assert actual == {
                "StackName": stack_arn,
                "TemplateStage": "Original",
            }
            return {"TemplateBody": template_body}

        def describe_stack_events(self, **actual: Any) -> Mapping[str, Any]:
            assert actual == {"StackName": stack_arn}
            if mode == "missing_event":
                return {"StackEvents": []}
            if mode == "duplicate_event":
                return {"StackEvents": [deepcopy(stack_event), deepcopy(stack_event)]}
            return {"StackEvents": [deepcopy(stack_event)]}

    event = _recovery_event(
        operation=operation,
        request=execute_request,
        coordinates={"stack_arn": stack_arn, "change_set_arn": change_set_arn},
        event_time="2026-08-30T19:00:00Z",
        event_id="55555555-5555-4555-8555-555555555555",
        request_id=execute_request_id,
    )

    class CloudTrail:
        def lookup_events(self, **_actual: Any) -> Mapping[str, Any]:
            return {"Events": [event]}

    evidence = broker._AwsEvidence(
        cloudformation_by_account={
            broker.AUTHORITY_ACCOUNT_ID: CloudFormation(),
            broker.MANAGEMENT_ACCOUNT_ID: object(),
        },
        sso_admin=object(),
        dynamodb=object(),
        cloudtrail_by_account={
            broker.AUTHORITY_ACCOUNT_ID: CloudTrail(),
            broker.MANAGEMENT_ACCOUNT_ID: object(),
        },
        s3control=object(),
        repair_table_name=broker.REPAIR_LEDGER_TABLE_NAME,
        deserializer=object(),
        config=cfg,
    )
    evidence.set_budget(broker._InvocationBudget(executor_context(operation)))

    parent_receipt_digest = "sha256:" + ("9" * 64)
    if error_code is not None:
        with pytest.raises(broker.RouteBrokerError) as caught:
            evidence.read_terminal_stack(
                operation=operation,
                expectation=expectation,
                dispatch=dispatch,
                parent_receipt_digest=parent_receipt_digest,
            )
        assert caught.value.code == error_code
        return
    readback = evidence.read_terminal_stack(
        operation=operation,
        expectation=expectation,
        dispatch=dispatch,
        parent_receipt_digest=parent_receipt_digest,
    )
    assert readback["stack_parameters_digest"] == terminal_parameters_digest
    assert readback["stack_terminal_event_time"] == broker._timestamp(NOW)
    assert readback["stack_terminal_event_digest"].startswith("sha256:")
    assert stack_reads == 2
    bounded_readback = dict(readback)
    bounded_readback.pop("readback_digest")
    bounded_readback["read_at"] = "2026-08-30T19:01:00Z"
    bounded_readback = broker.seal(bounded_readback, "readback_digest")
    assert broker._validate_terminal_readback(
        bounded_readback,
        config=cfg,
        operation=operation,
        expectation=expectation,
        dispatch=dispatch,
        parent_receipt_digest=parent_receipt_digest,
    ) == bounded_readback["readback_digest"]


def test_aws_create_recovery_binds_original_event_and_full_readback() -> None:
    operation = "delegation-create-v1"
    cfg0 = config()
    request0 = cfg0.request(operation)
    account = broker.operation_account(operation)
    coordinates0 = {
        "stack_arn": (
            f"arn:aws:cloudformation:{broker.REGION}:{account}:stack/"
            f"{request0['StackName']}/22222222-2222-4222-8222-222222222222"
        ),
        "change_set_arn": (
            f"arn:aws:cloudformation:{broker.REGION}:{account}:changeSet/"
            f"{request0['ChangeSetName']}/11111111-1111-4111-8111-111111111111"
        ),
    }
    event = _recovery_event(
        operation=operation,
        request=request0,
        coordinates=coordinates0,
        event_time="2026-08-30T19:00:00Z",
        event_id="55555555-5555-4555-8555-555555555555",
        request_id="33333333-3333-4333-8333-333333333333",
    )
    cfg, evidence, request, contract, _coordinates, calls = _recovery_aws_fixture(
        operation=operation, events=[event]
    )
    claim = broker._build_attempt_claim(
        config=cfg,
        stage=broker._CREATOR_STAGES[operation],
        kind="CREATE",
        operation=operation,
        function_version="21",
        request=request,
        claimed_at="2026-08-30T18:59:00Z",
        collision_admission_manifest=_attempt_collision_manifest(
            cfg,
            operation=operation,
            effect_request=request,
        ),
    )
    recovered = evidence.recover_create_dispatch(
        operation=operation,
        request=request,
        claim=claim,
        contract=contract,
    )
    dispatch, _digest = broker._validate_create_recovery(
        recovered,
        config=cfg,
        operation=operation,
        request=request,
        claim=claim,
        contract=contract,
    )
    assert dispatch["create_request_id"] == "33333333-3333-4333-8333-333333333333"
    assert [item["method"] for item in calls] == [
        "describe_change_set",
        "get_template",
    ]
def test_aws_execute_recovery_binds_original_event_and_semantic_snapshot() -> None:
    operation = "delegation-execute-v1"
    creator_operation = CREATE_TO_EXECUTE_INV[operation]
    cfg0 = config()
    creator0 = cfg0.request(creator_operation)
    account = broker.operation_account(operation)
    coordinates0 = {
        "stack_arn": (
            f"arn:aws:cloudformation:{broker.REGION}:{account}:stack/"
            f"{creator0['StackName']}/22222222-2222-4222-8222-222222222222"
        ),
        "change_set_arn": (
            f"arn:aws:cloudformation:{broker.REGION}:{account}:changeSet/"
            f"{creator0['ChangeSetName']}/11111111-1111-4111-8111-111111111111"
        ),
    }
    request0 = cfg0.request(operation)
    request0["StackName"] = coordinates0["stack_arn"]
    request0["ChangeSetName"] = coordinates0["change_set_arn"]
    event = _recovery_event(
        operation=operation,
        request=request0,
        coordinates=coordinates0,
        event_time="2026-08-30T19:02:00Z",
        event_id="66666666-6666-4666-8666-666666666666",
        request_id="44444444-4444-4444-8444-444444444444",
    )
    cfg, evidence, creator_request, contract, coordinates, calls = (
        _recovery_aws_fixture(
            operation=operation,
            events=[event],
            execution_status="EXECUTE_IN_PROGRESS",
        )
    )
    request = cfg.request(operation)
    request["StackName"] = coordinates["stack_arn"]
    request["ChangeSetName"] = coordinates["change_set_arn"]
    create_dispatch = {
        "kind": "CREATE",
        "operation": creator_operation,
        "change_set_arn": coordinates["change_set_arn"],
        "stack_arn": coordinates["stack_arn"],
        "create_request_id": "33333333-3333-4333-8333-333333333333",
        "create_request_digest": broker.digest_value(creator_request),
        "dispatched_at": "2026-08-30T19:00:00Z",
    }
    claim = broker._build_attempt_claim(
        config=cfg,
        stage=broker._EXECUTOR_STAGES[operation],
        kind="EXECUTE",
        operation=operation,
        function_version="22",
        request=request,
        claimed_at="2026-08-30T19:01:00Z",
        collision_admission_manifest=_attempt_collision_manifest(
            cfg,
            operation=operation,
            effect_request=request,
        ),
    )
    terminal_parameters_digest = "sha256:" + ("5" * 64)
    recovered = evidence.recover_execute_dispatch(
        operation=operation,
        request=request,
        claim=claim,
        create_dispatch=create_dispatch,
        terminal_parameters_digest=terminal_parameters_digest,
        creator_request=creator_request,
        contract=contract,
    )
    dispatch, _digest = broker._validate_execute_recovery(
        recovered,
        config=cfg,
        operation=operation,
        request=request,
        claim=claim,
        create_dispatch=create_dispatch,
        terminal_parameters_digest=terminal_parameters_digest,
        creator_request=creator_request,
        contract=contract,
    )
    assert dispatch["execute_request_id"] == "44444444-4444-4444-8444-444444444444"
    assert [item["method"] for item in calls] == [
        "describe_change_set",
        "get_template",
    ]
    forged = deepcopy(recovered)
    forged.pop("recovery_digest")
    forged["dispatch"]["terminal_parameters_digest"] = "sha256:" + ("6" * 64)
    forged = broker.seal(forged, "recovery_digest")
    with pytest.raises(broker.RouteBrokerError) as caught:
        broker._validate_execute_recovery(
            forged,
            config=cfg,
            operation=operation,
            request=request,
            claim=claim,
            create_dispatch=create_dispatch,
            terminal_parameters_digest=terminal_parameters_digest,
            creator_request=creator_request,
            contract=contract,
        )
    assert caught.value.code == "EXECUTE_RECOVERY_INVALID"


@pytest.mark.parametrize(
    ("mode", "error", "retryable", "read_calls"),
    [
        ("missing", "CREATE_RECOVERY_PENDING", True, 0),
        ("duplicate", "CREATE_RECOVERY_AMBIGUOUS", False, 0),
        ("foreign_token", "CREATE_RECOVERY_PENDING", True, 0),
        ("foreign_caller", "CREATE_RECOVERY_CLOUDTRAIL_INVALID", False, 0),
        ("foreign_account", "CREATE_RECOVERY_CLOUDTRAIL_INVALID", False, 0),
        ("bad_request_id", "CREATE_RECOVERY_CLOUDTRAIL_INVALID", False, 0),
        ("extra_parameter", "CREATE_RECOVERY_CLOUDTRAIL_INVALID", False, 0),
        ("pre_claim", "CREATE_RECOVERY_CLOUDTRAIL_INVALID", False, 0),
        ("foreign_change_set", "CREATE_RECOVERY_CLOUDTRAIL_INVALID", False, 0),
        ("live_drift", "CHANGE_SET_READBACK_INVALID", False, 1),
    ],
)
def test_aws_create_recovery_rejects_noncausal_or_drifted_evidence_before_cas(
    mode: str, error: str, retryable: bool, read_calls: int
) -> None:
    operation = "delegation-create-v1"
    cfg0 = config()
    request0 = cfg0.request(operation)
    account = broker.operation_account(operation)
    coordinates = {
        "stack_arn": (
            f"arn:aws:cloudformation:{broker.REGION}:{account}:stack/"
            f"{request0['StackName']}/22222222-2222-4222-8222-222222222222"
        ),
        "change_set_arn": (
            f"arn:aws:cloudformation:{broker.REGION}:{account}:changeSet/"
            f"{request0['ChangeSetName']}/11111111-1111-4111-8111-111111111111"
        ),
    }
    event = _recovery_event(
        operation=operation,
        request=request0,
        coordinates=coordinates,
        event_time="2026-08-30T19:00:00Z",
        event_id="55555555-5555-4555-8555-555555555555",
        request_id="33333333-3333-4333-8333-333333333333",
    )
    events = [event]
    response_change: dict[str, Any] = {}
    if mode == "missing":
        events = []
    elif mode == "duplicate":
        events = [event, deepcopy(event)]
    elif mode == "foreign_token":
        events = [
            _mutate_recovery_event(
                event,
                lambda value: value["requestParameters"].update(
                    {"clientToken": "gug376-foreign-client-token-0000000000000000"}
                ),
            )
        ]
    elif mode == "foreign_caller":
        events = [
            _mutate_recovery_event(
                event,
                lambda value: value["userIdentity"].update(
                    {
                        "arn": (
                            f"arn:aws:sts::{account}:assumed-role/"
                            "ForeignRole/session"
                        )
                    }
                ),
            )
        ]
    elif mode == "foreign_account":
        events = [
            _mutate_recovery_event(
                event,
                lambda value: value.update({"recipientAccountId": "111111111111"}),
            )
        ]
    elif mode == "bad_request_id":
        events = [
            _mutate_recovery_event(
                event, lambda value: value.update({"requestID": "not-a-uuid"})
            )
        ]
    elif mode == "extra_parameter":
        events = [
            _mutate_recovery_event(
                event,
                lambda value: value["requestParameters"].update(
                    {"roleARN": "arn:aws:iam::839393571433:role/Foreign"}
                ),
            )
        ]
    elif mode == "pre_claim":
        events = [
            _mutate_recovery_event(
                event,
                lambda value: value.update({"eventTime": "2026-08-30T18:58:59Z"}),
            )
        ]
    elif mode == "foreign_change_set":
        events = [
            _mutate_recovery_event(
                event,
                lambda value: value["responseElements"].update(
                    {
                        "id": (
                            f"arn:aws:cloudformation:{broker.REGION}:{account}:"
                            "changeSet/foreign/11111111-1111-4111-8111-111111111111"
                        )
                    }
                ),
            )
        ]
    elif mode == "live_drift":
        response_change = {"Description": "foreign description"}
    cfg, evidence, request, contract, _coordinates, calls = _recovery_aws_fixture(
        operation=operation,
        events=events,
        response_change=response_change,
    )
    claim = broker._build_attempt_claim(
        config=cfg,
        stage=broker._CREATOR_STAGES[operation],
        kind="CREATE",
        operation=operation,
        function_version="21",
        request=request,
        claimed_at="2026-08-30T18:59:00Z",
        collision_admission_manifest=_attempt_collision_manifest(
            cfg,
            operation=operation,
            effect_request=request,
        ),
    )
    with pytest.raises(broker.RouteBrokerError, match=error) as caught:
        evidence.recover_create_dispatch(
            operation=operation,
            request=request,
            claim=claim,
            contract=contract,
        )
    assert caught.value.retryable_read_only is retryable
    assert len(calls) == read_calls


@pytest.mark.parametrize(
    ("mode", "error", "retryable", "read_calls"),
    [
        ("missing", "EXECUTE_RECOVERY_PENDING", True, 0),
        ("duplicate", "EXECUTE_RECOVERY_AMBIGUOUS", False, 0),
        ("foreign_token", "EXECUTE_RECOVERY_PENDING", True, 0),
        ("foreign_caller", "EXECUTE_RECOVERY_CLOUDTRAIL_INVALID", False, 0),
        ("foreign_account", "EXECUTE_RECOVERY_CLOUDTRAIL_INVALID", False, 0),
        ("bad_request_id", "EXECUTE_RECOVERY_CLOUDTRAIL_INVALID", False, 0),
        ("extra_parameter", "EXECUTE_RECOVERY_CLOUDTRAIL_INVALID", False, 0),
        ("pre_claim", "EXECUTE_RECOVERY_CLOUDTRAIL_INVALID", False, 0),
        ("response_present", "EXECUTE_RECOVERY_CLOUDTRAIL_INVALID", False, 0),
        ("live_drift", "EXECUTE_RECOVERY_READBACK_INVALID", False, 1),
    ],
)
def test_aws_execute_recovery_rejects_noncausal_or_drifted_evidence_before_cas(
    mode: str, error: str, retryable: bool, read_calls: int
) -> None:
    operation = "delegation-execute-v1"
    creator_operation = CREATE_TO_EXECUTE_INV[operation]
    cfg0 = config()
    creator0 = cfg0.request(creator_operation)
    account = broker.operation_account(operation)
    coordinates = {
        "stack_arn": (
            f"arn:aws:cloudformation:{broker.REGION}:{account}:stack/"
            f"{creator0['StackName']}/22222222-2222-4222-8222-222222222222"
        ),
        "change_set_arn": (
            f"arn:aws:cloudformation:{broker.REGION}:{account}:changeSet/"
            f"{creator0['ChangeSetName']}/11111111-1111-4111-8111-111111111111"
        ),
    }
    request0 = cfg0.request(operation)
    request0["StackName"] = coordinates["stack_arn"]
    request0["ChangeSetName"] = coordinates["change_set_arn"]
    event = _recovery_event(
        operation=operation,
        request=request0,
        coordinates=coordinates,
        event_time="2026-08-30T19:02:00Z",
        event_id="66666666-6666-4666-8666-666666666666",
        request_id="44444444-4444-4444-8444-444444444444",
    )
    events = [event]
    response_change: dict[str, Any] = {}
    if mode == "missing":
        events = []
    elif mode == "duplicate":
        events = [event, deepcopy(event)]
    elif mode == "foreign_token":
        events = [
            _mutate_recovery_event(
                event,
                lambda value: value["requestParameters"].update(
                    {"clientRequestToken": "gug376-foreign-token-noncausal"}
                ),
            )
        ]
    elif mode == "foreign_caller":
        events = [
            _mutate_recovery_event(
                event,
                lambda value: value["userIdentity"].update(
                    {
                        "arn": (
                            f"arn:aws:sts::{account}:assumed-role/"
                            "ForeignRole/session"
                        )
                    }
                ),
            )
        ]
    elif mode == "foreign_account":
        events = [
            _mutate_recovery_event(
                event,
                lambda value: value.update({"recipientAccountId": "111111111111"}),
            )
        ]
    elif mode == "bad_request_id":
        events = [
            _mutate_recovery_event(
                event, lambda value: value.update({"requestID": "not-a-uuid"})
            )
        ]
    elif mode == "extra_parameter":
        events = [
            _mutate_recovery_event(
                event,
                lambda value: value["requestParameters"].update(
                    {"disableRollback": True}
                ),
            )
        ]
    elif mode == "pre_claim":
        events = [
            _mutate_recovery_event(
                event,
                lambda value: value.update({"eventTime": "2026-08-30T19:00:59Z"}),
            )
        ]
    elif mode == "response_present":
        events = [
            _mutate_recovery_event(
                event, lambda value: value.update({"responseElements": {}})
            )
        ]
    elif mode == "live_drift":
        response_change = {"Description": "foreign description"}
    cfg, evidence, creator_request, contract, coords, calls = _recovery_aws_fixture(
        operation=operation,
        events=events,
        execution_status="EXECUTE_IN_PROGRESS",
        response_change=response_change,
    )
    request = cfg.request(operation)
    request["StackName"] = coords["stack_arn"]
    request["ChangeSetName"] = coords["change_set_arn"]
    create_dispatch = {
        "kind": "CREATE",
        "operation": creator_operation,
        "change_set_arn": coords["change_set_arn"],
        "stack_arn": coords["stack_arn"],
        "create_request_id": "33333333-3333-4333-8333-333333333333",
        "create_request_digest": broker.digest_value(creator_request),
        "dispatched_at": "2026-08-30T19:00:00Z",
    }
    claim = broker._build_attempt_claim(
        config=cfg,
        stage=broker._EXECUTOR_STAGES[operation],
        kind="EXECUTE",
        operation=operation,
        function_version="22",
        request=request,
        claimed_at="2026-08-30T19:01:00Z",
        collision_admission_manifest=_attempt_collision_manifest(
            cfg,
            operation=operation,
            effect_request=request,
        ),
    )
    with pytest.raises(broker.RouteBrokerError, match=error) as caught:
        evidence.recover_execute_dispatch(
            operation=operation,
            request=request,
            claim=claim,
            create_dispatch=create_dispatch,
            terminal_parameters_digest="sha256:" + ("5" * 64),
            creator_request=creator_request,
            contract=contract,
        )
    assert caught.value.retryable_read_only is retryable
    assert len(calls) == read_calls


def test_no_import_time_aws_dependency_and_config_fits_environment() -> None:
    tree = ast.parse(
        (ROOT / "tooling/platform_authority_plan_permission_repair_route_broker.py").read_text(
            encoding="utf-8"
        )
    )
    imports: list[str] = []
    for node in tree.body:
        if isinstance(node, ast.Import):
            imports.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imports.append(node.module)
    assert "boto3" not in imports
    assert "botocore" not in imports
    envelope = broker.encode_runtime_config(_config_value())
    assert envelope["record_type"] == broker.COMPRESSED_CONFIG_RECORD_TYPE_V3
    assert envelope["encoding"] == "deflate-dict-v3+base85"
    assert len(broker.canonical_json(envelope).encode("utf-8")) <= 3500
    assert broker.decode_runtime_config(envelope) == _config_value()
    assert all(hasattr(broker, name) for name in broker.__all__)
    assert {
        "ATTEMPT_CLAIM_RECORD_TYPE",
        "CREATE_RECOVERY_FUNCTION_NAME",
        "CREATE_RECOVERY_RECORD_TYPE",
        "EXECUTE_RECOVERY_FUNCTION_NAME",
        "EXECUTE_RECOVERY_RECORD_TYPE",
        "RECOVERY_ALIAS",
        "create_dispatch_recovery_handler",
        "execute_dispatch_recovery_handler",
    }.issubset(broker.__all__)


def test_runtime_config_base85_is_canonical_and_bounded() -> None:
    config_value = _config_value()
    envelope = broker.encode_runtime_config(config_value)
    assert envelope["record_type"] == broker.COMPRESSED_CONFIG_RECORD_TYPE_V3
    assert envelope["encoding"] == "deflate-dict-v3+base85"
    assert "@" in envelope["payload"]
    # Python's b85 alphabet deliberately excludes ':'. Raw b85 therefore has
    # no lossy character substitution and is valid inside a JSON string.
    assert ":" not in base64._b85alphabet.decode("ascii")  # noqa: SLF001
    assert broker.decode_runtime_config(envelope) == config_value

    raw = broker.canonical_json(config_value).encode("utf-8")
    alternate = zlib.compressobj(
        level=1,
        method=zlib.DEFLATED,
        wbits=-zlib.MAX_WBITS,
        memLevel=9,
        strategy=zlib.Z_DEFAULT_STRATEGY,
        zdict=broker._RUNTIME_CONFIG_DICTIONARY_V3,
    )
    alternate_payload = alternate.compress(raw) + alternate.flush()
    alternate_envelope = dict(envelope)
    alternate_envelope["payload"] = base64.b85encode(alternate_payload).decode(
        "ascii"
    )
    assert alternate_envelope != envelope
    with pytest.raises(
        broker.RouteBrokerError, match="RUNTIME_CONFIG_ENVELOPE_INVALID"
    ):
        broker.decode_runtime_config(alternate_envelope)

    compressed = base64.b85decode(envelope["payload"])
    trailing = dict(envelope)
    trailing["payload"] = base64.b85encode(compressed + b"trailing").decode(
        "ascii"
    )
    with pytest.raises(
        broker.RouteBrokerError, match="RUNTIME_CONFIG_ENVELOPE_INVALID"
    ):
        broker.decode_runtime_config(trailing)

    bomb = zlib.compressobj(
        level=9,
        method=zlib.DEFLATED,
        wbits=-zlib.MAX_WBITS,
        memLevel=9,
        strategy=zlib.Z_DEFAULT_STRATEGY,
        zdict=broker._RUNTIME_CONFIG_DICTIONARY_V3,
    )
    bomb_payload = bomb.compress(b"x" * 65_537) + bomb.flush()
    bomb_envelope = dict(envelope)
    bomb_envelope["payload"] = base64.b85encode(bomb_payload).decode("ascii")
    with pytest.raises(
        broker.RouteBrokerError, match="RUNTIME_CONFIG_ENVELOPE_INVALID"
    ):
        broker.decode_runtime_config(bomb_envelope)


def test_runtime_config_reads_fixed_v2_golden_without_relabeling() -> None:
    config_value = _config_value()
    legacy_envelope = json.loads(
        (
            ROOT
            / "tests/test_deployment/fixtures/gug376_route_broker/"
            "runtime-config-v2-golden.json"
        ).read_text(encoding="utf-8")
    )
    assert sha256(broker._RUNTIME_CONFIG_DICTIONARY_V2).hexdigest() == (
        "d3b7a22de520d6bb478a7ac60d2603ac"
        "465a3383568e476748b0cdbc1492266a"
    )
    # The fixture is a byte-frozen envelope emitted by committed HEAD before
    # V3 existed.  Do not regenerate it from production constants: decoding
    # this independent blob is the compatibility contract.
    assert sha256(
        broker.canonical_json(legacy_envelope).encode("utf-8")
    ).hexdigest() == (
        "42b1439c589c27e4f49c3f528bbbab35"
        "c085861cfdd84098f0e1c0299b4dd194"
    )
    assert broker._encode_runtime_config_v2(config_value) == legacy_envelope
    assert broker.decode_runtime_config(legacy_envelope) == config_value

    current_envelope = broker.encode_runtime_config(config_value)
    assert current_envelope["record_type"] == (
        broker.COMPRESSED_CONFIG_RECORD_TYPE_V3
    )
    assert current_envelope != legacy_envelope


def test_runtime_config_v3_rejects_malformed_tokens_and_version_pairs() -> None:
    config_value = _config_value()
    envelope = broker.encode_runtime_config(config_value)

    mismatched = dict(envelope)
    mismatched["record_type"] = broker.COMPRESSED_CONFIG_RECORD_TYPE_V2
    with pytest.raises(
        broker.RouteBrokerError, match="RUNTIME_CONFIG_ENVELOPE_INVALID"
    ):
        broker.decode_runtime_config(mismatched)

    packed = broker._pack_runtime_config_v3(  # noqa: SLF001
        json.loads(broker.canonical_json(config_value))
    )
    packed["config_digest"] = ":" + ("0" * 39) + "/"
    malformed_raw = broker.canonical_json(packed).encode("utf-8")
    compressor = zlib.compressobj(
        level=9,
        method=zlib.DEFLATED,
        wbits=-zlib.MAX_WBITS,
        memLevel=9,
        strategy=zlib.Z_DEFAULT_STRATEGY,
        zdict=broker._RUNTIME_CONFIG_DICTIONARY_V3,
    )
    malformed_payload = compressor.compress(malformed_raw) + compressor.flush()
    malformed = dict(envelope)
    malformed["payload"] = base64.b85encode(malformed_payload).decode("ascii")
    with pytest.raises(
        broker.RouteBrokerError, match="RUNTIME_CONFIG_ENVELOPE_INVALID"
    ):
        broker.decode_runtime_config(malformed)

    escaped = {
        "digest": "sha256:" + ("a" * 64),
        "one_colon": ":literal",
        "two_colons": "::literal",
    }
    assert broker._unpack_runtime_config_v3(  # noqa: SLF001
        broker._pack_runtime_config_v3(escaped)  # noqa: SLF001
    ) == escaped


def test_broker_cloudtrail_pagination_reaches_second_page_and_rejects_cycle() -> None:
    class PagedTrail:
        def __init__(self, *, cycle: bool = False) -> None:
            self.cycle = cycle
            self.calls: list[dict[str, Any]] = []

        def lookup_events(self, **request: Any) -> Mapping[str, Any]:
            self.calls.append(request)
            if "NextToken" not in request:
                return {"Events": [], "NextToken": "page-2"}
            if self.cycle:
                return {"Events": [], "NextToken": "page-2"}
            return {"Events": [{"CloudTrailEvent": "{}"}]}

    client = PagedTrail()
    events = broker._lookup_cloudtrail_events(
        client,
        request={"MaxResults": 50},
        error_code="PLAN_CLOUDTRAIL_INCOMPLETE",
    )
    assert events == [{"CloudTrailEvent": "{}"}]
    assert client.calls[1]["NextToken"] == "page-2"
    with pytest.raises(
        broker.RouteBrokerError, match="PLAN_CLOUDTRAIL_INCOMPLETE"
    ):
        broker._lookup_cloudtrail_events(
            PagedTrail(cycle=True),
            request={"MaxResults": 50},
            error_code="PLAN_CLOUDTRAIL_INCOMPLETE",
        )
