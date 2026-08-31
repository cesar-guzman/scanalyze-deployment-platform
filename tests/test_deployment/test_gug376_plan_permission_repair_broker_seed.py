from __future__ import annotations

import base64
import copy
from datetime import datetime, timedelta, timezone
from fnmatch import fnmatchcase
from hashlib import sha256
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
from typing import Any, Mapping
import zipfile

import pytest
import yaml

from tests.test_deployment.test_gug376_temporary_change_set_route import (
    assert_closed_lambda_and_dynamodb_actions,
)
from tests.test_deployment.gug376_foundation_fixtures import (
    build_foundation_contract,
    build_pep_signed_receipt,
)
from tooling import platform_authority_plan_permission_repair_broker_seed as seed
from tooling import platform_authority_plan_permission_repair_broker_config as config_builder
from tooling import platform_authority_plan_permission_repair_route_broker as broker


REPO_ROOT = Path(__file__).resolve().parents[2]
CLI = (
    REPO_ROOT
    / "scripts/deployment/platform-authority-plan-permission-repair-broker-seed.py"
)
PEP_TEMPLATE = REPO_ROOT / "bootstrap/cfn-platform-authority-bootstrap-plan-repair-pep.yaml"
INSTANCE_ARN = "arn:aws:sso:::instance/ssoins-ABCDEFGHIJKLMNOP"
REPAIR_ID = "gug376-plan-permission-repair-" + "1" * 64


class _Loader(yaml.SafeLoader):
    def construct_mapping(
        self, node: yaml.MappingNode, deep: bool = False
    ) -> dict[Any, Any]:
        self.flatten_mapping(node)
        result: dict[Any, Any] = {}
        for key_node, value_node in node.value:
            key = self.construct_object(key_node, deep=deep)
            if key in result:
                raise yaml.constructor.ConstructorError(
                    "while constructing a mapping",
                    node.start_mark,
                    f"found duplicate key {key!r}",
                    key_node.start_mark,
                )
            result[key] = self.construct_object(value_node, deep=deep)
        return result


def _intrinsic(loader: _Loader, suffix: str, node: yaml.Node) -> dict[str, Any]:
    if isinstance(node, yaml.ScalarNode):
        value: Any = loader.construct_scalar(node)
    elif isinstance(node, yaml.SequenceNode):
        value = loader.construct_sequence(node)
    else:
        value = loader.construct_mapping(node)
    return {
        {"Ref": "Ref", "Sub": "Fn::Sub", "GetAtt": "Fn::GetAtt"}.get(
            suffix, f"Fn::{suffix}"
        ): value
    }


_Loader.add_multi_constructor("!", _intrinsic)


def _load(payload: bytes | Path) -> dict[str, Any]:
    text = (
        payload.read_text(encoding="utf-8")
        if isinstance(payload, Path)
        else payload.decode("utf-8")
    )
    loaded = yaml.load(text, Loader=_Loader)
    assert isinstance(loaded, dict)
    return loaded


def _pep_materialization_receipt(
    *, source_commit: str, source: bytes, rendered: bytes,
    protection_enabled: bool,
) -> dict[str, Any]:
    policy = "Retain" if protection_enabled else "Delete"
    value = {
        "record_type": seed.PEP_TEMPLATE_RECEIPT_TYPE,
        "schema_version": 1,
        "source_commit": source_commit,
        "source_path": seed.PEP_SOURCE_TEMPLATE_PATH.as_posix(),
        "source_sha256": "sha256:" + sha256(source).hexdigest(),
        "template_variant": "protection" if protection_enabled else "create",
        "output_name": (
            seed.PEP_PROTECTION_OUTPUT_NAME
            if protection_enabled
            else seed.PEP_OUTPUT_NAME
        ),
        "template_sha256": "sha256:" + sha256(rendered).hexdigest(),
        "template_bytes": len(rendered),
        "ledger_deletion_protection_enabled": protection_enabled,
        "lifecycle_deletion_policy": policy,
        "lifecycle_update_replace_policy": policy,
        "lifecycle_resource_ids": list(seed.PEP_LIFECYCLE_RESOURCE_IDS),
        "variant_controls_parameterless": True,
        "private_mode": "0600",
        "aws_calls": 0,
        "aws_mutations": 0,
        "deployment_authorized": False,
        "production_status": seed.PRODUCTION_STATUS,
    }
    value["receipt_digest"] = seed.digest_value(value)
    return value


def test_pep_template_lifecycle_variants_are_closed_and_distinct() -> None:
    source = PEP_TEMPLATE.read_bytes()
    create = seed.render_pep_template_from_source(
        source=source, protection_enabled=False
    )
    protection = seed.render_pep_template_from_source(
        source=source, protection_enabled=True
    )
    assert create != protection
    assert sha256(create).digest() != sha256(protection).digest()
    for payload, enabled, policy in (
        (create, False, "Delete"),
        (protection, True, "Retain"),
    ):
        template = _load(payload)
        assert "LedgerDeletionProtectionEnabled" not in template["Parameters"]
        assert "Conditions" not in template
        assert template["Resources"]["RepairLedger"]["Properties"][
            "DeletionProtectionEnabled"
        ] is enabled
        assert template["Outputs"]["LedgerDeletionProtectionMode"]["Value"] == (
            "true" if enabled else "false"
        )
        lifecycle = sorted(
            logical_id
            for logical_id, resource in template["Resources"].items()
            if "DeletionPolicy" in resource or "UpdateReplacePolicy" in resource
        )
        assert lifecycle == list(seed.PEP_LIFECYCLE_RESOURCE_IDS)
        assert all(
            template["Resources"][logical_id]["DeletionPolicy"] == policy
            and template["Resources"][logical_id]["UpdateReplacePolicy"] == policy
            for logical_id in lifecycle
        )


def test_pep_template_receipts_reject_variant_swap_and_digest_drift() -> None:
    source = PEP_TEMPLATE.read_bytes()
    create = seed.render_pep_template_from_source(
        source=source, protection_enabled=False
    )
    receipt = _pep_materialization_receipt(
        source_commit="a" * 40,
        source=source,
        rendered=create,
        protection_enabled=False,
    )
    assert seed.validate_pep_template_materialization_receipt(
        receipt, expected_protection_enabled=False
    ) == receipt
    with pytest.raises(seed.BrokerSeedError, match="PEP_TEMPLATE_MATERIALIZATION"):
        seed.validate_pep_template_materialization_receipt(
            receipt, expected_protection_enabled=True
        )
    drift = copy.deepcopy(receipt)
    drift["template_sha256"] = "sha256:" + "f" * 64
    with pytest.raises(seed.BrokerSeedError, match="PEP_TEMPLATE_MATERIALIZATION"):
        seed.validate_pep_template_materialization_receipt(
            drift, expected_protection_enabled=False
        )


def _resolve_policy_intrinsics(value: Any) -> Any:
    """Project the rendered policy shape that IAM actually counts."""

    if isinstance(value, list):
        return [_resolve_policy_intrinsics(item) for item in value]
    if not isinstance(value, dict):
        return value
    if set(value) == {"Fn::Sub"} and isinstance(value["Fn::Sub"], str):
        return value["Fn::Sub"].replace("${AWS::Partition}", "aws")
    return {key: _resolve_policy_intrinsics(item) for key, item in value.items()}


def _git(root: Path, *args: str) -> str:
    completed = subprocess.run(
        ["git", *args],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
        shell=False,
    )
    return completed.stdout.strip()


def _package_bytes(root: Path) -> bytes:
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_STORED) as archive:
        for relative in seed.PACKAGE_SOURCE_PATHS:
            info = zipfile.ZipInfo(relative.as_posix())
            info.date_time = (1980, 1, 1, 0, 0, 0)
            info.create_system = 3
            info.compress_type = zipfile.ZIP_STORED
            info.external_attr = (stat.S_IFREG | 0o644) << 16
            archive.writestr(info, (root / relative).read_bytes())
    return output.getvalue()


def _sealed_config(
    source_commit: str,
    foundation_publish_binding_digest: str,
    artifact_bucket: str,
    signing_profile_version_arn: str,
    pep_signed_artifact_receipt: Mapping[str, Any],
    *,
    route_not_before: str,
    route_not_after: str,
    recovery_not_after: str,
) -> dict[str, Any]:
    create_to_execute = {
        "seed-revoke-create-v1": "seed-revoke-execute-v1",
        "delegation-create-v1": "delegation-execute-v1",
        "pep-create-v1": "pep-execute-v1",
        "pep-protection-create-v1": "pep-protection-execute-v1",
        "delegation-revoke-create-v1": "delegation-revoke-execute-v1",
        "route-revoke-create-v1": "route-revoke-execute-v1",
    }
    stacks = {
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
    requests: dict[str, dict[str, Any]] = {}
    creator_contracts: dict[str, dict[str, Any]] = {}
    expectations: dict[str, dict[str, Any]] = {}
    change_set_names = {
        "seed-revoke-create-v1": "gug376-temporary-route-seed-revoke",
        "delegation-create-v1": "gug376-plan-repair-delegation-create",
        "pep-create-v1": "gug376-plan-repair-pep-create",
        "pep-protection-create-v1": "gug376-plan-repair-pep-protection-enable",
        "delegation-revoke-create-v1": "gug376-plan-repair-delegation-revoke",
        "route-revoke-create-v1": "gug376-temporary-route-invoker-revoke",
    }
    for index, (creator, executor) in enumerate(create_to_execute.items(), start=1):
        account, stack = stacks[executor]
        stem = creator.removesuffix("-create-v1")
        template_name = {
            "seed-revoke-create-v1": (
                "cfn-platform-authority-gug376-temporary-change-set-route.yaml"
            ),
            "route-revoke-create-v1": (
                "cfn-platform-authority-gug376-temporary-change-set-route.yaml"
            ),
            "delegation-create-v1": (
                "cfn-platform-authority-bootstrap-plan-repair-delegation.yaml"
            ),
            "delegation-revoke-create-v1": (
                "cfn-platform-authority-bootstrap-plan-repair-delegation.yaml"
            ),
            "pep-create-v1": (
                "cfn-platform-authority-bootstrap-plan-repair-pep.yaml"
            ),
            "pep-protection-create-v1": (
                "cfn-platform-authority-bootstrap-plan-repair-pep-protection.yaml"
            ),
        }[creator]
        template_version = {
            "pep-create-v1": "pep-template-version-1",
            "pep-protection-create-v1": "pep-protection-template-version-1",
        }.get(creator, "synthetic-version-1")
        parameters: list[dict[str, str]] = []
        if creator in {"pep-create-v1", "pep-protection-create-v1"}:
            pep_signed = pep_signed_artifact_receipt["signed_artifact"]
            pep_values = {
                "AuthorityAccountId": broker.AUTHORITY_ACCOUNT_ID,
                "ManagementAccountId": broker.MANAGEMENT_ACCOUNT_ID,
                "SourceCommit": source_commit,
                "SourceBundleDigest": pep_signed_artifact_receipt[
                    "source_bundle_digest"
                ],
                "RepairId": REPAIR_ID,
                "PrincipalId": "12345678-1234-4123-8123-123456789012",
                "IdentityStoreId": "d-1234567890",
                "IdentityCenterInstanceArn": INSTANCE_ARN,
                "PlanPermissionSetArn": (
                    "arn:aws:sso:::permissionSet/ssoins-1234567890abcdef/"
                    "ps-1111111111111111"
                ),
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
                "ArtifactBucket": pep_signed["bucket"],
                "ArtifactKey": pep_signed["key"],
                "ArtifactVersion": pep_signed["version"],
                "ArtifactCodeSha256": pep_signed["lambda_code_sha256"],
                "SigningProfileVersionArn": signing_profile_version_arn,
                "ImmutableConfigurationDigest": "sha256:" + "8" * 64,
            }
            if creator == "pep-create-v1":
                parameters = [
                    {"ParameterKey": key, "ParameterValue": value}
                    for key, value in pep_values.items()
                ]
            else:
                parameters = [
                    (
                        {"ParameterKey": key, "UsePreviousValue": True}
                    )
                    for key in pep_values
                ]
        requests[creator] = {
            "StackName": stack,
            "ChangeSetName": change_set_names[creator],
            "ClientToken": "gug376-" + broker.digest_value(creator)[7:55],
            "ChangeSetType": "CREATE" if stem in {"delegation", "pep"} else "UPDATE",
            "Description": "GUG-376 attested route broker operation",
            "Parameters": parameters,
            "Capabilities": ["CAPABILITY_NAMED_IAM"],
            "Tags": [
                {"Key": "managed_by", "Value": "cloudformation"},
                {"Key": "service", "Value": "scanalyze-platform-authority"},
                {"Key": "work_package", "Value": "GUG-376"},
            ],
            "IncludeNestedStacks": False,
            "ResourcesToImport": [],
            "NotificationARNs": [],
            "RollbackConfiguration": {
                "RollbackTriggers": [],
                "MonitoringTimeInMinutes": 0,
            },
            "TemplateURL": (
                f"https://{artifact_bucket}.s3.us-east-1.amazonaws.com/"
                "scanalyze/platform-authority/gug-376/plan-policy-repair/templates/"
                f"{source_commit}/{template_name}?versionId={template_version}"
            ),
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
        logical_id = "Change" + "".join(part.title() for part in creator.split("-"))
        creator_contracts[creator] = {
            "template_digest": template_digest,
            "expected_changes": (
                config_builder._pep_protection_changes(  # noqa: SLF001
                    {
                        "PlanLogGroup": "AWS::Logs::LogGroup",
                        "ReconcileLogGroup": "AWS::Logs::LogGroup",
                        "RepairLedger": "AWS::DynamoDB::Table",
                        "RepairLedgerKey": "AWS::KMS::Key",
                        "RepairLedgerKeyAlias": "AWS::KMS::Alias",
                        "RepairLogGroup": "AWS::Logs::LogGroup",
                    }
                )
                if creator == "pep-protection-create-v1"
                else [
                {
                    "action": "Remove" if "revoke" in creator else "Add",
                    "logical_resource_id": logical_id,
                    "resource_type": "AWS::CloudFormation::Stack",
                    "replacement": None,
                    "scope": [],
                    "details": [],
                }
                ]
            ),
        }
        if executor == "seed-revoke-execute-v1":
            static_outputs = {
                "BrokerInvokerAssignmentMode": "true",
                "ProductionAuthorized": "false",
                "SeedAssignmentMode": "false",
            }
            dynamic_outputs = [
                "BrokerInvokerPermissionSetArn",
                "BrokerSeedCreatorPermissionSetArn",
                "BrokerSeedExecutorPermissionSetArn",
            ]
        elif executor == "route-revoke-execute-v1":
            static_outputs = {
                "BrokerInvokerAssignmentMode": "false",
                "ProductionAuthorized": "false",
                "SeedAssignmentMode": "false",
            }
            dynamic_outputs = [
                "BrokerInvokerPermissionSetArn",
                "BrokerSeedCreatorPermissionSetArn",
                "BrokerSeedExecutorPermissionSetArn",
            ]
        elif executor == "delegation-execute-v1":
            static_outputs = {
                "ProductionAuthorized": "false",
                "RepairInvokerAssignmentMode": "true",
            }
            dynamic_outputs = ["RepairInvokerPermissionSetArn"]
        elif executor == "delegation-revoke-execute-v1":
            static_outputs = {
                "ProductionAuthorized": "false",
                "RepairInvokerAssignmentMode": "false",
            }
            dynamic_outputs = ["RepairInvokerPermissionSetArn"]
        elif executor == "pep-execute-v1":
            static_outputs = {
                "LedgerDeletionProtectionMode": "false",
                "ProductionAuthorized": "false",
            }
            dynamic_outputs = []
        elif executor == "pep-protection-execute-v1":
            static_outputs = {
                "LedgerDeletionProtectionMode": "true",
                "ProductionAuthorized": "false",
            }
            dynamic_outputs = []
        else:
            static_outputs = {"ProductionAuthorized": "false"}
            dynamic_outputs = []
        expectations[executor] = {
            "account_id": account,
            "stack_name": stack,
            "terminal_statuses": (
                ["UPDATE_COMPLETE"]
                if "revoke" in executor or executor == "pep-protection-execute-v1"
                else ["CREATE_COMPLETE"]
            ),
            "template_digest": template_digest,
            "expected_resources": [
                {
                    "logical_resource_id": "SyntheticResource",
                    "resource_type": "AWS::CloudFormation::Stack",
                }
            ],
            "expected_output_keys": sorted([*static_outputs, *dynamic_outputs]),
            "expected_static_outputs": static_outputs,
            "expected_tags": [],
        }
    output_contracts = {
        "route": {
            "account_id": broker.MANAGEMENT_ACCOUNT_ID,
            "stack_name": stacks["seed-revoke-execute-v1"][1],
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
            "stack_name": stacks["delegation-execute-v1"][1],
            "permission_set_output_keys": ["RepairInvokerPermissionSetArn"],
            "required_mode_outputs": {"RepairInvokerAssignmentMode": "true"},
        },
    }
    scopes = {
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
    ledger_id = seed.BROKER_LEDGER_ID
    binding = "sha256:" + "2" * 64
    initialization = broker.digest_value(
        {
            "record_type": broker.LEDGER_RECORD_TYPE,
            "ledger_id": ledger_id,
            "source_commit": source_commit,
            "binding_digest": binding,
            "initial_state": "READY",
            "initial_version": 0,
            "retry_permitted": False,
        }
    )
    value = {
        "schema_version": 1,
        "record_type": broker.CONFIG_RECORD_TYPE,
        "source_commit": source_commit,
        "ledger_id": ledger_id,
        "ledger_binding_digest": binding,
        "initialization_digest": initialization,
        "foundation_publish_binding_digest": foundation_publish_binding_digest,
        "repair_id": REPAIR_ID,
        "bootstrap_change_set_name": (
            "scanalyze-platform-authority-bootstrap-20260830180000"
        ),
        "identity_center_instance_arn": INSTANCE_ARN,
        "bootstrap_principal_id": "12345678-1234-4123-8123-123456789012",
        "route_not_before": route_not_before,
        "route_not_after": route_not_after,
        "recovery_not_after": recovery_not_after,
        "normal_plan_generated_role_arn": (
            "arn:aws:iam::042360977644:role/aws-reserved/"
            "sso.amazonaws.com/"
            "AWSReservedSSO_ScanalyzeAuthorityBootstrapPlan_"
            "0123456789ABCDEF"
        ),
        "normal_plan_generated_role_name": (
            "AWSReservedSSO_ScanalyzeAuthorityBootstrapPlan_"
            "0123456789ABCDEF"
        ),
        "requests": requests,
        "creator_contracts": creator_contracts,
        "permission_set_output_contracts": output_contracts,
        "terminal_expectations": expectations,
        "revocation_assignment_scopes": scopes,
        "retry_permitted": False,
        "production_authorized": False,
        "production_status": "NO-GO",
    }
    return broker.seal(value, "config_digest")


def _input(source_root: Path, source_commit: str) -> dict[str, Any]:
    package = _package_bytes(source_root)
    signed_package = b"synthetic-attested-signer-output-for-tests"
    observed = datetime.now(timezone.utc).replace(microsecond=0)
    route_not_before = observed + timedelta(minutes=70)
    route_not_after = observed + timedelta(minutes=145)
    recovery_not_after = route_not_after + timedelta(hours=24)
    route_not_before_text = route_not_before.isoformat().replace("+00:00", "Z")
    route_not_after_text = route_not_after.isoformat().replace("+00:00", "Z")
    recovery_not_after_text = recovery_not_after.isoformat().replace(
        "+00:00", "Z"
    )
    foundation_contract = build_foundation_contract(
        source_commit=source_commit, observed_at=observed
    )
    bootstrap_intent = foundation_contract["bootstrap_intent"]
    storage_binding = foundation_contract["foundation_publish_binding"]
    pep_receipt = build_pep_signed_receipt(
        source_commit=source_commit,
        observed_at=observed,
        bootstrap_intent=bootstrap_intent,
        foundation_publish_binding=storage_binding,
    )
    profile_arn = storage_binding["signing_profile_version_arn"]
    job_id = "12345678-1234-1234-1234-1234567890ab"
    template_bucket = storage_binding["bucket"]
    template_key = (
        "scanalyze/platform-authority/gug-376/plan-policy-repair/templates/"
        f"{source_commit}/cfn-platform-authority-bootstrap-plan-repair-pep.yaml"
    )
    template_version = "pep-template-version-1"
    protection_template_key = (
        "scanalyze/platform-authority/gug-376/plan-policy-repair/templates/"
        f"{source_commit}/"
        "cfn-platform-authority-bootstrap-plan-repair-pep-protection.yaml"
    )
    protection_template_version = "pep-protection-template-version-1"
    result = {
        "record_type": seed.RECORD_TYPE,
        "source_commit": source_commit,
        "management_account_id": seed.MANAGEMENT_ACCOUNT_ID,
        "authority_account_id": seed.AUTHORITY_ACCOUNT_ID,
        "region": seed.REGION,
        "route_not_before": route_not_before_text,
        "route_not_after": route_not_after_text,
        "repair_id": REPAIR_ID,
        "artifact_bootstrap_intent": bootstrap_intent,
        "foundation_publish_binding": storage_binding,
        "foundation_publish_binding_digest": storage_binding["binding_digest"],
        "source_template": {
            "path": seed.SOURCE_TEMPLATE_PATH.as_posix(),
            "sha256": "sha256:"
            + sha256((source_root / seed.SOURCE_TEMPLATE_PATH).read_bytes()).hexdigest(),
        },
        "broker_code": {},
        "pep_template": {
            "bucket": template_bucket,
            "key": template_key,
            "version": template_version,
            "url": (
                f"https://{template_bucket}.s3.us-east-1.amazonaws.com/"
                f"{template_key}?versionId={template_version}"
            ),
        },
        "pep_protection_template": {
            "bucket": template_bucket,
            "key": protection_template_key,
            "version": protection_template_version,
            "url": (
                f"https://{template_bucket}.s3.us-east-1.amazonaws.com/"
                f"{protection_template_key}?versionId={protection_template_version}"
            ),
        },
        "pep_artifact": {
            "bucket": pep_receipt["signed_artifact"]["bucket"],
            "key": pep_receipt["signed_artifact"]["key"],
            "version": pep_receipt["signed_artifact"]["version"],
        },
        "pep_runtime_binding": {},
        "broker_config": _sealed_config(
            source_commit,
            storage_binding["binding_digest"],
            template_bucket,
            profile_arn,
            pep_receipt,
            route_not_before=route_not_before_text,
            route_not_after=route_not_after_text,
            recovery_not_after=recovery_not_after_text,
        ),
    }
    job_arn = f"arn:aws:signer:us-east-1:042360977644:/signing-jobs/{job_id}"
    kms_key_arn = storage_binding["sse_kms_key_arn"]
    broker_code = {
        "schema_version": 1,
        "record_type": seed.BROKER_SIGNING_RECEIPT_TYPE,
        "source_commit": source_commit,
        "verifier": {
            "account_id": seed.AUTHORITY_ACCOUNT_ID,
            "caller_arn": (
                "arn:aws:sts::042360977644:assumed-role/"
                "AWSReservedSSO_ScanalyzeGug376ArtifactBootstrap_"
                "0123456789ABCDEF/cesar"
            ),
            "profile": (
                "042360977644_ScanalyzeGug376ArtifactBootstrap"
            ),
            "region": "us-east-1",
        },
        "unsigned_artifact": {
            "bucket": template_bucket,
            "key": (
                "scanalyze/platform-authority/gug-376/plan-policy-repair/"
                f"broker/unsigned/{source_commit}/route-broker-unsigned.zip"
            ),
            "version": "broker-unsigned-version-1",
            "sha256": "sha256:" + sha256(package).hexdigest(),
            "code_sha256": base64.b64encode(sha256(package).digest()).decode(
                "ascii"
            ),
            "bytes": len(package),
            "sse_algorithm": "aws:kms",
            "sse_kms_key_arn": kms_key_arn,
        },
        "signing_job": {
            "job_id": job_id,
            "job_owner": seed.AUTHORITY_ACCOUNT_ID,
            "job_invoker": seed.AUTHORITY_ACCOUNT_ID,
            "status": "Succeeded",
            "platform_id": "AWSLambda-SHA384-ECDSA",
            "profile_version_arn": profile_arn,
            "certificate_arn": (
                "arn:aws:acm:us-east-1:042360977644:certificate/"
                "00000000-0000-4000-8000-000000000002"
            ),
            "created_at": (observed - timedelta(minutes=5)).isoformat().replace(
                "+00:00", "Z"
            ),
            "completed_at": (observed - timedelta(minutes=2)).isoformat().replace(
                "+00:00", "Z"
            ),
            "signature_expires_at": (observed + timedelta(days=7)).isoformat().replace(
                "+00:00", "Z"
            ),
            "profile_status": "Active",
            "job_revocation_record_absent": True,
            "profile_revocation_record_absent": True,
        },
        "signed_artifact": {
            "bucket": template_bucket,
            "key": (
                "scanalyze/platform-authority/gug-376/plan-policy-repair/"
                f"broker/signed/{source_commit}/{job_id}.zip"
            ),
            "version": "broker-signed-version-1",
            "sha256": "sha256:" + sha256(signed_package).hexdigest(),
            "code_sha256": base64.b64encode(
                sha256(signed_package).digest()
            ).decode("ascii"),
            "bytes": len(signed_package),
            "sse_algorithm": "aws:kms",
            "sse_kms_key_arn": kms_key_arn,
        },
        "upstream_storage_binding": storage_binding,
        "revocation_check": {
            "status": "PROFILE_JOB_AND_CERTIFICATE_NOT_REVOKED",
            "checked_at": observed.isoformat().replace("+00:00", "Z"),
            "profile_version_arn_digest": seed.digest_value(profile_arn),
            "job_arn_digest": seed.digest_value(job_arn),
            "certificate_hash_digest": "sha256:" + "a" * 64,
            "source_marker": (
                "DESCRIBE_SIGNING_JOB_GET_SIGNING_PROFILE_ACM_CERTIFICATE_"
                "AND_SIGNER_DATA_REVOCATION"
            ),
        },
        "observed_at": observed.isoformat().replace("+00:00", "Z"),
        "source_marker": (
            "AWS_STS_S3_SIGNER_ACM_REVOCATION_AND_VERSIONED_OBJECT_READBACK"
        ),
        "aws_calls": 11,
        "aws_mutations": 0,
    }
    broker_code["receipt_digest"] = seed.digest_value(broker_code)
    result["broker_code"] = broker_code
    runtime_binding = {
        "schema_version": 1,
        "record_type": seed.PEP_RUNTIME_BINDING_TYPE,
        "source_commit": source_commit,
        "expected_boto3_version": "1.42.57",
        "expected_botocore_version": "1.42.97",
        "pep_signed_artifact_receipt_digest": pep_receipt["receipt_digest"],
        "pep_runtime_readback_digest": "sha256:" + "6" * 64,
        "upstream_storage_binding_digest": storage_binding[
            "binding_digest"
        ],
        "source_marker": (
            "VALIDATED_GUG376_PEP_SIGNED_ARTIFACT_RUNTIME_EVIDENCE"
        ),
    }
    runtime_binding["binding_digest"] = seed.digest_value(runtime_binding)
    result["pep_runtime_binding"] = runtime_binding
    return result


@pytest.fixture
def source_repo(tmp_path: Path) -> tuple[Path, str, dict[str, Any]]:
    root = tmp_path / "source"
    root.mkdir()
    paths = (seed.SOURCE_TEMPLATE_PATH, *seed.PACKAGE_SOURCE_PATHS)
    for relative in paths:
        target = root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes((REPO_ROOT / relative).read_bytes())
    _git(root, "init", "-b", "main")
    _git(root, "config", "user.name", "GUG-376 test")
    _git(root, "config", "user.email", "gug376@example.invalid")
    _git(root, "add", "--", *(path.as_posix() for path in paths))
    _git(root, "commit", "-m", "fixture: broker seed sources")
    source_commit = _git(root, "rev-parse", "HEAD")
    return root, source_commit, _input(root, source_commit)


def _private_root(tmp_path: Path, name: str = "private") -> Path:
    root = tmp_path / name
    root.mkdir(mode=0o700)
    root.chmod(0o700)
    return root


def test_render_is_source_bound_parameter_closed_and_runtime_decodable(
    source_repo: tuple[Path, str, dict[str, Any]],
) -> None:
    root, source_commit, value = source_repo
    first = seed.render_template(
        source_root=root, private_input=value, protection_enabled=False
    )
    second = seed.render_template(
        source_root=root, private_input=value, protection_enabled=False
    )
    protected = seed.render_template(
        source_root=root, private_input=value, protection_enabled=True
    )
    assert first == second
    assert first != protected
    # Raw base85 may legitimately contain '@@'; only reviewed placeholder
    # tokens are forbidden after rendering.
    assert seed._PLACEHOLDER_RE.search(first) is None  # noqa: SLF001
    rendered = _load(first)
    protected_rendered = _load(protected)
    assert "Parameters" not in rendered
    assert "Parameters" not in protected_rendered
    assert rendered["Resources"]["BrokerLedger"]["Properties"][
        "DeletionProtectionEnabled"
    ] is False
    assert protected_rendered["Resources"]["BrokerLedger"]["Properties"][
        "DeletionProtectionEnabled"
    ] is True
    assert rendered["Outputs"]["BrokerLedgerDeletionProtectionMode"][
        "Value"
    ] == "false"
    assert protected_rendered["Outputs"][
        "BrokerLedgerDeletionProtectionMode"
    ]["Value"] == "true"
    assert rendered["Outputs"]["ParametersAccepted"]["Value"] == "false"
    for logical_id in (
        "BrokerLedgerKey",
        "BrokerLedger",
        "CreatorLogGroup",
        "ExecutorLogGroup",
        "CreatorVersion",
        "ExecutorVersion",
    ):
        assert rendered["Resources"][logical_id]["DeletionPolicy"] == "Delete"
        assert rendered["Resources"][logical_id][
            "UpdateReplacePolicy"
        ] == "Delete"
        assert protected_rendered["Resources"][logical_id][
            "DeletionPolicy"
        ] == "Retain"
        assert protected_rendered["Resources"][logical_id][
            "UpdateReplacePolicy"
        ] == "Retain"
    assert rendered["Rules"]["ExactAuthorityAccountAndRegion"]
    creator = rendered["Resources"]["CreatorFunction"]["Properties"]
    executor = rendered["Resources"]["ExecutorFunction"]["Properties"]
    for function in (creator, executor):
        assert function["Runtime"] == "python3.12"
        assert function["ReservedConcurrentExecutions"] == 1
        assert function["CodeSigningConfigArn"] == {
            "Ref": "BrokerCodeSigningConfig"
        }
        assert function["Code"]["S3ObjectVersion"] == (
            value["broker_code"]["signed_artifact"]["version"]
        )
    envelope = json.loads(
        creator["Environment"]["Variables"]["BROKER_CONFIG_JSON"]
    )
    decoded = broker.decode_runtime_config(envelope)
    parsed = broker.BrokerConfig.from_mapping(decoded)
    assert parsed.source_commit == source_commit
    assert parsed.repair_id == REPAIR_ID
    assert parsed.ledger_id == seed.BROKER_LEDGER_ID
    assert parsed.config_digest == value["broker_config"]["config_digest"]
    assert broker._timestamp(parsed.recovery_not_after) == value["broker_config"][
        "recovery_not_after"
    ]


def test_connected_receipt_admission_requires_explicit_current_time(
    source_repo: tuple[Path, str, dict[str, Any]],
) -> None:
    _root, source_commit, value = source_repo
    with pytest.raises(
        seed.BrokerSeedError,
        match="BROKER_SIGNING_ADMISSION_TIME_REQUIRED",
    ):
        seed.validate_broker_signing_receipt(
            value["broker_code"],
            source_commit=source_commit,
            bootstrap_intent=value["artifact_bootstrap_intent"],
            foundation_publish_binding=value["foundation_publish_binding"],
        )


def test_archival_receipt_rejects_self_sealed_time_outside_causal_window(
    source_repo: tuple[Path, str, dict[str, Any]],
) -> None:
    _root, _source_commit, value = source_repo
    changed = copy.deepcopy(value)
    receipt = changed["broker_code"]
    access_start = datetime.fromisoformat(
        changed["artifact_bootstrap_intent"]["access_not_before"].replace(
            "Z", "+00:00"
        )
    )
    replayed_at = access_start - timedelta(seconds=1)
    receipt["signing_job"]["created_at"] = (
        replayed_at - timedelta(minutes=5)
    ).isoformat().replace("+00:00", "Z")
    receipt["signing_job"]["completed_at"] = (
        replayed_at - timedelta(minutes=2)
    ).isoformat().replace("+00:00", "Z")
    receipt["observed_at"] = replayed_at.isoformat().replace("+00:00", "Z")
    receipt["revocation_check"]["checked_at"] = receipt["observed_at"]
    receipt["receipt_digest"] = seed.digest_value(
        {key: item for key, item in receipt.items() if key != "receipt_digest"}
    )

    with pytest.raises(
        seed.BrokerSeedError,
        match="BROKER_SIGNING_CAUSAL_TIME_INVALID",
    ):
        seed.validate_input(changed)


def test_archival_receipt_rejects_replay_beyond_sealed_route_horizon(
    source_repo: tuple[Path, str, dict[str, Any]],
) -> None:
    _root, _source_commit, value = source_repo
    changed = copy.deepcopy(value)
    receipt = changed["broker_code"]
    receipt["signing_job"]["signature_expires_at"] = changed["route_not_after"]
    receipt["receipt_digest"] = seed.digest_value(
        {key: item for key, item in receipt.items() if key != "receipt_digest"}
    )

    with pytest.raises(
        seed.BrokerSeedError,
        match="BROKER_SIGNING_CAUSAL_TIME_INVALID",
    ):
        seed.validate_input(changed)


def test_pure_source_renderer_is_byte_identical_and_performs_no_source_io(
    source_repo: tuple[Path, str, dict[str, Any]], monkeypatch: pytest.MonkeyPatch
) -> None:
    root, _commit, value = source_repo
    source = (root / seed.SOURCE_TEMPLATE_PATH).read_bytes()
    expected = seed.render_template(source_root=root, private_input=value)

    def forbidden(*_args: Any, **_kwargs: Any) -> Any:
        raise AssertionError("pure renderer performed source/package I/O")

    monkeypatch.setattr(seed, "_source_bytes", forbidden)
    monkeypatch.setattr(seed, "build_broker_package", forbidden)
    assert (
        seed.render_template_from_source(source=source, private_input=value)
        == expected
    )


def test_pure_source_renderer_rejects_unreviewed_source_bytes(
    source_repo: tuple[Path, str, dict[str, Any]],
) -> None:
    root, _commit, value = source_repo
    source = (root / seed.SOURCE_TEMPLATE_PATH).read_bytes()
    with pytest.raises(seed.BrokerSeedError, match="SOURCE_TEMPLATE_DIGEST_MISMATCH"):
        seed.render_template_from_source(
            source=source + b"\n# drift\n", private_input=value
        )


def test_policy_projection_is_semantic_order_stable_and_resolves_partition() -> None:
    first = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "Z",
                "Effect": "Allow",
                "Principal": {
                    "AWS": {
                        "Fn::Sub": "arn:${AWS::Partition}:iam::042360977644:root"
                    }
                },
                "Action": "kms:DescribeKey",
                "Resource": "*",
                "Condition": {
                    "StringEquals": {"aws:RequestedRegion": "us-east-1"}
                },
            },
            {
                "Sid": "A",
                "Effect": "Deny",
                "Action": ["kms:ScheduleKeyDeletion", "kms:DisableKey"],
                "Resource": ["*"],
            },
        ],
    }
    second = copy.deepcopy(first)
    second["Statement"].reverse()
    second["Statement"][0]["Action"].reverse()
    second["Statement"][1]["Action"] = ["kms:DescribeKey"]
    second["Statement"][1]["Principal"]["AWS"] = [
        "arn:aws:iam::042360977644:root"
    ]
    second["Statement"][1]["Condition"]["StringEquals"][
        "aws:RequestedRegion"
    ] = ["us-east-1"]
    projected = seed.canonicalize_policy_document(first)
    assert seed.canonicalize_policy_document(second) == projected
    assert projected["Statement"][1]["Principal"]["AWS"] == [
        "arn:aws:iam::042360977644:root"
    ]


def test_rendered_seed_iam_actions_match_frozen_service_authorization_reference(
    source_repo: tuple[Path, str, dict[str, Any]],
) -> None:
    root, _commit, value = source_repo
    rendered = _load(seed.render_template(source_root=root, private_input=value))
    recovery_not_after = value["broker_config"]["recovery_not_after"]
    assert_closed_lambda_and_dynamodb_actions(rendered)
    raw = (REPO_ROOT / seed.SOURCE_TEMPLATE_PATH).read_text(encoding="utf-8")
    assert "dynamodb:TransactWriteItems" not in raw
    assert "lambda:DeleteRuntimeManagementConfig" not in raw


def test_rendered_broker_roles_have_exact_artifact_kms_identity_authority(
    source_repo: tuple[Path, str, dict[str, Any]],
) -> None:
    root, _commit, value = source_repo
    rendered = _load(seed.render_template(source_root=root, private_input=value))
    expected_key = value["foundation_publish_binding"]["sse_kms_key_arn"]
    expected = {
        "CreatorRole": (
            "DecryptExactPepInitialTemplateKeyThroughS3",
            value["pep_template"]["bucket"],
        ),
        "ExecutorRole": (
            "DecryptExactPepArtifactKeyThroughS3",
            value["pep_artifact"]["bucket"],
        ),
    }
    for logical_id, (sid, bucket) in expected.items():
        statements = rendered["Resources"][logical_id]["Properties"]["Policies"][
            0
        ]["PolicyDocument"]["Statement"]
        by_sid = {item["Sid"]: item for item in statements}
        decrypt = by_sid[sid]
        assert decrypt["Effect"] == "Allow"
        assert decrypt["Action"] == "kms:Decrypt"
        assert decrypt["Resource"] == expected_key
        assert decrypt["Condition"]["StringEquals"] == {
            "aws:RequestedRegion": "us-east-1",
            "kms:ViaService": "s3.us-east-1.amazonaws.com",
            "kms:EncryptionContext:aws:s3:arn": {
                "Fn::Sub": f"arn:${{AWS::Partition}}:s3:::{bucket}"
            },
        }
        if logical_id == "CreatorRole":
            assert decrypt["Condition"]["DateGreaterThanEquals"] == {
                "aws:CurrentTime": value["route_not_before"]
            }
            assert decrypt["Condition"]["DateLessThan"] == {
                "aws:CurrentTime": value["broker_config"]["recovery_not_after"]
            }
        else:
            assert "DateGreaterThanEquals" not in decrypt["Condition"]
            assert "DateLessThan" not in decrypt["Condition"]
            assert any(
                item.get("Sid") == "DBefore"
                and item["Condition"]["DateLessThan"]
                == {"aws:CurrentTime": value["route_not_before"]}
                for item in statements
            )
            assert any(
                item.get("Sid") == "DenyAfterRecovery"
                and item["Condition"]["DateGreaterThanEquals"]
                == {
                    "aws:CurrentTime": value["broker_config"][
                        "recovery_not_after"
                    ]
                }
                for item in statements
            )
        direct_deny = by_sid["DenyDirectKmsProviders"]
        assert direct_deny["Effect"] == "Deny"
        assert direct_deny["Action"] == "kms:*"
        assert direct_deny["Condition"]["ForAllValues:StringNotEquals"] == {
            "aws:CalledVia": [
                "cloudformation.amazonaws.com",
                "s3.amazonaws.com",
            ]
        }
    creator_statements = rendered["Resources"]["CreatorRole"]["Properties"][
        "Policies"
    ][0]["PolicyDocument"]["Statement"]
    by_sid = {item["Sid"]: item for item in creator_statements}
    assert by_sid["CreateExactPepInitialChangeSet"]["Condition"]["StringEquals"] == {
        "aws:RequestedRegion": "us-east-1",
        "cloudformation:ChangeSetName": "gug376-plan-repair-pep-create",
        "cloudformation:TemplateUrl": value["pep_template"]["url"],
    }
    assert by_sid["CreateExactPepProtectionChangeSet"]["Condition"][
        "StringEquals"
    ] == {
        "aws:RequestedRegion": "us-east-1",
        "cloudformation:ChangeSetName": (
            "gug376-plan-repair-pep-protection-enable"
        ),
        "cloudformation:TemplateUrl": value["pep_protection_template"]["url"],
    }
    assert by_sid["ReadExactPepProtectionTemplate"]["Resource"] == {
        "Fn::Sub": (
            "arn:${AWS::Partition}:s3:::"
            f"{value['pep_protection_template']['bucket']}/"
            f"{value['pep_protection_template']['key']}"
        )
    }
    assert by_sid["ReadExactPepProtectionTemplate"]["Condition"][
        "StringEquals"
    ]["s3:VersionId"] == value["pep_protection_template"]["version"]


def test_dispatch_recovery_functions_are_role_separated_and_read_only(
    source_repo: tuple[Path, str, dict[str, Any]],
) -> None:
    root, _commit, value = source_repo
    rendered = _load(seed.render_template(source_root=root, private_input=value))
    resources = rendered["Resources"]
    allowed = {
        "cloudformation:DescribeChangeSet",
        "cloudformation:DescribeStacks",
        "cloudformation:GetTemplate",
        "cloudformation:ListStackResources",
        "cloudtrail:LookupEvents",
        "dynamodb:DescribeTable",
        "dynamodb:GetItem",
        "dynamodb:UpdateItem",
        "logs:CreateLogStream",
        "logs:PutLogEvents",
        "sts:AssumeRole",
        "sts:SetSourceIdentity",
        "xray:PutTelemetryRecords",
        "xray:PutTraceSegments",
    }
    forbidden = {
        "cloudformation:CreateChangeSet",
        "cloudformation:ExecuteChangeSet",
        "cloudformation:DeleteStack",
        "cloudformation:DeleteChangeSet",
    }
    for logical_id in (
        "CreateDispatchRecoveryRole",
        "ExecuteDispatchRecoveryRole",
    ):
        statements = resources[logical_id]["Properties"]["Policies"][0][
            "PolicyDocument"
        ]["Statement"]
        actions = {
            action
            for statement in statements
            if statement["Effect"] == "Allow"
            for action in (
                statement["Action"]
                if isinstance(statement["Action"], list)
                else [statement["Action"]]
            )
        }
        assert actions == allowed
        assert not actions & forbidden
        assert all(
            statement["Condition"]["DateLessThan"]["aws:CurrentTime"]
            == value["route_not_before"]
            for statement in statements
            if statement["Sid"] == "DenyBeforeRoute"
        )
        assert all(
            statement["Condition"]["DateGreaterThanEquals"]["aws:CurrentTime"]
            == value["broker_config"]["recovery_not_after"]
            for statement in statements
            if statement["Sid"] == "DenyAfterRecovery"
        )
        by_sid = {statement["Sid"]: statement for statement in statements}
        log_suffix = (
            "create-dispatch-recovery"
            if logical_id == "CreateDispatchRecoveryRole"
            else "execute-dispatch-recovery"
        )
        assert by_sid["WriteExactRecoveryLogs"] == {
            "Sid": "WriteExactRecoveryLogs",
            "Effect": "Allow",
            "Action": ["logs:CreateLogStream", "logs:PutLogEvents"],
            "Resource": {
                "Fn::Sub": (
                    "arn:${AWS::Partition}:logs:us-east-1:042360977644:"
                    "log-group:/aws/lambda/scanalyze-platform-authority-gug376-"
                    f"route-{log_suffix}:*"
                )
            },
        }
        assert by_sid["WriteXrayTelemetry"] == {
            "Sid": "WriteXrayTelemetry",
            "Effect": "Allow",
            "Action": ["xray:PutTelemetryRecords", "xray:PutTraceSegments"],
            "Resource": "*",
        }
    expected = {
        "CreateDispatchRecoveryFunction": (
            "CreateDispatchRecoveryRole",
            "tooling.platform_authority_plan_permission_repair_route_broker."
            "create_dispatch_recovery_handler",
            "CreateDispatchRecoveryAlias",
            "CreateDispatchRecoveryAsyncPolicy",
        ),
        "ExecuteDispatchRecoveryFunction": (
            "ExecuteDispatchRecoveryRole",
            "tooling.platform_authority_plan_permission_repair_route_broker."
            "execute_dispatch_recovery_handler",
            "ExecuteDispatchRecoveryAlias",
            "ExecuteDispatchRecoveryAsyncPolicy",
        ),
    }
    for function_id, (role_id, handler, alias_id, event_id) in expected.items():
        function = resources[function_id]["Properties"]
        assert function["Role"] == {"Fn::GetAtt": f"{role_id}.Arn"}
        assert function["Handler"] == handler
        assert function["Code"] == resources["CreatorFunction"]["Properties"]["Code"]
        assert function["TracingConfig"] == {"Mode": "Active"}
        alias = resources[alias_id]["Properties"]
        assert alias["FunctionName"] == {"Ref": function_id}
        assert alias["Name"] == "recover-v1"
        event = resources[event_id]["Properties"]
        assert event == {
            "FunctionName": {"Ref": function_id},
            "Qualifier": "recover-v1",
            "MaximumEventAgeInSeconds": 60,
            "MaximumRetryAttempts": 0,
        }


def test_broker_protection_variant_includes_recovery_logs_and_versions(
    source_repo: tuple[Path, str, dict[str, Any]],
) -> None:
    root, _commit, value = source_repo
    create = _load(
        seed.render_template(
            source_root=root, private_input=value, protection_enabled=False
        )
    )
    protection = _load(
        seed.render_template(
            source_root=root, private_input=value, protection_enabled=True
        )
    )
    required = {
        "CreateDispatchRecoveryLogGroup",
        "ExecuteDispatchRecoveryLogGroup",
        "CreateDispatchRecoveryVersion",
        "ExecuteDispatchRecoveryVersion",
    }
    lifecycle = {
        logical_id
        for logical_id, resource in create["Resources"].items()
        if "DeletionPolicy" in resource or "UpdateReplacePolicy" in resource
    }
    assert required <= lifecycle
    assert all(
        create["Resources"][logical_id]["DeletionPolicy"] == "Delete"
        and create["Resources"][logical_id]["UpdateReplacePolicy"] == "Delete"
        and protection["Resources"][logical_id]["DeletionPolicy"] == "Retain"
        and protection["Resources"][logical_id]["UpdateReplacePolicy"] == "Retain"
        for logical_id in lifecycle
    )


@pytest.mark.parametrize("drift", ["missing", "foreign"])
def test_broker_seed_rejects_artifact_kms_binding_drift(
    source_repo: tuple[Path, str, dict[str, Any]], drift: str
) -> None:
    _root, _commit, original = source_repo
    changed = copy.deepcopy(original)
    binding = changed["foundation_publish_binding"]
    if drift == "missing":
        binding.pop("sse_kms_key_arn")
    else:
        binding["sse_kms_key_arn"] = binding["sse_kms_key_arn"].replace(
            "042360977644", "839393571433"
        )
    binding["binding_digest"] = seed.digest_value(
        {key: item for key, item in binding.items() if key != "binding_digest"}
    )
    changed["foundation_publish_binding_digest"] = binding["binding_digest"]
    with pytest.raises(seed.BrokerSeedError, match="FOUNDATION_PUBLISH_BINDING_INVALID"):
        seed.validate_input(changed)


def test_s3_template_url_percent_encodes_opaque_version_id() -> None:
    version = "A+B/C=="
    assert seed._VERSION_RE.fullmatch(version) is not None
    assert seed._expected_url(
        "scanalyze-artifacts", "templates/pep/template.yaml", version
    ) == (
        "https://scanalyze-artifacts.s3.us-east-1.amazonaws.com/"
        "templates/pep/template.yaml?versionId=A%2BB%2FC%3D%3D"
    )


def test_materialization_round_trips_percent_encoded_template_version_id(
    source_repo: tuple[Path, str, dict[str, Any]],
) -> None:
    root, _commit, original = source_repo
    value = copy.deepcopy(original)
    version = "A+B/C=="
    template = value["pep_template"]
    encoded_url = seed._expected_url(
        template["bucket"], template["key"], version
    )
    template["version"] = version
    template["url"] = encoded_url
    config = value["broker_config"]
    config["requests"]["pep-create-v1"]["TemplateURL"] = encoded_url
    config.pop("config_digest")
    value["broker_config"] = broker.seal(config, "config_digest")

    rendered = seed.render_template(source_root=root, private_input=value)
    assert b"versionId=A%2BB%2FC%3D%3D" in rendered

    raw = copy.deepcopy(value)
    raw["pep_template"]["url"] = (
        f"https://{template['bucket']}.s3.us-east-1.amazonaws.com/"
        f"{template['key']}?versionId={version}"
    )
    with pytest.raises(seed.BrokerSeedError, match="PEP_TEMPLATE_INVALID"):
        seed.render_template(source_root=root, private_input=raw)


def test_external_grant_cannot_enable_unsupported_broker_ledger_mutation(
    source_repo: tuple[Path, str, dict[str, Any]],
) -> None:
    root, _commit, value = source_repo
    rendered = _load(seed.render_template(source_root=root, private_input=value))
    resources = rendered["Resources"]
    unsupported = {
        "dynamodb:BatchWriteItem",
        "dynamodb:DeleteItem",
        "dynamodb:PartiQLDelete",
        "dynamodb:PartiQLInsert",
        "dynamodb:PartiQLUpdate",
    }
    resource_statements = resources["BrokerLedger"]["Properties"][
        "ResourcePolicy"
    ]["PolicyDocument"]["Statement"]
    resource_deny = next(
        item
        for item in resource_statements
        if item["Sid"] == "DenyUnsupportedBrokerLedgerMutationApis"
    )
    assert set(resource_deny["Action"]) == unsupported
    assert resource_deny["Principal"] == {"AWS": "*"}
    assert "Condition" not in resource_deny
    for role_name in ("CreatorRole", "ExecutorRole"):
        statements = resources[role_name]["Properties"]["Policies"][0][
            "PolicyDocument"
        ]["Statement"]
        allowed = {
            action
            for item in statements
            if item.get("Effect") == "Allow"
            for action in (
                [item["Action"]]
                if isinstance(item.get("Action"), str)
                else item.get("Action", [])
            )
        }
        assert unsupported.isdisjoint(allowed)


def test_broker_seed_source_uses_no_yaml_anchors_or_aliases() -> None:
    raw = (REPO_ROOT / seed.SOURCE_TEMPLATE_PATH).read_text(encoding="utf-8")
    scan_ready = (
        raw.replace("@@BROKER_CONFIG_JSON_YAML@@", "'{}'")
        .replace("@@BROKER_LEDGER_PROTECTION_BOOLEAN@@", "false")
        .replace("@@BROKER_DELETION_POLICY@@", "Delete")
        .replace("@@BROKER_UPDATE_REPLACE_POLICY@@", "Delete")
    )
    tokens = yaml.scan(scan_ready)
    assert not any(
        isinstance(token, (yaml.tokens.AnchorToken, yaml.tokens.AliasToken))
        for token in tokens
    )


def test_materialization_writes_reproducible_exact_zip_and_private_template(
    source_repo: tuple[Path, str, dict[str, Any]], tmp_path: Path
) -> None:
    root, _commit, value = source_repo
    private = _private_root(tmp_path)
    package_path, package_receipt = seed.build_private_broker_package(
        source_root=root,
        private_root=private,
        source_commit=value["source_commit"],
    )
    destination, receipt = seed.materialize_broker_seed(
        source_root=root,
        private_root=private,
        private_input=value,
    )
    assert destination == private / seed.OUTPUT_NAME
    assert stat.S_IMODE(destination.stat().st_mode) == 0o600
    assert stat.S_IMODE(package_path.stat().st_mode) == 0o600
    assert receipt["aws_calls"] == 0
    assert receipt["aws_mutations"] == 0
    assert receipt["production_status"] == "NO-GO"
    assert package_receipt["package_sha256"] == value["broker_code"][
        "unsigned_artifact"
    ]["sha256"]
    assert receipt["signed_package_code_sha256"] == value["broker_code"][
        "signed_artifact"
    ]["code_sha256"]
    projection = receipt["effective_policy_projection"]
    assert receipt["effective_policy_projection_digest"] == projection[
        "projection_digest"
    ]
    assert projection["record_type"] == seed.EFFECTIVE_POLICY_PROJECTION_TYPE
    assert projection["source_commit"] == value["source_commit"]
    assert projection["partition"] == "aws"
    assert projection["account_id"] == seed.AUTHORITY_ACCOUNT_ID
    assert projection["region"] == seed.REGION
    assert set(projection["policies"]) == {
        "creator_role_inline_policy",
        "executor_role_inline_policy",
        "create_dispatch_recovery_role_inline_policy",
        "execute_dispatch_recovery_role_inline_policy",
        "broker_ledger_resource_policy",
        "broker_ledger_key_policy",
    }
    for policy in projection["policies"].values():
        assert policy["document_digest"] == seed.digest_value(policy["document"])
        assert [item["Sid"] for item in policy["document"]["Statement"]] == sorted(
            item["Sid"] for item in policy["document"]["Statement"]
        )
        encoded = seed.canonical_json(policy["document"])
        assert "Fn::" not in encoded
        assert "${" not in encoded
    creator_selector = projection["policies"]["creator_role_inline_policy"][
        "selector"
    ]
    assert creator_selector == {
        "policy_name": "ExactBrokerCreation",
        "role_arn": (
            "arn:aws:iam::042360977644:role/ScanalyzeGug376RouteBrokerCreator"
        ),
        "role_name": "ScanalyzeGug376RouteBrokerCreator",
    }
    assert seed.validate_broker_seed_receipt(receipt) == receipt
    with zipfile.ZipFile(package_path) as archive:
        assert archive.namelist() == [path.as_posix() for path in seed.PACKAGE_SOURCE_PATHS]
        assert all(info.date_time == (1980, 1, 1, 0, 0, 0) for info in archive.infolist())
        assert all(info.compress_type == zipfile.ZIP_STORED for info in archive.infolist())
        for relative in seed.PACKAGE_SOURCE_PATHS:
            assert archive.read(relative.as_posix()) == (root / relative).read_bytes()
    completed = subprocess.run(
        [
            sys.executable,
            "-I",
            "-S",
            "-c",
            (
                "import sys;sys.path.insert(0,sys.argv[1]);"
                "import tooling.platform_authority_plan_permission_repair_route_broker as b;"
                "print(b.ROUTE_BROKER_STACK_NAME)"
            ),
            str(package_path),
        ],
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
        shell=False,
    )
    assert completed.stdout.strip() == broker.ROUTE_BROKER_STACK_NAME


def test_policy_projection_and_receipt_reject_tamper_and_extra_fields(
    source_repo: tuple[Path, str, dict[str, Any]], tmp_path: Path
) -> None:
    root, _commit, value = source_repo
    _destination, receipt = seed.materialize_broker_seed(
        source_root=root,
        private_root=_private_root(tmp_path, "receipt-tamper"),
        private_input=value,
    )
    extra = copy.deepcopy(receipt)
    extra["unexpected"] = True
    with pytest.raises(seed.BrokerSeedError, match="BROKER_SEED_RECEIPT_INVALID"):
        seed.validate_broker_seed_receipt(extra)

    document_drift = copy.deepcopy(receipt)
    document_drift["effective_policy_projection"]["policies"][
        "creator_role_inline_policy"
    ]["document"]["Statement"][0]["Action"] = ["iam:CreateUser"]
    with pytest.raises(
        seed.BrokerSeedError, match="EFFECTIVE_POLICY_DOCUMENT_DIGEST_INVALID"
    ):
        seed.validate_broker_seed_receipt(document_drift)

    selector_drift = copy.deepcopy(receipt["effective_policy_projection"])
    selector_drift["policies"]["broker_ledger_key_policy"]["selector"][
        "key_id"
    ] = "alias/unreviewed"
    with pytest.raises(seed.BrokerSeedError, match="EFFECTIVE_POLICY_SELECTOR_INVALID"):
        seed.validate_effective_policy_projection(
            selector_drift, source_commit=value["source_commit"]
        )

    intrinsic = copy.deepcopy(receipt["effective_policy_projection"])
    intrinsic["policies"]["broker_ledger_key_policy"]["document"]["Statement"][
        0
    ]["Resource"] = {"Fn::GetAtt": "BrokerLedgerKey.Arn"}
    with pytest.raises(
        seed.BrokerSeedError, match="EFFECTIVE_POLICY_INTRINSIC_INVALID"
    ):
        seed.validate_effective_policy_projection(
            intrinsic, source_commit=value["source_commit"]
        )


def test_materialization_pair_is_closed_distinct_and_parameterless(
    source_repo: tuple[Path, str, dict[str, Any]], tmp_path: Path
) -> None:
    root, _commit, value = source_repo
    pair = seed.materialize_broker_seed_pair(
        source_root=root,
        private_root=_private_root(tmp_path, "pair"),
        private_input=value,
    )
    assert set(pair) == {"broker_template", "broker_protection_template"}
    create_path, create_receipt = pair["broker_template"]
    protection_path, protection_receipt = pair["broker_protection_template"]
    assert create_path.name == seed.OUTPUT_NAME
    assert protection_path.name == seed.PROTECTION_OUTPUT_NAME
    assert create_receipt["template_variant"] == "create"
    assert protection_receipt["template_variant"] == "protection"
    assert create_receipt["template_sha256"] != protection_receipt[
        "template_sha256"
    ]
    assert "Parameters" not in _load(create_path.read_bytes())
    assert "Parameters" not in _load(protection_path.read_bytes())
    with pytest.raises(
        seed.BrokerSeedError,
        match="BROKER_SEED_RECEIPT_VARIANT_MISMATCH",
    ):
        seed.validate_broker_seed_receipt(
            create_receipt,
            expected_protection_enabled=True,
        )


def test_package_and_template_are_byte_reproducible_across_private_roots(
    source_repo: tuple[Path, str, dict[str, Any]], tmp_path: Path
) -> None:
    source, _commit, value = source_repo
    roots = [_private_root(tmp_path, "one"), _private_root(tmp_path, "two")]
    for root in roots:
        seed.build_private_broker_package(
            source_root=source,
            private_root=root,
            source_commit=value["source_commit"],
        )
        seed.materialize_broker_seed(
            source_root=source,
            private_root=root,
            private_input=value,
        )
    assert (roots[0] / seed.OUTPUT_NAME).read_bytes() == (
        roots[1] / seed.OUTPUT_NAME
    ).read_bytes()
    assert (roots[0] / seed.PACKAGE_OUTPUT_NAME).read_bytes() == (
        roots[1] / seed.PACKAGE_OUTPUT_NAME
    ).read_bytes()


@pytest.mark.parametrize(
    ("mutate", "code"),
    [
        (lambda value: value.update(extra="x"), "BROKER_SEED_FIELDS_INVALID"),
        (
            lambda value: value.update(authority_account_id="000000000000"),
            "BROKER_SEED_BINDING_INVALID",
        ),
        (
            lambda value: value.update(route_not_after=value["route_not_before"]),
            "BROKER_SEED_WINDOW_INVALID",
        ),
        (
            lambda value: value["source_template"].update(sha256="sha256:" + "0" * 64),
            "SOURCE_TEMPLATE_DIGEST_MISMATCH",
        ),
        (
            lambda value: value["broker_code"]["signed_artifact"].update(
                code_sha256="A" * 43 + "="
            ),
            "BROKER_SIGNING_RECEIPT_INVALID",
        ),
        (
            lambda value: value["broker_code"]["signing_job"].update(
                profile_version_arn="bad"
            ),
            "BROKER_SIGNING_RECEIPT_INVALID",
        ),
        (
            lambda value: value["pep_template"].update(url="https://example.invalid"),
            "PEP_TEMPLATE_INVALID",
        ),
        (
            lambda value: value["broker_config"].update(retry_permitted=True),
            "BROKER_CONFIG_INVALID",
        ),
    ],
)
def test_invalid_private_bindings_fail_closed(
    source_repo: tuple[Path, str, dict[str, Any]],
    mutate: Any,
    code: str,
) -> None:
    root, _commit, original = source_repo
    value = copy.deepcopy(original)
    mutate(value)
    with pytest.raises(seed.BrokerSeedError, match=code):
        seed.render_template(source_root=root, private_input=value)


@pytest.mark.parametrize(
    ("variant", "code"),
    [
        ("missing", "BROKER_SEED_FIELDS_INVALID"),
        ("foreign-key", "PEP_PROTECTION_TEMPLATE_INVALID"),
        ("duplicate-version", "PEP_TEMPLATE_CONFIG_BINDING_INVALID"),
        ("crossed-url", "PEP_TEMPLATE_CONFIG_BINDING_INVALID"),
    ],
)
def test_pep_protection_template_binding_fails_closed(
    source_repo: tuple[Path, str, dict[str, Any]], variant: str, code: str
) -> None:
    root, _commit, original = source_repo
    value = copy.deepcopy(original)
    if variant == "missing":
        value.pop("pep_protection_template")
    elif variant == "foreign-key":
        protection = value["pep_protection_template"]
        protection["key"] = protection["key"].replace(
            value["source_commit"], "f" * 40
        )
        protection["url"] = seed._expected_url(  # noqa: SLF001
            protection["bucket"], protection["key"], protection["version"]
        )
    else:
        config = value["broker_config"]
        if variant == "duplicate-version":
            protection = value["pep_protection_template"]
            protection["version"] = value["pep_template"]["version"]
            protection["url"] = seed._expected_url(  # noqa: SLF001
                protection["bucket"], protection["key"], protection["version"]
            )
            config["requests"]["pep-protection-create-v1"]["TemplateURL"] = (
                protection["url"]
            )
        else:
            config["requests"]["pep-protection-create-v1"]["TemplateURL"] = value[
                "pep_template"
            ]["url"]
        config.pop("config_digest")
        value["broker_config"] = broker.seal(config, "config_digest")
    with pytest.raises(seed.BrokerSeedError, match=code):
        seed.render_template(source_root=root, private_input=value)


def test_pep_runtime_storage_digest_must_match_broker_storage_binding(
    source_repo: tuple[Path, str, dict[str, Any]],
) -> None:
    root, _commit, original = source_repo
    value = copy.deepcopy(original)
    runtime = value["pep_runtime_binding"]
    runtime["upstream_storage_binding_digest"] = "sha256:" + "9" * 64
    runtime["binding_digest"] = seed.digest_value(
        {
            key: item
            for key, item in runtime.items()
            if key != "binding_digest"
        }
    )
    with pytest.raises(seed.BrokerSeedError, match="PEP_STORAGE_BINDING_INVALID"):
        seed.render_template(source_root=root, private_input=value)


def test_dirty_non_main_and_changed_package_sources_fail_closed(
    source_repo: tuple[Path, str, dict[str, Any]], tmp_path: Path
) -> None:
    root, _commit, value = source_repo
    (root / "dirty.txt").write_text("dirty", encoding="utf-8")
    with pytest.raises(seed.BrokerSeedError, match="SOURCE_NOT_EXACT_CLEAN_MAIN"):
        seed.render_template(source_root=root, private_input=value)
    (root / "dirty.txt").unlink()
    _git(root, "checkout", "-b", "not-main")
    with pytest.raises(seed.BrokerSeedError, match="SOURCE_NOT_EXACT_CLEAN_MAIN"):
        seed.render_template(source_root=root, private_input=value)
    _git(root, "checkout", "main")
    broker_source = root / seed.PACKAGE_SOURCE_PATHS[1]
    broker_source.write_bytes(broker_source.read_bytes() + b"\n# changed\n")
    with pytest.raises(seed.BrokerSeedError, match="SOURCE_NOT_EXACT_CLEAN_MAIN"):
        seed.build_broker_package(
            source_root=root,
            source_commit=value["source_commit"],
        )


def test_owner_only_root_o_excl_and_cli_boundary(
    source_repo: tuple[Path, str, dict[str, Any]], tmp_path: Path
) -> None:
    source, _commit, value = source_repo
    private = _private_root(tmp_path)
    input_path = private / "broker-seed-input.json"
    input_path.write_text(seed.canonical_json(value), encoding="utf-8")
    input_path.chmod(0o600)
    built = subprocess.run(
        [
            sys.executable,
            str(CLI),
            "build-package",
            "--source-root",
            str(source),
            "--private-root",
            str(private),
            "--source-commit",
            value["source_commit"],
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
        shell=False,
    )
    assert built.returncode == 0, built.stderr
    build_summary = json.loads(built.stdout)
    build_receipt = json.loads(
        (private / seed.PACKAGE_RECEIPT_OUTPUT_NAME).read_text(encoding="utf-8")
    )
    assert build_summary["receipt_name"] == seed.PACKAGE_RECEIPT_OUTPUT_NAME
    assert build_summary["signed"] is False
    assert build_summary["package_sha256"] == value["broker_code"][
        "unsigned_artifact"
    ]["sha256"]
    assert build_receipt["receipt_digest"] == build_summary["receipt_digest"]
    completed = subprocess.run(
        [
            sys.executable,
            str(CLI),
            "materialize-template",
            "--source-root",
            str(source),
            "--private-root",
            str(private),
            "--input-name",
            input_path.name,
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
        shell=False,
    )
    assert completed.returncode == 0, completed.stderr
    summary = json.loads(completed.stdout)
    create_receipt = json.loads(
        (private / seed.MATERIALIZATION_RECEIPT_OUTPUT_NAME).read_text(
            encoding="utf-8"
        )
    )
    protection_receipt = json.loads(
        (
            private / seed.PROTECTION_MATERIALIZATION_RECEIPT_OUTPUT_NAME
        ).read_text(encoding="utf-8")
    )
    assert summary["receipts"]["broker_template"]["receipt_name"] == (
        seed.MATERIALIZATION_RECEIPT_OUTPUT_NAME
    )
    assert summary["receipts"]["broker_template"]["receipt_digest"] == (
        create_receipt["receipt_digest"]
    )
    assert summary["receipts"]["broker_protection_template"][
        "receipt_digest"
    ] == protection_receipt["receipt_digest"]
    assert create_receipt["template_variant"] == "create"
    assert protection_receipt["template_variant"] == "protection"
    assert create_receipt["template_sha256"] != protection_receipt[
        "template_sha256"
    ]
    assert create_receipt["aws_calls"] == 0
    assert create_receipt["deployment_authorized"] is False
    assert "effective_policy_projection" not in summary
    for private_value in (
        value["repair_id"],
        value["broker_code"]["signed_artifact"]["version"],
        value["broker_code"]["signed_artifact"]["key"],
    ):
        assert private_value not in completed.stdout
    repeated = subprocess.run(
        completed.args,
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
        shell=False,
    )
    assert repeated.returncode == 2
    assert json.loads(repeated.stderr) == {"error": "PRIVATE_OUTPUT_EXISTS"}
    assert str(private) not in completed.stdout + completed.stderr


def test_private_mode_duplicate_json_and_symlink_are_rejected(tmp_path: Path) -> None:
    private = _private_root(tmp_path)
    bad = private / "input.json"
    bad.write_text('{"record_type":"one","record_type":"two"}', encoding="utf-8")
    bad.chmod(0o600)
    with pytest.raises(seed.BrokerSeedError, match="PRIVATE_JSON_DUPLICATE_KEY"):
        seed.load_private_input(private_root=private, name=bad.name)
    bad.chmod(0o644)
    with pytest.raises(seed.BrokerSeedError, match="PRIVATE_INPUT_INVALID"):
        seed.load_private_input(private_root=private, name=bad.name)
    bad.unlink()
    target = tmp_path / "target.json"
    target.write_text("{}", encoding="utf-8")
    target.chmod(0o600)
    bad.symlink_to(target)
    with pytest.raises(seed.BrokerSeedError, match="PRIVATE_INPUT_INVALID"):
        seed.load_private_input(private_root=private, name=bad.name)


def test_seed_template_has_signed_runtime_durable_ledger_and_zero_async_retries(
    source_repo: tuple[Path, str, dict[str, Any]],
) -> None:
    root, _commit, value = source_repo
    rendered = _load(seed.render_template(source_root=root, private_input=value))
    resources = rendered["Resources"]
    ledger = resources["BrokerLedger"]
    assert ledger["DependsOn"] == [
        "CreatorRole",
        "ExecutorRole",
        "CreateDispatchRecoveryRole",
        "ExecuteDispatchRecoveryRole",
    ]
    assert ledger["DeletionPolicy"] == "Delete"
    assert ledger["UpdateReplacePolicy"] == "Delete"
    assert ledger["Properties"]["DeletionProtectionEnabled"] is False
    assert ledger["Properties"]["PointInTimeRecoverySpecification"] == {
        "PointInTimeRecoveryEnabled": True,
        "RecoveryPeriodInDays": 35,
    }
    assert ledger["Properties"]["SSESpecification"]["SSEType"] == "KMS"
    ledger_policy = ledger["Properties"]["ResourcePolicy"]["PolicyDocument"]
    by_sid = {item["Sid"]: item for item in ledger_policy["Statement"]}
    outside = by_sid["DenyMutationsOutsideExactBrokerWriters"]
    assert outside["Condition"]["ArnNotEquals"]["aws:PrincipalArn"] == [
        {
            "Fn::Sub": (
                "arn:${AWS::Partition}:iam::042360977644:role/"
                "ScanalyzeGug376RouteBrokerCreator"
            )
        },
        {
            "Fn::Sub": (
                "arn:${AWS::Partition}:iam::042360977644:role/"
                "ScanalyzeGug376RouteBrokerExecutor"
            )
        },
        {
            "Fn::Sub": (
                "arn:${AWS::Partition}:iam::042360977644:role/"
                "ScanalyzeGug376RouteCreateDispatchRecovery"
            )
        },
        {
            "Fn::Sub": (
                "arn:${AWS::Partition}:iam::042360977644:role/"
                "ScanalyzeGug376RouteExecuteDispatchRecovery"
            )
        },
    ]
    assert set(outside["Action"]) == {
        "dynamodb:PutItem",
        "dynamodb:UpdateItem",
    }
    unsupported_actions = {
        "dynamodb:BatchWriteItem",
        "dynamodb:DeleteItem",
        "dynamodb:PartiQLDelete",
        "dynamodb:PartiQLInsert",
        "dynamodb:PartiQLUpdate",
    }
    unsupported = by_sid["DenyUnsupportedBrokerLedgerMutationApis"]
    assert unsupported["Effect"] == "Deny"
    assert unsupported["Principal"] == {"AWS": "*"}
    assert set(unsupported["Action"]) == unsupported_actions
    assert "Condition" not in unsupported
    cross_key = by_sid["DenyExactBrokerWritersOutsideLedgerKey"]
    assert cross_key["Condition"]["ForAllValues:StringNotEquals"] == {
        "dynamodb:LeadingKeys": ["gug376-route-broker"]
    }
    assert cross_key["Condition"]["Null"] == {
        "dynamodb:LeadingKeys": "false"
    }
    missing_key = by_sid["DenyExactBrokerWritersWithoutLedgerKey"]
    assert missing_key["Condition"]["Null"] == {
        "dynamodb:LeadingKeys": "true"
    }
    key = resources["BrokerLedgerKey"]["Properties"]
    assert key["EnableKeyRotation"] is True
    assert resources["BrokerCodeSigningConfig"]["Properties"]["CodeSigningPolicies"] == {
        "UntrustedArtifactOnDeployment": "Enforce"
    }
    assert resources["CreatorRuntimeManagementConfig"] == {
        "Type": "AWS::Lambda::RuntimeManagementConfig",
        "Properties": {
            "FunctionName": {"Ref": "CreatorFunction"},
            "UpdateRuntimeOn": "FunctionUpdate",
        },
    }
    assert resources["ExecutorRuntimeManagementConfig"] == {
        "Type": "AWS::Lambda::RuntimeManagementConfig",
        "Properties": {
            "FunctionName": {"Ref": "ExecutorFunction"},
            "UpdateRuntimeOn": "FunctionUpdate",
        },
    }
    assert resources["CreatorVersion"]["DependsOn"] == (
        "CreatorRuntimeManagementConfig"
    )
    assert resources["ExecutorVersion"]["DependsOn"] == (
        "ExecutorRuntimeManagementConfig"
    )
    event_configs = {
        logical_id: resource
        for logical_id, resource in resources.items()
        if resource["Type"] == "AWS::Lambda::EventInvokeConfig"
    }
    assert len(event_configs) == 15
    assert {
        resource["Properties"]["Qualifier"] for resource in event_configs.values()
    } == set(broker.ALL_ALIASES) | {broker.RECOVERY_ALIAS}
    assert all(
        resource["Properties"]["MaximumRetryAttempts"] == 0
        and resource["Properties"]["MaximumEventAgeInSeconds"] == 60
        and resource["DependsOn"] in resources
        and resources[resource["DependsOn"]]["Type"] == "AWS::Lambda::Alias"
        for resource in event_configs.values()
    )


def test_closeout_and_pep_role_arns_match_exact_source_contract(
    source_repo: tuple[Path, str, dict[str, Any]],
) -> None:
    root, _commit, value = source_repo
    rendered = _load(seed.render_template(source_root=root, private_input=value))
    creator_policy = rendered["Resources"]["CreatorRole"]["Properties"]["Policies"][0][
        "PolicyDocument"
    ]
    executor_policy = rendered["Resources"]["ExecutorRole"]["Properties"]["Policies"][0][
        "PolicyDocument"
    ]
    recovery_not_after = value["broker_config"]["recovery_not_after"]
    for policy in (creator_policy, executor_policy):
        assert any(
            statement.get("Effect") == "Deny"
            and statement.get("Action") == "*"
            and statement.get("Condition", {}).get("StringNotEquals")
            == {"aws:RequestedRegion": "us-east-1"}
            for statement in policy["Statement"]
        )
        assert any(
            statement.get("Effect") == "Deny"
            and statement.get("Condition", {}).get("DateLessThan")
            == {"aws:CurrentTime": value["route_not_before"]}
            for statement in policy["Statement"]
        )
        assert any(
            statement.get("Effect") == "Deny"
            and statement.get("Condition", {}).get("DateGreaterThanEquals")
            == {"aws:CurrentTime": recovery_not_after}
            for statement in policy["Statement"]
        )
        recovery_deny = next(
            statement
            for statement in policy["Statement"]
            if statement["Sid"] == "DenyAfterRecovery"
        )
        assert recovery_deny["Action"] == "*"
        assert recovery_deny["Resource"] == "*"
        assert recovery_deny["Condition"]["DateGreaterThanEquals"] == {
            "aws:CurrentTime": recovery_not_after
        }
    creator_after_route = next(
        statement
        for statement in creator_policy["Statement"]
        if statement["Sid"] == "DenyWritesAfterRoute"
    )
    assert set(creator_after_route["Action"]) == {
        "cloudformation:CreateChangeSet",
        "cloudformation:TagResource",
        "dynamodb:PutItem",
    }
    assert "dynamodb:UpdateItem" not in creator_after_route["Action"]
    assert not any(
        statement.get("Sid") == "DenyWritesAfterRoute"
        for statement in executor_policy["Statement"]
    )
    assert "cloudformation:DeleteChangeSet" not in {
        action
        for statement in creator_policy["Statement"]
        if statement.get("Effect") == "Allow"
        for action in (
            [statement["Action"]]
            if isinstance(statement.get("Action"), str)
            else statement.get("Action", [])
        )
    }


def test_executor_can_manage_exact_pep_ledger_policy_and_create_rollback_through_cfn(
    source_repo: tuple[Path, str, dict[str, Any]],
) -> None:
    root, _commit, value = source_repo
    rendered = _load(seed.render_template(source_root=root, private_input=value))
    recovery_not_after = value["broker_config"]["recovery_not_after"]
    creator_policy = rendered["Resources"]["CreatorRole"]["Properties"]["Policies"][0][
        "PolicyDocument"
    ]
    executor_policy = rendered["Resources"]["ExecutorRole"]["Properties"]["Policies"][0][
        "PolicyDocument"
    ]
    statement = next(
        item for item in executor_policy["Statement"] if item["Sid"] == "MPL"
    )
    assert "dynamodb:PutResourcePolicy" in statement["Action"]
    assert "dynamodb:GetResourcePolicy" not in statement["Action"]
    assert "dynamodb:DeleteResourcePolicy" in statement["Action"]
    assert "dynamodb:DeleteTable" in statement["Action"]
    assert statement["Resource"] == {
        "Fn::Sub": (
            "arn:${AWS::Partition}:dynamodb:us-east-1:042360977644:table/"
            "scanalyze-platform-authority-plan-policy-repair-ledger"
        )
    }
    assert statement["Condition"]["ForAnyValue:StringEquals"] == {
        "aws:CalledVia": "cloudformation.amazonaws.com"
    }
    closeout = next(
        statement
        for statement in creator_policy["Statement"]
        if statement["Sid"] == "ReadExactRepairTerminalRecordsForCloseout"
    )
    assert closeout["Action"] == "dynamodb:GetItem"
    assert closeout["Condition"]["ForAllValues:StringEquals"]["dynamodb:LeadingKeys"] == [
        REPAIR_ID,
        REPAIR_ID + "#reconcile-v1",
    ]
    assert closeout["Condition"]["Null"] == {
        "dynamodb:LeadingKeys": "false"
    }
    assert "scanalyze-platform-authority-state-backend" in str(creator_policy)
    public_access = next(
        statement
        for statement in creator_policy["Statement"]
        if statement["Sid"] == "ReadCloseoutEvidence"
    )
    assert public_access["Resource"] == "*"
    assert set(public_access["Action"]) == {
        "cloudtrail:LookupEvents",
        "s3:GetAccountPublicAccessBlock",
    }
    assert public_access["Condition"]["StringEquals"]["aws:RequestedRegion"] == (
        "us-east-1"
    )
    manage_roles = next(
        statement
        for statement in executor_policy["Statement"]
        if statement["Sid"] == "PepRolesViaCfn"
    )
    resources = str(manage_roles["Resource"])
    assert "role/ScanalyzeBootstrapPlanRepairPlan" in resources
    assert "role/ScanalyzeBootstrapPlanRepairExecution" in resources
    assert "role/ScanalyzeBootstrapPlanRepairReconcile" in resources
    assert "role/scanalyze/platform-authority/ScanalyzeBootstrapPlanRepairInspector" in resources
    assert "role/scanalyze/platform-authority/ScanalyzeBootstrapPlanRepairPlan" not in resources
    manage_lambda = next(
        statement
        for statement in executor_policy["Statement"]
        if statement["Sid"] == "ManagePepLambda"
    )
    lambda_actions = set(manage_lambda["Action"])
    assert {
        "lambda:GetRuntimeManagementConfig",
        "lambda:PutRuntimeManagementConfig",
        "lambda:GetFunctionCodeSigningConfig",
        "lambda:PutFunctionCodeSigningConfig",
        "lambda:DeleteFunctionCodeSigningConfig",
    } <= lambda_actions
    assert "lambda:DeleteRuntimeManagementConfig" not in lambda_actions
    assert "lambda:UpdateFunctionCodeSigningConfig" not in lambda_actions
    direct_deny = next(
        statement
        for statement in executor_policy["Statement"]
        if statement["Sid"] == "DenyDirectProviders"
    )
    assert "dynamodb:*" not in direct_deny["Action"]
    creator_ledger = next(
        statement
        for statement in creator_policy["Statement"]
        if statement["Sid"] == "ReadAndCasBrokerLedger"
    )
    executor_ledger = next(
        statement
        for statement in executor_policy["Statement"]
        if statement["Sid"] == "ReadAndCasBrokerLedger"
    )
    assert set(creator_ledger["Action"]) == {
        "dynamodb:GetItem",
        "dynamodb:PutItem",
        "dynamodb:UpdateItem",
    }
    assert set(executor_ledger["Action"]) == {
        "dynamodb:GetItem",
        "dynamodb:UpdateItem",
    }
    for statement in (creator_ledger, executor_ledger):
        assert statement["Resource"] == {
            "Fn::Sub": (
                "arn:${AWS::Partition}:dynamodb:us-east-1:042360977644:table/"
                "scanalyze-platform-authority-gug376-route-broker-ledger"
            )
        }
        assert statement["Condition"]["ForAllValues:StringEquals"] == {
            "dynamodb:LeadingKeys": ["gug376-route-broker"]
        }
        assert statement["Condition"]["Null"] == {
            "dynamodb:LeadingKeys": "false"
        }
    for sid, policy in (
        ("AssumeExactManagementCreator", creator_policy),
        ("AssumeManagementExecutor", executor_policy),
    ):
        assume = next(item for item in policy["Statement"] if item["Sid"] == sid)
        assert assume["Action"] == ["sts:AssumeRole", "sts:SetSourceIdentity"]
        if sid == "AssumeExactManagementCreator":
            assert assume["Condition"]["DateLessThan"]["aws:CurrentTime"] == (
                recovery_not_after
            )
        else:
            assert "Condition" not in assume
    execute_pep = next(
        statement
        for statement in executor_policy["Statement"]
        if statement["Sid"] == "ExecutePep"
    )
    assert execute_pep["Condition"]["DateLessThan"]["aws:CurrentTime"] == value[
        "route_not_after"
    ]
    execute_patterns = {
        item["Fn::Sub"].replace("${AWS::Partition}", "aws")
        for item in execute_pep["Condition"]["StringLike"][
            "cloudformation:ChangeSetName"
        ]
    }
    assert execute_patterns == {
        (
            "arn:aws:cloudformation:us-east-1:042360977644:changeSet/"
            "gug376-plan-repair-pep-create/*"
        ),
        (
            "arn:aws:cloudformation:us-east-1:042360977644:changeSet/"
            "gug376-plan-repair-pep-protection-enable/*"
        ),
    }
    execute_arn = (
        "arn:aws:cloudformation:us-east-1:042360977644:changeSet/"
        "gug376-plan-repair-pep-create/"
        "11111111-1111-4111-8111-111111111111"
    )
    assert any(fnmatchcase(execute_arn, pattern) for pattern in execute_patterns)
    assert not any(
        fnmatchcase("gug376-plan-repair-pep-create", pattern)
        for pattern in execute_patterns
    )
    assert not any(
        fnmatchcase(
            execute_arn.replace("042360977644", "839393571433"), pattern
        )
        for pattern in execute_patterns
    )
    globals_allow = next(
        statement
        for statement in executor_policy["Statement"]
        if statement["Sid"] == "PepGlobalsViaCfn"
    )
    assert globals_allow["Resource"] == "*"
    assert set(globals_allow["Action"]) == {
        "kms:CreateKey",
        "kms:ListAliases",
        "lambda:CreateCodeSigningConfig",
        "logs:DescribeLogGroups",
    }
    assert globals_allow["Condition"] == {
        "ForAnyValue:StringEquals": {
            "aws:CalledVia": "cloudformation.amazonaws.com"
        }
    }


def test_creator_separates_exact_pep_creation_from_tag_authorization(
    source_repo: tuple[Path, str, dict[str, Any]],
) -> None:
    root, _commit, value = source_repo
    rendered = _load(seed.render_template(source_root=root, private_input=value))
    policy = rendered["Resources"]["CreatorRole"]["Properties"]["Policies"][0][
        "PolicyDocument"
    ]
    by_sid = {statement["Sid"]: statement for statement in policy["Statement"]}
    create_routes = {
        "CreateExactPepInitialChangeSet": (
            "gug376-plan-repair-pep-create",
            value["pep_template"]["url"],
        ),
        "CreateExactPepProtectionChangeSet": (
            "gug376-plan-repair-pep-protection-enable",
            value["pep_protection_template"]["url"],
        ),
    }
    for sid, (change_set_name, template_url) in create_routes.items():
        create = by_sid[sid]
        assert create["Action"] == "cloudformation:CreateChangeSet"
        assert create["Condition"]["StringEquals"] == {
            "aws:RequestedRegion": "us-east-1",
            "cloudformation:ChangeSetName": change_set_name,
            "cloudformation:TemplateUrl": template_url,
        }
        assert "aws:RequestTag/" not in str(create["Condition"])
        assert "aws:TagKeys" not in str(create["Condition"])

    tag = next(
        statement
        for statement in policy["Statement"]
        if statement["Sid"] == "TagExactPepChangeSetOnCreate"
    )
    resources = {
        item["Fn::Sub"].replace("${AWS::Partition}", "aws")
        for item in tag["Resource"]
    }
    assert tag["Action"] == "cloudformation:TagResource"
    assert resources == {
        (
            "arn:aws:cloudformation:us-east-1:042360977644:stack/"
            "scanalyze-platform-authority-bootstrap-plan-repair-pep/*"
        ),
        (
            "arn:aws:cloudformation:us-east-1:042360977644:changeSet/"
            "gug376-plan-repair-pep-create/*"
        ),
        (
            "arn:aws:cloudformation:us-east-1:042360977644:changeSet/"
            "gug376-plan-repair-pep-protection-enable/*"
        ),
    }
    assert tag["Condition"]["StringEquals"] == {
        "aws:RequestedRegion": "us-east-1",
        "cloudformation:CreateAction": [
            "CreateChangeSet",
            "ExecuteChangeSet",
        ],
        "aws:RequestTag/managed_by": "cloudformation",
        "aws:RequestTag/service": "scanalyze-platform-authority",
        "aws:RequestTag/work_package": "GUG-376",
    }
    assert tag["Condition"]["ForAllValues:StringEquals"] == {
        "aws:TagKeys": ["managed_by", "service", "work_package"]
    }
    assert "cloudformation:ChangeSetName" not in str(tag["Condition"])
    assert "cloudformation:TemplateUrl" not in str(tag["Condition"])

    expected_tags = {
        "managed_by": "cloudformation",
        "service": "scanalyze-platform-authority",
        "work_package": "GUG-376",
    }
    condition = tag["Condition"]
    change_set_resource = next(
        resource
        for resource in resources
        if ":changeSet/gug376-plan-repair-pep-create/" in resource
    )
    for drift in ("account", "region", "name", "tag"):
        resource = change_set_resource
        requested_region = "us-east-1"
        tags = dict(expected_tags)
        if drift == "account":
            resource = resource.replace("042360977644", "839393571433")
        elif drift == "region":
            requested_region = "us-west-2"
        elif drift == "name":
            resource = resource.replace(
                "gug376-plan-repair-pep-create", "foreign-change-set"
            )
        else:
            tags["work_package"] = "GUG-999"
        assert not (
            resource in resources
            and requested_region
            == condition["StringEquals"]["aws:RequestedRegion"]
            and tags == expected_tags
            and set(tags)
            == set(
                condition["ForAllValues:StringEquals"]["aws:TagKeys"]
            )
        )


def test_generated_template_and_role_policies_fit_aws_limits(
    source_repo: tuple[Path, str, dict[str, Any]],
) -> None:
    root, _commit, value = source_repo
    payload = seed.render_template(source_root=root, private_input=value)
    assert len(payload) <= seed.MAX_TEMPLATE_URL_BYTES
    rendered = _load(payload)
    for logical_id in ("CreatorRole", "ExecutorRole"):
        policy = rendered["Resources"][logical_id]["Properties"]["Policies"][0][
            "PolicyDocument"
        ]
        compact = json.dumps(
            _resolve_policy_intrinsics(policy),
            separators=(",", ":"),
            ensure_ascii=True,
        )
        assert len(compact.encode("utf-8")) <= 10_240
    for logical_id in ("CreatorFunction", "ExecutorFunction"):
        environment = rendered["Resources"][logical_id]["Properties"]["Environment"][
            "Variables"
        ]
        size = sum(len(str(key)) + len(str(item)) for key, item in environment.items())
        assert size <= 4_096


def test_runtime_environment_keeps_capacity_for_realistic_pep_inventory(
    source_repo: tuple[Path, str, dict[str, Any]],
) -> None:
    root, _commit, original = source_repo
    value = copy.deepcopy(original)
    pep = _load(
        seed.render_pep_template_from_source(
            source=PEP_TEMPLATE.read_bytes(), protection_enabled=False
        )
    )
    inventory = [
        {"logical_resource_id": logical_id, "resource_type": resource["Type"]}
        for logical_id, resource in sorted(pep["Resources"].items())
    ]
    changes = [
        {
            "action": "Add",
            **item,
            "replacement": None,
            "scope": [],
            "details": [],
        }
        for item in inventory
    ]
    config = value["broker_config"]
    config["creator_contracts"]["pep-create-v1"]["expected_changes"] = changes
    config["terminal_expectations"]["pep-execute-v1"][
        "expected_resources"
    ] = inventory
    config.pop("config_digest")
    value["broker_config"] = broker.seal(config, "config_digest")
    assert len(changes) == 26
    assert all(item["action"] == "Add" and item["details"] == [] for item in changes)
    assert inventory == [
        {
            "logical_resource_id": item["logical_resource_id"],
            "resource_type": item["resource_type"],
        }
        for item in changes
    ]
    rendered = _load(seed.render_template(source_root=root, private_input=value))
    environment = rendered["Resources"]["CreatorFunction"]["Properties"][
        "Environment"
    ]["Variables"]
    assert set(environment) == {
        "BROKER_CONFIG_JSON",
        "BROKER_LEDGER_KEY_ARN",
        "LEDGER_TABLE_NAME",
    }
    size = sum(len(str(key)) + len(str(item)) for key, item in environment.items())
    assert size <= 4_096


def test_cli_imports_without_aws_sdk_and_help_is_offline() -> None:
    spec = importlib.util.spec_from_file_location("broker_seed_cli", CLI)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    before = set(sys.modules)
    spec.loader.exec_module(module)
    imported = set(sys.modules) - before
    assert not {"boto3", "botocore"} & imported
    completed = subprocess.run(
        [sys.executable, "-I", "-S", str(CLI), "--help"],
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
        shell=False,
    )
    assert completed.returncode == 0
    assert "performs no AWS call" in completed.stdout
