"""Factory output must satisfy the existing workforce configuration consumer.

These are local contract tests, with synthetic provider metadata only. They
exercise the real producer and consumer; no SDK, network or AWS invocation.
"""

from __future__ import annotations

import copy
import importlib.util
import json
from pathlib import Path

import pytest

from tooling import platform_authority_change_set_retirement_broker as broker
from tooling import platform_authority_retirement_entrypoint_service_role_materializer as compiler
from tooling import platform_authority_retirement_ledger_factory as factory

_spec = importlib.util.spec_from_file_location(
    "gug215_ledger_public_runtime_fixture",
    Path(__file__).with_name("test_gug215_workforce_retirement_runtime.py"),
)
_fixture = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_fixture)


def config(schema_version="2"):
    document = _fixture.binding_document()
    document["schema_version"] = schema_version
    if schema_version == "2":
        del document["function_version"]
    return broker.WorkforceRetirementConfig(document, broker.canonical_digest(document))


def provider_readback(request, cfg):
    """Project the actual CreateTable request into synthetic provider responses."""
    assert set(request) == {
        "TableName", "AttributeDefinitions", "KeySchema", "BillingMode",
        "SSESpecification", "DeletionProtectionEnabled", "TableClass", "ResourcePolicy", "Tags",
    }
    assert request["SSESpecification"] == {
        "Enabled": True, "SSEType": "KMS", "KMSMasterKeyId": "alias/aws/dynamodb"
    }
    backup_request = factory.update_pitr_request()
    assert set(backup_request) == {"TableName", "PointInTimeRecoverySpecification"}
    assert backup_request["TableName"] == request["TableName"]
    recovery = backup_request["PointInTimeRecoverySpecification"]
    assert set(recovery) == {"PointInTimeRecoveryEnabled", "RecoveryPeriodInDays"}
    return {
        "describe_table": {"Table": {
            "TableName": request["TableName"], "TableArn": cfg.table_arn,
            "TableStatus": "ACTIVE",
            "AttributeDefinitions": copy.deepcopy(request["AttributeDefinitions"]),
            "KeySchema": copy.deepcopy(request["KeySchema"]),
            "BillingModeSummary": {"BillingMode": request["BillingMode"]},
            "TableClassSummary": {"TableClass": request["TableClass"]},
            "DeletionProtectionEnabled": request["DeletionProtectionEnabled"],
            "SSEDescription": {"Status": "ENABLED", "SSEType": "KMS",
                               "KMSMasterKeyArn": _fixture.KMS},
        }},
        "describe_key": {"KeyMetadata": {
            "Arn": _fixture.KMS, "AWSAccountId": cfg.authority_account_id,
            "Enabled": True, "KeyManager": "AWS", "KeyState": "Enabled",
            "KeyUsage": "ENCRYPT_DECRYPT", "Origin": "AWS_KMS", "MultiRegion": False,
        }},
        "describe_time_to_live": {"TimeToLiveDescription": {"TimeToLiveStatus": "DISABLED"}},
        "describe_continuous_backups": {"ContinuousBackupsDescription": {
            "ContinuousBackupsStatus": "ENABLED", "PointInTimeRecoveryDescription": {
                "PointInTimeRecoveryStatus": "ENABLED" if recovery["PointInTimeRecoveryEnabled"] is True else "DISABLED",
                "RecoveryPeriodInDays": recovery["RecoveryPeriodInDays"],
            },
        }},
        "list_tags_of_resource": {"Tags": copy.deepcopy(request["Tags"])},
        "get_resource_policy": {"Policy": request["ResourcePolicy"]},
        "get_item_request": {
            "TableName": request["TableName"], "Key": {"retirement_id": {"S": cfg.retirement_id}},
            "ConsistentRead": True, "ProjectionExpression": "document",
        },
        "get_item": {},
    }


@pytest.mark.parametrize("schema_version", ["1", "2"])
def test_workforce_factory_output_is_accepted_by_real_configuration_consumer(schema_version):
    cfg = config(schema_version)
    request = factory.create_workforce_table_request()
    compiler._wf_certify_ledger(provider_readback(request, cfg), config=cfg, key_arn=_fixture.KMS)
    policy = json.loads(request["ResourcePolicy"])
    assert set(policy["Statement"][0]["Action"]) == {
        "dynamodb:BatchWriteItem", "dynamodb:DeleteItem", "dynamodb:PartiQLDelete",
        "dynamodb:PartiQLInsert", "dynamodb:PartiQLUpdate", "dynamodb:PutItem", "dynamodb:UpdateItem",
    }
    assert policy["Statement"][0]["Condition"]["ArnNotEquals"]["aws:PrincipalArn"] == cfg.execution_role_arn
    assert factory.WORKFORCE_FACTORY_ROLE_NAME not in request["ResourcePolicy"]


def test_legacy_factory_output_cannot_satisfy_workforce_controls():
    cfg = config()
    with pytest.raises(broker.BrokerError, match="LEDGER_TAGS_CHANGED"):
        compiler._wf_certify_ledger(provider_readback(factory.create_table_request(), cfg),
                                    config=cfg, key_arn=_fixture.KMS)


def test_workforce_rejects_api_operation_used_as_iam_action():
    cfg = config()
    row = provider_readback(factory.create_workforce_table_request(), cfg)
    policy = json.loads(row["get_resource_policy"]["Policy"])
    policy["Statement"][0]["Action"].append("dynamodb:TransactWriteItems")
    row["get_resource_policy"]["Policy"] = json.dumps(policy)
    with pytest.raises(broker.BrokerError, match="LEDGER_RESOURCE_POLICY_CHANGED"):
        compiler._wf_certify_ledger(row, config=cfg, key_arn=_fixture.KMS)
    assert "dynamodb:TransactWriteItems" in broker.RetirementBroker._ledger_write_actions(None)


@pytest.mark.parametrize("drift", ["tags", "factory_writer", "pitr", "ttl", "deletion", "key", "occupied"])
def test_factory_readback_drift_is_rejected_by_real_consumer(drift):
    cfg = config()
    row = provider_readback(factory.create_workforce_table_request(), cfg)
    if drift == "tags":
        next(tag for tag in row["list_tags_of_resource"]["Tags"] if tag["Key"] == "production")["Value"] = "false"
    elif drift == "factory_writer":
        policy = json.loads(row["get_resource_policy"]["Policy"])
        policy["Statement"][0]["Condition"]["ArnNotEquals"]["aws:PrincipalArn"] = (
            f"arn:aws:iam::{cfg.authority_account_id}:role/{factory.WORKFORCE_FACTORY_ROLE_NAME}"
        )
        row["get_resource_policy"]["Policy"] = json.dumps(policy)
    elif drift == "pitr":
        row["describe_continuous_backups"]["ContinuousBackupsDescription"]["PointInTimeRecoveryDescription"]["RecoveryPeriodInDays"] = 1
    elif drift == "ttl":
        row["describe_time_to_live"]["TimeToLiveDescription"]["TimeToLiveStatus"] = "ENABLED"
    elif drift == "deletion":
        row["describe_table"]["Table"]["DeletionProtectionEnabled"] = False
    elif drift == "key":
        row["get_item_request"]["Key"]["retirement_id"]["S"] = "different-synthetic-target"
    elif drift == "occupied":
        row["get_item"] = {"Item": {"document": {"S": "synthetic-existing-record"}}}
    with pytest.raises((broker.BrokerError, compiler.ServiceRoleMaterializationError)):
        compiler._wf_certify_ledger(row, config=cfg, key_arn=_fixture.KMS)
