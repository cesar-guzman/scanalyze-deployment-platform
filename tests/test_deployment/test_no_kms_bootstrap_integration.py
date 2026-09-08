"""Hermetic composition of provider observation and bootstrap configuration.

The existing World supplies fake Git/SSO/STS/IAM/Identity Store ports. The
broker-config harness supplies synthetic artifact receipts/readbacks and
replaces external artifact-admission validators. Neither snapshot production,
snapshot binding, configuration compilation, runtime codec nor collision
binding extraction is stubbed. No AWS, network, real credentials, signature
verification or CloudFormation deployment is exercised by this test.
"""

from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
from typing import Any

import pytest

from tests.test_deployment import (
    test_gug376_plan_permission_repair_broker_config as config_data,
    test_gug376_plan_permission_repair_iam_effective_authority as iam_data,
    test_gug376_plan_permission_repair_plan_seed_snapshot as snapshot_data,
)
from tooling import platform_authority_plan_permission_repair_broker_config as config
from tooling import platform_authority_plan_permission_repair_route_broker as broker


def _capture_unobserved_snapshot(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[dict[str, Any], snapshot_data.World]:
    # Align all synthetic clocks/source bindings before the producer observes
    # anything; never edit or reseal the resulting observed snapshot.
    monkeypatch.setattr(snapshot_data, "SOURCE_COMMIT", config_data.SOURCE_COMMIT)
    monkeypatch.setattr(snapshot_data, "CHANGE_SET_NAME", config_data.CHANGE_SET_NAME)
    monkeypatch.setattr(snapshot_data, "NOW", config_data.NOW)
    world = snapshot_data.World(tmp_path)
    describe_instance = world.sso.describe_instance

    def without_encryption(**request: Any) -> dict[str, Any]:
        response = describe_instance(**request)
        response.pop("EncryptionConfigurationDetails")
        return response

    monkeypatch.setattr(world.sso, "describe_instance", without_encryption)
    return world.capture(tmp_path), world


def _parameters(runtime_config: dict[str, Any], operation: str) -> dict[str, str]:
    return {
        item["ParameterKey"]: item["ParameterValue"]
        for item in runtime_config["requests"][operation]["Parameters"]
    }


def test_absent_api_block_composes_through_broker_and_no_kms_cloudformation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    snapshot, world = _capture_unobserved_snapshot(tmp_path, monkeypatch)
    captured_snapshot = deepcopy(snapshot)
    assert snapshot["identity_center_kms_mode"] == "NOT_OBSERVED"
    assert snapshot["identity_center_kms_key_arn"] is None

    # This harness creates a sealed artifact-foundation draft. Its discarded
    # example snapshot is never passed to any component in this composition.
    draft = config_data._unbound_input()  # noqa: SLF001
    assert "plan_snapshot" not in draft
    joined = config.bind_plan_snapshot(
        draft, plan_snapshot=snapshot, now=config_data.NOW
    )
    assert joined["plan_snapshot"] == captured_snapshot
    result = config_data._materialize(monkeypatch, joined)  # noqa: SLF001
    runtime_config = result["broker_config"]
    decoded = broker.decode_runtime_config(broker.encode_runtime_config(runtime_config))
    assert decoded == runtime_config
    parsed = broker.BrokerConfig.from_mapping(decoded)
    collision = broker._collision_parameter_bindings(parsed)  # noqa: SLF001
    assert collision["identity_center_kms_mode"] == "NOT_OBSERVED"
    assert collision["identity_center_kms_key_arn"] is None
    assert collision["identity_center_kms_binding_digest"] == broker.digest_value(
        {
            "binding_name": "identity_center_kms_key_arn",
            "identity_center_instance_arn": snapshot["identity_center_instance_arn"],
            "mode": "NOT_OBSERVED",
            "key_arn": None,
        }
    )
    assert parsed.identity_center_instance_arn == snapshot["identity_center_instance_arn"]
    assert decoded["source_commit"] == snapshot["source_commit"]
    assert decoded["normal_plan_generated_role_arn"] == snapshot["generated_role_arn"]

    delegation = _parameters(decoded, "delegation-create-v1")
    pep = _parameters(decoded, "pep-create-v1")
    assert delegation["UseIdentityCenterCustomerManagedKms"] == "false"
    assert delegation["IdentityCenterKmsKeyArn"] == ""
    assert pep["IdentityCenterKmsMode"] == "NOT_OBSERVED"
    assert pep["IdentityCenterKmsKeyArn"] == ""

    # Evaluate the reviewed delegation's KMS condition using the compiler's
    # actual parameter value, then inspect the selected IAM statements. This
    # is source-level CloudFormation projection, not a deployed-IAM assertion.
    template = iam_data._load_template(iam_data.MANAGEMENT_TEMPLATE)  # noqa: SLF001
    condition = template["Conditions"]["IdentityCenterCustomerManagedKmsEnabled"]
    assert condition == {
        "Fn::Equals": [{"Ref": "UseIdentityCenterCustomerManagedKms"}, "true"]
    }
    left, right = condition["Fn::Equals"]
    enabled = delegation[left["Ref"]] == right
    assert enabled is False
    selected_statements: list[dict[str, Any]] = []
    excluded_kms_statements = 0
    for resource in template["Resources"].values():
        if resource["Type"] != "AWS::IAM::Role":
            continue
        for policy in resource["Properties"]["Policies"]:
            for statement in policy["PolicyDocument"]["Statement"]:
                if "Fn::If" in statement:
                    name, when_true, when_false = statement["Fn::If"]
                    assert name == "IdentityCenterCustomerManagedKmsEnabled"
                    assert "kms:" in json.dumps(when_true)
                    selected = when_true if enabled else when_false
                    assert selected == {"Ref": "AWS::NoValue"}
                    excluded_kms_statements += 1
                else:
                    selected_statements.append(statement)
    assert excluded_kms_statements == 4
    assert selected_statements
    assert "kms:" not in json.dumps(selected_statements)
    assert snapshot == captured_snapshot
    assert snapshot["aws_mutations"] == 0
    assert snapshot["production_status"] == "NO-GO"
    calls = [item for item in world.timeline if item.startswith("call:")]
    assert calls[:2] == [
        f"call:{config.route.MANAGEMENT_ACCOUNT_ID}:sts:GetCallerIdentity",
        f"call:{config.route.AUTHORITY_ACCOUNT_ID}:sts:GetCallerIdentity",
    ]
    assert not any(":kms:" in call for call in calls)


def test_captured_snapshot_tampering_is_rejected_before_configuration(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    snapshot, _world = _capture_unobserved_snapshot(tmp_path, monkeypatch)
    captured_snapshot = deepcopy(snapshot)
    tampered = deepcopy(snapshot)
    tampered["identity_center_kms_mode"] = "AWS_OWNED_KMS_KEY"

    with pytest.raises(
        config.BrokerConfigMaterializationError, match="PLAN_SNAPSHOT_DIGEST_INVALID"
    ):
        config.bind_plan_snapshot(
            config_data._unbound_input(),  # noqa: SLF001
            plan_snapshot=tampered,
            now=config_data.NOW,
        )
    assert snapshot == captured_snapshot
