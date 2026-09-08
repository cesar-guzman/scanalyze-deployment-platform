"""Exercise the real materializer and collector contracts without AWS calls."""

from copy import deepcopy

import pytest

from tooling import platform_authority_gug376_identity_center_inventory_collector as collector
from tooling import platform_authority_gug376_live_request_materializer as materializer
from tooling import platform_authority_identity_center_encryption as encryption
from tooling.platform_authority_gug365_upstream_inventory import canonical_digest
from tests.test_deployment import test_gug392_live_request_materializer as harness


def _inputs():
    authority, identity = harness._plan_inputs()
    private = identity["private_targets"]
    private["identity_center_kms_mode"] = encryption.NOT_OBSERVED
    private["identity_center_kms_key_arn"] = None
    private["identity_center_kms_binding_digest"] = canonical_digest(
        {
            "binding_name": "identity_center_kms_key_arn",
            "identity_center_instance_arn": private["identity_center_instance_arn"],
            "mode": encryption.NOT_OBSERVED,
            "key_arn": None,
        }
    )
    identity["expected_state"]["instance"]["encryption"] = None
    return authority, identity


def test_materializer_preserves_absence_and_produces_no_kms_identity_policy():
    authority, identity = _inputs()
    plans = materializer.materialize_live_plans(
        authority_input=authority, identity_center_input=identity
    )
    private = plans.identity_center_plan["private_targets"]
    assert private["identity_center_kms_mode"] == encryption.NOT_OBSERVED
    assert private["identity_center_kms_key_arn"] is None
    runtime = deepcopy(plans.identity_center_plan)
    runtime["not_before"], runtime["not_after"] = harness.START, harness.END
    policy, digest = collector._render(
        runtime, None, live=True, live_discovery=True
    )
    assert digest == plans.identity_center_plan["expected_discovery_policy_digest"]
    for statement in policy["Statement"]:
        actions = statement.get("Action", [])
        actions = [actions] if isinstance(actions, str) else actions
        if statement.get("Effect") == "Allow":
            assert not any(action.startswith("kms:") for action in actions)
        assert "kms:Decrypt" not in statement.get("NotAction", [])
    instance = identity["expected_state"]["instance"]
    binding = {
        "expected_account_id": harness.IDENTITY_ACCOUNT,
        "identity_center_instance_arn": harness.IDENTITY_INSTANCE,
        "identity_store_id_digest": canonical_digest(private["identity_store_id"]),
        "identity_center_kms_binding_digest": private["identity_center_kms_binding_digest"],
    }
    assert collector._valid_live_instance_binding(instance, binding=binding)
    changed = deepcopy(instance)
    changed["encryption"] = encryption.expected_collector_projection(encryption.AWS_OWNED, None)
    assert not collector._valid_live_instance_binding(changed, binding=binding)


@pytest.mark.parametrize("key", ["", False, "unapproved-key"])
def test_no_kms_plan_rejects_non_null_key_before_policy_render(key):
    authority, identity = _inputs()
    identity["private_targets"]["identity_center_kms_key_arn"] = key
    with pytest.raises(materializer.LiveRequestMaterializationError):
        materializer.materialize_live_plans(
            authority_input=authority, identity_center_input=identity
        )


@pytest.mark.parametrize("projection", [
    {},
    {"key_type": "NOT_OBSERVED", "kms_key_arn": None, "status": "ENABLED"},
    {"key_type": "AWS_OWNED_KMS_KEY", "kms_key_arn": None, "status": "ENABLED"},
])
def test_no_kms_plan_cannot_claim_enabled_or_silently_change_mode(projection):
    authority, identity = _inputs()
    identity["expected_state"]["instance"]["encryption"] = projection
    with pytest.raises(materializer.LiveRequestMaterializationError):
        materializer.materialize_live_plans(
            authority_input=authority, identity_center_input=identity
        )


def test_exact_collector_shape_accepts_only_matching_no_kms_observation():
    state = harness._exact_expected_state()
    state["targets"]["identity_center_kms_mode"] = encryption.NOT_OBSERVED
    state["targets"]["identity_center_kms_key_arn"] = None
    state["facts"]["instance"]["encryption"] = None
    assert collector._valid_live_exact_shape(state["facts"], state["targets"])
    state["facts"]["instance"]["encryption"] = encryption.expected_collector_projection(encryption.AWS_OWNED, None)
    assert not collector._valid_live_exact_shape(state["facts"], state["targets"])
