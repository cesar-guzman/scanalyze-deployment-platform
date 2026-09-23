"""GUG-431 synthetic transport tests; no runner, cloud or publication execution."""
from __future__ import annotations

import base64
import copy
import json
import os
from pathlib import Path

import pytest
import yaml

from tests.test_deployment import test_nonprod_live_input_materializer as legacy
from tooling.authorize_deployment_backend import AuthorizationError, canonical_digest
from tooling.nonprod_live_input_materializer import (
    INFRASTRUCTURE_VARIABLES, LiveInputMaterializationError,
    MAX_SEALED_REQUEST_BYTES, _json_bytes, bind_live_infrastructure,
    materialize_live_inputs, merge_live_infrastructure_variables,
    persist_materialized_live_inputs, read_live_infrastructure_source,
    revalidate_private_root_at_action_time,
    stable_sealed_request_digest, validate_materialized_live_inputs,
)
from tooling.nonprod_live_controller import (
    _post_apply_observe_command, load_live_input_package,
)
from tooling.nonprod_live_orchestrator import build_plan_intent
from tooling.release_policy_gate import (
    build_deployment_projection, canonical_digest as release_digest,
)
from scripts.deployment.contract_projection import expected_resolvable_contracts


ROOT = Path(__file__).resolve().parents[2]


def _bundle() -> dict:
    return {
        name: json.loads((ROOT / "fixtures/valid" / filename).read_text())
        for name, filename in (
            ("manifest", "release-v2-complete.synthetic.json"),
            ("attestation", "release-attestation-v2-complete.synthetic.json"),
            ("trust_policy", "release-trust-policy-v1-synthetic.json"),
        )
    }


def _selection(target: dict, projection: dict, layer: str) -> dict:
    account = target["account_id"]
    region = target["region"]
    document = {
        "schema_version": "1", "record_type": "deployment_infrastructure_selection",
        **{key: target[key] for key in (
            "customer_id", "deployment_id", "account_id", "region", "environment",
        )},
        "partition": "aws", "layer": layer,
        "target_digest": target["record_digest"],
        "release_digest": canonical_digest(projection),
        "selections": {
            "internal_certificate_arn": {
                "arn": f"arn:aws:acm:{region}:{account}:certificate/11111111-1111-4111-8111-111111111111",
                "target_layer": "platform",
            },
            "api_access_log_group_arn": {
                "arn": f"arn:aws:logs:{region}:{account}:log-group:/synthetic/api-access",
                "target_layer": "edge-identity",
            },
            "route53_zone_id": {"zone_id": "Z1111111111111", "target_layer": "edge"},
        },
    }
    for item in document["selections"].values():
        item["description"] = "Synthetic transport fixture"
    document["record_digest"] = canonical_digest(document)
    return document


def _binding_inputs(layer: str = "platform") -> dict:
    target = legacy._sources("staging")["target_record"]
    bundle = _bundle()
    policy_digest = release_digest(bundle["trust_policy"])
    projection = build_deployment_projection(
        bundle["manifest"], bundle["attestation"], bundle["trust_policy"],
        target="staging", expected_policy_digest=policy_digest, evaluated_at=legacy.NOW,
    )
    selection = _selection(target, projection, layer)
    bindings = {
        "schema_version": "1", "record_type": "live_infrastructure_bindings",
        "layer": layer, "target_digest": target["record_digest"],
        "selection_digest": selection["record_digest"],
        "release_manifest_digest": projection["release_manifest_digest"],
        "release_policy_digest": policy_digest,
        "release_projection_digest": canonical_digest(projection),
        "release_version": projection["release_version"],
    }
    return {
        "selection": selection, "release_bundle": bundle, "bindings": bindings,
        "expected_bindings_digest": canonical_digest(bindings), "target": target,
        "layer": layer, "release_digest": projection["release_manifest_digest"],
        "now": legacy.NOW,
    }


def _output_fixture(filename: str) -> dict:
    text = (ROOT / "fixtures/valid" / filename).read_text()
    for old, new in (
        ("123456789012", legacy.DESTINATION_ACCOUNT_ID),
        ("cust_01ARZ3NDEKTSV4RRFFQ69G5FAV", legacy.CUSTOMER_ID),
        ("dep_01ARZ3NDEKTSV4RRFFQ69G5FAV", legacy.DEPLOYMENT_ID),
    ):
        text = text.replace(old, new)
    return json.loads(text)


def _sealed_v2(layer: str = "platform") -> tuple[dict, dict, dict]:
    inputs = _binding_inputs(layer)
    sealed = legacy._sealed_request("staging")
    sealed["schema_version"] = "2"
    release = sealed["release_bindings"]
    for key in ("release_version", "release_policy_digest", "release_projection_digest"):
        release[key] = inputs["bindings"][key]
    release["release_bundle_digest"] = canonical_digest(inputs["release_bundle"])
    release["infrastructure_selection_digest"] = inputs["selection"]["record_digest"]
    sealed["sources"]["infrastructure_selection"] = inputs["selection"]
    resolution = sealed["sources"]["contract_resolution"]
    resolution.update(consumer_layer=layer, release_version=release["release_version"],
                      release_digest=inputs["release_digest"])
    catalog = json.loads((ROOT / "deployment/contract-catalog.v1.json").read_text())
    dag = yaml.safe_load((ROOT / "deployment/layers.yaml").read_text())
    account = legacy.DESTINATION_ACCOUNT_ID
    network = {
        "vpc_id": "vpc-0123456789abcdef0", "vpc_cidr_block": "10.0.0.0/16",
        "private_subnet_ids": {"us-east-1a": "subnet-0123456789abcdef0"},
        "public_subnet_ids": {"us-east-1a": "subnet-0123456789abcdef1"},
        "vpc_endpoint_sg_id": "sg-0123456789abcdef0",
    }
    platform = {
        "ecs_cluster_arn": f"arn:aws:ecs:us-east-1:{account}:cluster/synthetic",
        "ecs_cluster_name": "synthetic",
        "alb_arn": f"arn:aws:elasticloadbalancing:us-east-1:{account}:loadbalancer/app/synthetic/0123456789abcdef",
        "alb_dns_name": "synthetic.invalid",
        "alb_listener_arn": f"arn:aws:elasticloadbalancing:us-east-1:{account}:listener/app/synthetic/0123456789abcdef/0123456789abcdef",
        "alb_security_group_id": "sg-0123456789abcdef0",
    }
    outputs = {
        "network/v2": network, "platform/v2": platform,
        "services/v2": {
            "service_arns": {"ingest": f"arn:aws:ecs:us-east-1:{account}:service/synthetic/ingest"},
            "task_definition_arns": {"ingest": f"arn:aws:ecs:us-east-1:{account}:task-definition/synthetic:1"},
            "target_group_arns": {"ingest": f"arn:aws:elasticloadbalancing:us-east-1:{account}:targetgroup/synthetic/0123456789abcdef"},
        },
        "identity-control-plane/v1": _output_fixture("contract-identity-control-plane-v1.json"),
        "edge-identity/v2": _output_fixture("contract-edge-identity-v2.json"),
    }
    evidence = []
    for contract_id in sorted(expected_resolvable_contracts(dag, catalog, layer)):
        producer = catalog["contracts"][contract_id]["producer"]
        evidence.append({
            "schema_version": "2", "customer_id": legacy.CUSTOMER_ID,
            "deployment_id": legacy.DEPLOYMENT_ID, "aws_account_id": account,
            "region": legacy.REGION, "scope": "regional", "layer": producer,
            "producer": f"roots/{producer}", "release_version": release["release_version"],
            "release_digest": inputs["release_digest"], "output_schema_version": contract_id,
            "outputs": outputs[contract_id], "contract_digest": canonical_digest(outputs[contract_id]),
            "produced_at": "2026-08-28T20:03:00Z", "terraform_workspace": "default",
            "state_key": f"{legacy.DEPLOYMENT_ID}/us-east-1/{producer}/terraform.tfstate",
            "module_source_digest": legacy._sha("5"),
        })
    resolution["required_contracts"] = evidence
    resolution["resolution_digest"] = canonical_digest({k: v for k, v in resolution.items() if k != "resolution_digest"})
    sealed["sealed_request_digest"] = stable_sealed_request_digest(sealed)
    claim = legacy._claim(sealed_request=sealed, environment="staging")
    claim.update(layer=layer, release_digest=inputs["release_digest"])
    claim["deployment_request"].update(target_layer=layer, release_digest=inputs["release_digest"])
    claim["deployment_request_digest"] = canonical_digest(claim["deployment_request"])
    claim["claim_digest"] = canonical_digest({k: v for k, v in claim.items() if k != "claim_digest"})
    return sealed, claim, inputs["release_bundle"]


def _stage_bundle(root: Path, bundle: dict) -> Path:
    root.mkdir(mode=0o700, exist_ok=True)
    path = root / "release-bundle.json"
    path.write_bytes(_json_bytes(bundle, compact=True))
    path.chmod(0o600)
    return path


def _materialize_v2(root: Path, layer: str = "platform"):
    sealed, claim, bundle = _sealed_v2(layer)
    _stage_bundle(root, bundle)
    materialization = materialize_live_inputs(
        claim=claim, sealed_request=sealed, deployment_id=legacy.DEPLOYMENT_ID,
        layer=layer, operation="plan", claim_digest=claim["claim_digest"],
        private_root=root, runtime_environment=legacy._runtime(), now=legacy.NOW,
    )
    return materialization, sealed, claim


def _load_package(root: Path, result, claim: dict):
    # Repository custody is an external prerequisite; validate_claim and every
    # materialized source/hash check remain real. Never create or commit a claim.
    with pytest.MonkeyPatch.context() as patch:
        patch.setattr("tooling.nonprod_live_controller.load_repository_claim",
                      lambda **_kwargs: copy.deepcopy(claim))
        return load_live_input_package(
            private_root=root, operation="plan", deployment_id=legacy.DEPLOYMENT_ID,
            execution_id=legacy.EXECUTION_ID, change_id=legacy.CHANGE_ID, layer=claim["layer"],
            main_sha=legacy.WORKFLOW_SHA, region=legacy.REGION,
            claim_digest=claim["claim_digest"], receipt_digest=result.receipt["receipt_digest"],
            now=legacy.NOW,
        )


@pytest.mark.parametrize("layer", INFRASTRUCTURE_VARIABLES)
def test_real_signed_binding_emits_exactly_one_root_variable(layer: str) -> None:
    inputs = _binding_inputs(layer)
    assert set(bind_live_infrastructure(**inputs)) == {INFRASTRUCTURE_VARIABLES[layer]}
    merged = merge_live_infrastructure_variables({"existing": [False, 0]}, **inputs)
    assert merged["existing"] == [False, 0]
    with pytest.raises(LiveInputMaterializationError, match="COLLISION"):
        merge_live_infrastructure_variables({INFRASTRUCTURE_VARIABLES[layer]: "old"}, **inputs)


@pytest.mark.parametrize("layer", INFRASTRUCTURE_VARIABLES)
def test_complete_v2_package_and_plan_observe_use_identical_pinned_sources(tmp_path: Path, layer: str) -> None:
    root = tmp_path / "private"
    result, sealed, claim = _materialize_v2(root, layer)
    assert len(_json_bytes(sealed, compact=True)) <= MAX_SEALED_REQUEST_BYTES
    assert len(base64.b64encode(_json_bytes(sealed, compact=True))) <= 48_000
    assert (root / "release-bundle.json").stat().st_size <= MAX_SEALED_REQUEST_BYTES
    persist_materialized_live_inputs(private_root=root, materialization=result)
    validate_materialized_live_inputs(private_root=root, expected=result)
    package = _load_package(root, result, claim)
    assert result.receipt["schema_version"] == "2"
    assert result.receipt["source_count"] == 11
    bindings = {**package.bindings, "state_status": "ABSENT", "state_lineage": None, "state_serial": None}
    plan = build_plan_intent(context=package.context, expected_bindings=bindings,
                             plan_inputs=package.plan_inputs)["command"]["argv"]
    observe = _post_apply_observe_command(package, plan_record=package.bindings,
                                         plan_dir=root / "materialized/plan")
    for key in ("infrastructure_selection", "release_bundle", "infrastructure_bindings",
                "expected_infrastructure_bindings_digest"):
        flag = "--" + key.replace("_", "-")
        assert plan[plan.index(flag) + 1] == observe[observe.index(flag) + 1] == package.plan_inputs[key]
    # The staged slot is not an execution source after persistence.
    (root / "release-bundle.json").write_text("{}")
    assert _load_package(root, result, claim).plan_inputs == package.plan_inputs


@pytest.mark.parametrize("field", ["customer_id", "deployment_id", "account_id", "region", "environment", "layer"])
def test_rehashed_selection_cannot_change_reviewed_target_or_layer(field: str) -> None:
    inputs = _binding_inputs()
    inputs["selection"][field] = {"account_id": "444555666777", "region": "us-west-2",
                                 "environment": "production", "layer": "edge"}.get(field, "wrong")
    selection = inputs["selection"]
    selection["record_digest"] = canonical_digest({k: v for k, v in selection.items() if k != "record_digest"})
    inputs["bindings"]["selection_digest"] = selection["record_digest"]
    inputs["expected_bindings_digest"] = canonical_digest(inputs["bindings"])
    with pytest.raises(LiveInputMaterializationError):
        bind_live_infrastructure(**inputs)


@pytest.mark.parametrize("mutation", ["signature", "signer", "policy", "manifest", "projection", "version", "extra-bundle", "inline-projection"])
def test_signature_policy_and_projection_remain_independently_bound(mutation: str) -> None:
    inputs = _binding_inputs()
    bundle, bindings = inputs["release_bundle"], inputs["bindings"]
    if mutation == "signature":
        bundle["attestation"]["signature"]["value"] = base64.b64encode(b"invalid").decode()
    elif mutation == "signer":
        bundle["attestation"]["signature"]["identity"] += "/untrusted"
    elif mutation == "policy":
        bundle["trust_policy"]["allowed_signers"][0]["identity"] += "/untrusted"
        bindings["release_policy_digest"] = release_digest(bundle["trust_policy"])
    elif mutation == "manifest":
        bundle["manifest"]["release_version"] = "tampered"
        bundle["manifest"]["release_manifest_digest"] = release_digest(bundle["manifest"], omit_fields={"release_manifest_digest"})
    elif mutation == "projection":
        bindings["release_projection_digest"] = legacy._sha("0")
    elif mutation == "version":
        bindings["release_version"] = "tampered"
    else:
        bundle["projection" if mutation == "inline-projection" else "extra"] = {}
    inputs["expected_bindings_digest"] = canonical_digest(bindings)
    with pytest.raises(LiveInputMaterializationError):
        bind_live_infrastructure(**inputs)


@pytest.mark.parametrize("defect", ["missing", "symlink", "hardlink", "mode", "duplicate", "oversize", "array", "nonfinite"])
def test_private_bundle_custody_and_strict_json(tmp_path: Path, defect: str) -> None:
    root = tmp_path / "private"
    path = _stage_bundle(root, _bundle())
    if defect == "missing":
        path.unlink()
    elif defect == "symlink":
        path.rename(root / "other.json")
        path.symlink_to(root / "other.json")
    elif defect == "hardlink":
        os.link(path, root / "other.json")
    elif defect == "mode":
        path.chmod(0o644)
    else:
        path.write_text({"duplicate": '{"a":1,"a":2}', "oversize": " " * 36_001,
                         "array": "[]", "nonfinite": '{"a":NaN}'}[defect])
    with pytest.raises(LiveInputMaterializationError, match="INFRASTRUCTURE_SOURCE_INVALID"):
        read_live_infrastructure_source(path)


@pytest.mark.parametrize("source", ["release_bundle", "infrastructure_selection", "infrastructure_bindings"])
def test_persisted_source_tampering_is_denied(tmp_path: Path, source: str) -> None:
    root = tmp_path / "private"
    result, _, claim = _materialize_v2(root)
    persist_materialized_live_inputs(private_root=root, materialization=result)
    path = root / "materialized/sources" / (source.replace("_", "-") + ".json")
    document = json.loads(path.read_text())
    document["tampered"] = True
    path.write_bytes(_json_bytes(document, compact=True))
    with pytest.raises(AuthorizationError, match="materialized source digest mismatch"):
        _load_package(root, result, claim)


def test_invalid_external_descriptor_digest_is_denied() -> None:
    inputs = _binding_inputs()
    inputs["expected_bindings_digest"] = legacy._sha("f")
    with pytest.raises(LiveInputMaterializationError):
        bind_live_infrastructure(**inputs)


def test_action_time_rebuild_requires_the_original_pinned_slot_to_remain_stable(tmp_path: Path) -> None:
    root = tmp_path / "private"
    result, sealed, claim = _materialize_v2(root)
    persist_materialized_live_inputs(private_root=root, materialization=result)
    sealed_path = root / "sealed-request.json"
    sealed_path.write_bytes(_json_bytes(sealed, compact=True))
    sealed_path.chmod(0o600)
    kwargs = {
        "private_root": root, "deployment_id": legacy.DEPLOYMENT_ID,
        "layer": "platform", "operation": "plan", "claim_digest": claim["claim_digest"],
        "environment": legacy._runtime(), "now": legacy.NOW,
    }
    with pytest.MonkeyPatch.context() as patch:
        patch.setattr("tooling.nonprod_live_input_materializer.load_repository_claim",
                      lambda **_kwargs: copy.deepcopy(claim))
        assert revalidate_private_root_at_action_time(**kwargs).receipt == result.receipt
        (root / "release-bundle.json").write_text("{}")
        with pytest.raises(LiveInputMaterializationError, match="INFRASTRUCTURE_BUNDLE_DIGEST_MISMATCH"):
            revalidate_private_root_at_action_time(**kwargs)
