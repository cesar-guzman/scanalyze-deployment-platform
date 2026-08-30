"""Hermetic tests for catalog-bound live layer-contract envelopes."""
from __future__ import annotations

import copy

import pytest

from tooling.live_contract_envelope import (
    LiveContractEnvelopeError,
    build_validated_layer_contract_envelope,
)
from tooling.validate_digest import canonicalize, compute_digest


CUSTOMER_ID = "cust_01J5A1B2C3D4E5F6G7H8J9K0M1"
DEPLOYMENT_ID = "dep_01J5A1B2C3D4E5F6G7H8J9K0M1"
ACCOUNT_ID = "111222333444"
AWS_REGION = "us-east-1"
RELEASE_VERSION = "2026.08.29"
RELEASE_DIGEST = "sha256:" + ("a" * 64)
MODULE_SOURCE_DIGEST = "sha256:" + ("b" * 64)
PRODUCED_AT = "2026-08-29T12:30:00Z"


def _network_outputs() -> dict:
    return {
        "vpc_id": "vpc-0123abcd",
        "private_subnet_ids": {
            "us-east-1a": "subnet-0123abcd",
            "us-east-1b": "subnet-1234abcd",
        },
        "public_subnet_ids": {
            "us-east-1a": "subnet-2345abcd",
            "us-east-1b": "subnet-3456abcd",
        },
        "vpc_cidr_block": "10.10.0.0/16",
        "vpc_endpoint_sg_id": "sg-0123abcd",
    }


def _global_outputs() -> dict:
    return {
        "ecs_execution_role_arn": (
            f"arn:aws:iam::{ACCOUNT_ID}:role/ScanalyzeExecution"
        ),
        "ecs_task_role_arns": {
            "scanalyze-ingest-api": (
                f"arn:aws:iam::{ACCOUNT_ID}:role/ScanalyzeIngest"
            )
        },
    }


def _network_document(*, nested: bool = False) -> dict:
    outputs = _network_outputs()
    if not nested:
        return {
            name: {"sensitive": False, "value": value}
            for name, value in outputs.items()
        }
    return {
        "contract_payload": {
            "sensitive": False,
            "value": {
                "layer": "network",
                "schema_version": "2",
                "outputs": outputs,
            },
        },
        "operator_only_output": {
            "sensitive": False,
            "value": "must-not-cross-the-contract-boundary",
        },
    }


def _build_network(terraform_outputs: dict | None = None) -> dict:
    return build_validated_layer_contract_envelope(
        terraform_outputs=terraform_outputs or _network_document(),
        layer="network",
        customer_id=CUSTOMER_ID,
        deployment_id=DEPLOYMENT_ID,
        account_id=ACCOUNT_ID,
        aws_region=AWS_REGION,
        release_version=RELEASE_VERSION,
        release_digest=RELEASE_DIGEST,
        produced_at=PRODUCED_AT,
        state_key=f"{DEPLOYMENT_ID}/{AWS_REGION}/network/terraform.tfstate",
        module_source_digest=MODULE_SOURCE_DIGEST,
    )


def test_builds_network_envelope_from_root_outputs() -> None:
    envelope = _build_network()

    assert envelope["outputs"] == _network_outputs()
    assert envelope["region"] == AWS_REGION
    assert envelope["scope"] == "regional"


def test_contract_payload_outputs_are_the_exclusive_publishable_boundary() -> None:
    document = _network_document(nested=True)

    envelope = _build_network(document)

    assert envelope["outputs"] == _network_outputs()
    assert "operator_only_output" not in envelope["outputs"]
    assert "must-not-cross-the-contract-boundary" not in repr(envelope)


def test_digest_is_canonical_sha256_of_exact_outputs() -> None:
    document = _network_document(nested=True)
    nested_outputs = document["contract_payload"]["value"]["outputs"]
    document["contract_payload"]["value"]["outputs"] = dict(
        reversed(list(nested_outputs.items()))
    )

    envelope = _build_network(document)

    assert envelope["contract_digest"] == compute_digest(
        canonicalize(_network_outputs())
    )


def test_sensitive_root_output_rejects_without_echoing_value() -> None:
    secret = "never-echo-this-sensitive-value"
    document = _network_document(nested=True)
    document["ignored_but_sensitive"] = {"sensitive": True, "value": secret}

    with pytest.raises(LiveContractEnvelopeError) as caught:
        _build_network(document)

    assert "sensitive value" in str(caught.value)
    assert secret not in str(caught.value)


def test_output_schema_mismatch_is_sanitized() -> None:
    rejected_value = "a-private-invalid-vpc-identifier"
    document = _network_document()
    document["vpc_id"]["value"] = rejected_value

    with pytest.raises(LiveContractEnvelopeError) as caught:
        _build_network(document)

    assert "contract outputs schema validation failed" in str(caught.value)
    assert rejected_value not in str(caught.value)


def test_envelope_schema_mismatch_is_sanitized() -> None:
    rejected_customer_id = "private-invalid-customer-identifier"

    with pytest.raises(LiveContractEnvelopeError) as caught:
        build_validated_layer_contract_envelope(
            terraform_outputs=_network_document(),
            layer="network",
            customer_id=rejected_customer_id,
            deployment_id=DEPLOYMENT_ID,
            account_id=ACCOUNT_ID,
            aws_region=AWS_REGION,
            release_version=RELEASE_VERSION,
            release_digest=RELEASE_DIGEST,
            produced_at=PRODUCED_AT,
            state_key=f"{DEPLOYMENT_ID}/{AWS_REGION}/network/terraform.tfstate",
            module_source_digest=MODULE_SOURCE_DIGEST,
        )

    assert "contract envelope schema validation failed" in str(caught.value)
    assert rejected_customer_id not in str(caught.value)


@pytest.mark.parametrize(
    ("field", "value"),
    (("layer", "platform"), ("schema_version", "1")),
)
def test_contract_payload_must_match_catalog_layer_and_version(
    field: str,
    value: str,
) -> None:
    document = _network_document(nested=True)
    document["contract_payload"]["value"][field] = value

    with pytest.raises(LiveContractEnvelopeError, match="contract_payload"):
        _build_network(document)


def test_metadata_is_bound_to_the_single_catalog_contract() -> None:
    envelope = _build_network(_network_document(nested=True))

    assert envelope["schema_version"] == "2"
    assert envelope["output_schema_version"] == "network/v2"
    assert envelope["producer"] == "roots/network"
    assert envelope["scope"] == "regional"
    assert envelope["terraform_workspace"] == "default"


def test_global_contract_serializes_global_not_operational_aws_region() -> None:
    terraform_document = {
        name: {"sensitive": False, "value": value}
        for name, value in _global_outputs().items()
    }

    envelope = build_validated_layer_contract_envelope(
        terraform_outputs=terraform_document,
        layer="global",
        customer_id=CUSTOMER_ID,
        deployment_id=DEPLOYMENT_ID,
        account_id=ACCOUNT_ID,
        aws_region=AWS_REGION,
        release_version=RELEASE_VERSION,
        release_digest=RELEASE_DIGEST,
        produced_at=PRODUCED_AT,
        state_key=f"{DEPLOYMENT_ID}/global/terraform.tfstate",
        module_source_digest=MODULE_SOURCE_DIGEST,
    )

    assert envelope["region"] == "global"
    assert envelope["scope"] == "global"
    assert AWS_REGION not in repr(envelope)


def test_rejects_state_key_outside_catalog_scope() -> None:
    document = copy.deepcopy(_network_document())

    with pytest.raises(LiveContractEnvelopeError, match="state_key"):
        build_validated_layer_contract_envelope(
            terraform_outputs=document,
            layer="network",
            customer_id=CUSTOMER_ID,
            deployment_id=DEPLOYMENT_ID,
            account_id=ACCOUNT_ID,
            aws_region=AWS_REGION,
            release_version=RELEASE_VERSION,
            release_digest=RELEASE_DIGEST,
            produced_at=PRODUCED_AT,
            state_key=f"{DEPLOYMENT_ID}/network/terraform.tfstate",
            module_source_digest=MODULE_SOURCE_DIGEST,
        )
