"""Offline, independently pinned OAC transition for the existing storage owner.

The transition is desired configuration, never an installation receipt. The
original foundation receipt remains immutable and current observations expire.
"""
from __future__ import annotations

import argparse
from datetime import UTC, datetime
from pathlib import Path

import jsonschema

from tooling.application_storage_foundation import (
    ROOT, TUPLE_FIELDS, _fresh, _require, _schema, _template, digest,
    evaluate_live_evidence, frontend_policy, record_digest, verify_receipt,
)
from tooling.authorize_deployment_backend import load_json_strict
from tooling.destination_baseline_package import write_package
from tooling.ssm_contract_live_io import canonical_parameter_name
from tooling.workload_foundation import canonical_bytes

EDGE_PINS = {"edge_envelope_digest", "edge_locator_digest", "edge_readback_digest", "release_version", "release_digest"}


def verify_edge(identity: dict, envelope: dict, locator: dict, observation: dict, pins: dict, *, evaluated_at: str) -> None:
    """Verify full envelope custody and separate actual distribution/OAC readback."""
    _require(isinstance(pins, dict) and set(pins) == EDGE_PINS, "storage edge pins are incomplete")
    _schema(observation, "edge-readback")
    envelope_schema = load_json_strict(ROOT / "schemas/layer-contract.v2.schema.json")
    output_schema = load_json_strict(ROOT / "schemas/contract-edge.v2.schema.json")
    try:
        jsonschema.Draft202012Validator(envelope_schema, format_checker=jsonschema.FormatChecker()).validate(envelope)
        jsonschema.Draft202012Validator(output_schema).validate(envelope["outputs"])
    except (jsonschema.ValidationError, KeyError, TypeError) as error:
        raise ValueError("storage edge envelope shape is invalid") from error
    _require(identity["aws_partition"] == "aws", "storage OAC currently requires the commercial AWS partition")
    _require(envelope["customer_id"] == identity["customer_id"] and envelope["deployment_id"] == identity["deployment_id"]
             and envelope["aws_account_id"] == identity["account_id"] and envelope["region"] == "global"
             and envelope["scope"] == "global" and envelope["layer"] == "edge" and envelope["producer"] == "roots/edge"
             and envelope["output_schema_version"] == "edge/v2" and envelope["terraform_workspace"] == "default"
             and envelope["state_key"] == f"{identity['deployment_id']}/edge/terraform.tfstate"
             and envelope["release_digest"] == pins["release_digest"] and envelope["release_version"] == pins["release_version"],
             "storage edge envelope target or release mismatch")
    _require(digest(envelope) == pins["edge_envelope_digest"] and digest(envelope["outputs"]) == envelope["contract_digest"],
             "storage edge envelope independent digest mismatch")
    catalog = load_json_strict(ROOT / "deployment/contract-catalog.v1.json")
    record = catalog["contracts"]["edge/v2"]
    _require(record["authority"] == "terraform-root" and record["producer"] == "edge" and record["scope"] == "global"
             and record["output_schema"] == "schemas/contract-edge.v2.schema.json" and record["transport"]["kind"] == "ssm",
             "storage edge catalog ownership mismatch")
    name = canonical_parameter_name(path_template=record["transport"]["path_template"], contract_id="edge/v2",
                                    deployment_id=identity["deployment_id"], release_digest=envelope["release_digest"],
                                    contract_digest=envelope["contract_digest"])
    _require(locator == {"name": name, "arn": f"arn:aws:ssm:{identity['region']}:{identity['account_id']}:parameter{name}", "version": 1}
             and type(locator["version"]) is int and digest(locator) == pins["edge_locator_digest"],
             "storage edge exact immutable locator mismatch")
    _require(all(observation[field] == identity[field] for field in TUPLE_FIELDS)
             and observation["readback_digest"] == record_digest(observation, "readback_digest") == pins["edge_readback_digest"],
             "storage edge readback independent digest or tuple mismatch")
    _fresh(observation["observed_at"], evaluated_at)
    actual = observation["distribution"]
    outputs = envelope["outputs"]
    _require(actual["id"] == outputs["cloudfront_distribution_id"] and actual["arn"] == outputs["cloudfront_distribution_arn"]
             and actual["arn"] == f"arn:aws:cloudfront::{identity['account_id']}:distribution/{actual['id']}"
             and actual["domain_name"] == outputs["cloudfront_domain_name"]
             and actual["tags"] == {"deployment_id": identity["deployment_id"], "managed_by": "terraform", "layer": "edge"},
             "storage actual distribution identity mismatch")
    domain = f"scanalyze-{identity['account_id']}-frontend.s3.{identity['region']}.amazonaws.com"
    oac_id = observation["origin_access_control"]["id"]
    _require(actual["origins"] == {
        "s3-frontend": {"domain_name": domain, "origin_path": f"/releases/{identity['deployment_id']}",
                        "origin_access_control_id": oac_id, "origin_access_identity": ""},
        "s3-runtime-config": {"domain_name": domain, "origin_path": f"/{identity['deployment_id']}",
                              "origin_access_control_id": oac_id, "origin_access_identity": ""},
    }, "storage actual frontend origins or OAC mismatch")


def _transition(receipt: dict, envelope: dict, locator: dict, observation: dict, initial_edge_readback_digest: str) -> dict:
    identity = {field: receipt[field] for field in TUPLE_FIELDS}
    distribution = observation["distribution"]
    value = {
        "schema_version": "1", "record_type": "application_storage_oac_transition",
        "foundation_receipt_digest": receipt["contract_digest"],
        "edge_envelope_digest": digest(envelope), "edge_locator_digest": digest(locator),
        "initial_edge_readback_digest": initial_edge_readback_digest,
        "release_digest": envelope["release_digest"], "release_version": envelope["release_version"],
        "distribution_id": distribution["id"], "distribution_arn": distribution["arn"],
        "origin_access_control_id": observation["origin_access_control"]["id"],
        "previous_template_sha256": receipt["template_sha256"],
        "template_sha256": digest(_template(identity, receipt["request_digest"], distribution["arn"])),
        "previous_policy_sha256": receipt["frontend_bucket"]["policy_sha256"],
        "policy_sha256": digest(frontend_policy(identity, distribution["arn"])),
    }
    value["transition_digest"] = record_digest(value, "transition_digest")
    return value


def build_oac_package(receipt: dict, expected_receipt_digest: str, expected_tuple: dict,
                      storage_readback: dict, expected_storage_readback_digest: str,
                      edge_envelope: dict, edge_locator: dict, edge_readback: dict,
                      expected_edge: dict, *, evaluated_at: str) -> dict[str, bytes]:
    durable = verify_receipt(receipt, expected_receipt_digest, expected_tuple)
    evaluate_live_evidence(durable, expected_receipt_digest, expected_tuple, storage_readback,
                          expected_storage_readback_digest, evaluated_at=evaluated_at,
                          application_storage_access={"phase": "foundation"}, expected_application_storage_access={"phase": "foundation"})
    verify_edge(expected_tuple, edge_envelope, edge_locator, edge_readback, expected_edge, evaluated_at=evaluated_at)
    transition = _transition(durable, edge_envelope, edge_locator, edge_readback, expected_edge["edge_readback_digest"])
    _schema(transition, "oac-transition")
    template = _template(expected_tuple, durable["request_digest"], transition["distribution_arn"])
    return {"cfn-application-storage-oac.json": canonical_bytes(template),
            "application-storage-oac-transition.json": canonical_bytes(transition)}


def verify_access(receipt: dict, identity: dict, access: dict, pins: dict, *, evaluated_at: str) -> tuple[str | None, str]:
    _schema(access, "access")
    _schema(pins, "access-pins")
    _require(access["phase"] == pins["phase"], "storage phase disagrees with protected phase pin")
    if pins["phase"] == "foundation":
        return None, receipt["template_sha256"]
    verify_edge(identity, access["edge_envelope"], access["edge_locator"], access["edge_readback"],
                {field: pins[field] for field in EDGE_PINS}, evaluated_at=evaluated_at)
    transition = access["transition"]
    _schema(transition, "oac-transition")
    _require(transition["transition_digest"] == record_digest(transition, "transition_digest") == pins["transition_digest"],
             "storage transition independent digest mismatch")
    expected = _transition(receipt, access["edge_envelope"], access["edge_locator"], access["edge_readback"],
                           transition["initial_edge_readback_digest"])
    _require(canonical_bytes(transition) == canonical_bytes(expected), "storage transition changed immutable bindings")
    return transition["distribution_arn"], transition["template_sha256"]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("receipt", "expected-tuple", "storage-readback", "edge-input", "expected-edge", "out-dir"):
        parser.add_argument("--" + name, required=True, type=Path)
    parser.add_argument("--expected-receipt-digest", required=True)
    parser.add_argument("--expected-storage-readback-digest", required=True)
    args = parser.parse_args(argv)
    try:
        edge = load_json_strict(args.edge_input)
        _require(isinstance(edge, dict) and set(edge) == {"edge_envelope", "edge_locator", "edge_readback"}, "storage edge input shape is invalid")
        package = build_oac_package(load_json_strict(args.receipt), args.expected_receipt_digest, load_json_strict(args.expected_tuple),
                                    load_json_strict(args.storage_readback), args.expected_storage_readback_digest,
                                    **edge, expected_edge=load_json_strict(args.expected_edge),
                                    evaluated_at=datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"))
        write_package(package, args.out_dir)
    except (ValueError, TypeError, KeyError, OSError):
        parser.exit(2, "STORAGE_OAC_REJECTED: input or output validation failed\n")
    print("PREPARED_OAC_TRANSITION_REQUIRES_INDEPENDENT_APPROVAL_NOT_INSTALLED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
