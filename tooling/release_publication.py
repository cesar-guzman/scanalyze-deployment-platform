"""Offline copy-by-digest preparation and readback checks; no publication client.

A prepared request is not execution authority. No writer, lease or cloud CLI is
exposed until the protected publication authorization contract is implemented.
"""
from __future__ import annotations

from copy import deepcopy
from datetime import UTC, datetime
from pathlib import Path
import re
from urllib.parse import urlsplit

import jsonschema

from scripts.deployment.contract_projection import load_json, validate_contract
from tooling.application_storage_foundation import evaluate_live_evidence
from tooling.authorize_deployment_backend import canonical_digest as document_digest
from tooling.release_policy_gate import (
    REQUIRED_ARTIFACT_IDS, RUNTIME_ARTIFACT_IDS, SERVICE_ARTIFACT_IDS,
    canonical_digest as release_digest, evaluate_release,
)
from tooling.verify_account_ready import verify_account_ready

ROOT = Path(__file__).resolve().parents[1]
TUPLE_FIELDS = ("customer_id", "deployment_id", "account_id", "region", "environment", "aws_partition")
FRONTEND = "scanalyze-frontend-ui"
MAX_AGE_SECONDS = 900
SHA256 = re.compile(r"sha256:[a-f0-9]{64}\Z")
SAFE_SEGMENT = re.compile(r"[A-Za-z0-9_~.-]+\Z")


class PublicationRejected(ValueError):
    """Sanitized failure; never contains source locators or document contents."""


def require(value: bool, code: str) -> None:
    if not value:
        raise PublicationRejected(code)


def record_digest(document: dict, field: str) -> str:
    return document_digest({key: value for key, value in document.items() if key != field})


def _schema(document: dict, name: str) -> None:
    schema = load_json(ROOT / "schemas" / name, "publication verifier schema")
    errors = jsonschema.Draft202012Validator(schema, format_checker=jsonschema.FormatChecker()).iter_errors(document)
    require(next(errors, None) is None, "PUBLICATION_SCHEMA_INVALID")


def _pinned(document: dict, expected: str, *, field: str | None = None) -> None:
    require(isinstance(expected, str) and SHA256.fullmatch(expected) is not None, "EXTERNAL_PIN_INVALID")
    actual = record_digest(document, field) if field else document_digest(document)
    require(actual == expected and (field is None or document.get(field) == expected), "EXTERNAL_PIN_MISMATCH")


def _time(value: str) -> datetime:
    require(isinstance(value, str), "EVIDENCE_TIME_INVALID")
    try:
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise PublicationRejected("EVIDENCE_TIME_INVALID") from None
    require(result.tzinfo is not None, "EVIDENCE_TIME_INVALID")
    return result.astimezone(UTC)


def _now(value: datetime) -> datetime:
    require(isinstance(value, datetime) and value.tzinfo is not None, "EVALUATION_TIME_REQUIRED")
    return value.astimezone(UTC)


def _validate_target(target: dict, anchor: dict, account_ready: dict, identity: dict) -> None:
    _schema(target, "deployment-target.v2.schema.json")
    _schema(anchor, "deployment-target-anchor.v1.schema.json")
    require(anchor == {"schema_version": "1", "deployment_id": target["deployment_id"],
                       "registry_version": target["registry_version"], "record_digest": target["record_digest"]},
            "TARGET_ANCHOR_MISMATCH")
    _pinned(target, anchor["record_digest"], field="record_digest")
    require(target["status"] in {"READY", "ACTIVE"}, "TARGET_NOT_EXECUTABLE")
    require(all(target[field] == identity[field] for field in TUPLE_FIELDS if field != "aws_partition"),
            "TARGET_TUPLE_MISMATCH")
    ready_anchor = {field: identity[field] for field in TUPLE_FIELDS if field != "aws_partition"}
    ready_anchor.update(baseline_version=target["account_ready"]["baseline_version"],
                        expected_contract_digest=target["account_ready"]["contract_digest"])
    schema = load_json(ROOT / "schemas/account-ready.v2.schema.json", "ACCOUNT_READY schema")
    require(verify_account_ready(account_ready, ready_anchor, schema).passed, "ACCOUNT_READY_REJECTED")
    require(target["state_binding"] == {
        field: account_ready["state_infrastructure"][field] for field in ("state_bucket", "state_kms_key")
    }, "TARGET_STATE_BINDING_MISMATCH")


def _segments(key: str) -> list[str]:
    require(isinstance(key, str) and 0 < len(key.encode("utf-8")) <= 1024, "OBJECT_KEY_INVALID")
    parts = key.split("/")
    require(all(part not in {"", ".", ".."} and SAFE_SEGMENT.fullmatch(part) is not None for part in parts),
            "OBJECT_KEY_INVALID")
    return parts


def _content_key(key: str, digest: str, prefix: str) -> None:
    parts = _segments(key)
    require(key.startswith(prefix) and parts.count("sha256") == 1, "DESTINATION_KEY_NOT_BOUND")
    marker = parts.index("sha256")
    require(marker + 2 < len(parts) and parts[marker + 1] == digest.removeprefix("sha256:"),
            "DESTINATION_KEY_DIGEST_MISMATCH")


def _source(artifact: dict) -> None:
    uri = artifact["uri"]
    if artifact["kind"] == "container":
        require(uri.count("@") == 1 and uri.endswith("@" + artifact["digest"]), "SOURCE_IMAGE_INVALID")
        location = urlsplit("//" + uri.rsplit("@", 1)[0])
        require(re.fullmatch(r"[a-z0-9]+(?:[.-][a-z0-9]+)*(?::[1-9][0-9]{0,4})?", location.netloc) is not None,
                "SOURCE_IMAGE_INVALID")
        require(not location.query and not location.fragment, "SOURCE_IMAGE_INVALID")
        _segments(location.path.removeprefix("/"))
    else:
        location = urlsplit(uri)
        require(location.scheme in {"s3", "https"} and bool(location.netloc)
                and location.username is None and location.password is None
                and not location.query and not location.fragment, "SOURCE_ARCHIVE_INVALID")
        _content_key(location.path.removeprefix("/"), artifact["digest"], "")


def prepare_publication(
    operation: dict, *, expected_operation_digest: str,
    release: dict, attestation: dict, trust_policy: dict,
    target: dict, target_anchor: dict, account_ready: dict,
    cicd_contract: dict, storage_receipt: dict, storage_readback: dict,
    storage_access: dict, expected_storage_access: dict, evaluated_at: datetime,
) -> dict:
    """Derive a finite copy plan only after all independently pinned inputs pass.

    The operation contains reviewed requested read scopes and exact archive keys;
    it is not an authorization grant. Live admission must be re-evaluated by a
    future executor at action time, under a separately implemented authority.
    """
    try:
        # All pin checks and projections use one detached snapshot. A caller
        # mutating its input during signature verification cannot alter the plan.
        inputs = deepcopy(dict(operation=operation, release=release, attestation=attestation,
                               trust_policy=trust_policy, target=target, target_anchor=target_anchor,
                               account_ready=account_ready, cicd_contract=cicd_contract,
                               storage_receipt=storage_receipt, storage_readback=storage_readback,
                               storage_access=storage_access, expected_storage_access=expected_storage_access))
        return _prepare(**inputs, expected_operation_digest=expected_operation_digest, evaluated_at=evaluated_at)
    except PublicationRejected:
        raise
    except (ValueError, TypeError, KeyError, AttributeError, OverflowError, RuntimeError):
        raise PublicationRejected("PUBLICATION_ADMISSION_REJECTED") from None


def _prepare(operation: dict, *, expected_operation_digest: str, release: dict,
             attestation: dict, trust_policy: dict, target: dict, target_anchor: dict,
             account_ready: dict, cicd_contract: dict, storage_receipt: dict,
             storage_readback: dict, storage_access: dict, expected_storage_access: dict,
             evaluated_at: datetime) -> dict:
    _schema(operation, "release-publication.v1.schema.json")
    require(operation["schema_version"] == "release-publication-request.v1", "REQUEST_REQUIRED")
    _pinned(operation, expected_operation_digest, field="request_digest")
    now = _now(evaluated_at)
    identity, pins = operation["target"], operation["pins"]
    for document, pin in (
        (release, "release_document_digest"), (attestation, "attestation_document_digest"),
        (target_anchor, "target_anchor_digest"), (cicd_contract, "cicd_contract_document_digest"),
        (storage_access, "storage_access_digest"), (expected_storage_access, "storage_access_pins_digest"),
    ):
        _pinned(document, pins[pin])
    decision = evaluate_release(release, attestation, trust_policy,
                                expected_policy_digest=pins["trust_policy_digest"], evaluated_at=now)
    require(decision.allowed, "RELEASE_POLICY_REJECTED")
    require(decision.manifest_digest == pins["release_manifest_digest"], "SIGNED_RELEASE_PIN_MISMATCH")
    require(release_digest(trust_policy) == pins["trust_policy_digest"], "TRUST_POLICY_PIN_MISMATCH")
    _validate_target(target, target_anchor, account_ready, identity)
    require(operation["promotion_role_arn"] == account_ready["roles"]["promotion"]["arn"], "PROMOTION_ROLE_MISMATCH")
    _, _, outputs, _ = validate_contract(
        cicd_contract, load_json(ROOT / "schemas/layer-contract.v2.schema.json", "CICD envelope schema"),
        catalog=load_json(ROOT / "deployment/contract-catalog.v1.json", "contract catalog"),
        layer="artifact-publication", **{field: identity[field] for field in ("customer_id", "deployment_id", "account_id", "region")},
        release_digest=pins["release_manifest_digest"], release_version=release["release_version"],
        resolved_at=now, max_contract_age_seconds=MAX_AGE_SECONDS, required_contracts={"cicd/v2"},
    )
    require(0 <= (now - _time(cicd_contract["produced_at"])).total_seconds() <= MAX_AGE_SECONDS,
            "CICD_EVIDENCE_NOT_FRESH")
    evaluate_live_evidence(
        storage_receipt, pins["storage_receipt_digest"], identity,
        storage_readback, pins["storage_readback_digest"], evaluated_at=now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        application_storage_access=storage_access, expected_application_storage_access=expected_storage_access,
    )
    require(outputs["artifact_kms_key_arn"] == storage_receipt["keys"]["cicd_artifacts"]["key_arn"],
            "CICD_STORAGE_KEY_MISMATCH")
    bucket = outputs["artifact_bucket_name"]
    require(bucket == identity["deployment_id"].replace("_", "-").lower() + "-cicd-artifacts",
            "CICD_BUCKET_SCOPE_MISMATCH")
    require(set(outputs["ecr_repository_urls"]) == set(outputs["ecr_repository_arns"]) == SERVICE_ARTIFACT_IDS,
            "CICD_REPOSITORY_INVENTORY_MISMATCH")
    artifacts = release["artifacts"]
    require(set(operation["source_reads"]) == REQUIRED_ARTIFACT_IDS, "SOURCE_SCOPE_INVENTORY_MISMATCH")
    require(set(operation["archive_keys"]) == RUNTIME_ARTIFACT_IDS, "ARCHIVE_KEY_INVENTORY_MISMATCH")
    copies = []
    for artifact_id in sorted(REQUIRED_ARTIFACT_IDS):
        artifact = artifacts[artifact_id]
        source = {"uri": artifact["uri"], "digest": artifact["digest"]}
        require(operation["source_reads"][artifact_id] == source, "SOURCE_READ_SCOPE_MISMATCH")
        _source(artifact)
        if artifact_id in SERVICE_ARTIFACT_IDS:
            repository = identity["deployment_id"].replace("_", "-").lower() + "/" + artifact_id
            url = f"{identity['account_id']}.dkr.ecr.{identity['region']}.amazonaws.com/{repository}"
            arn = f"arn:aws:ecr:{identity['region']}:{identity['account_id']}:repository/{repository}"
            require(outputs["ecr_repository_urls"][artifact_id] == url and outputs["ecr_repository_arns"][artifact_id] == arn,
                    "CICD_REPOSITORY_SCOPE_MISMATCH")
            destination = {"kind": "ecr", "repository_arn": arn, "repository_url": url}
        else:
            key = operation["archive_keys"][artifact_id]
            prefix = (f"releases/{identity['deployment_id']}/" if artifact_id == FRONTEND
                      else f"deployments/{identity['deployment_id']}/artifacts/")
            _content_key(key, artifact["digest"], prefix)
            require(artifact_id == FRONTEND or artifact["media_type"] == "application/zip", "LAMBDA_ARCHIVE_MEDIA_UNSUPPORTED")
            destination = {
                "kind": "s3", "bucket": storage_receipt["frontend_bucket"]["name"] if artifact_id == FRONTEND else bucket,
                "key": key, "sse_algorithm": "AES256" if artifact_id == FRONTEND else "aws:kms",
                "kms_key_arn": None if artifact_id == FRONTEND else outputs["artifact_kms_key_arn"],
            }
        copies.append({"artifact_id": artifact_id, "kind": artifact["kind"], "digest": artifact["digest"],
                       "media_type": artifact["media_type"], "source": source, "destination": destination})
    require(len({document_digest(row["destination"]) for row in copies}) == len(copies), "DESTINATION_COLLISION")
    plan = {
        "schema_version": "release-publication-plan.v1", "status": "PREPARED_NOT_PUBLISHED",
        "execution_requirement": "AUTHORIZATION_CONTRACT_REQUIRED", "frontend_status": "ASSETS_NOT_EXPANDED",
        "request_digest": expected_operation_digest, "change_id": operation["change_id"],
        "target": deepcopy(identity), "pins": deepcopy(pins), "promotion_role_arn": operation["promotion_role_arn"],
        "release_version": release["release_version"], "evaluated_at": now.isoformat().replace("+00:00", "Z"),
        "copy_mode": "copy-by-digest", "rebuild": False, "resign": False, "overwrite": False, "copies": copies,
    }
    plan["plan_digest"] = record_digest(plan, "plan_digest")
    _schema(plan, "release-publication.v1.schema.json")
    return plan


def verify_publication_readback(plan: dict, *, expected_plan_digest: str,
                                readback: dict, expected_readback_digest: str,
                                evaluated_at: datetime) -> dict:
    """Compare independently pinned observations; never issue execution authority."""
    try:
        plan, readback = deepcopy((plan, readback))
        _schema(plan, "release-publication.v1.schema.json")
        _schema(readback, "release-publication.v1.schema.json")
        require(plan["schema_version"] == "release-publication-plan.v1"
                and readback["schema_version"] == "release-publication-readback.v1", "READBACK_DOCUMENT_TYPE_INVALID")
        _pinned(plan, expected_plan_digest, field="plan_digest")
        _pinned(readback, expected_readback_digest, field="readback_digest")
        require(readback["plan_digest"] == expected_plan_digest, "READBACK_PLAN_MISMATCH")
        require(0 <= (_now(evaluated_at) - _time(readback["observed_at"])).total_seconds() <= MAX_AGE_SECONDS,
                "READBACK_NOT_FRESH")
        copies = {row["artifact_id"]: row for row in plan["copies"]}
        observed = {row["artifact_id"]: row for row in readback["observations"]}
        require(len(copies) == len(plan["copies"]) == len(observed) == len(readback["observations"]) == 10
                and set(copies) == set(observed) == REQUIRED_ARTIFACT_IDS, "READBACK_INCOMPLETE")
        for artifact_id, copy in copies.items():
            observation = observed[artifact_id]
            require(observation["destination"] == copy["destination"] and observation["digest"] == copy["digest"],
                    "READBACK_DESTINATION_OR_DIGEST_MISMATCH")
            version = observation["object_version"]
            require((version is None if copy["kind"] == "container" else isinstance(version, str)
                     and 0 < len(version.encode("utf-8")) <= 1024 and version.lower() != "null"
                     and all(ord(character) >= 33 and ord(character) != 127 for character in version)),
                    "READBACK_OBJECT_VERSION_INVALID")
        return {"status": "OBSERVATIONS_MATCH_PLAN_NOT_EXECUTION_AUTHORITY",
                "plan_digest": expected_plan_digest, "readback_digest": expected_readback_digest,
                "artifact_count": 10, "frontend_status": "ASSETS_NOT_EXPANDED"}
    except PublicationRejected:
        raise
    except (ValueError, TypeError, KeyError, AttributeError, OverflowError, RuntimeError):
        raise PublicationRejected("PUBLICATION_READBACK_REJECTED") from None


def build_publication_projection_binding(
    plan: dict, *, expected_plan_digest: str, readback: dict,
    expected_readback_digest: str, evaluated_at: datetime,
) -> dict:
    """Package verified observations for the explicit deployment projection v2.

    No copy is required when the signed sources already name the destinations.
    Pins must come from authenticated external custody. This JSON package does
    not authenticate AWS observations or establish a publication execution claim.
    """
    plan, readback = deepcopy((plan, readback))
    result = verify_publication_readback(
        plan, expected_plan_digest=expected_plan_digest, readback=readback,
        expected_readback_digest=expected_readback_digest, evaluated_at=evaluated_at,
    )
    return {"status": result["status"], "plan": plan, "readback": readback,
            "expected_plan_digest": expected_plan_digest, "expected_readback_digest": expected_readback_digest}


def publication_destination_projection(
    binding: dict, *, manifest: dict, attestation: dict, expected_policy_digest: str,
    expected_target: dict, target: str, evaluated_at: datetime,
) -> dict:
    """Reverify the complete publication binding and derive exact locators.

    Called only after the release signature gate. It preserves signed manifest
    bytes and emits S3 versions separately from keys. The containing projection
    needs an independently authenticated outer pin when transported to a consumer.
    """
    try:
        binding, manifest, attestation, expected_target = deepcopy((binding, manifest, attestation, expected_target))
        require(type(binding) is dict and set(binding) == {
            "status", "plan", "readback", "expected_plan_digest", "expected_readback_digest",
        }, "PUBLICATION_PROJECTION_BINDING_INVALID")
        checked = build_publication_projection_binding(
            binding["plan"], expected_plan_digest=binding["expected_plan_digest"],
            readback=binding["readback"], expected_readback_digest=binding["expected_readback_digest"],
            evaluated_at=evaluated_at,
        )
        require(binding == checked, "PUBLICATION_PROJECTION_BINDING_INVALID")
        plan, readback = checked["plan"], checked["readback"]
        require(type(expected_target) is dict and set(expected_target) == set(TUPLE_FIELDS)
                and plan["target"] == expected_target
                and expected_target["environment"] == ("dev" if target == "sandbox" else target),
                "PUBLICATION_PROJECTION_TARGET_MISMATCH")
        pins = plan["pins"]
        _pinned(manifest, pins["release_document_digest"])
        _pinned(attestation, pins["attestation_document_digest"])
        require(pins["release_manifest_digest"] == manifest["release_manifest_digest"]
                and pins["trust_policy_digest"] == expected_policy_digest
                and plan["release_version"] == manifest["release_version"], "PUBLICATION_PROJECTION_RELEASE_MISMATCH")
        require(plan["promotion_role_arn"] ==
                f"arn:aws:iam::{expected_target['account_id']}:role/ScanalyzeCustomer-Promotion",
                "PUBLICATION_PROJECTION_ROLE_MISMATCH")
        artifacts = manifest["artifacts"]
        require(set(artifacts) == REQUIRED_ARTIFACT_IDS, "PUBLICATION_PROJECTION_INCOMPLETE")
        observations = {row["artifact_id"]: row for row in readback["observations"]}
        services, archives = {}, {}
        for row in plan["copies"]:
            artifact_id, destination = row["artifact_id"], row["destination"]
            artifact = artifacts[artifact_id]
            require(row["kind"] == artifact["kind"] and row["digest"] == artifact["digest"]
                    and row["media_type"] == artifact["media_type"]
                    and row["source"] == {"uri": artifact["uri"], "digest": artifact["digest"]},
                    "PUBLICATION_PROJECTION_ARTIFACT_MISMATCH")
            if artifact_id in SERVICE_ARTIFACT_IDS:
                repository = expected_target["deployment_id"].replace("_", "-").lower() + "/" + artifact_id
                registry = f"{expected_target['account_id']}.dkr.ecr.{expected_target['region']}.amazonaws.com"
                require(destination == {
                    "kind": "ecr", "repository_url": f"{registry}/{repository}",
                    "repository_arn": f"arn:aws:ecr:{expected_target['region']}:{expected_target['account_id']}:repository/{repository}",
                }, "PUBLICATION_PROJECTION_REPOSITORY_MISMATCH")
                services[artifact_id.removeprefix("scanalyze-")] = destination["repository_url"] + "@" + row["digest"]
            else:
                require(destination["kind"] == "s3", "PUBLICATION_PROJECTION_ARCHIVE_INVALID")
                prefix = (f"releases/{expected_target['deployment_id']}/" if artifact_id == FRONTEND
                          else f"deployments/{expected_target['deployment_id']}/artifacts/")
                _content_key(destination["key"], row["digest"], prefix)
                if artifact_id == FRONTEND:
                    require(destination["sse_algorithm"] == "AES256" and destination["kms_key_arn"] is None,
                            "PUBLICATION_PROJECTION_ENCRYPTION_MISMATCH")
                else:
                    require(destination["bucket"] == expected_target["deployment_id"].replace("_", "-").lower() + "-cicd-artifacts"
                            and destination["sse_algorithm"] == "aws:kms"
                            and destination["kms_key_arn"].startswith(
                                f"arn:aws:kms:{expected_target['region']}:{expected_target['account_id']}:key/"),
                            "PUBLICATION_PROJECTION_ENCRYPTION_MISMATCH")
                version = observations[artifact_id]["object_version"]
                require(type(version) is str and 0 < len(version) <= 1024 and version.lower() != "null"
                        and all(33 <= ord(character) <= 126 for character in version),
                        "PUBLICATION_PROJECTION_VERSION_INVALID")
                archives[artifact_id] = {"uri": f"s3://{destination['bucket']}/{destination['key']}",
                                        "digest": row["digest"], "version_id": version}
        return {"service_images": services, "runtime_artifacts": archives, "publication_binding": checked}
    except PublicationRejected:
        raise
    except (ValueError, TypeError, KeyError, AttributeError, OverflowError, RuntimeError):
        raise PublicationRejected("PUBLICATION_PROJECTION_REJECTED") from None
