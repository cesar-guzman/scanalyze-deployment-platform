"""Prepare first-install bootstrap packages in two deterministic phases.

Phase 1 (content): build terminal/workload template bytes from an independently
anchored content request that contains no S3 VersionIds. Child bytes embed only
the content record digest.

Phase 2 (parent): bind already-prepared content hashes to real VersionIds via an
independently anchored publication binding, then materialize the parent stack.
Parent generation never rewrites child or workload bytes.

No AWS calls, state reads, publication, or execution are performed here. S3
version identifiers in a publication binding refer to a separately reviewed
publication; their syntax alone is not evidence that any object was published.
Bucket names are never an input. destination_baseline_package (target/v2) remains
the post-baseline producer and is unchanged by this module.
"""
from __future__ import annotations

import argparse
from copy import deepcopy
from datetime import UTC, datetime
import hashlib as _hashlib
import json as _json
import os
from pathlib import Path
import re
from urllib.parse import quote

import jsonschema
import yaml

from tooling.authorize_deployment_backend import load_json_strict
from tooling.destination_baseline_package import bind_deployment_mappings
from tooling.workload_foundation import build_workload_foundation, canonical_bytes, digest, verify_workload_foundation_receipt


REPO_ROOT = Path(__file__).resolve().parents[1]

CONTENT_ARTIFACT_NAMES = (
    "cfn-terminal-roles.yaml",
    "cfn-workload-foundation.json",
    "workload-foundation.json",
    "content-manifest.json",
)

FULL_ARTIFACT_NAMES = CONTENT_ARTIFACT_NAMES + (
    "cfn-tf-state-backend.yaml",
    "parameters.json",
    "manifest.json",
)


class _TemplateLoader(yaml.SafeLoader):
    pass


def _intrinsic(loader, suffix, node):
    value = (
        loader.construct_scalar(node)
        if isinstance(node, yaml.ScalarNode)
        else loader.construct_sequence(node, deep=True)
        if isinstance(node, yaml.SequenceNode)
        else loader.construct_mapping(node, deep=True)
    )
    return {suffix if suffix == "Ref" else "Fn::" + suffix: value}


_TemplateLoader.add_multi_constructor("!", _intrinsic)


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def _sha(data: bytes) -> str:
    return "sha256:" + _hashlib.sha256(data).hexdigest()


def _canonical_digest(record: dict, digest_key: str) -> str:
    digestible = {key: value for key, value in record.items() if key != digest_key}
    return _sha(
        _json.dumps(digestible, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    )


def _load_template(name: str) -> dict:
    source = REPO_ROOT / "bootstrap" / name
    _require(source.exists() and not source.is_symlink(), f"template {name} is missing")
    return yaml.load(source.read_bytes(), Loader=_TemplateLoader)


def _validate_shared_services(account_id: str, shared_services_account_id: str) -> None:
    _require(
        isinstance(shared_services_account_id, str)
        and re.fullmatch(r"(?!000000000000$)[0-9]{12}", shared_services_account_id) is not None
        and shared_services_account_id != account_id,
        "bootstrap shared-services account is invalid",
    )


def _validate_publication_version(version: str, label: str) -> None:
    _require(
        isinstance(version, str)
        and version.lower() != "null"
        and re.fullmatch(r"[A-Za-z0-9._~+/=-]{1,256}", version) is not None,
        f"bootstrap {label} is invalid",
    )


def _partition_for_region(region: str) -> str:
    if region.startswith("cn-"):
        return "aws-cn"
    if region.startswith("us-gov-"):
        return "aws-us-gov"
    return "aws"


def _verify_content_inputs(
    content: dict,
    anchor: dict,
    expected_content_digest: str,
    bedrock_model_arns: list[str],
) -> None:
    content_schema = load_json_strict(REPO_ROOT / "schemas" / "deployment-bootstrap-content-request.v1.schema.json")
    jsonschema.validate(content, content_schema)
    anchor_schema = load_json_strict(REPO_ROOT / "schemas" / "deployment-bootstrap-content-anchor.v1.schema.json")
    jsonschema.validate(anchor, anchor_schema)

    _require(content.get("schema_version") == "1", "bootstrap content schema version is invalid")
    _require(
        content.get("record_type") == "deployment_bootstrap_content_request",
        "bootstrap content record type is invalid",
    )
    _require("terminal_version_id" not in content, "bootstrap content must not include terminal_version_id")
    _require("workload_version_id" not in content, "bootstrap content must not include workload_version_id")

    computed = _canonical_digest(content, "record_digest")
    _require(computed == expected_content_digest, "bootstrap content external digest mismatch")
    _require(content.get("record_digest") == expected_content_digest, "bootstrap content internal digest mismatch")
    _require(
        anchor
        == {
            "schema_version": "1",
            "deployment_id": content["deployment_id"],
            "record_digest": content["record_digest"],
        },
        "bootstrap content anchor mismatch",
    )
    _require(
        digest(bedrock_model_arns) == content["model_selection_digest"],
        "bootstrap model selection digest mismatch",
    )
    _validate_shared_services(content["account_id"], content["shared_services_account_id"])


def _build_content_templates(
    content: dict,
    expected_content_digest: str,
    bedrock_model_arns: list[str],
) -> tuple[bytes, bytes, dict, str, str]:
    partition = _partition_for_region(content["region"])
    identity = {key: content[key] for key in ("customer_id", "deployment_id", "account_id", "region", "environment")}
    identity["aws_partition"] = partition

    workload, receipt = build_workload_foundation(identity, bedrock_model_arns)
    workload_bytes = canonical_bytes(workload)

    child = _load_template("cfn-terminal-roles.yaml")
    bind_deployment_mappings(child, content["deployment_id"])

    bindings = {
        "CustomerId": content["customer_id"],
        "DeploymentId": content["deployment_id"],
        "Environment": content["environment"],
        "SharedServicesAccountId": content["shared_services_account_id"],
    }
    for name, value in bindings.items():
        child["Parameters"][name]["AllowedValues"] = [value]
        child["Parameters"][name].pop("Default", None)

    child.setdefault("Metadata", {}).setdefault("Scanalyze", {})
    child["Metadata"]["Scanalyze"]["BootstrapRecordDigest"] = expected_content_digest
    child_bytes = canonical_bytes(child)
    return child_bytes, workload_bytes, receipt, _sha(child_bytes), receipt["template_sha256"]


def build_bootstrap_content_package(
    content: dict,
    anchor: dict,
    expected_content_digest: str,
    bedrock_model_arns: list[str],
) -> dict[str, bytes]:
    """Build deterministic pre-publication terminal/workload bytes from content admission."""
    _verify_content_inputs(content, anchor, expected_content_digest, bedrock_model_arns)
    child_bytes, workload_bytes, receipt, child_sha, workload_sha = _build_content_templates(
        content, expected_content_digest, bedrock_model_arns
    )

    artifacts = {
        "cfn-terminal-roles.yaml": child_bytes,
        "cfn-workload-foundation.json": workload_bytes,
        "workload-foundation.json": canonical_bytes(receipt),
    }
    manifest = {
        "schema_version": "1",
        "status": "CONTENT_PREPARED_NOT_PUBLISHED",
        "content_record_digest": expected_content_digest,
        "model_selection_digest": content["model_selection_digest"],
        "workload_foundation_digest": receipt["contract_digest"],
        "terminal_template_sha256": child_sha,
        "workload_template_sha256": workload_sha,
        "artifacts": {name: _sha(value) for name, value in sorted(artifacts.items())},
    }
    artifacts["content-manifest.json"] = canonical_bytes(manifest)
    return artifacts


def _verify_publication_inputs(
    content: dict,
    content_anchor: dict,
    expected_content_digest: str,
    publication: dict,
    publication_anchor: dict,
    expected_publication_digest: str,
    content_artifacts: dict[str, bytes],
    bedrock_model_arns: list[str],
) -> tuple[bytes, bytes, dict]:
    _verify_content_inputs(content, content_anchor, expected_content_digest, bedrock_model_arns)

    publication_schema = load_json_strict(
        REPO_ROOT / "schemas" / "deployment-bootstrap-publication-binding.v1.schema.json"
    )
    jsonschema.validate(publication, publication_schema)
    publication_anchor_schema = load_json_strict(
        REPO_ROOT / "schemas" / "deployment-bootstrap-publication-anchor.v1.schema.json"
    )
    jsonschema.validate(publication_anchor, publication_anchor_schema)

    _require(publication.get("schema_version") == "1", "bootstrap publication schema version is invalid")
    _require(
        publication.get("record_type") == "deployment_bootstrap_publication_binding",
        "bootstrap publication record type is invalid",
    )
    computed = _canonical_digest(publication, "binding_digest")
    _require(computed == expected_publication_digest, "bootstrap publication external digest mismatch")
    _require(
        publication.get("binding_digest") == expected_publication_digest,
        "bootstrap publication internal digest mismatch",
    )
    _require(
        publication_anchor
        == {
            "schema_version": "1",
            "deployment_id": publication["deployment_id"],
            "binding_digest": publication["binding_digest"],
        },
        "bootstrap publication anchor mismatch",
    )
    _require(
        publication["deployment_id"] == content["deployment_id"],
        "bootstrap publication deployment mismatch",
    )
    _require(
        publication["content_record_digest"] == expected_content_digest,
        "bootstrap publication content digest mismatch",
    )
    _validate_publication_version(publication["terminal_version_id"], "terminal_version_id")
    _validate_publication_version(publication["workload_version_id"], "workload_version_id")

    for name in ("cfn-terminal-roles.yaml", "cfn-workload-foundation.json", "workload-foundation.json"):
        _require(name in content_artifacts, f"bootstrap content artifact {name} is missing")

    child_bytes = content_artifacts["cfn-terminal-roles.yaml"]
    workload_bytes = content_artifacts["cfn-workload-foundation.json"]
    receipt = _json.loads(content_artifacts["workload-foundation.json"].decode("utf-8"))

    child_sha = _sha(child_bytes)
    workload_sha = _sha(workload_bytes)
    _require(child_sha == publication["terminal_template_sha256"], "bootstrap terminal template hash mismatch")
    _require(workload_sha == publication["workload_template_sha256"], "bootstrap workload template hash mismatch")

    target_tuple = {
        "customer_id": content["customer_id"],
        "deployment_id": content["deployment_id"],
        "account_id": content["account_id"],
        "region": content["region"],
        "environment": content["environment"],
        "aws_partition": _partition_for_region(content["region"]),
    }
    receipt = verify_workload_foundation_receipt(
        receipt,
        publication["workload_foundation_digest"],
        target_tuple,
    )
    _require(
        receipt["template_sha256"] == publication["workload_template_sha256"],
        "bootstrap workload receipt template hash mismatch",
    )

    # Authority check: supplied child must already carry the content digest; do not rewrite it.
    child_doc = yaml.load(child_bytes, Loader=_TemplateLoader)
    embedded = (
        (child_doc.get("Metadata") or {}).get("Scanalyze") or {}
    ).get("BootstrapRecordDigest")
    _require(embedded == expected_content_digest, "bootstrap child content digest embedding mismatch")
    return child_bytes, workload_bytes, receipt


def build_bootstrap_parent_package(
    content: dict,
    content_anchor: dict,
    expected_content_digest: str,
    publication: dict,
    publication_anchor: dict,
    expected_publication_digest: str,
    content_artifacts: dict[str, bytes],
    bedrock_model_arns: list[str],
) -> dict[str, bytes]:
    """Materialize parent/parameters from a publication binding without mutating content bytes."""
    child_bytes, workload_bytes, receipt = _verify_publication_inputs(
        content,
        content_anchor,
        expected_content_digest,
        publication,
        publication_anchor,
        expected_publication_digest,
        content_artifacts,
        bedrock_model_arns,
    )

    partition = _partition_for_region(content["region"])
    bindings = {
        "CustomerId": content["customer_id"],
        "DeploymentId": content["deployment_id"],
        "Environment": content["environment"],
        "SharedServicesAccountId": content["shared_services_account_id"],
    }
    child_sha = publication["terminal_template_sha256"]
    workload_sha = publication["workload_template_sha256"]

    suffix = "amazonaws.com.cn" if partition == "aws-cn" else "amazonaws.com"
    base = f"https://scanalyze-shared-releases.s3.{content['region']}.{suffix}/"
    terminal_url = (
        f"{base}terminal-roles/sha256/{child_sha.removeprefix('sha256:')}/"
        f"cfn-terminal-roles.yaml?versionId={quote(publication['terminal_version_id'], safe='')}"
    )
    workload_url = (
        f"{base}workload-foundation/sha256/{workload_sha.removeprefix('sha256:')}/"
        f"cfn-workload-foundation.json?versionId={quote(publication['workload_version_id'], safe='')}"
    )

    parent = _load_template("cfn-tf-state-backend.yaml")
    for name, value in bindings.items():
        parent["Parameters"][name]["AllowedValues"] = [value]
        parent["Parameters"][name].pop("Default", None)

    parent["Parameters"]["TerminalRolesTemplateUrl"] = {"Type": "String", "AllowedValues": [terminal_url]}
    parent["Parameters"]["WorkloadFoundationTemplateUrl"] = {"Type": "String", "AllowedValues": [workload_url]}
    parent.setdefault("Metadata", {}).setdefault("Scanalyze", {})
    parent["Metadata"]["Scanalyze"].update(
        {
            "TerminalRolesTemplateSha256": child_sha,
            "WorkloadFoundationTemplateSha256": workload_sha,
            "WorkloadFoundationDigest": receipt["contract_digest"],
            "BootstrapRecordDigest": expected_content_digest,
            "PublicationBindingDigest": expected_publication_digest,
            "ModelSelectionDigest": content["model_selection_digest"],
        }
    )
    parent["Rules"]["BoundDestination"] = {
        "Assertions": [
            {
                "Assert": {"Fn::Equals": [{"Ref": "AWS::AccountId"}, content["account_id"]]},
                "AssertDescription": "Destination account must match the anchored target.",
            },
            {
                "Assert": {"Fn::Equals": [{"Ref": "AWS::Region"}, content["region"]]},
                "AssertDescription": "Destination region must match the anchored target.",
            },
        ]
    }
    parent["Resources"]["WorkloadFoundation"] = {
        "Type": "AWS::CloudFormation::Stack",
        "DeletionPolicy": "Retain",
        "UpdateReplacePolicy": "Retain",
        "DependsOn": ["TerminalRoles"],
        "Properties": {
            "TemplateURL": {"Ref": "WorkloadFoundationTemplateUrl"},
            "Tags": deepcopy(parent["Resources"]["TerminalRoles"]["Properties"]["Tags"]),
        },
    }
    parent["Outputs"]["WorkloadFoundationDigest"] = {"Value": receipt["contract_digest"]}
    parent["Description"] = (
        "Fixed destination baseline and workload IAM foundation; generated from an "
        "externally anchored content request and publication binding. No application execution."
    )

    parameters = [
        {"ParameterKey": name, "ParameterValue": value}
        for name, value in sorted(
            {
                **bindings,
                "TerminalRolesTemplateUrl": terminal_url,
                "WorkloadFoundationTemplateUrl": workload_url,
            }.items()
        )
    ]

    # Preserve exact content bytes; never regenerate child/workload in this phase.
    artifacts = {
        "cfn-terminal-roles.yaml": child_bytes,
        "cfn-workload-foundation.json": workload_bytes,
        "workload-foundation.json": content_artifacts["workload-foundation.json"],
        "cfn-tf-state-backend.yaml": canonical_bytes(parent),
        "parameters.json": canonical_bytes(parameters),
    }
    if "content-manifest.json" in content_artifacts:
        artifacts["content-manifest.json"] = content_artifacts["content-manifest.json"]

    manifest = {
        "schema_version": "1",
        "status": "PREPARED_NOT_DEPLOYED",
        "content_record_digest": expected_content_digest,
        "publication_binding_digest": expected_publication_digest,
        "model_selection_digest": content["model_selection_digest"],
        "workload_foundation_digest": receipt["contract_digest"],
        "terminal_template_sha256": child_sha,
        "workload_template_sha256": workload_sha,
        "artifacts": {name: _sha(value) for name, value in sorted(artifacts.items())},
    }
    artifacts["manifest.json"] = canonical_bytes(manifest)
    return artifacts


def write_package(artifacts: dict[str, bytes], destination: Path) -> None:
    destination = destination.absolute()
    _require(not destination.exists() and not destination.is_symlink(), "package destination already exists")
    parent = destination.parent.resolve(strict=True)
    _require(parent != REPO_ROOT and REPO_ROOT not in parent.parents, "package output must be outside the repository")
    _require(destination.parent == parent, "package output parent must be canonical")
    destination.mkdir(mode=0o700)
    for name, data in sorted(artifacts.items()):
        _require(Path(name).name == name, "package artifact name is invalid")
        descriptor = os.open(destination / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb") as output:
            output.write(data)


def build_validation_receipt(
    artifacts: dict[str, bytes],
    *,
    deployment_id: str,
    content_record_digest: str,
    model_selection_digest: str,
    workload_foundation_digest: str,
    publication_binding_digest: str | None = None,
    status: str = "VALIDATED",
) -> dict:
    """Build a closed validation receipt for content or full bootstrap package output."""
    artifact_digests = {name: _sha(data) for name, data in sorted(artifacts.items())}
    receipt: dict = {
        "schema_version": "1",
        "record_type": "bootstrap_package_validation_receipt",
        "status": status,
        "deployment_id": deployment_id,
        "content_record_digest": content_record_digest,
        "model_selection_digest": model_selection_digest,
        "workload_foundation_digest": workload_foundation_digest,
        "artifact_digests": artifact_digests,
        "generated_at": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    if publication_binding_digest is not None:
        receipt["publication_binding_digest"] = publication_binding_digest
    receipt_bytes = _json.dumps(receipt, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
    receipt["receipt_digest"] = "sha256:" + _hashlib.sha256(receipt_bytes).hexdigest()
    return receipt


def _load_content_artifacts(content_dir: Path) -> dict[str, bytes]:
    _require(content_dir.is_dir() and not content_dir.is_symlink(), "content package directory is invalid")
    artifacts: dict[str, bytes] = {}
    for name in ("cfn-terminal-roles.yaml", "cfn-workload-foundation.json", "workload-foundation.json"):
        path = content_dir / name
        _require(path.is_file() and not path.is_symlink(), f"content artifact {name} is missing")
        artifacts[name] = path.read_bytes()
    manifest_path = content_dir / "content-manifest.json"
    if manifest_path.is_file() and not manifest_path.is_symlink():
        artifacts["content-manifest.json"] = manifest_path.read_bytes()
    return artifacts


def _add_common_model_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--model-selection",
        type=Path,
        required=True,
        help="Closed JSON object with bedrock_model_arns list; no policy documents.",
    )
    parser.add_argument("--out-dir", type=Path, required=False, default=None)
    parser.add_argument(
        "--validate-only",
        action="store_true",
        default=False,
        help="Validate inputs and emit receipt without writing the package.",
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    content_parser = subparsers.add_parser(
        "content",
        help="Prepare deterministic terminal/workload content bytes (no VersionIds).",
    )
    content_parser.add_argument("--content", type=Path, required=True)
    content_parser.add_argument("--content-anchor", type=Path, required=True)
    content_parser.add_argument("--expected-content-digest", required=True)
    _add_common_model_args(content_parser)

    parent_parser = subparsers.add_parser(
        "parent",
        help="Materialize parent from publication binding without rewriting content bytes.",
    )
    parent_parser.add_argument("--content", type=Path, required=True)
    parent_parser.add_argument("--content-anchor", type=Path, required=True)
    parent_parser.add_argument("--expected-content-digest", required=True)
    parent_parser.add_argument("--publication", type=Path, required=True)
    parent_parser.add_argument("--publication-anchor", type=Path, required=True)
    parent_parser.add_argument("--expected-publication-digest", required=True)
    parent_parser.add_argument(
        "--content-dir",
        type=Path,
        required=True,
        help="Directory containing content-phase artifacts (child/workload bytes).",
    )
    _add_common_model_args(parent_parser)

    args = parser.parse_args(argv)

    try:
        models = load_json_strict(args.model_selection)
        _require(set(models) == {"bedrock_model_arns"}, "model selection fields are invalid")
        content = load_json_strict(args.content)
        content_anchor = load_json_strict(args.content_anchor)

        if args.command == "content":
            artifacts = build_bootstrap_content_package(
                content=content,
                anchor=content_anchor,
                expected_content_digest=args.expected_content_digest,
                bedrock_model_arns=models["bedrock_model_arns"],
            )
            manifest = _json.loads(artifacts["content-manifest.json"])
            receipt = build_validation_receipt(
                artifacts,
                deployment_id=content["deployment_id"],
                content_record_digest=args.expected_content_digest,
                model_selection_digest=content["model_selection_digest"],
                workload_foundation_digest=manifest["workload_foundation_digest"],
                status="VALIDATED",
            )
            status_line = "CONTENT_PREPARED_NOT_PUBLISHED"
        else:
            publication = load_json_strict(args.publication)
            artifacts = build_bootstrap_parent_package(
                content=content,
                content_anchor=content_anchor,
                expected_content_digest=args.expected_content_digest,
                publication=publication,
                publication_anchor=load_json_strict(args.publication_anchor),
                expected_publication_digest=args.expected_publication_digest,
                content_artifacts=_load_content_artifacts(args.content_dir),
                bedrock_model_arns=models["bedrock_model_arns"],
            )
            manifest = _json.loads(artifacts["manifest.json"])
            receipt = build_validation_receipt(
                artifacts,
                deployment_id=content["deployment_id"],
                content_record_digest=args.expected_content_digest,
                model_selection_digest=content["model_selection_digest"],
                workload_foundation_digest=manifest["workload_foundation_digest"],
                publication_binding_digest=args.expected_publication_digest,
                status="VALIDATED",
            )
            status_line = "PREPARED_NOT_DEPLOYED"

        if args.validate_only:
            print(_json.dumps(receipt, indent=2))
            return 0

        _require(args.out_dir is not None, "--out-dir is required unless --validate-only is used")
        write_package(artifacts, args.out_dir)
        receipt_path = args.out_dir / "validation-receipt.json"
        descriptor = os.open(receipt_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb") as output:
            output.write(_json.dumps(receipt, indent=2, sort_keys=True).encode())
    except (ValueError, OSError, jsonschema.ValidationError):
        parser.exit(2, 'bootstrap package preparation failed; input or output validation did not pass\n')


    print(status_line)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
