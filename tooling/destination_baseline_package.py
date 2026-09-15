"""Prepare a fixed destination-baseline package from an externally anchored target.

No AWS calls, state reads, publication, or execution are performed. S3 version
identifiers refer to a separately reviewed publication; their syntax is not
evidence that any object has been published. Bucket names are never an input.
"""
from __future__ import annotations

import argparse
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import re
from urllib.parse import quote

import yaml

from tooling.authorize_deployment_backend import load_json_strict
from tooling.deployment_registry import _validate as validate_registry_record
from tooling.workload_foundation import build_workload_foundation, canonical_bytes, digest


REPO_ROOT = Path(__file__).resolve().parents[1]


class _TemplateLoader(yaml.SafeLoader):
    pass


def _intrinsic(loader, suffix, node):
    value = loader.construct_scalar(node) if isinstance(node, yaml.ScalarNode) else loader.construct_sequence(node, deep=True) if isinstance(node, yaml.SequenceNode) else loader.construct_mapping(node, deep=True)
    return {suffix if suffix == "Ref" else "Fn::" + suffix: value}


_TemplateLoader.add_multi_constructor("!", _intrinsic)


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def _load_template(name: str) -> dict:
    return yaml.load((REPO_ROOT / "bootstrap" / name).read_text(), Loader=_TemplateLoader)


def _sha(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def bind_deployment_mappings(child: dict, deployment_id: str) -> None:
    """Bind one destination using a CFN-valid key, preserving its real identity.

    Deployment IDs contain an underscore, which CloudFormation mapping keys do
    not accept. The producer already pins DeploymentId to one AllowedValue, so a
    fixed mapping key avoids interpreting the identifier as CFN syntax.
    """
    prefix = deployment_id.replace("_", "-").lower()
    fields = {"DeploymentNames": ("SanitizedDeploymentId", prefix),
              "DeploymentDocumentBuckets": ("Name", prefix + "-documents")}
    for mapping, (field, value) in fields.items():
        child["Mappings"][mapping] = {"Bound": {field: value}}

    def visit(value):
        if isinstance(value, list):
            for item in value:
                visit(item)
        elif isinstance(value, dict):
            if set(value) == {"Fn::FindInMap"} and value["Fn::FindInMap"][0] in fields:
                mapping, key, field = value["Fn::FindInMap"]
                _require(key == {"Ref": "DeploymentId"} and field == fields[mapping][0],
                         "deployment mapping source is unexpected")
                value["Fn::FindInMap"] = [mapping, "Bound", field]
            else:
                for item in value.values():
                    visit(item)
    visit(child)


def build_destination_baseline_package(
    target: dict, anchor: dict, *, expected_target_digest: str,
    bedrock_model_arns: list[str], expected_model_selection_digest: str,
    shared_services_account_id: str, terminal_version_id: str, workload_version_id: str,
) -> dict[str, bytes]:
    """Return deterministic artifact bytes; the caller must install them separately."""
    validate_registry_record(target)
    _require(target["schema_version"] == "2", "baseline package requires target v2")
    _require(target["status"] in {"REQUESTED", "BASELINING", "READY", "ACTIVE"}, "baseline target lifecycle is not eligible")
    _require(target["record_digest"] == expected_target_digest, "baseline external target digest mismatch")
    _require(anchor == {"schema_version": "1", "deployment_id": target["deployment_id"], "registry_version": target["registry_version"], "record_digest": target["record_digest"]}, "baseline target anchor mismatch")
    _require(digest(bedrock_model_arns) == expected_model_selection_digest, "baseline model selection digest mismatch")
    _require(isinstance(shared_services_account_id, str) and re.fullmatch(r"(?!000000000000$)[0-9]{12}", shared_services_account_id) is not None and shared_services_account_id != target["account_id"], "baseline shared-services account is invalid")
    for version in (terminal_version_id, workload_version_id):
        _require(isinstance(version, str) and version.lower() != "null" and re.fullmatch(r"[A-Za-z0-9._~+/=-]{1,256}", version) is not None, "baseline publication version is invalid")
    partition = "aws-cn" if target["region"].startswith("cn-") else "aws-us-gov" if target["region"].startswith("us-gov-") else "aws"
    identity = {key: target[key] for key in ("customer_id", "deployment_id", "account_id", "region", "environment")}
    identity["aws_partition"] = partition
    workload, receipt = build_workload_foundation(identity, bedrock_model_arns)
    workload_bytes = canonical_bytes(workload)
    child = _load_template("cfn-terminal-roles.yaml")
    bind_deployment_mappings(child, target["deployment_id"])
    bindings = {"CustomerId": target["customer_id"], "DeploymentId": target["deployment_id"], "Environment": target["environment"], "SharedServicesAccountId": shared_services_account_id}
    for name, value in bindings.items():
        child["Parameters"][name]["AllowedValues"] = [value]
        child["Parameters"][name].pop("Default", None)
    child["Metadata"]["Scanalyze"]["TargetRecordDigest"] = expected_target_digest
    child_bytes = canonical_bytes(child)
    child_sha = _sha(child_bytes)
    suffix = "amazonaws.com.cn" if partition == "aws-cn" else "amazonaws.com"
    base = f"https://scanalyze-shared-releases.s3.{target['region']}.{suffix}/"
    terminal_url = f"{base}terminal-roles/sha256/{child_sha.removeprefix('sha256:')}/cfn-terminal-roles.yaml?versionId={quote(terminal_version_id, safe='')}"
    workload_url = f"{base}workload-foundation/sha256/{receipt['template_sha256'].removeprefix('sha256:')}/cfn-workload-foundation.json?versionId={quote(workload_version_id, safe='')}"
    parent = _load_template("cfn-tf-state-backend.yaml")
    for name, value in bindings.items():
        parent["Parameters"][name]["AllowedValues"] = [value]
        parent["Parameters"][name].pop("Default", None)
    parent["Parameters"]["TerminalRolesTemplateUrl"] = {"Type": "String", "AllowedValues": [terminal_url]}
    parent["Parameters"]["WorkloadFoundationTemplateUrl"] = {"Type": "String", "AllowedValues": [workload_url]}
    parent["Metadata"]["Scanalyze"].update({"TerminalRolesTemplateSha256": child_sha, "WorkloadFoundationTemplateSha256": receipt["template_sha256"], "WorkloadFoundationDigest": receipt["contract_digest"], "TargetRecordDigest": expected_target_digest, "ModelSelectionDigest": expected_model_selection_digest})
    parent["Rules"]["BoundDestination"] = {"Assertions": [
        {"Assert": {"Fn::Equals": [{"Ref": "AWS::AccountId"}, target["account_id"]]}, "AssertDescription": "Destination account must match the anchored target."},
        {"Assert": {"Fn::Equals": [{"Ref": "AWS::Region"}, target["region"]]}, "AssertDescription": "Destination region must match the anchored target."},
    ]}
    parent["Resources"]["WorkloadFoundation"] = {"Type": "AWS::CloudFormation::Stack", "DeletionPolicy": "Retain", "UpdateReplacePolicy": "Retain", "DependsOn": ["TerminalRoles"], "Properties": {"TemplateURL": {"Ref": "WorkloadFoundationTemplateUrl"}, "Tags": deepcopy(parent["Resources"]["TerminalRoles"]["Properties"]["Tags"])}}
    parent["Outputs"]["WorkloadFoundationDigest"] = {"Value": receipt["contract_digest"]}
    parent["Description"] = "Fixed destination baseline and workload IAM foundation; generated from an externally anchored target. No application execution."
    parameters = [{"ParameterKey": name, "ParameterValue": value} for name, value in sorted({**bindings, "TerminalRolesTemplateUrl": terminal_url, "WorkloadFoundationTemplateUrl": workload_url}.items())]
    artifacts = {
        "cfn-terminal-roles.yaml": child_bytes,
        "cfn-workload-foundation.json": workload_bytes,
        "cfn-tf-state-backend.yaml": canonical_bytes(parent),
        "parameters.json": canonical_bytes(parameters),
        "workload-foundation.json": canonical_bytes(receipt),
    }
    manifest = {"schema_version": "1", "status": "PREPARED_NOT_DEPLOYED", "target_record_digest": expected_target_digest, "model_selection_digest": expected_model_selection_digest, "workload_foundation_digest": receipt["contract_digest"], "artifacts": {name: _sha(value) for name, value in sorted(artifacts.items())}}
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


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", type=Path, required=True)
    parser.add_argument("--target-anchor", type=Path, required=True)
    parser.add_argument("--expected-target-digest", required=True)
    parser.add_argument("--model-selection", type=Path, required=True, help="Closed JSON object with bedrock_model_arns list; no policy documents.")
    parser.add_argument("--expected-model-selection-digest", required=True, help="Independent digest of the canonical model ARN list.")
    parser.add_argument("--shared-services-account-id", required=True)
    parser.add_argument("--terminal-version-id", required=True)
    parser.add_argument("--workload-version-id", required=True)
    parser.add_argument("--out-dir", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        models = load_json_strict(args.model_selection)
        _require(set(models) == {"bedrock_model_arns"}, "model selection fields are invalid")
        artifacts = build_destination_baseline_package(load_json_strict(args.target), load_json_strict(args.target_anchor), expected_target_digest=args.expected_target_digest, bedrock_model_arns=models["bedrock_model_arns"], expected_model_selection_digest=args.expected_model_selection_digest, shared_services_account_id=args.shared_services_account_id, terminal_version_id=args.terminal_version_id, workload_version_id=args.workload_version_id)
        write_package(artifacts, args.out_dir)
    except (ValueError, OSError):
        parser.exit(2, "baseline package preparation failed; input or output validation did not pass\n")
    print("PREPARED_NOT_DEPLOYED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
