from copy import deepcopy
import hashlib
import json
import re
from urllib.parse import parse_qs, urlsplit

import pytest

from tooling.workload_foundation import (
    SERVICES, build_workload_foundation, canonical_bytes, digest,
    verify_workload_foundation_receipt,
)
from tooling.destination_baseline_package import _load_template, bind_deployment_mappings, build_destination_baseline_package, write_package


IDENTITY = {"customer_id": "cust_01ARZ3NDEKTSV4RRFFQ69G5FAW", "deployment_id": "dep_01ARZ3NDEKTSV4RRFFQ69G5FAV", "account_id": "111111111111", "region": "us-east-1", "environment": "production", "aws_partition": "aws"}
MODELS = ["arn:aws:bedrock:us-east-1::foundation-model/example.model-v1"]


def _target():
    target = {key: value for key, value in IDENTITY.items() if key != "aws_partition"}
    target.update({"schema_version": "2", "record_type": "deployment_target", "status": "BASELINING", "registry_version": 1, "runtime_origin": {"schema_version": "1", "domain_name": "synthetic.example.com"}, "account_ready": {"schema_version": "2", "baseline_version": "v2.1.0", "contract_digest": "sha256:" + "b" * 64}, "state_binding": {"state_bucket": "arn:aws:s3:::scanalyze-111111111111-tf-state", "state_kms_key": "arn:aws:kms:us-east-1:111111111111:key/synthetic-key"}})
    target["record_digest"] = digest(target)
    anchor = {key: target[key] for key in ("deployment_id", "registry_version", "record_digest")}
    anchor["schema_version"] = "1"
    return target, anchor


def _package(target=None, anchor=None, **overrides):
    original, original_anchor = _target()
    return build_destination_baseline_package(target or original, anchor or original_anchor, **{
        "expected_target_digest": original["record_digest"], "bedrock_model_arns": MODELS,
        "expected_model_selection_digest": digest(MODELS), "shared_services_account_id": "222222222222",
        "terminal_version_id": "synthetic-terminal-v1", "workload_version_id": "synthetic-workload-v1", **overrides,
    })


def test_foundation_is_fixed_to_eight_ecs_roles_and_two_policies():
    template, receipt = build_workload_foundation(IDENTITY, MODELS)
    assert verify_workload_foundation_receipt(receipt, receipt["contract_digest"], IDENTITY) == receipt
    assert receipt["template_sha256"] == "sha256:" + hashlib.sha256(canonical_bytes(template)).hexdigest()
    roles = [value for value in template["Resources"].values() if value["Type"] == "AWS::IAM::Role"]
    policies = [value for value in template["Resources"].values() if value["Type"] == "AWS::IAM::ManagedPolicy"]
    assert len(roles) == 8 and len(policies) == 2
    expected_names = {IDENTITY["deployment_id"] + "-ecs-task-execution"} | {IDENTITY["deployment_id"] + "-workload-" + service for service in SERVICES}
    assert {value["Properties"]["RoleName"] for value in roles} == expected_names
    for role in roles:
        properties = role["Properties"]
        assert properties["AssumeRolePolicyDocument"] == {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"Service": "ecs-tasks.amazonaws.com"}, "Action": "sts:AssumeRole", "Condition": {"StringEquals": {"aws:SourceAccount": IDENTITY["account_id"]}}}]}
        assert properties["PermissionsBoundary"] == {"Ref": "WorkloadBoundary"}
        assert "Policies" not in properties
        assert role["DeletionPolicy"] == role["UpdateReplacePolicy"] == "Retain"
        tags = {tag["Key"]: tag["Value"] for tag in properties["Tags"]}
        assert tags["deployment_id"] == IDENTITY["deployment_id"]
        assert tags["layer"] == "global"
    for policy in policies:
        assert len(canonical_bytes(policy["Properties"]["PolicyDocument"])) <= 6144


@pytest.mark.parametrize("field,value", [("account_id", "333333333333"), ("ecs_task_execution_role_arn", "arn:aws:iam::111111111111:role/admin"), ("schema_version", "2"), ("unexpected", True), ("template_sha256", "sha256:invalid")])
def test_receipt_tampering_is_rejected_even_if_self_rehashed(field, value):
    _, receipt = build_workload_foundation(IDENTITY, MODELS)
    receipt[field] = value
    receipt["contract_digest"] = digest({key: item for key, item in receipt.items() if key != "contract_digest"})
    with pytest.raises(ValueError):
        verify_workload_foundation_receipt(receipt, receipt["contract_digest"], IDENTITY)


def test_external_digest_cannot_be_replaced_by_self_digest():
    _, receipt = build_workload_foundation(IDENTITY, MODELS)
    expected = receipt["contract_digest"]
    receipt["policy_digests"]["workload"] = "sha256:" + "c" * 64
    receipt["contract_digest"] = digest({key: value for key, value in receipt.items() if key != "contract_digest"})
    with pytest.raises(ValueError):
        verify_workload_foundation_receipt(receipt, expected, IDENTITY)


def test_receipt_invalid_target_type_is_rejected_without_echoing_input():
    _, receipt = build_workload_foundation(IDENTITY, MODELS)
    malformed = {**IDENTITY, "environment": []}
    with pytest.raises(ValueError, match="foundation environment is invalid"):
        verify_workload_foundation_receipt(receipt, receipt["contract_digest"], malformed)


@pytest.mark.parametrize("models", [["*"], [MODELS[0].replace("us-east-1", "us-west-2")], MODELS * 2, [MODELS[0].replace("::", ":222222222222:")]])
def test_foundation_rejects_wildcard_foreign_or_duplicate_models(models):
    with pytest.raises(ValueError):
        build_workload_foundation(IDENTITY, models)


def test_package_binds_cors_and_nested_templates_without_bucket_input():
    artifacts = _package()
    assert artifacts == _package()
    child = json.loads(artifacts["cfn-terminal-roles.yaml"])
    parent = json.loads(artifacts["cfn-tf-state-backend.yaml"])
    assert child["Mappings"]["DeploymentDocumentBuckets"] == {"Bound": {"Name": IDENTITY["deployment_id"].replace("_", "-").lower() + "-documents"}}
    assert child["Mappings"]["DeploymentNames"] == {"Bound": {"SanitizedDeploymentId": IDENTITY["deployment_id"].replace("_", "-").lower()}}
    assert "SanitizedDeploymentId" not in child["Parameters"]
    assert not any("BucketName" in name for name in child["Parameters"])
    assert child["Parameters"]["DeploymentId"]["AllowedValues"] == [IDENTITY["deployment_id"]]
    for parameter, artifact in (("TerminalRolesTemplateUrl", "cfn-terminal-roles.yaml"), ("WorkloadFoundationTemplateUrl", "cfn-workload-foundation.json")):
        url, = parent["Parameters"][parameter]["AllowedValues"]
        assert hashlib.sha256(artifacts[artifact]).hexdigest() in url
        assert "?versionId=synthetic-" in url
    assert parent["Resources"]["WorkloadFoundation"]["Properties"]["TemplateURL"] == {"Ref": "WorkloadFoundationTemplateUrl"}
    manifest = json.loads(artifacts["manifest.json"])
    assert manifest["status"] == "PREPARED_NOT_DEPLOYED"
    for name, expected in manifest["artifacts"].items():
        assert expected == "sha256:" + hashlib.sha256(artifacts[name]).hexdigest()


@pytest.mark.parametrize("override", [{"expected_target_digest": "sha256:" + "a" * 64}, {"expected_model_selection_digest": "sha256:" + "a" * 64}, {"terminal_version_id": "null"}, {"shared_services_account_id": IDENTITY["account_id"]}])
def test_package_rejects_unanchored_or_invalid_inputs(override):
    with pytest.raises(ValueError):
        _package(**override)


def test_package_rejects_deployment_tampering_even_with_internal_digest():
    target, anchor = _target()
    target["deployment_id"] = "dep_01ARZ3NDEKTSV4RRFFQ69G5FAX"
    target["record_digest"] = digest({key: value for key, value in target.items() if key != "record_digest"})
    with pytest.raises(ValueError):
        _package(target, anchor)


def test_package_preserves_publication_version_query_values():
    version = "synthetic+version/with=padding"
    artifacts = _package(terminal_version_id=version, workload_version_id=version)
    parent = json.loads(artifacts["cfn-tf-state-backend.yaml"])
    for name in ("TerminalRolesTemplateUrl", "WorkloadFoundationTemplateUrl"):
        url, = parent["Parameters"][name]["AllowedValues"]
        assert parse_qs(urlsplit(url).query) == {"versionId": [version]}


def test_package_writes_private_new_outputs_and_never_overwrites(tmp_path):
    artifacts = _package()
    destination = tmp_path.resolve() / "package"
    write_package(artifacts, destination)
    assert destination.stat().st_mode & 0o777 == 0o700
    for name, value in artifacts.items():
        assert (destination / name).read_bytes() == value
        assert (destination / name).stat().st_mode & 0o777 == 0o600
    with pytest.raises(ValueError):
        write_package(artifacts, destination)


def assert_bound_mappings_resolve(child, deployment_id):
    """Check emitted CFN keys and resolve every reference, independent of rewrite."""
    assert all(re.fullmatch(r"[a-zA-Z0-9.-]+", key)
               for mapping in child["Mappings"].values() for key in mapping)
    values = []
    def visit(node):
        if isinstance(node, list):
            for item in node:
                visit(item)
        elif isinstance(node, dict):
            if set(node) == {"Fn::FindInMap"}:
                mapping, key, field = node["Fn::FindInMap"]
                assert isinstance(key, str), "emitted map reference must use the fixed key"
                values.append(child["Mappings"][mapping][key][field])
            else:
                for item in node.values():
                    visit(item)
    visit(child)
    prefix = deployment_id.replace("_", "-").lower()
    assert len(values) > 0 and set(values) == {prefix, prefix + "-documents"}
    assert child["Parameters"]["DeploymentId"]["AllowedValues"] == [deployment_id]


def test_bound_mapping_keys_fix_original_cfn_error_without_changing_resources():
    # This is the causal old producer output: CFN E7001 rejects the underscore.
    original = _load_template("cfn-terminal-roles.yaml")
    deployment_id = IDENTITY["deployment_id"]
    prefix = deployment_id.replace("_", "-").lower()
    original["Mappings"]["DeploymentNames"] = {deployment_id: {"SanitizedDeploymentId": prefix}}
    original["Mappings"]["DeploymentDocumentBuckets"] = {deployment_id: {"Name": prefix + "-documents"}}
    assert any(re.fullmatch(r"[a-zA-Z0-9.-]+", key) is None
               for mapping in original["Mappings"].values() for key in mapping)
    corrected = deepcopy(original)
    bind_deployment_mappings(corrected, deployment_id)
    corrected["Parameters"]["DeploymentId"]["AllowedValues"] = [deployment_id]
    assert_bound_mappings_resolve(corrected, deployment_id)
    assert_bound_mappings_resolve(json.loads(_package()["cfn-terminal-roles.yaml"]), deployment_id)
    # Every original FindInMap still resolves to exactly the same resource name.
    def resolve(node, mappings):
        if isinstance(node, list):
            return [resolve(item, mappings) for item in node]
        if isinstance(node, dict):
            if set(node) == {"Fn::FindInMap"}:
                mapping, key, field = node["Fn::FindInMap"]
                return mappings[mapping][deployment_id if key == {"Ref": "DeploymentId"} else key][field]
            return {key: resolve(value, mappings) for key, value in node.items()}
        return node
    assert resolve(original["Resources"], original["Mappings"]) == resolve(corrected["Resources"], corrected["Mappings"])
