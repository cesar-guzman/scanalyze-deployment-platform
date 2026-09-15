import json
import os
import subprocess
import sys
from copy import deepcopy
from pathlib import Path

import pytest

from tooling.destination_bootstrap_package import (
    _canonical_digest,
    _sha,
    build_bootstrap_content_package,
    build_bootstrap_parent_package,
    write_package,
)
from tooling.workload_foundation import digest
from tests.test_account_ready.test_workload_foundation import assert_bound_mappings_resolve


MODELS = ["arn:aws:bedrock:us-east-1::foundation-model/amazon.nova-pro-v1:0"]
MODEL_DIGEST = digest(MODELS)


def _content_without_digest(**overrides):
    base = {
        "schema_version": "1",
        "record_type": "deployment_bootstrap_content_request",
        "customer_id": "cust_01M260EYHD9Q3AQTM2N48Q4RW9",
        "deployment_id": "dep_01M260EYHD8VGSR9MB6Q32BP9K",
        "account_id": "905418363887",
        "region": "us-east-1",
        "environment": "production",
        "shared_services_account_id": "111122223333",
        "model_selection_digest": MODEL_DIGEST,
    }
    base.update(overrides)
    return base


def _seal_content(**overrides):
    content = _content_without_digest(**overrides)
    content["record_digest"] = _canonical_digest(content, "record_digest")
    return content


def _content_anchor(content):
    return {
        "schema_version": "1",
        "deployment_id": content["deployment_id"],
        "record_digest": content["record_digest"],
    }


def _seal_publication(content_digest, child_sha, workload_sha, workload_foundation_digest, terminal_version_id, workload_version_id, deployment_id="dep_01M260EYHD8VGSR9MB6Q32BP9K"):
    publication = {
        "schema_version": "1",
        "record_type": "deployment_bootstrap_publication_binding",
        "deployment_id": deployment_id,
        "content_record_digest": content_digest,
        "terminal_template_sha256": child_sha,
        "workload_template_sha256": workload_sha,
        "workload_foundation_digest": workload_foundation_digest,
        "terminal_version_id": terminal_version_id,
        "workload_version_id": workload_version_id,
    }
    publication["binding_digest"] = _canonical_digest(publication, "binding_digest")
    return publication


def _publication_anchor(publication):
    return {
        "schema_version": "1",
        "deployment_id": publication["deployment_id"],
        "binding_digest": publication["binding_digest"],
    }


def _prepare_content():
    content = _seal_content()
    artifacts = build_bootstrap_content_package(
        content=content,
        anchor=_content_anchor(content),
        expected_content_digest=content["record_digest"],
        bedrock_model_arns=MODELS,
    )
    manifest = json.loads(artifacts["content-manifest.json"])
    return content, artifacts, manifest


def test_content_package_is_deterministic():
    content = _seal_content()
    anchor = _content_anchor(content)
    first = build_bootstrap_content_package(content, anchor, content["record_digest"], MODELS)
    second = build_bootstrap_content_package(content, anchor, content["record_digest"], MODELS)
    assert first == second
    assert first["cfn-terminal-roles.yaml"] == second["cfn-terminal-roles.yaml"]
    manifest = json.loads(first["content-manifest.json"])
    assert manifest["status"] == "CONTENT_PREPARED_NOT_PUBLISHED"
    assert "terminal_version_id" not in content
    assert content["record_digest"].encode() in first["cfn-terminal-roles.yaml"]
    assert_bound_mappings_resolve(json.loads(first["cfn-terminal-roles.yaml"]), content["deployment_id"])


def test_changing_only_version_ids_preserves_children_but_changes_parent():
    content, content_artifacts, manifest = _prepare_content()
    pub_a = _seal_publication(
        content["record_digest"],
        manifest["terminal_template_sha256"],
        manifest["workload_template_sha256"],
        manifest["workload_foundation_digest"],
        "VersionId.AAA",
        "VersionId.W1",
    )
    pub_b = _seal_publication(
        content["record_digest"],
        manifest["terminal_template_sha256"],
        manifest["workload_template_sha256"],
        manifest["workload_foundation_digest"],
        "VersionId.BBB",
        "VersionId.W1",
    )
    parent_a = build_bootstrap_parent_package(
        content,
        _content_anchor(content),
        content["record_digest"],
        pub_a,
        _publication_anchor(pub_a),
        pub_a["binding_digest"],
        content_artifacts,
        MODELS,
    )
    parent_b = build_bootstrap_parent_package(
        content,
        _content_anchor(content),
        content["record_digest"],
        pub_b,
        _publication_anchor(pub_b),
        pub_b["binding_digest"],
        content_artifacts,
        MODELS,
    )
    assert parent_a["cfn-terminal-roles.yaml"] == parent_b["cfn-terminal-roles.yaml"] == content_artifacts["cfn-terminal-roles.yaml"]
    assert parent_a["cfn-workload-foundation.json"] == parent_b["cfn-workload-foundation.json"]
    assert parent_a["cfn-tf-state-backend.yaml"] != parent_b["cfn-tf-state-backend.yaml"]
    assert b"VersionId.AAA" in parent_a["cfn-tf-state-backend.yaml"]
    assert b"VersionId.BBB" in parent_b["cfn-tf-state-backend.yaml"]
    assert b"VersionId.AAA" not in parent_a["cfn-terminal-roles.yaml"]


def test_content_rejects_version_ids_in_request():
    content = _seal_content()
    content["terminal_version_id"] = "v1"
    # reseal would include version id; force digest match for schema/extra check path
    content["record_digest"] = _canonical_digest(content, "record_digest")
    with pytest.raises(Exception):
        build_bootstrap_content_package(
            content,
            _content_anchor(content),
            content["record_digest"],
            MODELS,
        )


@pytest.mark.parametrize(
    "field,value",
    [
        ("account_id", "123123123123"),
        ("environment", "sandbox"),
        ("shared_services_account_id", "999988887777"),
        ("model_selection_digest", "sha256:" + ("ab" * 32)),
    ],
)
def test_altered_tuple_or_model_fails_anchor(field, value):
    content = _seal_content()
    anchor = _content_anchor(content)
    expected = content["record_digest"]
    mutated = deepcopy(content)
    mutated[field] = value
    # keep old digest so external digest check fails (or model mismatch)
    with pytest.raises(ValueError):
        build_bootstrap_content_package(mutated, anchor, expected, MODELS)


def test_model_list_mismatch_rejected():
    content = _seal_content()
    with pytest.raises(ValueError, match="model selection digest mismatch"):
        build_bootstrap_content_package(
            content,
            _content_anchor(content),
            content["record_digest"],
            ["arn:aws:bedrock:us-east-1::foundation-model/amazon.nova-lite-v1:0"],
        )


def test_publication_hash_mismatch_rejected():
    content, content_artifacts, manifest = _prepare_content()
    publication = _seal_publication(
        content["record_digest"],
        "sha256:" + ("00" * 32),
        manifest["workload_template_sha256"],
        manifest["workload_foundation_digest"],
        "VersionId.AAA",
        "VersionId.W1",
    )
    with pytest.raises(ValueError, match="terminal template hash mismatch"):
        build_bootstrap_parent_package(
            content,
            _content_anchor(content),
            content["record_digest"],
            publication,
            _publication_anchor(publication),
            publication["binding_digest"],
            content_artifacts,
            MODELS,
        )


def test_publication_version_mismatch_digest_rejected():
    content, content_artifacts, manifest = _prepare_content()
    publication = _seal_publication(
        content["record_digest"],
        manifest["terminal_template_sha256"],
        manifest["workload_template_sha256"],
        manifest["workload_foundation_digest"],
        "VersionId.AAA",
        "VersionId.W1",
    )
    bad_anchor = _publication_anchor(publication)
    bad_anchor["binding_digest"] = "sha256:" + ("11" * 32)
    with pytest.raises(ValueError, match="publication anchor mismatch"):
        build_bootstrap_parent_package(
            content,
            _content_anchor(content),
            content["record_digest"],
            publication,
            bad_anchor,
            publication["binding_digest"],
            content_artifacts,
            MODELS,
        )


def test_missing_content_artifact_rejected():
    content, content_artifacts, manifest = _prepare_content()
    publication = _seal_publication(
        content["record_digest"],
        manifest["terminal_template_sha256"],
        manifest["workload_template_sha256"],
        manifest["workload_foundation_digest"],
        "VersionId.AAA",
        "VersionId.W1",
    )
    incomplete = {k: v for k, v in content_artifacts.items() if k != "cfn-terminal-roles.yaml"}
    with pytest.raises(ValueError, match="content artifact cfn-terminal-roles.yaml is missing"):
        build_bootstrap_parent_package(
            content,
            _content_anchor(content),
            content["record_digest"],
            publication,
            _publication_anchor(publication),
            publication["binding_digest"],
            incomplete,
            MODELS,
        )


def test_source_template_bytes_change_breaks_publication_binding():
    content, content_artifacts, manifest = _prepare_content()
    publication = _seal_publication(
        content["record_digest"],
        manifest["terminal_template_sha256"],
        manifest["workload_template_sha256"],
        manifest["workload_foundation_digest"],
        "VersionId.AAA",
        "VersionId.W1",
    )
    tampered = dict(content_artifacts)
    tampered["cfn-terminal-roles.yaml"] = content_artifacts["cfn-terminal-roles.yaml"] + b"\n# tampered\n"
    with pytest.raises(ValueError, match="terminal template hash mismatch"):
        build_bootstrap_parent_package(
            content,
            _content_anchor(content),
            content["record_digest"],
            publication,
            _publication_anchor(publication),
            publication["binding_digest"],
            tampered,
            MODELS,
        )


def test_write_package_private_mode_and_no_overwrite(tmp_path):
    content, artifacts, _manifest = _prepare_content()
    out_dir = tmp_path / "pkg"
    write_package(artifacts, out_dir)
    assert oct(out_dir.stat().st_mode)[-3:] == "700"
    sample = out_dir / "cfn-terminal-roles.yaml"
    assert oct(sample.stat().st_mode)[-3:] == "600"
    with pytest.raises(ValueError, match="package destination already exists"):
        write_package(artifacts, out_dir)


def test_cli_content_validate_only(tmp_path):
    content = _seal_content()
    content_file = tmp_path / "content.json"
    content_file.write_text(json.dumps(content))
    anchor_file = tmp_path / "content-anchor.json"
    anchor_file.write_text(json.dumps(_content_anchor(content)))
    models_file = tmp_path / "models.json"
    models_file.write_text(json.dumps({"bedrock_model_arns": MODELS}))
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "tooling.destination_bootstrap_package",
            "content",
            "--content",
            str(content_file),
            "--content-anchor",
            str(anchor_file),
            "--expected-content-digest",
            content["record_digest"],
            "--model-selection",
            str(models_file),
            "--validate-only",
        ],
        capture_output=True,
        text=True,
        cwd=str(Path(__file__).resolve().parents[2]),
    )
    assert result.returncode == 0, result.stderr
    receipt = json.loads(result.stdout)
    assert receipt["status"] == "VALIDATED"
    assert receipt["content_record_digest"] == content["record_digest"]


def test_cli_content_and_parent_write(tmp_path):
    content = _seal_content()
    repo = Path(__file__).resolve().parents[2]
    content_file = tmp_path / "content.json"
    content_file.write_text(json.dumps(content))
    anchor_file = tmp_path / "content-anchor.json"
    anchor_file.write_text(json.dumps(_content_anchor(content)))
    models_file = tmp_path / "models.json"
    models_file.write_text(json.dumps({"bedrock_model_arns": MODELS}))
    content_out = tmp_path / "content-out"
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "tooling.destination_bootstrap_package",
            "content",
            "--content",
            str(content_file),
            "--content-anchor",
            str(anchor_file),
            "--expected-content-digest",
            content["record_digest"],
            "--model-selection",
            str(models_file),
            "--out-dir",
            str(content_out),
        ],
        capture_output=True,
        text=True,
        cwd=str(repo),
    )
    assert result.returncode == 0, result.stderr
    assert "CONTENT_PREPARED_NOT_PUBLISHED" in result.stdout
    assert oct((content_out / "validation-receipt.json").stat().st_mode)[-3:] == "600"

    manifest = json.loads((content_out / "content-manifest.json").read_text())
    publication = _seal_publication(
        content["record_digest"],
        manifest["terminal_template_sha256"],
        manifest["workload_template_sha256"],
        manifest["workload_foundation_digest"],
        "VersionId.REAL1",
        "VersionId.REALW",
    )
    publication_file = tmp_path / "publication.json"
    publication_file.write_text(json.dumps(publication))
    publication_anchor_file = tmp_path / "publication-anchor.json"
    publication_anchor_file.write_text(json.dumps(_publication_anchor(publication)))
    parent_out = tmp_path / "parent-out"
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "tooling.destination_bootstrap_package",
            "parent",
            "--content",
            str(content_file),
            "--content-anchor",
            str(anchor_file),
            "--expected-content-digest",
            content["record_digest"],
            "--publication",
            str(publication_file),
            "--publication-anchor",
            str(publication_anchor_file),
            "--expected-publication-digest",
            publication["binding_digest"],
            "--content-dir",
            str(content_out),
            "--model-selection",
            str(models_file),
            "--out-dir",
            str(parent_out),
        ],
        capture_output=True,
        text=True,
        cwd=str(repo),
    )
    assert result.returncode == 0, result.stderr
    assert "PREPARED_NOT_DEPLOYED" in result.stdout
    assert (parent_out / "cfn-tf-state-backend.yaml").read_bytes() != b""
    assert (parent_out / "cfn-terminal-roles.yaml").read_bytes() == (content_out / "cfn-terminal-roles.yaml").read_bytes()


def _parent_with_tampered_receipt(mutator):
    content, content_artifacts, manifest = _prepare_content()
    publication = _seal_publication(
        content["record_digest"],
        manifest["terminal_template_sha256"],
        manifest["workload_template_sha256"],
        manifest["workload_foundation_digest"],
        "VersionId.AAA",
        "VersionId.W1",
    )
    receipt = json.loads(content_artifacts["workload-foundation.json"])
    mutator(receipt)
    tampered = dict(content_artifacts)
    tampered["workload-foundation.json"] = json.dumps(receipt, sort_keys=True, separators=(",", ":")).encode()
    # Keep both external anchors/digests and template files unchanged.
    with pytest.raises(ValueError):
        build_bootstrap_parent_package(
            content,
            _content_anchor(content),
            content["record_digest"],
            publication,
            _publication_anchor(publication),
            publication["binding_digest"],
            tampered,
            MODELS,
        )


def test_tampered_workload_receipt_policy_digest_rejected():
    def mutate(receipt):
        receipt["policy_digests"]["workload"] = "sha256:" + ("cd" * 32)

    _parent_with_tampered_receipt(mutate)


def test_tampered_workload_receipt_account_id_rejected():
    def mutate(receipt):
        receipt["account_id"] = "123123123123"

    _parent_with_tampered_receipt(mutate)


def test_two_field_workload_receipt_rejected():
    def mutate(receipt):
        keep = {
            "contract_digest": receipt["contract_digest"],
            "template_sha256": receipt["template_sha256"],
        }
        receipt.clear()
        receipt.update(keep)

    _parent_with_tampered_receipt(mutate)


def test_resealed_receipt_for_other_target_rejected():
    from tooling.workload_foundation import build_workload_foundation

    content, content_artifacts, manifest = _prepare_content()
    publication = _seal_publication(
        content["record_digest"],
        manifest["terminal_template_sha256"],
        manifest["workload_template_sha256"],
        manifest["workload_foundation_digest"],
        "VersionId.AAA",
        "VersionId.W1",
    )
    other_identity = {
        "customer_id": content["customer_id"],
        "deployment_id": content["deployment_id"],
        "account_id": "123123123123",
        "region": content["region"],
        "environment": content["environment"],
        "aws_partition": "aws",
    }
    _template, other_receipt = build_workload_foundation(other_identity, MODELS)
    tampered = dict(content_artifacts)
    tampered["workload-foundation.json"] = json.dumps(
        other_receipt, sort_keys=True, separators=(",", ":")
    ).encode()
    with pytest.raises(ValueError):
        build_bootstrap_parent_package(
            content,
            _content_anchor(content),
            content["record_digest"],
            publication,
            _publication_anchor(publication),
            publication["binding_digest"],
            tampered,
            MODELS,
        )
