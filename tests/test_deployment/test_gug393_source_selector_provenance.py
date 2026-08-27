"""Focused regression tests for GUG-393 source-selector provenance."""

from __future__ import annotations

from typing import Any

import pytest

from tooling import platform_authority_gug393_private_input_discovery as discovery
from tooling.platform_authority_gug365_upstream_inventory import canonical_digest


AUTHORITY_ACCOUNT = "222222222222"
IDENTITY_CENTER_ACCOUNT = "333333333333"
SOURCE_COMMIT = "a" * 40
SOURCE_TREE = "b" * 40
GUG363_PLAN_DIGEST = canonical_digest({"reviewed_plan": "GUG-363"})
GUG365_PLAN_DIGEST = canonical_digest({"reviewed_plan": "GUG-365"})


def _source_bundle() -> tuple[dict[str, Any], dict[str, str]]:
    bucket = "scanalyze-platform-authority-artifacts"
    kms_key_arn = (
        f"arn:aws:kms:us-east-1:{AUTHORITY_ACCOUNT}:"
        "key/12345678-1234-1234-1234-1234567890ab"
    )
    broker_unsigned = {
        "bucket": bucket,
        "key": "platform-authority/gug-363/broker-unsigned.zip",
        "sse_kms_key_arn": kms_key_arn,
    }
    broker_signed = {
        "bucket": bucket,
        "key": "platform-authority/gug-363/broker-signed.zip",
        "sse_kms_key_arn": kms_key_arn,
    }
    factory_unsigned = {
        "bucket": bucket,
        "key": "platform-authority/gug-365/factory-unsigned.zip",
        "sse_kms_key_arn": kms_key_arn,
    }
    factory_signed = {
        "bucket": bucket,
        "key": "platform-authority/gug-365/factory-signed.zip",
        "sse_kms_key_arn": kms_key_arn,
    }
    runtime = {
        "arn": (
            f"arn:aws:lambda:us-east-1:{AUTHORITY_ACCOUNT}:"
            "function:scanalyze-platform-authority-ledger-factory"
        ),
        "immutable_version_arn": (
            f"arn:aws:lambda:us-east-1:{AUTHORITY_ACCOUNT}:"
            "function:scanalyze-platform-authority-ledger-factory:7"
        ),
    }
    roles = {
        "retire_approve": (
            f"arn:aws:iam::{AUTHORITY_ACCOUNT}:role/aws-reserved/"
            "sso.amazonaws.com/AWSReservedSSO_"
            "ScanalyzeAuthorityRetireApprove_fedcba9876543210"
        ),
        "retire_class": (
            f"arn:aws:iam::{AUTHORITY_ACCOUNT}:role/aws-reserved/"
            "sso.amazonaws.com/AWSReservedSSO_"
            "ScanalyzeAuthorityRetireClass_0123456789abcdef"
        ),
    }
    authority_targets = {
        "artifact_bucket_arn": f"arn:aws:s3:::{bucket}",
        "broker_signed_object_arn": (
            f"arn:aws:s3:::{bucket}/{broker_signed['key']}"
        ),
        "broker_unsigned_object_arn": (
            f"arn:aws:s3:::{bucket}/{broker_unsigned['key']}"
        ),
        "ledger_factory_signed_object_arn": (
            f"arn:aws:s3:::{bucket}/{factory_signed['key']}"
        ),
        "ledger_factory_unsigned_object_arn": (
            f"arn:aws:s3:::{bucket}/{factory_unsigned['key']}"
        ),
        "artifact_kms_key_arn": kms_key_arn,
        "signing_profile_arn": (
            f"arn:aws:signer:us-east-1:{AUTHORITY_ACCOUNT}:"
            "/signing-profiles/ScanalyzePlatformAuthority"
        ),
        "code_signing_config_arn": (
            f"arn:aws:lambda:us-east-1:{AUTHORITY_ACCOUNT}:"
            "code-signing-config:csc-0123456789abcdef0"
        ),
        "runtime_source_function_arn": runtime["arn"],
        "runtime_source_function_version_arn": runtime["immutable_version_arn"],
        "retire_approve_generated_role_arn": roles["retire_approve"],
        "retire_class_generated_role_arn": roles["retire_class"],
    }
    _, actor_policy_digest = discovery.render_application_actor_policy(
        authority_targets,
        authority_account_id=AUTHORITY_ACCOUNT,
    )
    instance_id = "ssoins-A1B2C3D4E5F6G7H8"
    approved_user_id = "00000000-0000-4000-8000-000000000001"
    plan363 = {
        "source": {"commit": SOURCE_COMMIT, "tree": SOURCE_TREE},
        "parameters": {
            "AuthorityAccountId": AUTHORITY_ACCOUNT,
            "IdentityStoreArn": (
                "arn:aws:identitystore:::identitystore/d-a1b2c3d4e5"
            ),
            "IdentityCenterInstanceArn": (
                f"arn:aws:sso:::instance/{instance_id}"
            ),
            "IdentityCenterApplicationArn": (
                f"arn:aws:sso::{IDENTITY_CENTER_ACCOUNT}:application/"
                f"{instance_id}/apl-Z9Y8X7W6V5U4T3S2"
            ),
            "IdentityCenterRedirectUri": "http://127.0.0.1:49152/callback",
            "ApproverIdentityStoreUserId": approved_user_id,
            "ClassifierIdentityStoreUserId": approved_user_id,
            "ApproverPermissionSetRoleArn": roles["retire_approve"],
            "ClassifierPermissionSetRoleArn": roles["retire_class"],
            "IdentityCenterApplicationActorPolicySha256": actor_policy_digest,
        },
        "artifact_signing_contract": {
            "unsigned_source": broker_unsigned,
            "signed_destination": broker_signed,
            "signer": {
                "profile_version_arn": (
                    f"arn:aws:signer:us-east-1:{AUTHORITY_ACCOUNT}:"
                    "/signing-profiles/ScanalyzePlatformAuthority/AbCdEf1234"
                )
            },
            "code_signing_config": {
                "arn": authority_targets["code_signing_config_arn"]
            },
        },
        "plan_digest": GUG363_PLAN_DIGEST,
    }
    factory_contract = {
        "unsigned_source": factory_unsigned,
        "signed_destination": factory_signed,
    }
    plan365 = {
        "ledger_factory_artifact_signing_contract": factory_contract,
        "ledger_factory_artifact_signing_contract_digest": canonical_digest(
            factory_contract
        ),
        "ledger_factory_function": runtime,
        "plan_digest": GUG365_PLAN_DIGEST,
    }
    body = {
        "record_type": discovery.SOURCE_BUNDLE_TYPE,
        "schema_version": 1,
        "gug363_plan": plan363,
        "gug365_plan": plan365,
        "identity_center_application_name": "ScanalyzeAuthority",
        "identity_center_application_provider_arn": (
            "arn:aws:sso::aws:applicationProvider/custom"
        ),
        "identity_center_kms_key_arn": (
            f"arn:aws:kms:us-east-1:{IDENTITY_CENTER_ACCOUNT}:"
            "key/abcdefab-cdef-abcd-efab-cdefabcdefab"
        ),
    }
    return (
        {**body, "source_bundle_digest": canonical_digest(body)},
        runtime,
    )


def test_runtime_source_selectors_are_provenanced_to_gug365(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        discovery.gug363,
        "validate_materialization_plan",
        lambda *args, **kwargs: None,
    )
    monkeypatch.setattr(
        discovery.gug365,
        "validate_service_role_materialization_plan",
        lambda *args, **kwargs: None,
    )
    bundle, runtime = _source_bundle()

    document = discovery.derive_source_contract(
        source_bundle=bundle,
        source_commit_sha=SOURCE_COMMIT,
        source_tree_sha=SOURCE_TREE,
    ).document

    expected_pointers = {
        "runtime_source_function_arn": "/ledger_factory_function/arn",
        "runtime_source_function_version_arn": (
            "/ledger_factory_function/immutable_version_arn"
        ),
    }
    for field, pointer in expected_pointers.items():
        assert document["authority_targets"][field] == runtime[
            "arn" if field.endswith("function_arn") else "immutable_version_arn"
        ]
        selector = document["selector_provenance"][field]
        assert selector == {
            "artifact_digest": GUG365_PLAN_DIGEST,
            "json_pointer": pointer,
            "value_digest": canonical_digest(document["authority_targets"][field]),
        }
        assert selector["artifact_digest"] != GUG363_PLAN_DIGEST
