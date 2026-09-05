"""Offline contracts for the GUG-392 private request materializer."""

from __future__ import annotations

import copy
from datetime import UTC, datetime, timedelta
from hashlib import sha256
import json
import os
from pathlib import Path
import stat
from typing import Any, Mapping

import pytest

from tooling.platform_authority_gug365_upstream_inventory import (
    canonical_digest,
    canonical_json,
)
from tooling.platform_authority_gug376_authority_inventory_collector import (
    CollectorError,
    POLICY as AUTHORITY_POLICY,
    read_private_json,
    write_private_json as custody_write_private_json,
)
from tooling.platform_authority_gug376_identity_center_inventory_collector import (
    NAMES,
    _valid_live_exact_shape,
    _render as render_identity_center_source,
)
import tooling.platform_authority_gug376_live_request_materializer as materializer
import tooling.platform_authority_gug376_live_executor as live_executor
import tests.test_deployment.test_gug376_live_readonly_orchestrator as offline_collector_harness


START = datetime(2026, 8, 26, 18, 0, tzinfo=UTC)
END = START + timedelta(minutes=30)
NOW = START + timedelta(minutes=5)
REQUEST_END = START + timedelta(minutes=10)
SOURCE_SHA = "1" * 40
TREE_SHA = "2" * 40
AUTHORITY_ACCOUNT = "111122223333"
IDENTITY_ACCOUNT = "444455556666"
IDENTITY_INSTANCE = "arn:aws:sso:::instance/ssoins-1234567890abcdef"
HOST_DIGEST = canonical_digest({"host": "synthetic-gug392"})
APPROVAL_REFERENCE_DIGEST = canonical_digest(
    {"external_approval_reference": "synthetic-gug392"}
)
ROOT = Path(__file__).parents[2]
AUTHORITY_INPUT_EXAMPLE = (
    ROOT
    / "docs/operations/platform-authority-gug392-authority-plan-input.example.json"
)
IDENTITY_INPUT_EXAMPLE = (
    ROOT
    / "docs/operations/platform-authority-gug392-identity-center-absent-plan-input.example.json"
)
AUTHORITY_EXACT_INPUT_EXAMPLE = (
    ROOT
    / "docs/operations/platform-authority-gug392-authority-exact-plan-input.example.json"
)
IDENTITY_EXACT_INPUT_EXAMPLE = (
    ROOT
    / "docs/operations/platform-authority-gug392-identity-center-exact-plan-input.example.json"
)


def _stamp(value: datetime) -> str:
    return value.isoformat().replace("+00:00", "Z")


def _authority_plan(*, exact: bool = False) -> dict[str, Any]:
    bucket = "arn:aws:s3:::synthetic-private-artifacts"
    targets = {
        "artifact_bucket_arn": bucket,
        "broker_signed_object_arn": f"{bucket}/broker-signed.zip",
        "broker_unsigned_object_arn": f"{bucket}/broker-unsigned.zip",
        "ledger_factory_signed_object_arn": f"{bucket}/factory-signed.zip",
        "ledger_factory_unsigned_object_arn": f"{bucket}/factory-unsigned.zip",
        "artifact_kms_key_arn": (
            f"arn:aws:kms:us-east-1:{AUTHORITY_ACCOUNT}:"
            "key/11111111-1111-1111-1111-111111111111"
        ),
        "signing_profile_arn": (
            f"arn:aws:signer:us-east-1:{AUTHORITY_ACCOUNT}:"
            "/signing-profiles/synthetic"
        ),
        "code_signing_config_arn": (
            f"arn:aws:lambda:us-east-1:{AUTHORITY_ACCOUNT}:"
            "code-signing-config:csc-0123456789abcdef0"
        ),
        "runtime_source_function_arn": (
            f"arn:aws:lambda:us-east-1:{AUTHORITY_ACCOUNT}:"
            "function:synthetic-source"
        ),
        "runtime_source_function_version_arn": (
            f"arn:aws:lambda:us-east-1:{AUTHORITY_ACCOUNT}:"
            "function:synthetic-source:7"
        ),
        "retire_approve_generated_role_arn": (
            f"arn:aws:iam::{AUTHORITY_ACCOUNT}:role/aws-reserved/"
            "sso.amazonaws.com/"
            "AWSReservedSSO_ScanalyzeAuthorityRetireApprove_"
            + ("fedcba9876543210" if exact else "0000000000000000")
        ),
        "retire_class_generated_role_arn": (
            f"arn:aws:iam::{AUTHORITY_ACCOUNT}:role/aws-reserved/"
            "sso.amazonaws.com/"
            "AWSReservedSSO_ScanalyzeAuthorityRetireClass_"
            + ("0123456789abcdef" if exact else "0000000000000000")
        ),
    }
    plan: dict[str, Any] = {
        "targets": targets,
        "not_before": _stamp(START),
        "not_after": _stamp(END),
        "expected_policy_digest": canonical_digest("pending"),
        "expected_account_id": AUTHORITY_ACCOUNT,
        "expected_principal_arn": (
            f"arn:aws:sts::{AUTHORITY_ACCOUNT}:"
            "assumed-role/SyntheticAuthority/operator"
        ),
        "authority_verification_digest": canonical_digest(
            {"authority": "verification"}
        ),
        "expected_generated_role_trust_policy_digests": (
            {
                "retire_approve": canonical_digest(
                    {
                        "identity_center_role": targets[
                            "retire_approve_generated_role_arn"
                        ].rsplit("/", 1)[-1]
                    }
                ),
                "retire_class": canonical_digest(
                    {
                        "identity_center_role": targets[
                            "retire_class_generated_role_arn"
                        ].rsplit("/", 1)[-1]
                    }
                ),
            }
            if exact
            else {
                key: canonical_digest(
                    {
                        "classification": "ABSENT_READY",
                        "not_applicable": "generated-role-trust-policy",
                        "role": key,
                    }
                )
                for key in ("retire_approve", "retire_class")
            }
        ),
    }
    rendered = AUTHORITY_POLICY.read_text(encoding="utf-8")
    substitutions = {
        **targets,
        "inventory_not_before": _stamp(START),
        "inventory_not_after": _stamp(END),
    }
    for key, value in substitutions.items():
        rendered = rendered.replace("${" + key + "}", value)
    plan["expected_policy_digest"] = canonical_digest(json.loads(rendered))
    return plan


def _identity_plan(*, exact: bool = False) -> dict[str, Any]:
    store = "d-1234567890"
    user = "12345678-1234-1234-1234-123456789012"
    private_targets = {
        "application_actor_policy_digest": (
            materializer.render_application_actor_policy(
                _authority_plan(exact=exact)["targets"],
                authority_account_id=AUTHORITY_ACCOUNT,
            )[1]
        ),
        "application_name": "SyntheticAuthority",
        "application_provider_arn": (
            "arn:aws:sso::aws:applicationProvider/custom"
        ),
        "application_redirect_uri": (
            "http://127.0.0.1:18443/callback"
        ),
        "approved_user_id": user,
        "approved_single_operator_user_arn": (
            f"arn:aws:identitystore:::user/{store}/{user}"
        ),
        "authority_account_arn": f"arn:aws:sso:::account/{AUTHORITY_ACCOUNT}",
        "identity_center_instance_arn": IDENTITY_INSTANCE,
        "identity_center_kms_mode": "CUSTOMER_MANAGED_KEY",
        "identity_center_kms_key_arn": (
            f"arn:aws:kms:us-east-1:{IDENTITY_ACCOUNT}:"
            "key/22222222-2222-2222-2222-222222222222"
        ),
        "identity_store_arn": (
            f"arn:aws:identitystore:::identitystore/{store}"
        ),
        "identity_store_id": store,
    }
    private_targets["identity_center_kms_binding_digest"] = canonical_digest(
        {
            "binding_name": "identity_center_kms_key_arn",
            "identity_center_instance_arn": IDENTITY_INSTANCE,
            "mode": private_targets["identity_center_kms_mode"],
            "key_arn": private_targets["identity_center_kms_key_arn"],
        }
    )
    expected_instance = {
        "identity_store_id": store,
        "instance_arn": IDENTITY_INSTANCE,
        "owner_account_id": IDENTITY_ACCOUNT,
        "status": "ACTIVE",
        "encryption": {
            "key_type": private_targets["identity_center_kms_mode"],
            "kms_key_arn": private_targets["identity_center_kms_key_arn"],
            "status": "ENABLED",
        },
    }
    plan: dict[str, Any] = {
        "private_targets": private_targets,
        "not_before": _stamp(START),
        "not_after": _stamp(END),
        "expected_account_id": IDENTITY_ACCOUNT,
        "expected_principal_arn": (
            f"arn:aws:sts::{IDENTITY_ACCOUNT}:"
            "assumed-role/SyntheticIdentity/operator"
        ),
        "authority_verification_digest": canonical_digest(
            {"identity": "verification"}
        ),
        "expected_discovery_policy_digest": canonical_digest("pending"),
        "expected_exact_policy_digest": canonical_digest(
            {
                "not_applicable": "identity-center-exact-policy",
                "classification": "ABSENT_READY",
            }
        ),
        "expected_target_digest": canonical_digest({}),
        "expected_facts_digest": canonical_digest(
            {
                "discovery": {
                    "instances": [
                        {
                            key: expected_instance[key]
                            for key in (
                                "identity_store_id",
                                "instance_arn",
                                "owner_account_id",
                                "status",
                            )
                        }
                    ],
                    "applications": [],
                    "permission_sets": [],
                },
                "instance": expected_instance,
            }
        ),
    }
    runtime_plan = copy.deepcopy(plan)
    runtime_plan["not_before"], runtime_plan["not_after"] = START, END
    plan["expected_discovery_policy_digest"] = render_identity_center_source(
        runtime_plan, None, live=True, live_discovery=True
    )[1]
    return plan


def _profiles() -> dict[str, Any]:
    return {
        "authority": {
            "name": "synthetic-authority",
            "source": "DIRECT_SSO",
            "chain_depth": 0,
        },
        "identity_center": {
            "name": "synthetic-identity",
            "source": "DIRECT_SSO",
            "chain_depth": 0,
        },
    }


def _role_digests() -> dict[str, str]:
    return {
        "authority": canonical_digest("SyntheticAuthorityReadOnly"),
        "identity_center": canonical_digest("SyntheticIdentityReadOnly"),
    }


def _root(tmp_path: Path, name: str = "private") -> Path:
    root = tmp_path / name
    root.mkdir(mode=0o700, parents=True)
    root.chmod(0o700)
    return root


def _sdk_root(tmp_path: Path, name: str = "sdk-runtime") -> Path:
    root = tmp_path / name
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    root.chmod(0o700)
    return root.resolve(strict=True)


def _arguments(root: Path) -> dict[str, Any]:
    return {
        "authority_plan": _authority_plan(),
        "identity_center_plan": _identity_plan(),
        "profiles": _profiles(),
        "expected_sso_role_name_digests": _role_digests(),
        "source_commit_sha": SOURCE_SHA,
        "source_tree_sha": TREE_SHA,
        "run_id": "synthetic-run-0001",
        "not_before": _stamp(START + timedelta(minutes=1)),
        "expires_at": _stamp(REQUEST_END),
        "host_digest": HOST_DIGEST,
        "private_root_digest": materializer.private_root_binding_digest(root),
        "sdk_runtime_root": str(
            _sdk_root(root.parent, f"{root.name}-sdk-runtime")
        ),
        "approval_reference_digest": APPROVAL_REFERENCE_DIGEST,
        "request_file": "gug376-live-request.json",
        "owner_checkpoint_file": "gug376-owner-checkpoint.json",
    }


def _materialize(root: Path) -> materializer.MaterializedLiveRequest:
    return materializer.materialize_live_request(**_arguments(root))


def _plan_inputs(*, exact: bool = False) -> tuple[dict[str, Any], dict[str, Any]]:
    authority = _authority_plan(exact=exact)
    authority.pop("expected_policy_digest")
    identity = _identity_plan(exact=exact)
    for key in (
        "expected_discovery_policy_digest",
        "expected_exact_policy_digest",
        "expected_target_digest",
        "expected_facts_digest",
    ):
        identity.pop(key)
    identity["expected_state"] = {
        "classification": "ABSENT_READY",
        "instance": {
            "identity_store_id": identity["private_targets"]["identity_store_id"],
            "instance_arn": IDENTITY_INSTANCE,
            "owner_account_id": IDENTITY_ACCOUNT,
            "status": "ACTIVE",
            "encryption": {
                "key_type": identity["private_targets"][
                    "identity_center_kms_mode"
                ],
                "kms_key_arn": identity["private_targets"][
                    "identity_center_kms_key_arn"
                ],
                "status": "ENABLED",
            },
        },
    }
    return authority, identity


def _exact_expected_state(*, boundary_present: bool = False) -> dict[str, Any]:
    identity = _identity_plan(exact=True)
    private = identity["private_targets"]
    application = (
        f"arn:aws:sso::{IDENTITY_ACCOUNT}:application/"
        "ssoins-1234567890abcdef/apl-1234567890abcdef"
    )
    permission_arns = {
        NAMES[0]: (
            "arn:aws:sso:::permissionSet/"
            "ssoins-1234567890abcdef/ps-approve1234567890"
        ),
        NAMES[1]: (
            "arn:aws:sso:::permissionSet/"
            "ssoins-1234567890abcdef/ps-classify123456789"
        ),
    }
    targets = {
        "management_account_id": IDENTITY_ACCOUNT,
        "authority_account_arn": private["authority_account_arn"],
        "identity_center_instance_arn": IDENTITY_INSTANCE,
        "identity_store_arn": private["identity_store_arn"],
        "approved_single_operator_user_arn": private[
            "approved_single_operator_user_arn"
        ],
        "identity_center_kms_mode": private["identity_center_kms_mode"],
        "identity_center_kms_key_arn": private["identity_center_kms_key_arn"],
        "identity_center_application_arn": application,
        "retire_approve_permission_set_arn": permission_arns[NAMES[0]],
        "retire_class_permission_set_arn": permission_arns[NAMES[1]],
    }
    approved_user_digest = canonical_digest(private["approved_user_id"])
    discovery = {
        "instances": [
            {
                "identity_store_id": private["identity_store_id"],
                "instance_arn": IDENTITY_INSTANCE,
                "owner_account_id": IDENTITY_ACCOUNT,
                "status": "ACTIVE",
            }
        ],
        "applications": [
            {"application_arn": application, "name": private["application_name"]}
        ],
        "permission_sets": [
            {"name": name, "permission_set_arn": permission_arns[name]}
            for name in NAMES
        ],
    }
    actor_policy_digest = private["application_actor_policy_digest"]
    permission_policy_digests = {
        name: value[1]
        for name, value in materializer.render_permission_set_inline_policies(
            authority_account_id=AUTHORITY_ACCOUNT,
            identity_center_targets=targets,
        ).items()
    }
    exact_tags = sorted(
        (
            {
                "key_digest": canonical_digest(key),
                "value_digest": canonical_digest(value),
            }
            for key, value in (
                ("managed_by", "identity-center"),
                ("service", "scanalyze-platform-authority"),
                ("work_package", "GUG-376"),
                ("environment", "non-production"),
                ("production", "false"),
            )
        ),
        key=canonical_json,
    )
    facts: dict[str, Any] = {
        "discovery": discovery,
        "instance": {
            **discovery["instances"][0],
            "encryption": {
                "key_type": private["identity_center_kms_mode"],
                "kms_key_arn": private["identity_center_kms_key_arn"],
                "status": "ENABLED",
            },
        },
        "application": {
            "application_arn": application,
            "description": {
                "ApplicationArn": application,
                "ApplicationProviderArn": private["application_provider_arn"],
                "NameDigest": canonical_digest(private["application_name"]),
                "ApplicationAccount": IDENTITY_ACCOUNT,
                "InstanceArn": IDENTITY_INSTANCE,
                "Status": "ENABLED",
                "PortalOptionsDigest": canonical_digest(
                    {
                        "SignInOptions": {
                            "Origin": "APPLICATION",
                            "ApplicationUrl": private[
                                "application_redirect_uri"
                            ].removesuffix("/callback"),
                        },
                        "Visibility": "ENABLED",
                    }
                ),
                "DescriptionDigest": canonical_digest(
                    "GUG-376 non-production authority application"
                ),
                "CreatedDate": "2026-08-26T17:55:00Z",
                "CreatedFrom": "us-east-1",
            },
            "grants": ["authorization_code"],
            "scopes": [
                {
                    "authorized_targets_digest": canonical_digest(
                        [IDENTITY_INSTANCE]
                    ),
                    "scope": "sts:identity_context",
                }
            ],
            "redirect_uris": [
                {
                    "loopback_pkce": True,
                    "uri_digest": canonical_digest(
                        private["application_redirect_uri"]
                    ),
                }
            ],
            "authentication_methods": [
                {
                    "AuthenticationMethod": {
                        "Iam": {
                            "ActorPolicy": {"policy_digest": actor_policy_digest}
                        }
                    }
                }
            ],
            "assignment_configuration": {"AssignmentRequired": True},
            "actor_policy": {"policy_digest": actor_policy_digest},
            "assignments": [
                {
                    "application_arn": application,
                    "principal_id": approved_user_digest,
                    "principal_type": "USER",
                }
            ],
            "tags": exact_tags,
        },
        "permission_sets": {},
        "assignments": {},
        "provisioning": {},
        "target_accounts": {},
        "operator": {"UserId": private["approved_user_id"]},
    }
    for name in NAMES:
        arn = permission_arns[name]
        facts["permission_sets"][name] = {
            "instance_arn": IDENTITY_INSTANCE,
            "permission_set_arn": arn,
            "description": {
                "PermissionSet": {
                    "Name": name,
                    "PermissionSetArn": arn,
                    "SessionDuration": "PT1H",
                    "DescriptionDigest": canonical_digest(
                        (
                            "GUG-215 approver single-operator permission set"
                            if name == NAMES[0]
                            else "GUG-215 classifier single-operator permission set"
                        )
                    ),
                    "CreatedDate": "2026-08-26T17:55:00Z",
                }
            },
            "managed_policies": [],
            "customer_managed_policies": [],
            "inline_policy": {
                "policy_digest": permission_policy_digests[name]
            },
            "boundary": (
                {"ManagedPolicyArn": "arn:aws:iam::aws:policy/ReadOnlyAccess"}
                if boundary_present
                else None
            ),
            "tags": copy.deepcopy(exact_tags),
        }
        facts["assignments"][name] = [
            {
                "account_arn": private["authority_account_arn"],
                "permission_set_arn": arn,
                "principal_id": approved_user_digest,
                "principal_type": "USER",
            }
        ]
        facts["provisioning"][name] = [
            {"permission_set_arn": arn, "status": "SUCCEEDED"}
        ]
        facts["target_accounts"][name] = [
            {
                "account_arn": private["authority_account_arn"],
                "permission_set_arn": arn,
            }
        ]
    return {
        "classification": "EXACT_PRESENT_NO_TOUCH",
        "targets": targets,
        "facts": facts,
    }


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("key_type", "AWS_OWNED_KEY"),
        (
            "kms_key_arn",
            "arn:aws:kms:us-east-1:444455556666:"
            "key/33333333-3333-3333-3333-333333333333",
        ),
        ("status", "DISABLED"),
    ),
)
def test_live_exact_state_rejects_instance_encryption_drift(
    field: str, value: str
) -> None:
    state = _exact_expected_state()
    assert _valid_live_exact_shape(state["facts"], state["targets"])

    drifted = copy.deepcopy(state["facts"])
    drifted["instance"]["encryption"][field] = value

    assert not _valid_live_exact_shape(drifted, state["targets"])


def test_plan_materialization_computes_live_policy_and_absence_digests(
    tmp_path: Path,
) -> None:
    authority_input, identity_input = _plan_inputs()
    first = materializer.materialize_live_plans(
        authority_input=authority_input,
        identity_center_input=identity_input,
    )
    second = materializer.materialize_live_plans(
        authority_input=dict(reversed(tuple(authority_input.items()))),
        identity_center_input=dict(reversed(tuple(identity_input.items()))),
    )
    assert first == second
    assert first.identity_center_plan["expected_target_digest"] == canonical_digest({})
    assert first.identity_center_plan["expected_facts_digest"] == canonical_digest(
        {
            "discovery": {
                "instances": [
                    {
                        "identity_store_id": "d-1234567890",
                        "instance_arn": IDENTITY_INSTANCE,
                        "owner_account_id": IDENTITY_ACCOUNT,
                        "status": "ACTIVE",
                    }
                ],
                "applications": [],
                "permission_sets": [],
            },
            "instance": identity_input["expected_state"]["instance"],
        }
    )
    runtime_identity = copy.deepcopy(first.identity_center_plan)
    runtime_identity["not_before"], runtime_identity["not_after"] = START, END
    assert first.identity_center_plan["expected_discovery_policy_digest"] == (
        render_identity_center_source(
            runtime_identity, None, live=True, live_discovery=True
        )[1]
    )

    root = _root(tmp_path)
    materializer.persist_materialized_live_plans(
        root,
        first,
        authority_plan_file="authority-plan.json",
        identity_center_plan_file="identity-center-plan.json",
    )
    assert read_private_json(root, "authority-plan.json") == first.authority_plan
    assert read_private_json(root, "identity-center-plan.json") == (
        first.identity_center_plan
    )
    assert all(
        stat.S_IMODE((root / name).stat().st_mode) == 0o600
        for name in ("authority-plan.json", "identity-center-plan.json")
    )
    with pytest.raises(
        materializer.LiveRequestMaterializationError,
        match="PRIVATE_ARTIFACT_EXISTS",
    ):
        materializer.persist_materialized_live_plans(
            root,
            first,
            authority_plan_file="authority-plan.json",
            identity_center_plan_file="identity-center-plan.json",
        )


def test_documented_absent_plan_inputs_materialize_without_hidden_fields() -> None:
    result = materializer.materialize_live_plans(
        authority_input=json.loads(AUTHORITY_INPUT_EXAMPLE.read_text()),
        identity_center_input=json.loads(IDENTITY_INPUT_EXAMPLE.read_text()),
    )
    assert result.authority_plan["expected_account_id"] == "111122223333"
    assert result.identity_center_plan["expected_account_id"] == "444455556666"
    assert result.identity_center_plan["expected_target_digest"] == canonical_digest({})


def test_documented_exact_plan_inputs_materialize_without_hidden_fields() -> None:
    identity_input = json.loads(IDENTITY_EXACT_INPUT_EXAMPLE.read_text())
    result = materializer.materialize_live_plans(
        authority_input=json.loads(AUTHORITY_EXACT_INPUT_EXAMPLE.read_text()),
        identity_center_input=identity_input,
    )
    assert result.authority_plan["expected_account_id"] == "111122223333"
    assert result.identity_center_plan["expected_account_id"] == "444455556666"
    assert result.identity_center_plan["expected_target_digest"] == canonical_digest(
        identity_input["expected_state"]["targets"]
    )
    assert result.identity_center_plan["expected_facts_digest"] == canonical_digest(
        identity_input["expected_state"]["facts"]
    )


@pytest.mark.parametrize(
    ("target", "replacement"),
    (
        (
            "retire_approve_generated_role_arn",
            "AWSReservedSSO_Approve_0123456789abcdef",
        ),
        (
            "retire_class_generated_role_arn",
            "AWSReservedSSO_ScanalyzeAuthorityRetireApprove_0123456789abcdef",
        ),
        (
            "retire_class_generated_role_arn",
            "AWSReservedSSO_ScanalyzeAuthorityRetireClass_0123456789abcde",
        ),
    ),
)
def test_plan_materialization_rejects_noncanonical_generated_role_names(
    target: str, replacement: str
) -> None:
    authority_input, identity_input = _plan_inputs()
    prefix = (
        f"arn:aws:iam::{AUTHORITY_ACCOUNT}:role/aws-reserved/"
        "sso.amazonaws.com/"
    )
    authority_input["targets"][target] = prefix + replacement
    with pytest.raises(
        materializer.LiveRequestMaterializationError,
        match="GENERATED_ROLE_SOURCE_CONTRACT_INVALID",
    ):
        materializer.materialize_live_plans(
            authority_input=authority_input,
            identity_center_input=identity_input,
        )


@pytest.mark.parametrize("classification", ("ABSENT_READY", "EXACT_PRESENT_NO_TOUCH"))
def test_plan_materialization_rejects_unbound_actor_policy_digest(
    classification: str,
) -> None:
    authority_input, identity_input = _plan_inputs(
        exact=classification == "EXACT_PRESENT_NO_TOUCH"
    )
    identity_input["private_targets"]["application_actor_policy_digest"] = (
        canonical_digest({"unreviewed": "actor-policy"})
    )
    if classification == "EXACT_PRESENT_NO_TOUCH":
        identity_input["expected_state"] = _exact_expected_state()
    with pytest.raises(
        materializer.LiveRequestMaterializationError,
        match="APPLICATION_ACTOR_POLICY_BINDING_INVALID",
    ):
        materializer.materialize_live_plans(
            authority_input=authority_input,
            identity_center_input=identity_input,
        )


def test_absent_plan_rejects_generated_role_trust_overclaim() -> None:
    authority_input, identity_input = _plan_inputs()
    authority_input["expected_generated_role_trust_policy_digests"][
        "retire_approve"
    ] = canonical_digest({"unreviewed": "trust-policy"})
    with pytest.raises(
        materializer.LiveRequestMaterializationError,
        match="ABSENT_GENERATED_ROLE_TRUST_SENTINEL_INVALID",
    ):
        materializer.materialize_live_plans(
            authority_input=authority_input,
            identity_center_input=identity_input,
        )


@pytest.mark.parametrize("placeholder_mode", ("missing", "duplicate"))
def test_actor_policy_renderer_rejects_placeholder_source_drift(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    placeholder_mode: str,
) -> None:
    original = materializer.APPLICATION_ACTOR_POLICY_SOURCE.read_text()
    marker = "${classifier_permission_set_role_arn}"
    altered = (
        original.replace(marker, "missing")
        if placeholder_mode == "missing"
        else original.replace(marker, marker + marker)
    )
    source = tmp_path / "actor-policy.json"
    source.write_text(altered)
    monkeypatch.setattr(materializer, "APPLICATION_ACTOR_POLICY_SOURCE", source)
    monkeypatch.setattr(
        materializer,
        "APPLICATION_ACTOR_POLICY_SOURCE_SHA256",
        sha256(altered.encode()).hexdigest(),
    )
    authority_input = _authority_plan()
    with pytest.raises(
        materializer.LiveRequestMaterializationError,
        match="APPLICATION_ACTOR_POLICY_SOURCE_INVALID",
    ):
        materializer.render_application_actor_policy(
            authority_input["targets"],
            authority_account_id=AUTHORITY_ACCOUNT,
        )


@pytest.mark.parametrize(
    ("mutation", "code"),
    (
        ("role-name", "GENERATED_ROLE_SOURCE_CONTRACT_INVALID"),
        ("actor-digest", "APPLICATION_ACTOR_POLICY_BINDING_INVALID"),
    ),
)
def test_request_materialization_recertifies_source_contract(
    tmp_path: Path, mutation: str, code: str
) -> None:
    arguments = _arguments(_root(tmp_path))
    if mutation == "role-name":
        arguments["authority_plan"]["targets"][
            "retire_approve_generated_role_arn"
        ] = (
            f"arn:aws:iam::{AUTHORITY_ACCOUNT}:role/aws-reserved/"
            "sso.amazonaws.com/AWSReservedSSO_Approve_0123456789abcdef"
        )
    else:
        arguments["identity_center_plan"]["private_targets"][
            "application_actor_policy_digest"
        ] = canonical_digest({"unreviewed": "actor-policy"})
    with pytest.raises(materializer.LiveRequestMaterializationError, match=code):
        materializer.materialize_live_request(**arguments)


def test_exact_plan_materialization_is_closed_and_request_ready(
    tmp_path: Path,
) -> None:
    authority_input, identity_input = _plan_inputs(exact=True)
    exact = _exact_expected_state()
    identity_input["expected_state"] = exact
    plans = materializer.materialize_live_plans(
        authority_input=authority_input,
        identity_center_input=identity_input,
    )
    assert plans.identity_center_plan["expected_target_digest"] == canonical_digest(
        exact["targets"]
    )
    assert plans.identity_center_plan["expected_facts_digest"] == canonical_digest(
        exact["facts"]
    )
    runtime_identity = copy.deepcopy(plans.identity_center_plan)
    runtime_identity["not_before"], runtime_identity["not_after"] = START, END
    assert plans.identity_center_plan["expected_exact_policy_digest"] == (
        render_identity_center_source(
            runtime_identity,
            exact["targets"],
            live=True,
            live_discovery=False,
        )[1]
    )
    encoded = canonical_json(plans.identity_center_plan)
    assert "Emails" not in encoded and "UserName" not in encoded

    arguments = _arguments(_root(tmp_path))
    arguments["authority_plan"] = plans.authority_plan
    arguments["identity_center_plan"] = plans.identity_center_plan
    request = materializer.materialize_live_request(**arguments)
    assert request.owner_checkpoint["identity_center_plan_digest"] == (
        materializer.identity_center_plan_binding(runtime_identity)[1]
    )


def test_exact_plan_materialization_rejects_source_divergent_inline_policy() -> None:
    authority_input, identity_input = _plan_inputs(exact=True)
    exact = _exact_expected_state()
    exact["facts"]["permission_sets"][NAMES[0]]["inline_policy"][
        "policy_digest"
    ] = canonical_digest({"unreviewed": "permission-set-policy"})
    identity_input["expected_state"] = exact
    with pytest.raises(
        materializer.LiveRequestMaterializationError,
        match="PERMISSION_SET_POLICY_BINDING_INVALID",
    ):
        materializer.materialize_live_plans(
            authority_input=authority_input,
            identity_center_input=identity_input,
        )


def test_permission_set_policy_renderer_rejects_source_drift(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    exact = _exact_expected_state()
    sources = dict(materializer.PERMISSION_SET_POLICY_SOURCES)
    name = NAMES[0]
    original_source, expected_sha256 = sources[name]
    drifted_source = tmp_path / "permission-set-policy.json"
    drifted_source.write_bytes(original_source.read_bytes() + b"\n")
    sources[name] = (drifted_source, expected_sha256)
    monkeypatch.setattr(materializer, "PERMISSION_SET_POLICY_SOURCES", sources)
    with pytest.raises(
        materializer.LiveRequestMaterializationError,
        match="PERMISSION_SET_POLICY_SOURCE_DRIFT",
    ):
        materializer.render_permission_set_inline_policies(
            authority_account_id=AUTHORITY_ACCOUNT,
            identity_center_targets=exact["targets"],
        )


@pytest.mark.parametrize(
    "path",
    (
        "application-assignment-extra",
        "application-description-extra",
        "application-provider-drift",
        "application-name-drift",
        "application-portal-drift",
        "missing-grant",
        "wrong-grant",
        "missing-scope",
        "wrong-scope",
        "scope-target-drift",
        "missing-redirect",
        "non-loopback-redirect",
        "redirect-owner-drift",
        "missing-authentication",
        "actor-policy-drift",
        "assignment-not-required",
        "missing-application-tag",
        "extra-application-tag",
        "missing-permission-tag",
        "permission-description-drift",
        "permission-description-extra",
        "raw-tag",
        "second-application-user",
        "wrong-account-principal",
        "failed-provisioning",
        "permission-boundary",
        "managed-policy",
        "customer-managed-policy",
        "relay-state",
        "missing-inline-policy",
        "wrong-session-duration",
    ),
)
def test_exact_plan_materialization_rejects_nested_or_topology_expansion(
    path: str,
) -> None:
    authority_input, identity_input = _plan_inputs(exact=True)
    exact = _exact_expected_state()
    facts = exact["facts"]
    if path == "application-assignment-extra":
        facts["application"]["assignments"][0]["email"] = "private@example.invalid"
    elif path == "application-description-extra":
        facts["application"]["description"]["Unexpected"] = "drift"
    elif path == "application-provider-drift":
        facts["application"]["description"]["ApplicationProviderArn"] = (
            "arn:aws:sso::aws:applicationProvider/another"
        )
    elif path == "application-name-drift":
        facts["application"]["description"]["NameDigest"] = canonical_digest(
            "AnotherApplication"
        )
    elif path == "application-portal-drift":
        facts["application"]["description"]["PortalOptionsDigest"] = (
            canonical_digest({"Visibility": "DISABLED"})
        )
    elif path == "missing-grant":
        facts["application"]["grants"] = []
    elif path == "wrong-grant":
        facts["application"]["grants"] = ["refresh_token"]
    elif path == "missing-scope":
        facts["application"]["scopes"] = []
    elif path == "wrong-scope":
        facts["application"]["scopes"][0]["scope"] = "openid"
    elif path == "scope-target-drift":
        facts["application"]["scopes"][0]["authorized_targets_digest"] = (
            canonical_digest([])
        )
    elif path == "missing-redirect":
        facts["application"]["redirect_uris"] = []
    elif path == "non-loopback-redirect":
        facts["application"]["redirect_uris"][0]["loopback_pkce"] = False
    elif path == "redirect-owner-drift":
        facts["application"]["redirect_uris"][0]["uri_digest"] = (
            canonical_digest("http://127.0.0.1:28443/callback")
        )
    elif path == "missing-authentication":
        facts["application"]["authentication_methods"] = []
    elif path == "actor-policy-drift":
        drift = {"policy_digest": canonical_digest({"actor": "another"})}
        facts["application"]["actor_policy"] = drift
        facts["application"]["authentication_methods"][0][
            "AuthenticationMethod"
        ]["Iam"]["ActorPolicy"] = drift
    elif path == "assignment-not-required":
        facts["application"]["assignment_configuration"] = {
            "AssignmentRequired": False
        }
    elif path == "missing-application-tag":
        facts["application"]["tags"].pop()
    elif path == "extra-application-tag":
        facts["application"]["tags"].append(
            {
                "key_digest": canonical_digest("extra"),
                "value_digest": canonical_digest("drift"),
            }
        )
    elif path == "missing-permission-tag":
        facts["permission_sets"][NAMES[0]]["tags"].pop()
    elif path == "permission-description-drift":
        facts["permission_sets"][NAMES[0]]["description"]["PermissionSet"][
            "DescriptionDigest"
        ] = canonical_digest("drift")
    elif path == "permission-description-extra":
        facts["permission_sets"][NAMES[0]]["description"]["PermissionSet"][
            "Description"
        ] = "raw private description"
    elif path == "raw-tag":
        facts["application"]["tags"][0]["Value"] = "raw-private-value"
    elif path == "second-application-user":
        facts["application"]["assignments"].append(
            dict(facts["application"]["assignments"][0])
        )
    elif path == "wrong-account-principal":
        facts["assignments"][NAMES[0]][0]["principal_id"] = canonical_digest(
            "another-user"
        )
    elif path == "failed-provisioning":
        facts["provisioning"][NAMES[1]][0]["status"] = "FAILED"
    elif path == "permission-boundary":
        facts["permission_sets"][NAMES[0]]["boundary"] = {
            "ManagedPolicyArn": "arn:aws:iam::aws:policy/ReadOnlyAccess"
        }
    elif path == "managed-policy":
        facts["permission_sets"][NAMES[0]]["managed_policies"] = [
            {
                "Name": "ReadOnlyAccess",
                "Arn": "arn:aws:iam::aws:policy/ReadOnlyAccess",
            }
        ]
    elif path == "customer-managed-policy":
        facts["permission_sets"][NAMES[0]]["customer_managed_policies"] = [
            {"Name": "Forbidden", "Path": "/"}
        ]
    elif path == "relay-state":
        facts["permission_sets"][NAMES[0]]["description"]["PermissionSet"][
            "RelayStateDigest"
        ] = canonical_digest("forbidden-relay-state")
    elif path == "missing-inline-policy":
        facts["permission_sets"][NAMES[0]]["inline_policy"] = None
    else:
        facts["permission_sets"][NAMES[0]]["description"]["PermissionSet"][
            "SessionDuration"
        ] = "PT2H"
    identity_input["expected_state"] = exact
    with pytest.raises(
        materializer.LiveRequestMaterializationError,
        match="IDENTITY_CENTER_EXPECTED_STATE_INVALID",
    ):
        materializer.materialize_live_plans(
            authority_input=authority_input,
            identity_center_input=identity_input,
        )


def test_plan_materialization_rejects_unclosed_or_sensitive_expected_state() -> None:
    authority_input, identity_input = _plan_inputs()
    identity_input["unexpected"] = True
    with pytest.raises(
        materializer.LiveRequestMaterializationError,
        match="IDENTITY_CENTER_PLAN_INPUT_INVALID",
    ):
        materializer.materialize_live_plans(
            authority_input=authority_input,
            identity_center_input=identity_input,
        )

    _, identity_input = _plan_inputs()
    identity_input["expected_state"] = {
        "classification": "EXACT_PRESENT_NO_TOUCH",
        "targets": {},
        "facts": {
            "operator": {
                "UserId": "synthetic",
                "Emails": [{"Value": "sensitive@example.invalid"}],
            }
        },
    }
    with pytest.raises(
        materializer.LiveRequestMaterializationError,
        match="IDENTITY_CENTER_EXPECTED_STATE_INVALID",
    ):
        materializer.materialize_live_plans(
            authority_input=authority_input,
            identity_center_input=identity_input,
        )


def test_materialization_is_deterministic_and_digest_order_is_acyclic(
    tmp_path: Path,
) -> None:
    root = _root(tmp_path)
    first = _materialize(root)
    reordered = _arguments(root)
    reordered["profiles"] = dict(reversed(tuple(reordered["profiles"].items())))
    second = materializer.materialize_live_request(**reordered)
    assert first == second

    request = first.request
    checkpoint = first.owner_checkpoint
    request_core = {
        key: value
        for key, value in request.items()
        if key not in {"owner_checkpoint_digest", "request_digest"}
    }
    assert checkpoint["request_binding_digest"] == canonical_digest(request_core)
    assert checkpoint["checkpoint_digest"] == canonical_digest(
        {key: value for key, value in checkpoint.items() if key != "checkpoint_digest"}
    )
    assert request["owner_checkpoint_digest"] == checkpoint["checkpoint_digest"]
    assert request["request_digest"] == canonical_digest(
        {key: value for key, value in request.items() if key != "request_digest"}
    )
    assert first.request_bytes == (canonical_json(request) + "\n").encode()
    assert first.owner_checkpoint_bytes == (
        canonical_json(checkpoint) + "\n"
    ).encode()
    assert request["implementation_issue"] == "GUG-392"
    assert request["parent_issue"] == "GUG-376"
    assert request["approval_reference_digest"] == APPROVAL_REFERENCE_DIGEST
    assert checkpoint["approval_reference_digest"] == APPROVAL_REFERENCE_DIGEST
    assert request["sdk_runtime_root"] == _arguments(root)["sdk_runtime_root"]
    assert checkpoint["sdk_runtime_root"] == request["sdk_runtime_root"]
    assert checkpoint["sdk_runtime_root_digest"] == canonical_digest(
        request["sdk_runtime_root"]
    )
    assert request["read_only"] is request["live_read_only_authorized"] is True
    assert request["aws_mutations"] == 0
    assert request["deployment_authorized"] is False
    assert request["production_status"] == "NO-GO"


def test_private_persistence_and_read_hydrate_json_timestamps(
    tmp_path: Path,
) -> None:
    root = _root(tmp_path)
    result = _materialize(root)
    materializer.persist_materialized_live_request(root, result)

    for name in (result.request["request_file"], result.request["owner_checkpoint_file"]):
        path = root / name
        metadata = path.stat()
        assert stat.S_IMODE(metadata.st_mode) == 0o600
        assert metadata.st_nlink == 1
        assert path.read_bytes() == (
            canonical_json(read_private_json(root, name)) + "\n"
        ).encode()
    assert stat.S_IMODE(root.stat().st_mode) == 0o700

    validated = materializer.read_materialized_live_request(
        root,
        result.request["request_file"],
        now=NOW,
        expected_source_commit_sha=SOURCE_SHA,
        expected_source_tree_sha=TREE_SHA,
        expected_host_digest=HOST_DIGEST,
        expected_approval_reference_digest=APPROVAL_REFERENCE_DIGEST,
        expected_request_digest=result.request["request_digest"],
        expected_checkpoint_digest=result.owner_checkpoint["checkpoint_digest"],
    )
    assert validated.request == result.request
    assert validated.owner_checkpoint == result.owner_checkpoint
    assert isinstance(
        validated.runtime_config["authority_plan"]["not_before"], datetime
    )
    assert isinstance(
        validated.runtime_config["identity_center_plan"]["not_after"], datetime
    )
    assert validated.runtime_config["authority_plan"]["not_before"] == START
    assert validated.runtime_config["sdk_runtime_root"] == result.request[
        "sdk_runtime_root"
    ]

    before = {path.name: path.read_bytes() for path in root.iterdir()}
    with pytest.raises(
        materializer.LiveRequestMaterializationError,
        match="PRIVATE_ARTIFACT_EXISTS",
    ):
        materializer.persist_materialized_live_request(root, result)
    assert {path.name: path.read_bytes() for path in root.iterdir()} == before


def test_resealed_request_or_substituted_checkpoint_is_rejected(
    tmp_path: Path,
) -> None:
    root = _root(tmp_path)
    result = _materialize(root)
    request = copy.deepcopy(result.request)
    checkpoint = copy.deepcopy(result.owner_checkpoint)
    request["run_id"] = "synthetic-run-0002"
    request_core = {
        key: value
        for key, value in request.items()
        if key not in {"owner_checkpoint_digest", "request_digest"}
    }
    checkpoint["request_binding_digest"] = canonical_digest(request_core)
    checkpoint["checkpoint_digest"] = canonical_digest(
        {key: value for key, value in checkpoint.items() if key != "checkpoint_digest"}
    )
    request["owner_checkpoint_digest"] = checkpoint["checkpoint_digest"]
    request["request_digest"] = canonical_digest(
        {key: value for key, value in request.items() if key != "request_digest"}
    )
    with pytest.raises(
        materializer.LiveRequestMaterializationError,
        match="PRIVATE_REQUEST_BINDING_MISMATCH",
    ):
        materializer.validate_materialized_live_request(
            request,
            checkpoint,
            now=NOW,
            expected_source_commit_sha=SOURCE_SHA,
            expected_source_tree_sha=TREE_SHA,
            expected_host_digest=HOST_DIGEST,
            expected_private_root_digest=result.request["private_root_digest"],
            expected_approval_reference_digest=APPROVAL_REFERENCE_DIGEST,
        )

    substituted_approval = canonical_digest({"approval": "substituted"})
    request = copy.deepcopy(result.request)
    checkpoint = copy.deepcopy(result.owner_checkpoint)
    request["approval_reference_digest"] = substituted_approval
    request_core = {
        key: value
        for key, value in request.items()
        if key not in {"owner_checkpoint_digest", "request_digest"}
    }
    checkpoint["approval_reference_digest"] = substituted_approval
    checkpoint["request_binding_digest"] = canonical_digest(request_core)
    checkpoint["checkpoint_digest"] = canonical_digest(
        {key: value for key, value in checkpoint.items() if key != "checkpoint_digest"}
    )
    request["owner_checkpoint_digest"] = checkpoint["checkpoint_digest"]
    request["request_digest"] = canonical_digest(
        {key: value for key, value in request.items() if key != "request_digest"}
    )
    with pytest.raises(
        materializer.LiveRequestMaterializationError,
        match="APPROVAL_REFERENCE_MISMATCH",
    ):
        materializer.validate_materialized_live_request(
            request,
            checkpoint,
            now=NOW,
            expected_source_commit_sha=SOURCE_SHA,
            expected_source_tree_sha=TREE_SHA,
            expected_host_digest=HOST_DIGEST,
            expected_private_root_digest=result.request["private_root_digest"],
            expected_approval_reference_digest=APPROVAL_REFERENCE_DIGEST,
        )

    foreign = _materialize(_root(tmp_path, "foreign")).owner_checkpoint
    with pytest.raises(
        materializer.LiveRequestMaterializationError,
        match="OWNER_CHECKPOINT_BINDING_MISMATCH",
    ):
        materializer.validate_materialized_live_request(
            result.request,
            foreign,
            now=NOW,
            expected_source_commit_sha=SOURCE_SHA,
            expected_source_tree_sha=TREE_SHA,
            expected_host_digest=HOST_DIGEST,
            expected_private_root_digest=result.request["private_root_digest"],
            expected_approval_reference_digest=APPROVAL_REFERENCE_DIGEST,
        )


@pytest.mark.parametrize(
    ("case", "code"),
    (
        ("relative", "SDK_RUNTIME_ROOT_INVALID"),
        ("noncanonical", "SDK_RUNTIME_ROOT_INVALID"),
        ("missing", "SDK_RUNTIME_ROOT_INVALID"),
        ("inside-source", "SDK_RUNTIME_INSIDE_SOURCE_ROOT"),
    ),
)
def test_sdk_runtime_root_must_be_canonical_existing_and_outside_source(
    tmp_path: Path, case: str, code: str
) -> None:
    root = _root(tmp_path)
    arguments = _arguments(root)
    sdk_root = Path(arguments["sdk_runtime_root"])
    if case == "relative":
        arguments["sdk_runtime_root"] = "sdk-runtime"
    elif case == "noncanonical":
        detour = _sdk_root(tmp_path, "detour")
        arguments["sdk_runtime_root"] = f"{detour}/../{sdk_root.name}"
    elif case == "missing":
        arguments["sdk_runtime_root"] = str(
            (tmp_path / "missing-sdk-runtime").resolve()
        )
    else:
        arguments["sdk_runtime_root"] = str(ROOT.resolve(strict=True))

    with pytest.raises(materializer.LiveRequestMaterializationError, match=code):
        materializer.materialize_live_request(**arguments)
    assert list(root.iterdir()) == []


def test_validator_rejects_resealed_sdk_runtime_path_or_digest_mismatch(
    tmp_path: Path,
) -> None:
    root = _root(tmp_path)
    result = _materialize(root)
    alternate = str(_sdk_root(tmp_path, "alternate-sdk-runtime"))

    request = copy.deepcopy(result.request)
    request["sdk_runtime_root"] = alternate
    request["request_digest"] = canonical_digest(
        {key: value for key, value in request.items() if key != "request_digest"}
    )
    with pytest.raises(
        materializer.LiveRequestMaterializationError,
        match="SDK_RUNTIME_ROOT_BINDING_MISMATCH",
    ):
        materializer.validate_materialized_live_request(
            request,
            result.owner_checkpoint,
            now=NOW,
            expected_source_commit_sha=SOURCE_SHA,
            expected_source_tree_sha=TREE_SHA,
            expected_host_digest=HOST_DIGEST,
            expected_private_root_digest=result.request["private_root_digest"],
            expected_approval_reference_digest=APPROVAL_REFERENCE_DIGEST,
        )

    request = copy.deepcopy(result.request)
    checkpoint = copy.deepcopy(result.owner_checkpoint)
    checkpoint["sdk_runtime_root_digest"] = canonical_digest(alternate)
    checkpoint["checkpoint_digest"] = canonical_digest(
        {key: value for key, value in checkpoint.items() if key != "checkpoint_digest"}
    )
    request["owner_checkpoint_digest"] = checkpoint["checkpoint_digest"]
    request["request_digest"] = canonical_digest(
        {key: value for key, value in request.items() if key != "request_digest"}
    )
    with pytest.raises(
        materializer.LiveRequestMaterializationError,
        match="SDK_RUNTIME_ROOT_BINDING_MISMATCH",
    ):
        materializer.validate_materialized_live_request(
            request,
            checkpoint,
            now=NOW,
            expected_source_commit_sha=SOURCE_SHA,
            expected_source_tree_sha=TREE_SHA,
            expected_host_digest=HOST_DIGEST,
            expected_private_root_digest=result.request["private_root_digest"],
            expected_approval_reference_digest=APPROVAL_REFERENCE_DIGEST,
        )


@pytest.mark.parametrize(
    ("target", "field", "replacement", "error"),
    [
        ("request", "read_only", 1, "PRIVATE_REQUEST_DIGEST_MISMATCH"),
        ("request", "schema_version", True, "PRIVATE_REQUEST_DIGEST_MISMATCH"),
        ("request", "aws_mutations", 0.0, "PRIVATE_REQUEST_DIGEST_MISMATCH"),
        (
            "checkpoint",
            "read_only",
            1,
            "OWNER_CHECKPOINT_DIGEST_MISMATCH",
        ),
        (
            "checkpoint",
            "schema_version",
            True,
            "OWNER_CHECKPOINT_DIGEST_MISMATCH",
        ),
        (
            "checkpoint",
            "aws_mutations",
            0.0,
            "OWNER_CHECKPOINT_DIGEST_MISMATCH",
        ),
    ],
)
def test_reader_rejects_type_substitution_with_stale_reviewed_digest(
    tmp_path: Path,
    target: str,
    field: str,
    replacement: object,
    error: str,
) -> None:
    root = _root(tmp_path)
    result = _materialize(root)
    materializer.persist_materialized_live_request(root, result)
    filename = (
        result.request["request_file"]
        if target == "request"
        else result.request["owner_checkpoint_file"]
    )
    path = root / filename
    value = read_private_json(root, filename)
    value[field] = replacement
    path.write_text(canonical_json(value) + "\n", encoding="utf-8")

    with pytest.raises(materializer.LiveRequestMaterializationError, match=error):
        materializer.read_materialized_live_request(
            root,
            result.request["request_file"],
            now=NOW,
            expected_source_commit_sha=SOURCE_SHA,
            expected_source_tree_sha=TREE_SHA,
            expected_host_digest=HOST_DIGEST,
            expected_approval_reference_digest=APPROVAL_REFERENCE_DIGEST,
            expected_request_digest=result.request["request_digest"],
            expected_checkpoint_digest=result.owner_checkpoint[
                "checkpoint_digest"
            ],
        )


@pytest.mark.parametrize("target", ["request", "checkpoint"])
def test_validator_rejects_resealed_bool_integer_substitution(
    tmp_path: Path, target: str
) -> None:
    result = _materialize(_root(tmp_path))
    request = copy.deepcopy(result.request)
    checkpoint = copy.deepcopy(result.owner_checkpoint)
    if target == "request":
        request["read_only"] = 1
        request["request_digest"] = canonical_digest(
            {key: value for key, value in request.items() if key != "request_digest"}
        )
        error = "PRIVATE_REQUEST_BINDING_MISMATCH"
    else:
        checkpoint["read_only"] = 1
        checkpoint["checkpoint_digest"] = canonical_digest(
            {
                key: value
                for key, value in checkpoint.items()
                if key != "checkpoint_digest"
            }
        )
        request["owner_checkpoint_digest"] = checkpoint["checkpoint_digest"]
        request["request_digest"] = canonical_digest(
            {key: value for key, value in request.items() if key != "request_digest"}
        )
        error = "PRIVATE_REQUEST_BINDING_MISMATCH"

    with pytest.raises(materializer.LiveRequestMaterializationError, match=error):
        materializer.validate_materialized_live_request(
            request,
            checkpoint,
            now=NOW,
            expected_source_commit_sha=SOURCE_SHA,
            expected_source_tree_sha=TREE_SHA,
            expected_host_digest=HOST_DIGEST,
            expected_private_root_digest=result.request["private_root_digest"],
            expected_approval_reference_digest=APPROVAL_REFERENCE_DIGEST,
        )


@pytest.mark.parametrize(
    ("case", "code"),
    [
        ("same-profile", "PROFILE_BINDING_INVALID"),
        ("default-profile", "PROFILE_BINDING_INVALID"),
        ("forbidden-profile", "PROFILE_BINDING_INVALID"),
        ("role-chain", "PROFILE_BINDING_INVALID"),
        ("same-effective-account", "CROSS_DOMAIN_PLAN_BINDING_INVALID"),
        ("wrong-authority-target", "CROSS_DOMAIN_PLAN_BINDING_INVALID"),
        ("long-window", "REQUEST_WINDOW_INVALID"),
        ("outside-plan", "REQUEST_WINDOW_INVALID"),
        ("fractional-time", "REQUEST_WINDOW_INVALID"),
        ("file-collision", "PRIVATE_OUTPUT_COLLISION"),
        ("reserved-request", "PRIVATE_OUTPUT_COLLISION"),
        ("reserved-checkpoint", "PRIVATE_OUTPUT_COLLISION"),
        ("wrong-source", "SOURCE_BINDING_INVALID"),
        ("bad-role-digest", "SSO_ROLE_BINDING_INVALID"),
        ("bad-approval-digest", "APPROVAL_REFERENCE_DIGEST_INVALID"),
    ],
)
def test_materializer_fails_closed_before_private_io(
    tmp_path: Path, case: str, code: str
) -> None:
    root = _root(tmp_path)
    arguments = _arguments(root)
    if case == "same-profile":
        arguments["profiles"]["identity_center"]["name"] = (
            arguments["profiles"]["authority"]["name"]
        )
    elif case == "default-profile":
        arguments["profiles"]["authority"]["name"] = "default"
    elif case == "forbidden-profile":
        arguments["profiles"]["authority"]["name"] = (
            "042360977644_ScanalyzeAuthorityBootstrapPlan"
        )
    elif case == "role-chain":
        arguments["profiles"]["authority"]["chain_depth"] = 1
    elif case == "same-effective-account":
        arguments["identity_center_plan"]["expected_account_id"] = AUTHORITY_ACCOUNT
    elif case == "wrong-authority-target":
        arguments["identity_center_plan"]["private_targets"][
            "authority_account_arn"
        ] = "arn:aws:sso:::account/999999999999"
    elif case == "long-window":
        arguments["expires_at"] = _stamp(START + timedelta(minutes=20))
    elif case == "outside-plan":
        arguments["not_before"] = _stamp(START - timedelta(minutes=1))
    elif case == "fractional-time":
        arguments["not_before"] = "2026-08-26T18:01:00.100000Z"
    elif case == "file-collision":
        arguments["owner_checkpoint_file"] = arguments["request_file"]
    elif case == "reserved-request":
        arguments["request_file"] = materializer.CONSUMPTION_CLAIM
    elif case == "reserved-checkpoint":
        arguments["owner_checkpoint_file"] = "gug376-authority-snapshot-1.json"
    elif case == "wrong-source":
        arguments["source_commit_sha"] = "not-a-sha"
    elif case == "bad-role-digest":
        arguments["expected_sso_role_name_digests"]["authority"] = "bad"
    else:
        arguments["approval_reference_digest"] = "bad"
    with pytest.raises(materializer.LiveRequestMaterializationError, match=code):
        materializer.materialize_live_request(**arguments)
    assert list(root.iterdir()) == []


def test_reader_rejects_expiry_local_drift_and_unsafe_custody(
    tmp_path: Path,
) -> None:
    root = _root(tmp_path)
    result = _materialize(root)
    materializer.persist_materialized_live_request(root, result)
    common = {
        "private_root": root,
        "request_file": result.request["request_file"],
        "expected_source_commit_sha": SOURCE_SHA,
        "expected_source_tree_sha": TREE_SHA,
        "expected_host_digest": HOST_DIGEST,
        "expected_approval_reference_digest": APPROVAL_REFERENCE_DIGEST,
        "expected_request_digest": result.request["request_digest"],
        "expected_checkpoint_digest": result.owner_checkpoint[
            "checkpoint_digest"
        ],
    }
    with pytest.raises(
        materializer.LiveRequestMaterializationError,
        match="REQUEST_WINDOW_INACTIVE",
    ):
        materializer.read_materialized_live_request(
            **common, now=REQUEST_END
        )
    with pytest.raises(
        materializer.LiveRequestMaterializationError,
        match="PRIVATE_REQUEST_LOCAL_BINDING_MISMATCH",
    ):
        materializer.read_materialized_live_request(
            **dict(common, expected_host_digest=canonical_digest("foreign")),
            now=NOW,
        )
    with pytest.raises(
        materializer.LiveRequestMaterializationError,
        match="REVIEWED_PRIVATE_DIGEST_MISMATCH",
    ):
        materializer.read_materialized_live_request(
            **dict(
                common,
                expected_request_digest=canonical_digest("unreviewed-request"),
            ),
            now=NOW,
        )

    os.link(root / result.request["request_file"], root / "hardlink.json")
    with pytest.raises(
        materializer.LiveRequestMaterializationError,
        match="PRIVATE_INPUT_CUSTODY_INVALID",
    ):
        materializer.read_materialized_live_request(**common, now=NOW)

    bad = _root(tmp_path, "bad-mode")
    bad.chmod(0o755)
    with pytest.raises(materializer.LiveRequestMaterializationError):
        materializer.persist_materialized_live_request(bad, _materialize(bad))


def test_checkpoint_is_published_before_request_activation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = _root(tmp_path)
    result = _materialize(root)
    writes: list[str] = []

    def fail_request(
        private_root: Path, name: str, value: dict[str, Any]
    ) -> None:
        writes.append(name)
        if name == result.request["request_file"]:
            raise CollectorError("SYNTHETIC_REQUEST_WRITE_FAILURE")
        custody_write_private_json(private_root, name, value)

    monkeypatch.setattr(materializer, "write_private_json", fail_request)
    with pytest.raises(
        materializer.LiveRequestMaterializationError,
        match="SYNTHETIC_REQUEST_WRITE_FAILURE",
    ):
        materializer.persist_materialized_live_request(root, result)
    assert writes == [
        result.request["owner_checkpoint_file"],
        result.request["request_file"],
    ]
    assert (root / result.request["owner_checkpoint_file"]).is_file()
    assert not (root / result.request["request_file"]).exists()


def _reviewed_request(
    root: Path,
) -> tuple[
    materializer.MaterializedLiveRequest,
    materializer.ValidatedLiveRequest,
]:
    result = _materialize(root)
    materializer.persist_materialized_live_request(root, result)
    validated = materializer.read_materialized_live_request(
        root,
        result.request["request_file"],
        now=NOW,
        expected_source_commit_sha=SOURCE_SHA,
        expected_source_tree_sha=TREE_SHA,
        expected_host_digest=HOST_DIGEST,
        expected_approval_reference_digest=APPROVAL_REFERENCE_DIGEST,
        expected_request_digest=result.request["request_digest"],
        expected_checkpoint_digest=result.owner_checkpoint["checkpoint_digest"],
    )
    return result, validated


def _reviewed_exact_request(
    root: Path,
) -> tuple[
    materializer.MaterializedLiveRequest,
    materializer.ValidatedLiveRequest,
    dict[str, Any],
]:
    authority_input, identity_input = _plan_inputs(exact=True)
    exact_state = _exact_expected_state()
    identity_input["expected_state"] = exact_state
    plans = materializer.materialize_live_plans(
        authority_input=authority_input,
        identity_center_input=identity_input,
    )
    arguments = _arguments(root)
    arguments["authority_plan"] = plans.authority_plan
    arguments["identity_center_plan"] = plans.identity_center_plan
    result = materializer.materialize_live_request(**arguments)
    materializer.persist_materialized_live_request(root, result)
    validated = materializer.read_materialized_live_request(
        root,
        result.request["request_file"],
        now=NOW,
        expected_source_commit_sha=SOURCE_SHA,
        expected_source_tree_sha=TREE_SHA,
        expected_host_digest=HOST_DIGEST,
        expected_approval_reference_digest=APPROVAL_REFERENCE_DIGEST,
        expected_request_digest=result.request["request_digest"],
        expected_checkpoint_digest=result.owner_checkpoint["checkpoint_digest"],
    )
    return result, validated, exact_state


def _provider_bindings(
    validated: materializer.ValidatedLiveRequest,
) -> dict[str, str]:
    request = validated.request
    runtime = validated.runtime_config
    return {
        "authority_profile": request["profiles"]["authority"]["name"],
        "identity_center_profile": request["profiles"]["identity_center"]["name"],
        "authority_expected_account_id": runtime["authority_plan"][
            "expected_account_id"
        ],
        "authority_expected_principal_digest": request["profile_expectations"][
            "authority"
        ]["expected_principal_digest"],
        "authority_expected_sso_role_name_digest": request[
            "profile_expectations"
        ]["authority"]["expected_sso_role_name_digest"],
        "identity_expected_account_id": runtime["identity_center_plan"][
            "expected_account_id"
        ],
        "identity_expected_principal_digest": request["profile_expectations"][
            "identity_center"
        ]["expected_principal_digest"],
        "identity_expected_sso_role_name_digest": request[
            "profile_expectations"
        ]["identity_center"]["expected_sso_role_name_digest"],
        "authority_verification_digest": runtime["authority_plan"][
            "authority_verification_digest"
        ],
        "identity_authority_verification_digest": runtime[
            "identity_center_plan"
        ]["authority_verification_digest"],
        "sdk_runtime_root": runtime["sdk_runtime_root"],
    }


class _LiveIdentityReader:
    def __init__(
        self,
        actor: Any,
        plan: Mapping[str, Any],
        exact_state: Mapping[str, Any] | None,
    ) -> None:
        self.actor = actor
        self.plan = plan
        self.exact_state = exact_state

    def _page(
        self, operation: str, items: list[dict[str, Any]], token: object | None
    ) -> Mapping[str, Any]:
        assert token is None
        return self.actor.call(
            operation,
            {
                "items": copy.deepcopy(items),
                "next_token": None,
                "truncated": False,
                "complete": True,
            },
            token=token,
        )

    def _discovery(self) -> Mapping[str, Any]:
        if self.exact_state is not None:
            return self.exact_state["facts"]["discovery"]
        private = self.plan["private_targets"]
        return {
            "instances": [
                {
                    "identity_store_id": private["identity_store_id"],
                    "instance_arn": IDENTITY_INSTANCE,
                    "owner_account_id": self.plan["expected_account_id"],
                    "status": "ACTIVE",
                }
            ],
            "applications": [],
            "permission_sets": [],
        }

    def list_instances(self, token: object | None) -> Mapping[str, Any]:
        return self._page(
            "sso:ListInstances", self._discovery()["instances"], token
        )

    def list_applications(
        self, instance_arn: str, application_name: str, token: object | None
    ) -> Mapping[str, Any]:
        assert instance_arn == IDENTITY_INSTANCE
        assert application_name == self.plan["private_targets"]["application_name"]
        return self._page(
            "sso:ListApplications", self._discovery()["applications"], token
        )

    def list_permission_sets(
        self, instance_arn: str, names: tuple[str, str], token: object | None
    ) -> Mapping[str, Any]:
        assert instance_arn == IDENTITY_INSTANCE and names == NAMES
        return self._page(
            "sso:ListPermissionSets", self._discovery()["permission_sets"], token
        )

    def _facts(self) -> Mapping[str, Any]:
        assert self.exact_state is not None
        return self.exact_state["facts"]

    def _instance(self) -> Mapping[str, Any]:
        if self.exact_state is not None:
            return self._facts()["instance"]
        private = self.plan["private_targets"]
        return {
            "identity_store_id": private["identity_store_id"],
            "instance_arn": private["identity_center_instance_arn"],
            "owner_account_id": self.plan["expected_account_id"],
            "status": "ACTIVE",
            "encryption": {
                "key_type": private["identity_center_kms_mode"],
                "kms_key_arn": private["identity_center_kms_key_arn"],
                "status": "ENABLED",
            },
        }

    def describe_instance(self, instance_arn: str) -> Mapping[str, Any]:
        assert instance_arn == IDENTITY_INSTANCE
        return self.actor.call(
            "sso:DescribeInstance",
            {"complete": True, "value": copy.deepcopy(self._instance())},
        )

    def read_application(self, application_arn: str) -> Mapping[str, Any]:
        assert application_arn == self.exact_state["targets"][
            "identity_center_application_arn"
        ]
        for operation in (
            "sso:DescribeApplication",
            "sso:ListApplicationAuthenticationMethods",
            "sso:GetApplicationAuthenticationMethod",
            "sso:ListApplicationGrants",
            "sso:GetApplicationGrant",
            "sso:ListApplicationAccessScopes",
            "sso:GetApplicationAccessScope",
            "sso:GetApplicationAssignmentConfiguration",
            "sso:ListApplicationAssignments",
            "sso:ListTagsForResource",
        ):
            self.actor.call(operation, {"synthetic": "projected"})
        return {
            "complete": True,
            "value": copy.deepcopy(self._facts()["application"]),
        }

    def read_permission_set(
        self, instance_arn: str, permission_set_arn: str
    ) -> Mapping[str, Any]:
        assert instance_arn == IDENTITY_INSTANCE
        for operation in (
            "sso:GetPermissionsBoundaryForPermissionSet",
            "sso:DescribePermissionSet",
            "sso:ListManagedPoliciesInPermissionSet",
            "sso:ListCustomerManagedPolicyReferencesInPermissionSet",
            "sso:GetInlinePolicyForPermissionSet",
            "sso:ListTagsForResource",
        ):
            self.actor.call(operation, {"synthetic": "projected"})
        by_arn = {
            value["permission_set_arn"]: value
            for value in self._facts()["permission_sets"].values()
        }
        return {"complete": True, "value": copy.deepcopy(by_arn[permission_set_arn])}

    def _name_for_arn(self, permission_set_arn: str) -> str:
        return next(
            name
            for name, value in self._facts()["permission_sets"].items()
            if value["permission_set_arn"] == permission_set_arn
        )

    def list_assignments(
        self,
        instance_arn: str,
        permission_set_arn: str,
        account_arn: str,
        token: object | None,
    ) -> Mapping[str, Any]:
        assert instance_arn == IDENTITY_INSTANCE
        assert account_arn == self.plan["private_targets"]["authority_account_arn"]
        return self._page(
            "sso:ListAccountAssignments",
            self._facts()["assignments"][self._name_for_arn(permission_set_arn)],
            token,
        )

    def list_provisioning(
        self, instance_arn: str, permission_set_arn: str, token: object | None
    ) -> Mapping[str, Any]:
        assert instance_arn == IDENTITY_INSTANCE
        page = self._page(
            "sso:ListPermissionSetProvisioningStatus",
            self._facts()["provisioning"][self._name_for_arn(permission_set_arn)],
            token,
        )
        self.actor.call(
            "sso:DescribePermissionSetProvisioningStatus",
            {"synthetic": "projected"},
        )
        return page

    def list_target_accounts(
        self, instance_arn: str, permission_set_arn: str, token: object | None
    ) -> Mapping[str, Any]:
        assert instance_arn == IDENTITY_INSTANCE
        return self._page(
            "sso:ListAccountsForProvisionedPermissionSet",
            self._facts()["target_accounts"][self._name_for_arn(permission_set_arn)],
            token,
        )

    def describe_approved_user(
        self, identity_store_id: str, user_id: str
    ) -> Mapping[str, Any]:
        assert identity_store_id == self.plan["private_targets"]["identity_store_id"]
        assert user_id == self.plan["private_targets"]["approved_user_id"]
        return self.actor.call(
            "identitystore:DescribeUser",
            {"complete": True, "value": copy.deepcopy(self._facts()["operator"])},
        )


class _LiveIdentitySession(offline_collector_harness._Session):
    def open_discovery(self) -> Any:
        self.actor.owner.reader_opens += 1
        return _LiveIdentityReader(
            self.actor, self.plan, self.actor.owner.exact_state
        )

    def open_exact(self) -> Any:
        self.actor.owner.reader_opens += 1
        return _LiveIdentityReader(
            self.actor, self.plan, self.actor.owner.exact_state
        )


class _LiveIdentitySessionFactory:
    def __init__(
        self, owner: Any, capture: int, ledger: Any
    ) -> None:
        self.owner, self.capture, self.ledger = owner, capture, ledger

    def open_sts(
        self,
        *,
        policy: Mapping[str, Any],
        policy_digest: str,
        region: str,
        stage: str = "discovery",
    ) -> Any:
        assert canonical_digest(policy) == policy_digest
        assert region == "us-east-1"
        actor = offline_collector_harness._Actor(
            self.owner,
            "identity_center",
            self.capture,
            stage,
            self.ledger,
            policy_digest,
        )
        return _LiveIdentitySession(actor, self.owner.config["identity_center_plan"])


def _generated_role_facts(
    config: Mapping[str, Any], exact_state: Mapping[str, Any]
) -> list[dict[str, Any]]:
    targets = config["authority_plan"]["targets"]
    role_bindings = (
        (
            targets["retire_approve_generated_role_arn"],
            exact_state["facts"]["permission_sets"][NAMES[0]][
                "inline_policy"
            ]["policy_digest"],
        ),
        (
            targets["retire_class_generated_role_arn"],
            exact_state["facts"]["permission_sets"][NAMES[1]][
                "inline_policy"
            ]["policy_digest"],
        ),
    )
    roles = []
    for role_arn, policy_digest in role_bindings:
        resource = role_arn.split(":role/", 1)[-1]
        role_name = resource.rsplit("/", 1)[-1]
        summary = {
            "Path": "/" + resource.removesuffix(role_name),
            "RoleName": role_name,
            "Arn": role_arn,
            "CreateDate": "2026-08-26T17:56:00Z",
            "MaxSessionDuration": 3600,
            "RoleIdDigest": canonical_digest({"role": role_name}),
            "AssumeRolePolicyDocumentDigest": canonical_digest(
                {"identity_center_role": role_name}
            ),
        }
        roles.append(
            {
                "role_arn": role_arn,
                "discovered": [copy.deepcopy(summary)],
                "role": {"Role": copy.deepcopy(summary)},
                "attached_policies": [],
                "inline_policies": [
                    {
                        "RoleName": role_name,
                        "PolicyName": f"AWSSSO_{role_name}",
                        "PolicyDocumentDigest": policy_digest,
                    }
                ],
                "tags": [],
            }
        )
    return sorted(roles, key=canonical_json)


class _LiveAuthorityReader(offline_collector_harness._AuthorityReader):
    def iam_roles(self, token: object | None) -> Mapping[str, Any]:
        if self.actor.owner.exact_state is None:
            if self.actor.owner.authority_role_fault == "collision":
                collision_arn = (
                    f"arn:aws:iam::{AUTHORITY_ACCOUNT}:role/aws-reserved/"
                    "sso.amazonaws.com/"
                    "AWSReservedSSO_ScanalyzeAuthorityRetireApprove_"
                    "0123456789abcdef"
                )
                return self.actor.call(
                    offline_collector_harness.AUTHORITY_OPERATIONS["iam_roles"],
                    {
                        "items": [
                            {
                                "role_arn": collision_arn,
                                "collision": True,
                                "discovered": [{"Arn": collision_arn}],
                            }
                        ],
                        "next_cursor": None,
                        "truncated": False,
                    },
                    token=token,
                )
            return super().iam_roles(token)
        roles = _generated_role_facts(
            self.actor.owner.config, self.actor.owner.exact_state
        )
        if self.actor.owner.authority_role_fault == "missing":
            roles.pop()
        elif self.actor.owner.authority_role_fault == "wrong-policy":
            roles[0]["inline_policies"][0]["PolicyDocumentDigest"] = (
                canonical_digest({"policy": "drift"})
            )
        elif self.actor.owner.authority_role_fault == "wrong-trust":
            drift = canonical_digest({"trust": "drift"})
            roles[0]["discovered"][0][
                "AssumeRolePolicyDocumentDigest"
            ] = drift
            roles[0]["role"]["Role"][
                "AssumeRolePolicyDocumentDigest"
            ] = drift
        elif self.actor.owner.authority_role_fault == "extra-attached":
            roles[0]["attached_policies"] = [
                {
                    "PolicyName": "ReadOnlyAccess",
                    "PolicyArn": "arn:aws:iam::aws:policy/ReadOnlyAccess",
                }
            ]
        return self.actor.call(
            offline_collector_harness.AUTHORITY_OPERATIONS["iam_roles"],
            {
                "items": roles,
                "next_cursor": None,
                "truncated": False,
            },
            token=token,
        )


class _LiveAuthoritySession(offline_collector_harness._Session):
    def open_reader(self) -> Any:
        self.actor.owner.reader_opens += 1
        return _LiveAuthorityReader(self.actor, self.plan)


class _LiveAuthoritySessionFactory:
    def __init__(
        self, owner: Any, capture: int, ledger: Any
    ) -> None:
        self.owner, self.capture, self.ledger = owner, capture, ledger

    def open_sts(
        self,
        *,
        policy: Mapping[str, Any],
        policy_digest: str,
        region: str,
        stage: str = "authority",
    ) -> Any:
        assert canonical_digest(policy) == policy_digest
        assert region == "us-east-1"
        actor = offline_collector_harness._Actor(
            self.owner,
            "authority",
            self.capture,
            stage,
            self.ledger,
            policy_digest,
        )
        return _LiveAuthoritySession(
            actor, self.owner.config["authority_plan"]
        )


class _OfflineCausalProvider(offline_collector_harness.FakeProvider):
    """Collector-complete fake; it can be accepted only by one monkeypatched test."""

    mode = "ATTESTED_LIVE"
    concrete_provider = True

    def __init__(
        self,
        config: Mapping[str, Any],
        *,
        exact_state: Mapping[str, Any] | None = None,
        authority_role_fault: str | None = None,
    ) -> None:
        super().__init__(config)
        self._ledger: Any = None
        self.exact_state = exact_state
        self.authority_role_fault = authority_role_fault

    def build_authority(self, **kwargs: Any) -> Any:
        self._ledger = kwargs["ledger"]
        assert kwargs["profile"] == self.config["profiles"]["authority"]["name"]
        assert kwargs["retries"] == 0
        self.builds.append(("authority", kwargs["capture_index"]))
        return _LiveAuthoritySessionFactory(
            self, kwargs["capture_index"], kwargs["ledger"]
        )

    def build_identity(self, **kwargs: Any) -> Any:
        self._ledger = kwargs["ledger"]
        assert kwargs["profile"] == self.config["profiles"]["identity_center"]["name"]
        assert kwargs["retries"] == 0
        self.builds.append(("identity_center", kwargs["capture_index"]))
        return _LiveIdentitySessionFactory(
            self, kwargs["capture_index"], kwargs["ledger"]
        )

    def evaluation_time(self) -> datetime:
        return START + timedelta(minutes=7)

    def transcript_summary(self) -> dict[str, Any]:
        calls, transcript_digest = self._ledger.finalize()
        return {
            "provider_calls": calls,
            "aws_calls": calls,
            "aws_mutations": 0,
            "live_provider_evidence": True,
            "transcript_digest": transcript_digest,
        }


class _ExpiryBeforeSealProvider(_OfflineCausalProvider):
    def __init__(
        self, config: Mapping[str, Any], current_time: list[datetime]
    ) -> None:
        super().__init__(config)
        self._current_time = current_time

    def transcript_summary(self) -> dict[str, Any]:
        summary = super().transcript_summary()
        self._current_time[0] = REQUEST_END
        return summary


def test_claim_mints_one_provider_and_one_execution_capability(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = _root(tmp_path)
    result, validated = _reviewed_request(root)
    monkeypatch.setattr(
        materializer, "_current_source_identity", lambda: (SOURCE_SHA, TREE_SHA)
    )
    monkeypatch.setattr(materializer, "_current_host_digest", lambda: HOST_DIGEST)
    monkeypatch.setattr(materializer, "_current_time", lambda: NOW)

    capability = materializer.claim_materialized_live_request(
        validated, private_root=root
    )
    claim = read_private_json(root, materializer.CONSUMPTION_CLAIM)
    assert claim["request_digest"] == result.request["request_digest"]
    assert stat.S_IMODE(
        (root / materializer.CONSUMPTION_CLAIM).stat().st_mode
    ) == 0o600
    with pytest.raises(
        materializer.LiveRequestMaterializationError,
        match="PRIVATE_CONSUMPTION_ALREADY_CLAIMED",
    ):
        materializer.claim_materialized_live_request(validated, private_root=root)

    runtime = validated.runtime_config
    provider_bindings = _provider_bindings(validated)
    alternate_sdk_root = str(_sdk_root(tmp_path, "alternate-sdk-runtime"))
    with pytest.raises(
        materializer.LiveRequestMaterializationError,
        match="LIVE_PROVIDER_CAPABILITY_BINDING_MISMATCH",
    ):
        materializer.assert_live_provider_capability_bindings(
            capability,
            **dict(provider_bindings, sdk_runtime_root=alternate_sdk_root),
        )
    gate = materializer.assert_live_provider_capability_bindings(
        capability, **provider_bindings
    )
    gate()
    with pytest.raises(
        materializer.LiveRequestMaterializationError,
        match="LIVE_REQUEST_EXECUTION_CAPABILITY_ALREADY_USED",
    ):
        materializer.assert_live_provider_capability_bindings(
            capability, **provider_bindings
        )

    execution_bindings = {
        "private_root": root,
        "source_commit_sha": SOURCE_SHA,
        "source_tree_sha": TREE_SHA,
        "request_digest": result.request["request_digest"],
        "checkpoint_digest": result.owner_checkpoint["checkpoint_digest"],
        "approval_reference_digest": APPROVAL_REFERENCE_DIGEST,
        "runtime_config": runtime,
    }
    materializer.assert_live_request_execution_capability(
        capability, **execution_bindings
    )
    with pytest.raises(
        materializer.LiveRequestMaterializationError,
        match="LIVE_REQUEST_EXECUTION_CAPABILITY_ALREADY_USED",
    ):
        materializer.assert_live_request_execution_capability(
            capability, **execution_bindings
        )


def test_offline_causal_harness_runs_materializer_collectors_executor_and_bundle(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = _root(tmp_path)
    result, validated = _reviewed_request(root)
    monkeypatch.setattr(
        materializer, "_current_source_identity", lambda: (SOURCE_SHA, TREE_SHA)
    )
    monkeypatch.setattr(materializer, "_current_host_digest", lambda: HOST_DIGEST)
    monkeypatch.setattr(materializer, "_current_time", lambda: NOW)
    monkeypatch.setattr(offline_collector_harness, "START", START)
    monkeypatch.setattr(offline_collector_harness, "END", END)
    capability = materializer.claim_materialized_live_request(
        validated, private_root=root
    )
    materializer.assert_live_provider_capability_bindings(
        capability, **_provider_bindings(validated)
    )
    provider = _OfflineCausalProvider(validated.runtime_config)
    monkeypatch.setattr(
        live_executor,
        "is_attested_live_provider",
        lambda value, supplied: value is provider and supplied is capability,
    )

    run, handoff = live_executor.execute_live(
        validated.runtime_config,
        provider,
        private_root=root,
        now=NOW,
        actual_source_commit_sha=SOURCE_SHA,
        actual_source_tree_sha=TREE_SHA,
        request_digest=result.request["request_digest"],
        checkpoint_digest=result.owner_checkpoint["checkpoint_digest"],
        approval_reference_digest=APPROVAL_REFERENCE_DIGEST,
        execution_capability=capability,
    )

    assert live_executor.validate_live_bundle(run, handoff) == (run, handoff)
    assert run["authority_classification"] == "ABSENT_READY"
    assert run["identity_center_classification"] == "ABSENT_READY"
    assert run["provider_calls"] == run["aws_calls"] == 26
    assert len(run["identity_center_session_digests"]) == 2
    evidence = read_private_json(
        root, offline_collector_harness.live.EVIDENCE_MANIFEST_NAME
    )
    assert live_executor.validate_private_live_evidence_manifest(
        evidence, private_root=root, run_record=run
    ) == evidence
    assert evidence["evidence_manifest_digest"] == run[
        "evidence_manifest_digest"
    ]
    assert evidence["provider_calls"] == len(evidence["transcript_events"])
    assert all(
        set(event) == live_executor._PRIVATE_EVENT_FIELDS
        and event["started_at"] <= event["completed_at"] <= evidence["sealed_at"]
        for event in evidence["transcript_events"]
    )
    assert evidence["authority_receipt"]["status"] == "LIVE_READ_ONLY_CAPTURED"
    assert evidence["identity_center_receipt"]["status"] == "LIVE_READ_ONLY_CAPTURED"
    assert stat.S_IMODE(
        (root / offline_collector_harness.live.EVIDENCE_MANIFEST_NAME).stat().st_mode
    ) == 0o600
    assert handoff["deployment_authorized"] is False
    assert handoff["production_status"] == "NO-GO"


def _execute_exact_causal(
    root: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    authority_role_fault: str | None = None,
) -> tuple[
    dict[str, Any],
    dict[str, Any],
    _OfflineCausalProvider,
    dict[str, Any],
]:
    result, validated, exact_state = _reviewed_exact_request(root)
    monkeypatch.setattr(
        materializer, "_current_source_identity", lambda: (SOURCE_SHA, TREE_SHA)
    )
    monkeypatch.setattr(materializer, "_current_host_digest", lambda: HOST_DIGEST)
    monkeypatch.setattr(materializer, "_current_time", lambda: NOW)
    monkeypatch.setattr(offline_collector_harness, "START", START)
    monkeypatch.setattr(offline_collector_harness, "END", END)
    capability = materializer.claim_materialized_live_request(
        validated, private_root=root
    )
    materializer.assert_live_provider_capability_bindings(
        capability, **_provider_bindings(validated)
    )
    provider = _OfflineCausalProvider(
        validated.runtime_config,
        exact_state=exact_state,
        authority_role_fault=authority_role_fault,
    )
    monkeypatch.setattr(
        live_executor,
        "is_attested_live_provider",
        lambda value, supplied: value is provider and supplied is capability,
    )

    run, handoff = live_executor.execute_live(
        validated.runtime_config,
        provider,
        private_root=root,
        now=NOW,
        actual_source_commit_sha=SOURCE_SHA,
        actual_source_tree_sha=TREE_SHA,
        request_digest=result.request["request_digest"],
        checkpoint_digest=result.owner_checkpoint["checkpoint_digest"],
        approval_reference_digest=APPROVAL_REFERENCE_DIGEST,
        execution_capability=capability,
    )
    return run, handoff, provider, exact_state


def test_exact_causal_harness_binds_four_sessions_and_direct_application_user(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = _root(tmp_path)
    run, handoff, provider, exact_state = _execute_exact_causal(
        root, monkeypatch
    )

    assert run["authority_classification"] == "PREEXISTING_NO_TOUCH"
    assert run["identity_center_classification"] == "EXACT_PRESENT_NO_TOUCH"
    assert len(run["identity_center_session_digests"]) == 4
    assert run["provider_calls"] == run["aws_calls"] > 24
    assert [item[-1] for item in provider.attempts].count(
        "sso:ListApplicationAssignments"
    ) == 2
    identity_snapshots = [
        read_private_json(root, name)
        for name in offline_collector_harness.live.ARTIFACT_NAMES[2:]
    ]
    assert all(
        snapshot["facts"]["application"]["assignments"]
        == exact_state["facts"]["application"]["assignments"]
        and all(
            permission["boundary"] is None
            for permission in snapshot["facts"]["permission_sets"].values()
        )
        for snapshot in identity_snapshots
    )
    authority_snapshots = [
        read_private_json(root, name)
        for name in offline_collector_harness.live.ARTIFACT_NAMES[:2]
    ]
    assert all(
        len(snapshot["surfaces"]["iam_roles"]["items"]) == 2
        for snapshot in authority_snapshots
    )
    manifest = read_private_json(
        root, offline_collector_harness.live.EVIDENCE_MANIFEST_NAME
    )
    verification = live_executor.validate_private_live_evidence_bundle(
        manifest, run, handoff, private_root=root
    )
    assert verification["status"] == "PRIVATE_EVIDENCE_VERIFIED"
    assert verification["production_status"] == "NO-GO"


@pytest.mark.parametrize(
    "fault", ("missing", "wrong-policy", "wrong-trust", "extra-attached")
)
def test_exact_causal_harness_rejects_generated_role_topology_drift(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fault: str
) -> None:
    root = _root(tmp_path)
    with pytest.raises(
        live_executor.LiveExecutorError,
        match="CROSS_DOMAIN_ROLE_TOPOLOGY_INVALID",
    ):
        _execute_exact_causal(
            root, monkeypatch, authority_role_fault=fault
        )


def _absent_causal_bundle(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    authority_role_fault: str | None = None,
) -> tuple[Path, dict[str, Any], dict[str, Any]]:
    root = _root(tmp_path)
    result, validated = _reviewed_request(root)
    monkeypatch.setattr(
        materializer, "_current_source_identity", lambda: (SOURCE_SHA, TREE_SHA)
    )
    monkeypatch.setattr(materializer, "_current_host_digest", lambda: HOST_DIGEST)
    monkeypatch.setattr(materializer, "_current_time", lambda: NOW)
    monkeypatch.setattr(offline_collector_harness, "START", START)
    monkeypatch.setattr(offline_collector_harness, "END", END)
    capability = materializer.claim_materialized_live_request(
        validated, private_root=root
    )
    materializer.assert_live_provider_capability_bindings(
        capability, **_provider_bindings(validated)
    )
    provider = _OfflineCausalProvider(
        validated.runtime_config,
        authority_role_fault=authority_role_fault,
    )
    monkeypatch.setattr(
        live_executor,
        "is_attested_live_provider",
        lambda value, supplied: value is provider and supplied is capability,
    )
    run, handoff = live_executor.execute_live(
        validated.runtime_config,
        provider,
        private_root=root,
        now=NOW,
        actual_source_commit_sha=SOURCE_SHA,
        actual_source_tree_sha=TREE_SHA,
        request_digest=result.request["request_digest"],
        checkpoint_digest=result.owner_checkpoint["checkpoint_digest"],
        approval_reference_digest=APPROVAL_REFERENCE_DIGEST,
        execution_capability=capability,
    )
    return root, run, handoff


def _reseal_private_transcript_manifest(manifest: dict[str, Any]) -> None:
    events = manifest["transcript_events"]
    manifest["transcript_digest"] = canonical_digest(events)
    manifest["provider_calls"] = manifest["aws_calls"] = len(events)
    for domain, receipt_key in (
        ("authority", "authority_receipt"),
        ("identity_center", "identity_center_receipt"),
    ):
        domain_events = [event for event in events if event["domain"] == domain]
        receipt = manifest[receipt_key]
        receipt["transcript_digest"] = canonical_digest(domain_events)
        receipt["provider_calls"] = receipt["aws_calls"] = len(domain_events)
        receipt["receipt_digest"] = canonical_digest(
            {
                key: value
                for key, value in receipt.items()
                if key != "receipt_digest"
            }
        )
    manifest["evidence_manifest_digest"] = canonical_digest(
        {
            key: value
            for key, value in manifest.items()
            if key != "evidence_manifest_digest"
        }
    )


@pytest.mark.parametrize(
    "fault",
    (
        "missing_sts",
        "late_sts",
        "duplicate_sts",
        "dangling_page",
        "token_mismatch",
        "token_repeat",
        "stream_mismatch",
        "stream_rebind",
        "page_limit",
    ),
)
def test_private_evidence_verifier_replays_sts_and_pagination_causality(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fault: str
) -> None:
    root, _, _ = _absent_causal_bundle(tmp_path, monkeypatch)
    manifest = read_private_json(
        root, offline_collector_harness.live.EVIDENCE_MANIFEST_NAME
    )
    events = manifest["transcript_events"]
    first = events[0]
    session_events = [
        event
        for event in events
        if event["session_digest"] == first["session_digest"]
    ]
    assert session_events[0]["operation"] == "sts:GetCallerIdentity"
    assert len(session_events) >= 4

    if fault == "missing_sts":
        session_events[0]["operation"] = "s3:ListAllMyBuckets"
    elif fault == "late_sts":
        session_events[0]["operation"], session_events[1]["operation"] = (
            session_events[1]["operation"],
            session_events[0]["operation"],
        )
    elif fault == "duplicate_sts":
        session_events[1].update(
            operation="sts:GetCallerIdentity",
            pagination_stream_digest=None,
            page_token_digest=None,
            next_token_digest=None,
            complete=True,
            truncated=False,
        )
    elif fault == "dangling_page":
        session_events[1].update(
            operation="s3:ListAllMyBuckets",
            page_token_digest=None,
            next_token_digest=canonical_digest("dangling-page"),
            complete=False,
            truncated=True,
        )
    elif fault == "token_mismatch":
        stream_digest = session_events[1]["pagination_stream_digest"]
        session_events[1].update(
            operation="s3:ListAllMyBuckets",
            page_token_digest=None,
            next_token_digest=canonical_digest("expected-page"),
            complete=False,
            truncated=True,
        )
        session_events[2].update(
            operation="s3:ListAllMyBuckets",
            pagination_stream_digest=stream_digest,
            page_token_digest=canonical_digest("different-page"),
            next_token_digest=None,
            complete=True,
            truncated=False,
        )
    elif fault == "token_repeat":
        first_token = canonical_digest("first-page")
        second_token = canonical_digest("second-page")
        stream_digest = session_events[1]["pagination_stream_digest"]
        for event, page_token, next_token in (
            (session_events[1], None, first_token),
            (session_events[2], first_token, second_token),
            (session_events[3], second_token, first_token),
        ):
            event.update(
                operation="s3:ListAllMyBuckets",
                pagination_stream_digest=stream_digest,
                page_token_digest=page_token,
                next_token_digest=next_token,
                complete=False,
                truncated=True,
            )
    elif fault == "stream_mismatch":
        first_token = canonical_digest("expected-page")
        session_events[1].update(
            operation="s3:ListAllMyBuckets",
            page_token_digest=None,
            next_token_digest=first_token,
            complete=False,
            truncated=True,
        )
        session_events[2].update(
            operation="s3:ListAllMyBuckets",
            pagination_stream_digest=canonical_digest("different-stream"),
            page_token_digest=first_token,
            next_token_digest=None,
            complete=True,
            truncated=False,
        )
    elif fault == "stream_rebind":
        base_index = events.index(session_events[1])
        base = copy.deepcopy(session_events[1])
        stream_a = canonical_digest("stream-a")
        stream_b = canonical_digest("stream-b")
        token_a = canonical_digest("token-a")
        token_b = canonical_digest("token-b")
        events[base_index : base_index + 1] = [
            {
                **copy.deepcopy(base),
                "pagination_stream_digest": stream_a,
                "page_token_digest": None,
                "next_token_digest": token_a,
                "complete": False,
                "truncated": True,
            },
            {
                **copy.deepcopy(base),
                "pagination_stream_digest": stream_b,
                "page_token_digest": None,
                "next_token_digest": token_b,
                "complete": False,
                "truncated": True,
            },
            {
                **copy.deepcopy(base),
                "pagination_stream_digest": stream_b,
                "page_token_digest": token_a,
                "next_token_digest": None,
                "complete": True,
                "truncated": False,
            },
        ]
        for ordinal, event in enumerate(events, 1):
            event["ordinal"] = ordinal
    else:
        assert fault == "page_limit"
        base_index = events.index(session_events[1])
        base = copy.deepcopy(session_events[1])
        pages: list[dict[str, Any]] = []
        page_token = None
        for index in range(51):
            next_token = (
                canonical_digest(f"page-{index + 1}") if index < 50 else None
            )
            pages.append(
                {
                    **copy.deepcopy(base),
                    "operation": "s3:ListAllMyBuckets",
                    "page_token_digest": page_token,
                    "next_token_digest": next_token,
                    "complete": next_token is None,
                    "truncated": next_token is not None,
                }
            )
            page_token = next_token
        events[base_index : base_index + 1] = pages
        for ordinal, event in enumerate(events, 1):
            event["ordinal"] = ordinal
    _reseal_private_transcript_manifest(manifest)

    with pytest.raises(
        live_executor.LiveExecutorError,
        match="PRIVATE_EVIDENCE_MANIFEST_INVALID",
    ):
        live_executor.validate_private_live_evidence_manifest(
            manifest, private_root=root
        )


@pytest.mark.parametrize("page_count", (3, 50))
def test_private_evidence_verifier_accepts_closed_multi_page_chain(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, page_count: int
) -> None:
    root, _, _ = _absent_causal_bundle(tmp_path, monkeypatch)
    manifest = read_private_json(
        root, offline_collector_harness.live.EVIDENCE_MANIFEST_NAME
    )
    events = manifest["transcript_events"]
    base_index = next(
        index
        for index, event in enumerate(events)
        if event["domain"] == "authority"
        and event["operation"] == "s3:ListAllMyBuckets"
    )
    base = events[base_index]
    pages: list[dict[str, Any]] = []
    page_token = None
    for index in range(page_count):
        next_token = (
            canonical_digest(f"valid-page-{index + 1}")
            if index < page_count - 1
            else None
        )
        pages.append(
            {
                **copy.deepcopy(base),
                "page_token_digest": page_token,
                "next_token_digest": next_token,
                "complete": next_token is None,
                "truncated": next_token is not None,
            }
        )
        page_token = next_token
    events[base_index : base_index + 1] = pages
    for ordinal, event in enumerate(events, 1):
        event["ordinal"] = ordinal
    _reseal_private_transcript_manifest(manifest)

    assert live_executor.validate_private_live_evidence_manifest(
        manifest, private_root=root
    ) == manifest


def test_private_evidence_verifier_distinguishes_equal_tokens_across_streams(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root, _, _ = _absent_causal_bundle(tmp_path, monkeypatch)
    manifest = read_private_json(
        root, offline_collector_harness.live.EVIDENCE_MANIFEST_NAME
    )
    events = manifest["transcript_events"]
    base_index = next(
        index
        for index, event in enumerate(events)
        if event["domain"] == "authority"
        and event["operation"] == "s3:ListAllMyBuckets"
    )
    base = events[base_index]
    shared_token = canonical_digest("shared-provider-token")
    stream_a = canonical_digest("stream-a")
    stream_b = canonical_digest("stream-b")
    pages = [
        {
            **copy.deepcopy(base),
            "pagination_stream_digest": stream_a,
            "page_token_digest": None,
            "next_token_digest": shared_token,
            "complete": False,
            "truncated": True,
        },
        {
            **copy.deepcopy(base),
            "pagination_stream_digest": stream_b,
            "page_token_digest": None,
            "next_token_digest": shared_token,
            "complete": False,
            "truncated": True,
        },
        {
            **copy.deepcopy(base),
            "pagination_stream_digest": stream_a,
            "page_token_digest": shared_token,
            "next_token_digest": None,
            "complete": True,
            "truncated": False,
        },
        {
            **copy.deepcopy(base),
            "pagination_stream_digest": stream_b,
            "page_token_digest": shared_token,
            "next_token_digest": None,
            "complete": True,
            "truncated": False,
        },
    ]
    events[base_index : base_index + 1] = pages
    for ordinal, event in enumerate(events, 1):
        event["ordinal"] = ordinal
    _reseal_private_transcript_manifest(manifest)

    assert live_executor.validate_private_live_evidence_manifest(
        manifest, private_root=root
    ) == manifest


def test_absent_causal_harness_rejects_generated_role_prefix_collision(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with pytest.raises(
        live_executor.LiveExecutorError,
        match="CROSS_DOMAIN_ROLE_TOPOLOGY_INVALID",
    ):
        _absent_causal_bundle(
            tmp_path,
            monkeypatch,
            authority_role_fault="collision",
        )


@pytest.mark.parametrize(
    ("action", "artifact_index"),
    [
        *(("missing", index) for index in range(4)),
        *(("tamper", index) for index in range(4)),
        ("swap", 0),
        ("swap", 2),
        ("hardlink", 0),
    ],
)
def test_private_evidence_verifier_requires_each_physical_snapshot_and_custody(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    action: str,
    artifact_index: int,
) -> None:
    root, run, handoff = _absent_causal_bundle(tmp_path, monkeypatch)
    names = offline_collector_harness.live.ARTIFACT_NAMES
    target = root / names[artifact_index]
    if action == "missing":
        target.unlink()
    elif action == "tamper":
        snapshot = read_private_json(root, names[artifact_index])
        snapshot["unreviewed_private_field"] = "tampered"
        target.write_text(canonical_json(snapshot) + "\n", encoding="utf-8")
    elif action == "swap":
        other = root / names[artifact_index + 1]
        target_bytes, other_bytes = target.read_bytes(), other.read_bytes()
        target.write_bytes(other_bytes)
        other.write_bytes(target_bytes)
    else:
        os.link(target, root / "snapshot-hardlink.json")
    manifest = read_private_json(
        root, offline_collector_harness.live.EVIDENCE_MANIFEST_NAME
    )
    with pytest.raises(
        live_executor.LiveExecutorError,
        match="PRIVATE_EVIDENCE_SNAPSHOT_INVALID",
    ):
        live_executor.validate_private_live_evidence_bundle(
            manifest, run, handoff, private_root=root
        )


def test_private_evidence_verifier_rejects_resealed_non_monotonic_transcript(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root, _, _ = _absent_causal_bundle(tmp_path, monkeypatch)
    manifest = read_private_json(
        root, offline_collector_harness.live.EVIDENCE_MANIFEST_NAME
    )
    manifest["transcript_events"][1]["started_at"] = _stamp(
        START + timedelta(minutes=4)
    )
    _reseal_private_transcript_manifest(manifest)
    with pytest.raises(
        live_executor.LiveExecutorError,
        match="PRIVATE_EVIDENCE_MANIFEST_INVALID",
    ):
        live_executor.validate_private_live_evidence_manifest(
            manifest, private_root=root
        )


def test_executor_rechecks_private_window_after_transcript_before_sealing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = _root(tmp_path)
    result, validated = _reviewed_request(root)
    current_time = [NOW]
    monkeypatch.setattr(
        materializer, "_current_source_identity", lambda: (SOURCE_SHA, TREE_SHA)
    )
    monkeypatch.setattr(materializer, "_current_host_digest", lambda: HOST_DIGEST)
    monkeypatch.setattr(materializer, "_current_time", lambda: current_time[0])
    monkeypatch.setattr(offline_collector_harness, "START", START)
    monkeypatch.setattr(offline_collector_harness, "END", END)
    capability = materializer.claim_materialized_live_request(
        validated, private_root=root
    )
    materializer.assert_live_provider_capability_bindings(
        capability, **_provider_bindings(validated)
    )
    provider = _ExpiryBeforeSealProvider(validated.runtime_config, current_time)
    monkeypatch.setattr(
        live_executor,
        "is_attested_live_provider",
        lambda value, supplied: value is provider and supplied is capability,
    )

    with pytest.raises(live_executor.LiveExecutorError, match="REQUEST_WINDOW_INACTIVE"):
        live_executor.execute_live(
            validated.runtime_config,
            provider,
            private_root=root,
            now=NOW,
            actual_source_commit_sha=SOURCE_SHA,
            actual_source_tree_sha=TREE_SHA,
            request_digest=result.request["request_digest"],
            checkpoint_digest=result.owner_checkpoint["checkpoint_digest"],
            approval_reference_digest=APPROVAL_REFERENCE_DIGEST,
            execution_capability=capability,
        )


def test_executor_fails_if_manifest_persistence_crosses_request_expiry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = _root(tmp_path)
    result, validated = _reviewed_request(root)
    current_time = [NOW]
    monkeypatch.setattr(
        materializer, "_current_source_identity", lambda: (SOURCE_SHA, TREE_SHA)
    )
    monkeypatch.setattr(materializer, "_current_host_digest", lambda: HOST_DIGEST)
    monkeypatch.setattr(materializer, "_current_time", lambda: current_time[0])
    monkeypatch.setattr(offline_collector_harness, "START", START)
    monkeypatch.setattr(offline_collector_harness, "END", END)
    capability = materializer.claim_materialized_live_request(
        validated, private_root=root
    )
    materializer.assert_live_provider_capability_bindings(
        capability, **_provider_bindings(validated)
    )
    provider = _OfflineCausalProvider(validated.runtime_config)
    monkeypatch.setattr(
        live_executor,
        "is_attested_live_provider",
        lambda value, supplied: value is provider and supplied is capability,
    )
    original_write = live_executor.write_private_json

    def delayed_manifest_write(
        private_root: Path, name: str, value: Mapping[str, Any]
    ) -> None:
        original_write(private_root, name, value)
        if name == offline_collector_harness.live.EVIDENCE_MANIFEST_NAME:
            current_time[0] = REQUEST_END

    monkeypatch.setattr(live_executor, "write_private_json", delayed_manifest_write)

    with pytest.raises(
        live_executor.LiveExecutorError, match="REQUEST_WINDOW_INACTIVE"
    ):
        live_executor.execute_live(
            validated.runtime_config,
            provider,
            private_root=root,
            now=NOW,
            actual_source_commit_sha=SOURCE_SHA,
            actual_source_tree_sha=TREE_SHA,
            request_digest=result.request["request_digest"],
            checkpoint_digest=result.owner_checkpoint["checkpoint_digest"],
            approval_reference_digest=APPROVAL_REFERENCE_DIGEST,
            execution_capability=capability,
        )
    assert (
        root / offline_collector_harness.live.EVIDENCE_MANIFEST_NAME
    ).is_file()


def test_executor_fails_if_final_recertification_crosses_request_expiry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = _root(tmp_path)
    result, validated = _reviewed_request(root)
    current_time = [NOW]
    monkeypatch.setattr(
        materializer, "_current_source_identity", lambda: (SOURCE_SHA, TREE_SHA)
    )
    monkeypatch.setattr(materializer, "_current_host_digest", lambda: HOST_DIGEST)
    monkeypatch.setattr(materializer, "_current_time", lambda: current_time[0])
    monkeypatch.setattr(offline_collector_harness, "START", START)
    monkeypatch.setattr(offline_collector_harness, "END", END)
    capability = materializer.claim_materialized_live_request(
        validated, private_root=root
    )
    materializer.assert_live_provider_capability_bindings(
        capability, **_provider_bindings(validated)
    )
    provider = _OfflineCausalProvider(validated.runtime_config)
    monkeypatch.setattr(
        live_executor,
        "is_attested_live_provider",
        lambda value, supplied: value is provider and supplied is capability,
    )
    original_validate = live_executor.validate_private_live_evidence_manifest

    def delayed_final_recertification(
        value: Mapping[str, Any],
        *,
        private_root: Path,
        run_record: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        checked = original_validate(
            value, private_root=private_root, run_record=run_record
        )
        if run_record is not None:
            current_time[0] = REQUEST_END
        return checked

    monkeypatch.setattr(
        live_executor,
        "validate_private_live_evidence_manifest",
        delayed_final_recertification,
    )

    with pytest.raises(
        live_executor.LiveExecutorError, match="REQUEST_WINDOW_INACTIVE"
    ):
        live_executor.execute_live(
            validated.runtime_config,
            provider,
            private_root=root,
            now=NOW,
            actual_source_commit_sha=SOURCE_SHA,
            actual_source_tree_sha=TREE_SHA,
            request_digest=result.request["request_digest"],
            checkpoint_digest=result.owner_checkpoint["checkpoint_digest"],
            approval_reference_digest=APPROVAL_REFERENCE_DIGEST,
            execution_capability=capability,
        )


@pytest.mark.parametrize(
    ("replacement", "code"),
    (
        ("source", "SOURCE_CHECKOUT_CHANGED"),
        ("request", "REVIEWED_PRIVATE_DIGEST_MISMATCH"),
    ),
)
def test_capability_gate_rejects_action_time_source_or_request_replacement(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    replacement: str,
    code: str,
) -> None:
    root = _root(tmp_path)
    result, validated = _reviewed_request(root)
    monkeypatch.setattr(
        materializer, "_current_source_identity", lambda: (SOURCE_SHA, TREE_SHA)
    )
    monkeypatch.setattr(materializer, "_current_host_digest", lambda: HOST_DIGEST)
    monkeypatch.setattr(materializer, "_current_time", lambda: NOW)
    capability = materializer.claim_materialized_live_request(
        validated, private_root=root
    )

    if replacement == "source":
        monkeypatch.setattr(
            materializer,
            "_current_source_identity",
            lambda: ("3" * 40, "4" * 40),
        )
    else:
        request = read_private_json(root, result.request["request_file"])
        request["request_digest"] = canonical_digest("replacement")
        (root / result.request["request_file"]).write_text(
            canonical_json(request) + "\n", encoding="utf-8"
        )

    gate = materializer.execution_capability_validity_gate(capability)
    with pytest.raises(materializer.LiveRequestMaterializationError, match=code):
        gate()


def test_module_is_offline_and_contains_no_provider_factory() -> None:
    source = Path(materializer.__file__).read_text(encoding="utf-8")
    for forbidden in (
        "import boto3",
        "import botocore",
        "socket.",
        "build_live_provider",
        "aws sts",
    ):
        assert forbidden not in source
