from __future__ import annotations

import copy
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from tooling import platform_authority_gug395_preplan_collision_probe as subject


SOURCE_COMMIT = "1" * 40
SOURCE_TREE = "2" * 40
NOT_BEFORE = "2026-08-28T01:00:00Z"
EXPIRES_AT = "2026-08-28T01:15:00Z"
AUTHORITY_ACCOUNT = "042360977644"
IDENTITY_ACCOUNT = "839393571433"
AUTHORITY_PRINCIPAL = (
    "arn:aws:sts::042360977644:assumed-role/AWSReadOnlyAccess/gug395-audit"
)
IDENTITY_PRINCIPAL = (
    "arn:aws:sts::839393571433:assumed-role/ReadOnlyAccess/gug395-audit"
)


def _digest(label: str) -> str:
    return subject.canonical_digest({"label": label})


def _reseal(value: dict[str, Any], field: str) -> None:
    value.pop(field, None)
    value[field] = subject.canonical_digest(value)


def _profiles() -> dict[str, dict[str, str]]:
    return {
        "authority": {
            "name": "042360977644_AWSReadOnlyAccess",
            "expected_account_id": AUTHORITY_ACCOUNT,
            "expected_principal_digest": subject.canonical_digest(
                AUTHORITY_PRINCIPAL
            ),
            "expected_sso_role_name_digest": _digest("authority-role"),
            "authority_verification_digest": _digest("authority-verification"),
        },
        "identity_center": {
            "name": "839393571433_ReadOnlyAccess",
            "expected_account_id": IDENTITY_ACCOUNT,
            "expected_principal_digest": subject.canonical_digest(
                IDENTITY_PRINCIPAL
            ),
            "expected_sso_role_name_digest": _digest("identity-role"),
            "authority_verification_digest": _digest("identity-verification"),
        },
    }


def _budget_contract(**overrides: int) -> dict[str, Any]:
    budget: dict[str, Any] = {
        "max_pages": subject.MAX_PAGES,
        "max_provider_calls": subject.MAX_PROVIDER_CALLS,
        "max_session_bootstrap_attempts": (
            subject.MAX_SESSION_BOOTSTRAP_ATTEMPTS
        ),
        "max_credential_vending_calls": subject.MAX_CREDENTIAL_VENDING_CALLS,
        "max_network_calls": subject.MAX_NETWORK_CALLS,
        "max_page_calls": subject.MAX_PAGE_CALLS,
        "max_response_bytes": subject.MAX_RESPONSE_BYTES,
        "max_total_response_bytes": subject.MAX_TOTAL_RESPONSE_BYTES,
        "max_owned_buckets": subject.MAX_OWNED_BUCKETS,
        "max_kms_keys": subject.MAX_KMS_KEYS,
        "max_signing_profiles": subject.MAX_SIGNING_PROFILES,
        "max_code_signing_configs": subject.MAX_CODE_SIGNING_CONFIGS,
        "max_applications": subject.MAX_APPLICATIONS,
        "max_permission_sets": subject.MAX_PERMISSION_SETS,
        "max_modeled_cost_nano_usd": subject.MAX_MODELED_COST_NANO_USD,
        "per_network_call_cost_nano_usd": (
            subject.PER_NETWORK_CALL_COST_NANO_USD
        ),
        "per_projected_byte_cost_nano_usd": (
            subject.PER_PROJECTED_BYTE_COST_NANO_USD
        ),
    }
    budget.update(overrides)
    _reseal(budget, "budget_digest")
    return budget


def _request() -> dict[str, Any]:
    profiles = _profiles()
    authority_tag_digest = subject.canonical_digest(
        subject.AUTHORITY_TAG_CONTRACT
    )
    identity_tag_digest = subject.canonical_digest(
        subject.IDENTITY_TAG_CONTRACT
    )
    instance_arn = "arn:aws:sso:::instance/ssoins-1234567890abcdef"
    targets = {
        "artifact_bucket": {
            "domain": "authority",
            "selector_kind": "GLOBAL_BUCKET_NAME_AND_TAG",
            "name": "scanalyze-gug395-example",
            "expected_tag_contract_digest": authority_tag_digest,
        },
        "kms_key": {
            "domain": "authority",
            "selector_kind": "KMS_ALIAS_OR_TAG",
            "alias_name": "alias/scanalyze-gug395",
            "expected_tag_contract_digest": authority_tag_digest,
        },
        "signing_profile": {
            "domain": "authority",
            "selector_kind": "SIGNING_PROFILE_NAME_OR_TAG",
            "name": "scanalyze_gug395",
            "expected_tag_contract_digest": authority_tag_digest,
        },
        "code_signing_config": {
            "domain": "authority",
            "selector_kind": "TAG_ONLY",
            "expected_tag_contract_digest": authority_tag_digest,
        },
        "identity_center_application": {
            "domain": "identity_center",
            "selector_kind": "INSTANCE_NAME_OR_TAG",
            "instance_arn": instance_arn,
            "name": "ScanalyzeAuthorityRetirement",
            "expected_tag_contract_digest": identity_tag_digest,
        },
        "classifier_permission_set": {
            "domain": "identity_center",
            "selector_kind": "INSTANCE_NAME_OR_TAG",
            "instance_arn": instance_arn,
            "name": "ScanalyzeAuthorityRetireClass",
            "expected_tag_contract_digest": identity_tag_digest,
        },
        "approver_permission_set": {
            "domain": "identity_center",
            "selector_kind": "INSTANCE_NAME_OR_TAG",
            "instance_arn": instance_arn,
            "name": "ScanalyzeAuthorityRetireApprove",
            "expected_tag_contract_digest": identity_tag_digest,
        },
    }
    policies = {
        domain: subject._closed_policy(
            domain=domain,
            not_before=NOT_BEFORE,
            expires_at=EXPIRES_AT,
        )
        for domain in ("authority", "identity_center")
    }
    policy_digests = {
        domain: subject.canonical_digest(policy)
        for domain, policy in policies.items()
    }
    budget = _budget_contract()
    request: dict[str, Any] = {
        "record_type": subject.REQUEST_TYPE,
        "schema_version": 1,
        "implementation_issue": subject.IMPLEMENTATION_ISSUE,
        "seed_issue": subject.SEED_ISSUE,
        "downstream_consumer_issue": subject.DOWNSTREAM_CONSUMER_ISSUE,
        "environment": "authority-non-production",
        "region": subject.REGION,
        "source_commit_sha": SOURCE_COMMIT,
        "source_tree_sha": SOURCE_TREE,
        "source_verification_digest": _digest("source-verification"),
        "repository_tree_entries_digest": _digest("tree-entries"),
        "preplan_source_commit_sha": "3" * 40,
        "preplan_source_tree_sha": "4" * 40,
        "preplan_seed_digest": _digest("seed"),
        "mutation_plan_digest": _digest("plan"),
        "private_custody_digest": _digest("custody"),
        "operational_host_digest": _digest("host"),
        "approval_reference_digest": _digest("approval"),
        "bound_values_digest": _digest("bound-values"),
        "operation_catalog_digest": _digest("operations"),
        "phase_catalog_digest": _digest("phases"),
        "provider_slot_catalog_digest": _digest("slots"),
        "targets": targets,
        "target_catalog_digest": subject.canonical_digest(targets),
        "expected_tag_contract_digest": subject.canonical_digest(
            {
                "authority": subject.AUTHORITY_TAG_CONTRACT,
                "identity_center": subject.IDENTITY_TAG_CONTRACT,
            }
        ),
        "profiles": profiles,
        "profile_binding_digest": subject.canonical_digest(profiles),
        "sdk_runtime_root": "/tmp/gug395-sdk",
        "sdk_runtime_root_digest": subject.canonical_digest(
            "/tmp/gug395-sdk"
        ),
        "not_before": NOT_BEFORE,
        "expires_at": EXPIRES_AT,
        "created_at": NOT_BEFORE,
        "window_digest": subject.canonical_digest(
            {"not_before": NOT_BEFORE, "expires_at": EXPIRES_AT}
        ),
        "policies": policies,
        "policy_digests": policy_digests,
        "policy_set_digest": subject.canonical_digest(policy_digests),
        "budget": budget,
        "budget_digest": budget["budget_digest"],
        "read_only": True,
        "aws_calls": 0,
        "aws_mutations": 0,
        "deployment_authorized": False,
        "production": False,
        "production_status": subject.PRODUCTION_STATUS,
    }
    _reseal(request, "request_digest")
    subject.validate_collision_probe_request(request)
    return request


def _identity(
    domain: str,
    capture_index: int,
    *,
    session_marker: str | None = None,
) -> dict[str, Any]:
    account = (
        AUTHORITY_ACCOUNT if domain == "authority" else IDENTITY_ACCOUNT
    )
    principal = (
        AUTHORITY_PRINCIPAL if domain == "authority" else IDENTITY_PRINCIPAL
    )
    observed_minute = capture_index if domain == "authority" else capture_index + 3
    return {
        "source": "DIRECT_SSO",
        "chain_depth": 0,
        "account_id": account,
        "region": subject.REGION,
        "principal_arn": principal,
        "session_id_digest": _digest(
            session_marker or f"{domain}-session-{capture_index}"
        ),
        "started_at": f"2026-08-28T01:0{observed_minute - 1}:00Z",
        "expires_at": "2026-08-28T02:00:00Z",
        "observed_at": f"2026-08-28T01:0{observed_minute}:00Z",
        "policy_digest": subject.canonical_digest(
            subject._closed_policy(
                domain=domain,
                not_before=NOT_BEFORE,
                expires_at=EXPIRES_AT,
            )
        ),
        "authority_verification_digest": _profiles()[domain][
            "authority_verification_digest"
        ],
    }


def _authority_facts(
    collisions: list[str], *, facts_marker: str
) -> dict[str, Any]:
    bucket_details = (
        []
        if facts_marker == "stable"
        else [
            {
                "name": "unrelated-owned-bucket",
                "tags": {"Absent": "NoSuchTagSet"},
                "tag_contract_matches": False,
            }
        ]
    )
    artifact_collision = "artifact_bucket" in collisions
    alias_matches = (
        [{"AliasName": "alias/scanalyze-gug395"}]
        if "kms_key" in collisions
        else []
    )
    profile_matches = (
        [{"profileName": "scanalyze_gug395"}]
        if "signing_profile" in collisions
        else []
    )
    profile_details = [
        {
            "summary": item,
            "profile": {"profileName": item["profileName"]},
            "tags": {},
            "tag_contract_matches": False,
        }
        for item in profile_matches
    ]
    signing_configurations = (
        [
            {
                "CodeSigningConfigArn": (
                    "arn:aws:lambda:us-east-1:042360977644:"
                    "code-signing-config:csc-example"
                ),
                "CodeSigningConfigId": "csc-example",
            }
        ]
        if "code_signing_config" in collisions
        else []
    )
    signing_config_details = [
        {
            "arn": item["CodeSigningConfigArn"],
            "configuration": {"CodeSigningConfig": item},
            "tags": {},
            "tag_contract_matches": True,
        }
        for item in signing_configurations
    ]
    return {
        "artifact_bucket": {
            "target_name": "scanalyze-gug395-example",
            "owned_bucket_count": len(bucket_details),
            "owned_matches": [],
            "head": {
                "status_code": 200 if artifact_collision else 404,
                "collision": artifact_collision,
                "absent": not artifact_collision,
            },
            "bucket_details": bucket_details,
            "tag_matches": [],
            "collision": artifact_collision,
        },
        "kms_key": {
            "target_alias_name": "alias/scanalyze-gug395",
            "keys_examined": 0,
            "discovered_keys": [],
            "discovered_aliases": alias_matches,
            "alias_matches": alias_matches,
            "key_details": [],
            "tag_matches": [],
            "collision": bool(alias_matches),
        },
        "signing_profile": {
            "target_profile_name": "scanalyze_gug395",
            "signing_profiles_examined": len(profile_matches),
            "discovered_profiles": profile_matches,
            "name_matches": profile_matches,
            "tag_matches": [],
            "details": profile_details,
            "collision": bool(profile_matches),
        },
        "code_signing_config": {
            "tag_contract_digest": subject.canonical_digest(
                subject.AUTHORITY_TAG_CONTRACT
            ),
            "code_signing_configs_examined": len(signing_configurations),
            "discovered_configurations": signing_configurations,
            "details": signing_config_details,
            "matches": signing_config_details,
            "collision": bool(signing_config_details),
        },
    }


def _identity_facts(
    collisions: list[str],
    *,
    facts_marker: str,
    complete: bool,
    prerequisites_ready: bool,
) -> dict[str, Any]:
    instance = {
        "InstanceArn": "arn:aws:sso:::instance/ssoins-1234567890abcdef",
        "Status": "ACTIVE" if prerequisites_ready else "CREATING",
        "OwnerAccountId": IDENTITY_ACCOUNT,
    }
    applications: list[dict[str, Any]] = []
    if facts_marker != "stable":
        applications.append(
            {
                "ApplicationArn": "arn:aws:sso::839393571433:application/unrelated",
                "ApplicationAccount": IDENTITY_ACCOUNT,
                "InstanceArn": instance["InstanceArn"],
                "Name": "UnrelatedApplication",
            }
        )
    if "identity_center_application" in collisions:
        applications.append(
            {
                "ApplicationArn": "arn:aws:sso::839393571433:application/target",
                "ApplicationAccount": IDENTITY_ACCOUNT,
                "InstanceArn": instance["InstanceArn"],
                "Name": "ScanalyzeAuthorityRetirement",
            }
        )
    described_applications = [
        {
            "summary": item,
            "description": {
                "ApplicationArn": item["ApplicationArn"],
                "ApplicationAccount": IDENTITY_ACCOUNT,
                "InstanceArn": instance["InstanceArn"],
                "NameDigest": subject.canonical_digest(item["Name"]),
            },
            "tags": [],
            "name_matches": item["Name"] == "ScanalyzeAuthorityRetirement",
            "tag_contract_matches": False,
        }
        for item in applications
    ]
    application_matches = [
        item
        for item in described_applications
        if item["name_matches"] or item["tag_contract_matches"]
    ]
    permission_names = []
    if "classifier_permission_set" in collisions:
        permission_names.append("ScanalyzeAuthorityRetireClass")
    if "approver_permission_set" in collisions:
        permission_names.append("ScanalyzeAuthorityRetireApprove")
    described_permission_sets = [
        {
            "arn": f"arn:aws:sso:::permissionSet/example/{index}",
            "description": {
                "PermissionSet": {
                    "Name": name,
                    "PermissionSetArn": (
                        f"arn:aws:sso:::permissionSet/example/{index}"
                    ),
                }
            },
            "name": name,
            "tags": [],
            "tag_contract_matches": False,
        }
        for index, name in enumerate(permission_names, start=1)
    ]
    permission_set_arns = [
        item["arn"] for item in described_permission_sets
    ]
    return {
        "target_instance_arn": instance["InstanceArn"],
        "target_application_name": "ScanalyzeAuthorityRetirement",
        "target_permission_set_names": [
            "ScanalyzeAuthorityRetireApprove",
            "ScanalyzeAuthorityRetireClass",
        ],
        "instances": [instance],
        "instance_matches": [instance],
        "applications": applications,
        "applications_examined": len(applications),
        "described_applications": described_applications,
        "application_matches": application_matches,
        "permission_sets_examined": len(permission_set_arns),
        "permission_set_arns": permission_set_arns,
        "described_permission_sets": described_permission_sets,
        "permission_set_matches": described_permission_sets,
        "application_collision": bool(application_matches),
        "classifier_permission_set_collision": (
            "classifier_permission_set" in collisions
        ),
        "approver_permission_set_collision": (
            "approver_permission_set" in collisions
        ),
        "complete": complete,
    }


def _provider_facts(
    domain: str,
    *,
    collisions: list[str] | None = None,
    facts_marker: str = "stable",
    complete: bool = True,
    prerequisites_ready: bool = True,
) -> dict[str, Any]:
    checked_collisions = sorted([] if collisions is None else collisions)
    if domain == "authority" and "artifact_bucket" not in checked_collisions:
        checked_collisions = sorted([*checked_collisions, "artifact_bucket"])
    facts = (
        _authority_facts(checked_collisions, facts_marker=facts_marker)
        if domain == "authority"
        else _identity_facts(
            checked_collisions,
            facts_marker=facts_marker,
            complete=complete,
            prerequisites_ready=prerequisites_ready,
        )
    )
    resource_counts = (
        {
            "owned_buckets_examined": facts["artifact_bucket"][
                "owned_bucket_count"
            ],
            "kms_keys_examined": facts["kms_key"]["keys_examined"],
            "signing_profiles_examined": facts["signing_profile"][
                "signing_profiles_examined"
            ],
            "code_signing_configs_examined": facts[
                "code_signing_config"
            ]["code_signing_configs_examined"],
        }
        if domain == "authority"
        else {
            "applications_examined": facts["applications_examined"],
            "permission_sets_examined": facts["permission_sets_examined"],
        }
    )
    return {
        "complete": True if domain == "authority" else complete,
        "prerequisites_ready": (
            True if domain == "authority" else prerequisites_ready
        ),
        "collisions": checked_collisions,
        "collision_count": len(checked_collisions),
        "resource_counts": resource_counts,
        "facts": facts,
    }


def _snapshot(
    domain: str,
    capture_index: int,
    *,
    collisions: list[str] | None = None,
    facts_marker: str = "stable",
    session_marker: str | None = None,
    complete: bool = True,
    prerequisites_ready: bool = True,
) -> dict[str, Any]:
    semantic_facts = _provider_facts(
        domain,
        collisions=collisions,
        facts_marker=facts_marker,
        complete=complete,
        prerequisites_ready=prerequisites_ready,
    )
    snapshot: dict[str, Any] = {
        "domain": domain,
        "capture_index": capture_index,
        "identity": _identity(
            domain, capture_index, session_marker=session_marker
        ),
        **semantic_facts,
        "facts_digest": subject.canonical_digest(semantic_facts),
        "transcript_segment_digest": _digest(
            f"{domain}-transcript-segment-{capture_index}"
        ),
    }
    _reseal(snapshot, "snapshot_digest")
    return snapshot


def _pairs(
    *, authority_collisions: list[str] | None = None
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    authority = [
        _snapshot(
            "authority", index, collisions=authority_collisions
        )
        for index in (1, 2)
    ]
    identity = [
        _snapshot("identity_center", index) for index in (1, 2)
    ]
    return authority, identity


def _stamp(second: int) -> str:
    value = datetime(2026, 8, 28, 1, 0, tzinfo=UTC) + timedelta(
        seconds=second
    )
    return value.isoformat().replace("+00:00", "Z")


def _successful_provider_and_budget_evidence(
    request: dict[str, Any],
    *,
    credential_vends: int = 0,
    omit_operation: tuple[str, int, str] | None = None,
    authority_snapshots: list[dict[str, Any]] | None = None,
    identity_center_snapshots: list[dict[str, Any]] | None = None,
) -> tuple[dict[str, Any], list[dict[str, Any]], dict[str, Any], list[dict[str, Any]]]:
    ledger = subject.CollisionCallLedger()
    budget = subject.CollisionProbeBudget(request)
    sessions = (
        ("authority", 1),
        ("authority", 2),
        ("identity_center", 1),
        ("identity_center", 2),
    )
    operations = {
        "authority": (
            "sts:GetCallerIdentity",
            "s3:ListAllMyBuckets",
            "s3:HeadBucket",
            "kms:ListAliases",
            "kms:ListKeys",
            "signer:ListSigningProfiles",
            "lambda:ListCodeSigningConfigs",
        ),
        "identity_center": (
            "sts:GetCallerIdentity",
            "sso:ListInstances",
            "sso:ListApplications",
            "sso:ListPermissionSets",
        ),
    }
    supplied_snapshots = {
        "authority": authority_snapshots,
        "identity_center": identity_center_snapshots,
    }
    session_start_seconds = (1, 61, 181, 241)
    for session_index, (domain, capture_index) in enumerate(sessions):
        budget.record_session_bootstrap("sso:GetRoleCredentials")
        if session_index < credential_vends:
            budget.record_credential_vend("sso:GetRoleCredentials")
        session_digest = _digest(f"{domain}-session-{capture_index}")
        snapshots = supplied_snapshots[domain]
        snapshot = (
            snapshots[capture_index - 1]
            if snapshots is not None
            else _snapshot(domain, capture_index)
        )
        identity = snapshot["identity"]
        fixed_requests: dict[str, dict[str, Any]] = {
            "sts:GetCallerIdentity": {},
            "s3:ListAllMyBuckets": {},
            "s3:HeadBucket": {
                "Bucket": request["targets"]["artifact_bucket"]["name"]
            },
            "kms:ListAliases": {},
            "kms:ListKeys": {},
            "signer:ListSigningProfiles": {
                "includeCanceled": True,
                "statuses": ["Active", "Canceled", "Revoked"],
            },
            "lambda:ListCodeSigningConfigs": {},
            "sso:ListInstances": {},
            "sso:ListApplications": {
                "InstanceArn": request["targets"][
                    "identity_center_application"
                ]["instance_arn"]
            },
            "sso:ListPermissionSets": {
                "InstanceArn": request["targets"][
                    "identity_center_application"
                ]["instance_arn"]
            },
        }
        for operation_index, operation in enumerate(operations[domain]):
            if omit_operation == (domain, capture_index, operation):
                continue
            request_body = fixed_requests[operation]
            is_page = operation in subject.PAGINATED_ACTIONS
            budget.reserve_provider_call(operation, is_page=is_page)
            ticket = ledger.authorize(
                domain=domain,
                session_digest=session_digest,
                operation=operation,
                retries=0,
                request=request_body,
                pagination_key=(
                    subject.canonical_digest(
                        {
                            "session": session_digest,
                            "operation": operation,
                            "request": request_body,
                        }
                    )
                    if is_page
                    else None
                ),
                started_at=_stamp(
                    session_start_seconds[session_index]
                    + operation_index * 2
                ),
            )
            budget.record_response(16)
            response = (
                {
                    "Account": identity["account_id"],
                    "Arn": identity["principal_arn"],
                    "UserIdPresent": True,
                }
                if operation == "sts:GetCallerIdentity"
                else (
                    snapshot["facts"]["artifact_bucket"]["head"]
                    if operation == "s3:HeadBucket"
                    else {"operation": operation, "projected": True}
                )
            )
            ledger.complete(
                ticket,
                response,
                completed_at=_stamp(
                    session_start_seconds[session_index]
                    + operation_index * 2
                    + 1
                ),
            )
        if snapshots is not None:
            segment = [
                event
                for event in ledger.partial_evidence_events()
                if event["session_digest"] == session_digest
            ]
            snapshot["transcript_segment_digest"] = subject.canonical_digest(
                segment
            )
            _reseal(snapshot, "snapshot_digest")
    provider_calls, transcript_digest = ledger.finalize()
    transcript_events = ledger.evidence_events()
    provider_summary = {
        "provider_calls": provider_calls,
        "aws_calls": provider_calls,
        "aws_mutations": 0,
        "live_provider_evidence": True,
        "transcript_digest": transcript_digest,
    }
    return (
        provider_summary,
        transcript_events,
        budget.summary(),
        budget.evidence_events(),
    )


def _reseal_transcript_session(
    *,
    provider_summary: dict[str, Any],
    transcript_events: list[dict[str, Any]],
    snapshots: list[dict[str, Any]],
    session_digest: str,
) -> None:
    provider_summary["transcript_digest"] = subject.canonical_digest(
        transcript_events
    )
    snapshot = next(
        item
        for item in snapshots
        if item["identity"]["session_id_digest"] == session_digest
    )
    snapshot["transcript_segment_digest"] = subject.canonical_digest(
        [
            event
            for event in transcript_events
            if event["session_digest"] == session_digest
        ]
    )
    _reseal(snapshot, "snapshot_digest")


def _build_success_result(
    *,
    credential_vends: int = 0,
    authority_collisions: list[str] | None = None,
    request: dict[str, Any] | None = None,
) -> subject.CollisionProbeResult:
    checked_request = _request() if request is None else request
    authority, identity = _pairs(
        authority_collisions=authority_collisions
    )
    provider, transcript, budget, budget_events = (
        _successful_provider_and_budget_evidence(
            checked_request,
            credential_vends=credential_vends,
            authority_snapshots=authority,
            identity_center_snapshots=identity,
        )
    )
    return subject.build_collision_probe_result(
        request=checked_request,
        authority_snapshots=authority,
        identity_center_snapshots=identity,
        provider_summary=provider,
        transcript_events=transcript,
        budget_summary=budget,
        budget_events=budget_events,
        sealed_at="2026-08-28T01:10:00Z",
    )


def _claim(request: dict[str, Any]) -> dict[str, Any]:
    claim = {
        "record_type": subject.CLAIM_TYPE,
        "schema_version": 1,
        "request_digest": request["request_digest"],
        "source_verification_digest": request["source_verification_digest"],
        "claimed_at": "2026-08-28T01:05:00Z",
        "aws_calls": 0,
        "aws_mutations": 0,
        "deployment_authorized": False,
        "production_status": subject.PRODUCTION_STATUS,
    }
    _reseal(claim, "claim_digest")
    return claim


def _write_result_custody(
    private_root: Path,
) -> tuple[dict[str, Any], dict[str, Any]]:
    request = _request()
    request["private_custody_digest"] = subject.private_root_digest(
        private_root
    )
    _reseal(request, "request_digest")
    claim = _claim(request)
    subject.persist_collision_probe_request(
        private_root=private_root,
        request=request,
    )
    subject.write_private_json(
        private_root, subject.DEFAULT_CLAIM_FILE, claim
    )
    return request, claim


def _verified_source_record(request: dict[str, Any]) -> dict[str, Any]:
    record = {
        "record_type": subject.source_verifier.RECORD_TYPE,
        "schema_version": 1,
        "verifier_id": subject.source_verifier.VERIFIER_ID,
        "expected_remote_ref": subject.EXPECTED_REMOTE_REF,
        "source_commit_sha": request["source_commit_sha"],
        "source_tree_sha": request["source_tree_sha"],
        "remote_ref_commit_sha": request["source_commit_sha"],
        "checkout_clean": True,
        "required_source_count": len(subject._SOURCE_PATHS),
        "required_source_set_digest": _digest("required-source-set"),
        "repository_tree_entries_digest": request[
            "repository_tree_entries_digest"
        ],
        "aws_calls": 0,
        "aws_mutations": 0,
    }
    _reseal(record, "verification_digest")
    return record


def _persist_claimable_request(
    private_root: Path,
    *,
    host_digest: str,
) -> tuple[dict[str, Any], subject.VerifiedCollisionProbeSource]:
    request = _request()
    request["private_custody_digest"] = subject.private_root_digest(
        private_root
    )
    request["operational_host_digest"] = host_digest
    source_record = _verified_source_record(request)
    request["source_verification_digest"] = source_record[
        "verification_digest"
    ]
    _reseal(request, "request_digest")
    subject.persist_collision_probe_request(
        private_root=private_root,
        request=request,
    )
    return request, subject.VerifiedCollisionProbeSource(
        subject._VERIFIED_SOURCE_SENTINEL,
        source_record,
        private_root.parent.resolve(),
    )


def test_target_catalog_is_the_exact_seven_target_private_selector_set(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(subject, "validate_preplan_seed", lambda seed: None)
    values = {
        "artifact_bucket_name": "scanalyze-gug395-example",
        "authority_account_id": "042360977644",
        "kms_alias_name": "alias/scanalyze-gug395",
        "identity_center_application_name": "ScanalyzeAuthorityRetirement",
        "identity_center_instance_arn": (
            "arn:aws:sso:::instance/ssoins-1234567890abcdef"
        ),
        "classifier_permission_set_name": "ScanalyzeAuthorityRetireClass",
        "approver_permission_set_name": "ScanalyzeAuthorityRetireApprove",
        "signing_profile_name": "scanalyze_gug395",
    }
    seed = {
        "decisions": [
            {
                "key": key,
                "value": value,
                "value_digest": subject.canonical_digest(value),
            }
            for key, value in values.items()
        ]
    }

    catalog = subject.collision_target_catalog(seed)

    assert tuple(catalog) == subject.TARGET_ORDER
    assert len(catalog) == 7
    assert [catalog[name]["domain"] for name in subject.TARGET_ORDER] == [
        "authority",
        "authority",
        "authority",
        "authority",
        "identity_center",
        "identity_center",
        "identity_center",
    ]
    assert catalog["artifact_bucket"]["name"] == values[
        "artifact_bucket_name"
    ]
    assert catalog["kms_key"]["alias_name"] == values["kms_alias_name"]
    assert catalog["identity_center_application"]["instance_arn"] == values[
        "identity_center_instance_arn"
    ]
    assert all(
        set(target).isdisjoint({"arn", "resource_id"})
        for target in catalog.values()
    )


@pytest.mark.parametrize(
    ("authority_collisions", "expected"),
    [
        (None, subject.COLLISION_BLOCKED),
        (["artifact_bucket"], subject.COLLISION_BLOCKED),
    ],
)
def test_two_unique_stable_sessions_apply_the_connected_collision_lattice(
    authority_collisions: list[str] | None,
    expected: str,
) -> None:
    authority, identity = _pairs(
        authority_collisions=authority_collisions
    )

    result = subject.classify_collision_probe_snapshots(
        authority_snapshots=authority,
        identity_center_snapshots=identity,
    )

    assert result["classification"] == expected
    assert result["evidence_stable"] is True
    assert result["evidence_complete"] is True
    assert result["reconciliation_only"] is False
    assert len(set(result["authority"]["session_digests"])) == 2
    assert len(set(result["identity_center"]["session_digests"])) == 2
    assert len(set(result["authority"]["snapshot_digests"])) == 2
    assert len(set(result["identity_center"]["snapshot_digests"])) == 2


@pytest.mark.parametrize(
    "destabilize",
    ["facts", "incomplete", "prerequisites"],
)
def test_any_unstable_pair_is_uncertain_and_reconciliation_only(
    destabilize: str,
) -> None:
    authority, identity = _pairs()
    if destabilize == "facts":
        authority[1] = _snapshot(
            "authority", 2, facts_marker="changed"
        )
    elif destabilize == "incomplete":
        identity[1] = _snapshot("identity_center", 2, complete=False)
    else:
        identity[1] = _snapshot(
            "identity_center", 2, prerequisites_ready=False
        )

    result = subject.classify_collision_probe_snapshots(
        authority_snapshots=authority,
        identity_center_snapshots=identity,
    )

    assert result["classification"] == subject.UNCERTAIN
    destabilized_domain = (
        "authority" if destabilize == "facts" else "identity_center"
    )
    assert result[destabilized_domain]["classification"] == subject.UNCERTAIN
    assert result["evidence_stable"] is False
    assert result["evidence_complete"] is False
    assert result["reconciliation_only"] is True


def test_session_digest_splice_is_rejected_instead_of_downgraded() -> None:
    authority, identity = _pairs()
    authority[1] = _snapshot(
        "authority", 2, session_marker="authority-session-1"
    )

    with pytest.raises(
        subject.CollisionProbeError,
        match="^COLLISION_SNAPSHOT_PAIR_INVALID$",
    ):
        subject.classify_collision_probe_snapshots(
            authority_snapshots=authority,
            identity_center_snapshots=identity,
        )


def test_uncertain_domain_precedes_a_stable_collision_in_global_lattice() -> None:
    authority, identity = _pairs(
        authority_collisions=["artifact_bucket"]
    )
    identity[1] = _snapshot(
        "identity_center", 2, facts_marker="unstable"
    )

    result = subject.classify_collision_probe_snapshots(
        authority_snapshots=authority,
        identity_center_snapshots=identity,
    )

    assert result["authority"]["classification"] == subject.COLLISION_BLOCKED
    assert result["identity_center"]["classification"] == subject.UNCERTAIN
    assert result["classification"] == subject.UNCERTAIN
    assert result["reconciliation_only"] is True


def test_global_budget_records_provider_vending_page_bytes_and_cost(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        subject, "validate_collision_probe_request", lambda request: None
    )
    budget = subject.CollisionProbeBudget({"budget": _budget_contract()})

    budget.record_session_bootstrap("sso:GetRoleCredentials")
    budget.record_credential_vend("sso:GetRoleCredentials")
    budget.reserve_provider_call("sts:GetCallerIdentity", is_page=False)
    budget.record_response(128)
    budget.reserve_provider_call("s3:ListAllMyBuckets", is_page=True)
    budget.record_response(256)

    summary = budget.summary()
    events = budget.evidence_events()

    assert summary["provider_calls"] == 2
    assert summary["session_bootstrap_attempts"] == 1
    assert summary["credential_vending_calls"] == 1
    assert summary["network_calls"] == 3
    assert summary["page_calls"] == 1
    assert summary["projected_response_bytes"] == 384
    assert summary["modeled_cost_nano_usd"] == (
        3 * subject.PER_NETWORK_CALL_COST_NANO_USD + 384
    )
    assert [event["ordinal"] for event in events] == list(
        range(1, len(events) + 1)
    )
    assert [event["kind"] for event in events] == [
        "SESSION_BOOTSTRAP",
        "CREDENTIAL_VEND",
        "PROVIDER_CALL",
        "PROJECTED_RESPONSE",
        "PROVIDER_CALL",
        "PROJECTED_RESPONSE",
    ]


@pytest.mark.parametrize(
    ("overrides", "exercise", "code"),
    [
        (
            {"max_provider_calls": 0},
            lambda budget: budget.reserve_provider_call(
                "sts:GetCallerIdentity", is_page=False
            ),
            "COLLISION_PROVIDER_CALL_BUDGET_EXCEEDED",
        ),
        (
            {"max_session_bootstrap_attempts": 0},
            lambda budget: budget.record_session_bootstrap(
                "sso:GetRoleCredentials"
            ),
            "COLLISION_SESSION_BOOTSTRAP_BUDGET_EXCEEDED",
        ),
        (
            {"max_credential_vending_calls": 0},
            lambda budget: budget.record_credential_vend(
                "sso:GetRoleCredentials"
            ),
            "COLLISION_CREDENTIAL_VENDING_BUDGET_EXCEEDED",
        ),
        (
            {"max_response_bytes": 7},
            lambda budget: budget.record_response(8),
            "COLLISION_RESPONSE_BYTE_BUDGET_EXCEEDED",
        ),
        (
            {"max_modeled_cost_nano_usd": 0},
            lambda budget: budget.reserve_provider_call(
                "sts:GetCallerIdentity", is_page=False
            ),
            "COLLISION_COST_BUDGET_EXCEEDED",
        ),
    ],
)
def test_global_budget_caps_fail_closed_without_incrementing_counters(
    monkeypatch: pytest.MonkeyPatch,
    overrides: dict[str, int],
    exercise: Any,
    code: str,
) -> None:
    monkeypatch.setattr(
        subject, "validate_collision_probe_request", lambda request: None
    )
    budget = subject.CollisionProbeBudget(
        {"budget": _budget_contract(**overrides)}
    )

    with pytest.raises(subject.CollisionProbeError, match=f"^{code}$"):
        exercise(budget)

    summary = budget.summary()
    assert summary["provider_calls"] == 0
    assert summary["session_bootstrap_attempts"] == 0
    assert summary["credential_vending_calls"] == 0
    assert summary["network_calls"] == 0
    assert summary["projected_response_bytes"] == 0


def test_call_ledger_requires_sts_first_and_exact_domain_action() -> None:
    ledger = subject.CollisionCallLedger()
    session = _digest("authority-session")

    with pytest.raises(
        subject.CollisionProbeError, match="^COLLISION_STS_FIRST_REQUIRED$"
    ):
        ledger.authorize(
            domain="authority",
            session_digest=session,
            operation="s3:ListAllMyBuckets",
            retries=0,
            started_at=NOT_BEFORE,
        )

    second = subject.CollisionCallLedger()
    with pytest.raises(
        subject.CollisionProbeError,
        match="^COLLISION_PROVIDER_CALL_NOT_ALLOWED$",
    ):
        second.authorize(
            domain="identity_center",
            session_digest=_digest("identity-session"),
            operation="s3:ListAllMyBuckets",
            retries=0,
            started_at=NOT_BEFORE,
        )


@pytest.mark.parametrize(
    "operation", ["signer:ListTagsForResource", "lambda:ListTags"]
)
def test_non_paginated_list_named_actions_are_not_counted_as_pages(
    operation: str,
) -> None:
    request = _request()
    budget = subject.CollisionProbeBudget(request)
    ledger = subject.CollisionCallLedger()
    session = _digest("authority-non-page-list-session")
    budget.reserve_provider_call("sts:GetCallerIdentity", is_page=False)
    sts = ledger.authorize(
        domain="authority",
        session_digest=session,
        operation="sts:GetCallerIdentity",
        retries=0,
        request={},
        started_at="2026-08-28T01:00:00Z",
    )
    ledger.complete(
        sts,
        {},
        completed_at="2026-08-28T01:00:01Z",
    )
    budget.record_response(2)
    budget.reserve_provider_call(operation, is_page=False)
    ticket = ledger.authorize(
        domain="authority",
        session_digest=session,
        operation=operation,
        retries=0,
        request={"ResourceArn": "redacted"},
        started_at="2026-08-28T01:00:02Z",
    )
    ledger.complete(ticket, {}, completed_at="2026-08-28T01:00:03Z")
    budget.record_response(2)

    assert budget.summary()["page_calls"] == 0
    assert ledger.evidence_events()[-1]["pagination_stream_digest"] is None


def test_call_ledger_commits_complete_pagination_without_plaintext_tokens() -> None:
    ledger = subject.CollisionCallLedger()
    session = _digest("authority-session")
    sts = ledger.authorize(
        domain="authority",
        session_digest=session,
        operation="sts:GetCallerIdentity",
        retries=0,
        started_at="2026-08-28T01:00:00Z",
    )
    ledger.complete(
        sts,
        {"account": "redacted"},
        completed_at="2026-08-28T01:00:01Z",
    )
    stream = _digest("bucket-pagination-stream")
    first = ledger.authorize(
        domain="authority",
        session_digest=session,
        operation="s3:ListAllMyBuckets",
        retries=0,
        pagination_key=stream,
        started_at="2026-08-28T01:00:02Z",
    )
    ledger.complete(
        first,
        {"buckets": []},
        complete=False,
        truncated=True,
        next_token="private-page-token",
        completed_at="2026-08-28T01:00:03Z",
    )
    second = ledger.authorize(
        domain="authority",
        session_digest=session,
        operation="s3:ListAllMyBuckets",
        retries=0,
        page_token="private-page-token",
        pagination_key=stream,
        started_at="2026-08-28T01:00:04Z",
    )
    ledger.complete(
        second,
        {"buckets": []},
        completed_at="2026-08-28T01:00:05Z",
    )

    count, transcript_digest = ledger.finalize()
    events = ledger.evidence_events()

    assert count == 3
    assert transcript_digest == subject.canonical_digest(events)
    assert events[1]["next_token_digest"] == subject.canonical_digest(
        "private-page-token"
    )
    assert "private-page-token" not in subject.canonical_json(events)


def test_call_ledger_rejects_an_unfinished_pagination_stream() -> None:
    ledger = subject.CollisionCallLedger()
    session = _digest("authority-session")
    sts = ledger.authorize(
        domain="authority",
        session_digest=session,
        operation="sts:GetCallerIdentity",
        retries=0,
        started_at="2026-08-28T01:00:00Z",
    )
    ledger.complete(sts, completed_at="2026-08-28T01:00:01Z")
    page = ledger.authorize(
        domain="authority",
        session_digest=session,
        operation="s3:ListAllMyBuckets",
        retries=0,
        started_at="2026-08-28T01:00:02Z",
    )
    ledger.complete(
        page,
        complete=False,
        truncated=True,
        next_token="more",
        completed_at="2026-08-28T01:00:03Z",
    )

    with pytest.raises(
        subject.CollisionProbeError,
        match="^COLLISION_PROVIDER_TRANSCRIPT_INCOMPLETE$",
    ):
        ledger.finalize()


@pytest.mark.parametrize(
    "mutate",
    [
        lambda profiles: profiles["authority"].__setitem__(
            "name", "042360977644_AWSAdministratorAccess"
        ),
        lambda profiles: profiles["identity_center"].__setitem__(
            "expected_account_id", "042360977644"
        ),
    ],
)
def test_profile_and_account_bindings_fail_closed(mutate: Any) -> None:
    request = _request()
    mutate(request["profiles"])
    request["profile_binding_digest"] = subject.canonical_digest(
        request["profiles"]
    )
    _reseal(request, "request_digest")

    with pytest.raises(
        subject.CollisionProbeError,
        match="^COLLISION_PROFILE_BINDINGS_INVALID$",
    ):
        subject.validate_collision_probe_request(request)


def test_policy_binding_rejects_even_a_narrower_unattested_policy() -> None:
    request = _request()
    request["policies"]["authority"]["Statement"][1]["Action"].remove(
        "s3:HeadBucket"
    )
    request["policy_digests"]["authority"] = subject.canonical_digest(
        request["policies"]["authority"]
    )
    request["policy_set_digest"] = subject.canonical_digest(
        request["policy_digests"]
    )
    _reseal(request, "request_digest")

    with pytest.raises(
        subject.CollisionProbeError,
        match="^COLLISION_POLICY_BINDING_MISMATCH$",
    ):
        subject.validate_collision_probe_request(request)


def test_request_catalog_validation_is_order_independent_but_shape_exact() -> None:
    request = _request()
    request["targets"] = dict(reversed(list(request["targets"].items())))
    request["target_catalog_digest"] = subject.canonical_digest(
        request["targets"]
    )
    _reseal(request, "request_digest")

    subject.validate_collision_probe_request(request)

    request["targets"]["artifact_bucket"]["domain"] = "identity_center"
    request["target_catalog_digest"] = subject.canonical_digest(
        request["targets"]
    )
    _reseal(request, "request_digest")
    with pytest.raises(
        subject.CollisionProbeError,
        match="^COLLISION_TARGET_CATALOG_INVALID$",
    ):
        subject.validate_collision_probe_request(request)


@pytest.mark.parametrize("credential_vends", range(5))
def test_complete_result_replays_four_sessions_and_exact_cost(
    credential_vends: int,
) -> None:
    result = _build_success_result(credential_vends=credential_vends)
    evidence = result.private_evidence
    receipt = result.public_receipt
    transcript = evidence["transcript_events"]
    sessions: dict[str, list[str]] = {}
    for event in transcript:
        sessions.setdefault(event["session_digest"], []).append(
            event["operation"]
        )

    assert len(sessions) == 4
    assert all(
        operations[0] == "sts:GetCallerIdentity"
        for operations in sessions.values()
    )
    assert receipt["session_bootstrap_attempts"] == 4
    assert receipt["credential_vending_calls"] == credential_vends
    assert receipt["network_calls"] == (
        receipt["provider_calls"] + credential_vends
    )
    expected_nano = (
        receipt["network_calls"] * subject.PER_NETWORK_CALL_COST_NANO_USD
        + receipt["projected_response_bytes"]
        * subject.PER_PROJECTED_BYTE_COST_NANO_USD
    )
    assert receipt["modeled_cost_usd_upper"] == (
        f"{expected_nano // 1_000_000_000}."
        f"{expected_nano % 1_000_000_000:09d}"
    )
    budget_kinds = [event["kind"] for event in evidence["budget_events"]]
    assert budget_kinds.count("SESSION_BOOTSTRAP") == 4
    assert budget_kinds.count("CREDENTIAL_VEND") == credential_vends
    subject.validate_private_collision_probe_evidence(evidence)
    subject.validate_public_collision_probe_receipt(receipt)


def test_budget_transcript_operation_splice_is_rejected() -> None:
    request = _request()
    authority, identity = _pairs()
    provider, transcript, budget, budget_events = (
        _successful_provider_and_budget_evidence(
            request,
            authority_snapshots=authority,
            identity_center_snapshots=identity,
        )
    )
    spliced = copy.deepcopy(budget_events)
    first_provider = next(
        event for event in spliced if event["kind"] == "PROVIDER_CALL"
    )
    first_provider["operation"] = "s3:HeadBucket"

    with pytest.raises(
        subject.CollisionProbeError,
        match="^COLLISION_BUDGET_PROVIDER_TRANSCRIPT_MISMATCH$",
    ):
        subject.build_collision_probe_result(
            request=request,
            authority_snapshots=authority,
            identity_center_snapshots=identity,
            provider_summary=provider,
            transcript_events=transcript,
            budget_summary=budget,
            budget_events=spliced,
            sealed_at="2026-08-28T01:10:00Z",
        )


def test_budget_replay_rederives_list_page_accounting() -> None:
    request = _request()
    authority, identity = _pairs()
    provider, transcript, budget, budget_events = (
        _successful_provider_and_budget_evidence(
            request,
            authority_snapshots=authority,
            identity_center_snapshots=identity,
        )
    )
    forged_budget = copy.deepcopy(budget)
    forged_events = copy.deepcopy(budget_events)
    first_list = next(
        event
        for event in forged_events
        if event["kind"] == "PROVIDER_CALL"
        and event["operation"].split(":", 1)[1].startswith("List")
    )
    first_list["page_call"] = False
    forged_budget["page_calls"] -= 1
    _reseal(forged_budget, "summary_digest")

    with pytest.raises(
        subject.CollisionProbeError,
        match="^COLLISION_BUDGET_EVIDENCE_INVALID$",
    ):
        subject.build_collision_probe_result(
            request=request,
            authority_snapshots=authority,
            identity_center_snapshots=identity,
            provider_summary=provider,
            transcript_events=transcript,
            budget_summary=forged_budget,
            budget_events=forged_events,
            sealed_at="2026-08-28T01:10:00Z",
        )


def test_budget_replay_rejects_malformed_operation_without_crashing() -> None:
    request = _request()
    _, _, budget, budget_events = (
        _successful_provider_and_budget_evidence(request)
    )
    malformed_events = copy.deepcopy(budget_events)
    first_provider = next(
        event
        for event in malformed_events
        if event["kind"] == "PROVIDER_CALL"
    )
    first_provider["operation"] = "malformed"

    with pytest.raises(
        subject.CollisionProbeError,
        match="^COLLISION_BUDGET_EVIDENCE_INVALID$",
    ):
        subject._validate_budget_evidence(
            request,
            budget,
            malformed_events,
            complete=True,
        )


def test_budget_replay_requires_each_response_after_its_provider_call() -> None:
    request = _request()
    authority, identity = _pairs()
    provider, transcript, budget, budget_events = (
        _successful_provider_and_budget_evidence(
            request,
            authority_snapshots=authority,
            identity_center_snapshots=identity,
        )
    )
    forged_events = copy.deepcopy(budget_events)
    response_index = next(
        index
        for index in range(len(forged_events) - 1)
        if forged_events[index]["kind"] == "PROJECTED_RESPONSE"
        and forged_events[index + 1]["kind"] == "PROVIDER_CALL"
    )
    forged_events[response_index], forged_events[response_index + 1] = (
        forged_events[response_index + 1],
        forged_events[response_index],
    )
    for ordinal, event in enumerate(forged_events, start=1):
        event["ordinal"] = ordinal

    with pytest.raises(
        subject.CollisionProbeError,
        match="^COLLISION_BUDGET_EVIDENCE_INVALID$",
    ):
        subject.build_collision_probe_result(
            request=request,
            authority_snapshots=authority,
            identity_center_snapshots=identity,
            provider_summary=provider,
            transcript_events=transcript,
            budget_summary=budget,
            budget_events=forged_events,
            sealed_at="2026-08-28T01:10:00Z",
        )


def test_snapshot_transcript_session_splice_is_rejected() -> None:
    request = _request()
    authority, identity = _pairs()
    provider, transcript, budget, budget_events = (
        _successful_provider_and_budget_evidence(
            request,
            authority_snapshots=authority,
            identity_center_snapshots=identity,
        )
    )
    authority[0]["identity"]["session_id_digest"] = _digest(
        "spliced-authority-session"
    )
    _reseal(authority[0], "snapshot_digest")

    with pytest.raises(
        subject.CollisionProbeError,
        match="^COLLISION_SNAPSHOT_TRANSCRIPT_MISMATCH$",
    ):
        subject.build_collision_probe_result(
            request=request,
            authority_snapshots=authority,
            identity_center_snapshots=identity,
            provider_summary=provider,
            transcript_events=transcript,
            budget_summary=budget,
            budget_events=budget_events,
            sealed_at="2026-08-28T01:10:00Z",
        )


@pytest.mark.parametrize(
    ("field", "forged_value"),
    [
        (
            "request_digest",
            subject.canonical_digest({"Bucket": "different-global-bucket"}),
        ),
        (
            "response_digest",
            subject.canonical_digest(
                {"status_code": 404, "collision": False, "absent": True}
            ),
        ),
    ],
)
def test_head_bucket_transcript_is_exactly_bound_to_target_and_facts(
    field: str, forged_value: str
) -> None:
    request = _request()
    authority, identity = _pairs()
    provider, transcript, budget, budget_events = (
        _successful_provider_and_budget_evidence(
            request,
            authority_snapshots=authority,
            identity_center_snapshots=identity,
        )
    )
    head_event = next(
        event
        for event in transcript
        if event["session_digest"]
        == authority[0]["identity"]["session_id_digest"]
        and event["operation"] == "s3:HeadBucket"
    )
    head_event[field] = forged_value
    _reseal_transcript_session(
        provider_summary=provider,
        transcript_events=transcript,
        snapshots=authority,
        session_digest=head_event["session_digest"],
    )

    with pytest.raises(
        subject.CollisionProbeError,
        match="^COLLISION_SNAPSHOT_TRANSCRIPT_MISMATCH$",
    ):
        subject.build_collision_probe_result(
            request=request,
            authority_snapshots=authority,
            identity_center_snapshots=identity,
            provider_summary=provider,
            transcript_events=transcript,
            budget_summary=budget,
            budget_events=budget_events,
            sealed_at="2026-08-28T01:10:00Z",
        )


def test_resealed_transcript_event_before_request_window_is_rejected() -> None:
    request = _request()
    authority, identity = _pairs()
    provider, transcript, budget, budget_events = (
        _successful_provider_and_budget_evidence(
            request,
            authority_snapshots=authority,
            identity_center_snapshots=identity,
        )
    )
    first_event = transcript[0]
    first_event["started_at"] = "2026-08-28T00:59:58Z"
    first_event["completed_at"] = "2026-08-28T00:59:59Z"
    _reseal_transcript_session(
        provider_summary=provider,
        transcript_events=transcript,
        snapshots=authority,
        session_digest=first_event["session_digest"],
    )

    with pytest.raises(
        subject.CollisionProbeError,
        match="^COLLISION_PROVIDER_TRANSCRIPT_INVALID$",
    ):
        subject.build_collision_probe_result(
            request=request,
            authority_snapshots=authority,
            identity_center_snapshots=identity,
            provider_summary=provider,
            transcript_events=transcript,
            budget_summary=budget,
            budget_events=budget_events,
            sealed_at="2026-08-28T01:10:00Z",
        )


@pytest.mark.parametrize(
    ("operation", "field", "forged_value"),
    [
        (
            "sts:GetCallerIdentity",
            "response_digest",
            subject.canonical_digest(
                {
                    "Account": IDENTITY_ACCOUNT,
                    "Arn": AUTHORITY_PRINCIPAL,
                    "UserIdPresent": True,
                }
            ),
        ),
        (
            "signer:ListSigningProfiles",
            "request_digest",
            subject.canonical_digest({"includeCanceled": True}),
        ),
    ],
)
def test_fixed_transcript_operations_require_exact_request_or_response(
    operation: str, field: str, forged_value: str
) -> None:
    request = _request()
    authority, identity = _pairs()
    provider, transcript, budget, budget_events = (
        _successful_provider_and_budget_evidence(
            request,
            authority_snapshots=authority,
            identity_center_snapshots=identity,
        )
    )
    event = next(
        item
        for item in transcript
        if item["session_digest"]
        == authority[0]["identity"]["session_id_digest"]
        and item["operation"] == operation
    )
    event[field] = forged_value
    _reseal_transcript_session(
        provider_summary=provider,
        transcript_events=transcript,
        snapshots=authority,
        session_digest=event["session_digest"],
    )

    with pytest.raises(
        subject.CollisionProbeError,
        match="^COLLISION_SNAPSHOT_TRANSCRIPT_MISMATCH$",
    ):
        subject.build_collision_probe_result(
            request=request,
            authority_snapshots=authority,
            identity_center_snapshots=identity,
            provider_summary=provider,
            transcript_events=transcript,
            budget_summary=budget,
            budget_events=budget_events,
            sealed_at="2026-08-28T01:10:00Z",
        )


@pytest.mark.parametrize("domain", ["authority", "identity_center"])
def test_snapshot_target_selector_must_match_the_request_catalog(
    domain: str,
) -> None:
    request = _request()
    authority, identity = _pairs()
    selected = authority if domain == "authority" else identity
    for snapshot in selected:
        if domain == "authority":
            snapshot["facts"]["artifact_bucket"]["target_name"] = (
                "different-global-bucket-name"
            )
        else:
            snapshot["facts"]["target_application_name"] = (
                "DifferentIdentityCenterApplication"
            )
        semantic_facts = {
            key: snapshot[key]
            for key in (
                "complete",
                "prerequisites_ready",
                "collisions",
                "collision_count",
                "resource_counts",
                "facts",
            )
        }
        snapshot["facts_digest"] = subject.canonical_digest(semantic_facts)
        _reseal(snapshot, "snapshot_digest")
    provider, transcript, budget, budget_events = (
        _successful_provider_and_budget_evidence(
            request,
            authority_snapshots=authority,
            identity_center_snapshots=identity,
        )
    )

    with pytest.raises(
        subject.CollisionProbeError,
        match="^COLLISION_SNAPSHOT_SEMANTICS_INVALID$",
    ):
        subject.build_collision_probe_result(
            request=request,
            authority_snapshots=authority,
            identity_center_snapshots=identity,
            provider_summary=provider,
            transcript_events=transcript,
            budget_summary=budget,
            budget_events=budget_events,
            sealed_at="2026-08-28T01:10:00Z",
        )


@pytest.mark.parametrize("status_code", [400, 403, 404])
def test_completed_snapshot_rejects_ambiguous_head_bucket_status(
    status_code: int,
) -> None:
    request = _request()
    authority, identity = _pairs()
    for snapshot in authority:
        snapshot["facts"]["artifact_bucket"]["head"] = {
            "status_code": status_code,
            "collision": False,
            "absent": True,
        }
        semantic_facts = {
            key: snapshot[key]
            for key in (
                "complete",
                "prerequisites_ready",
                "collisions",
                "collision_count",
                "resource_counts",
                "facts",
            )
        }
        snapshot["facts_digest"] = subject.canonical_digest(semantic_facts)
        _reseal(snapshot, "snapshot_digest")
    provider, transcript, budget, budget_events = (
        _successful_provider_and_budget_evidence(
            request,
            authority_snapshots=authority,
            identity_center_snapshots=identity,
        )
    )

    with pytest.raises(
        subject.CollisionProbeError,
        match="^COLLISION_SNAPSHOT_SEMANTICS_INVALID$",
    ):
        subject.build_collision_probe_result(
            request=request,
            authority_snapshots=authority,
            identity_center_snapshots=identity,
            provider_summary=provider,
            transcript_events=transcript,
            budget_summary=budget,
            budget_events=budget_events,
            sealed_at="2026-08-28T01:10:00Z",
        )


def test_snapshot_session_requires_its_fixed_inventory_surface() -> None:
    request = _request()
    authority, identity = _pairs()
    provider, transcript, budget, budget_events = (
        _successful_provider_and_budget_evidence(
            request,
            omit_operation=("authority", 1, "s3:HeadBucket"),
            authority_snapshots=authority,
            identity_center_snapshots=identity,
        )
    )

    with pytest.raises(
        subject.CollisionProbeError,
        match="^COLLISION_SNAPSHOT_TRANSCRIPT_MISMATCH$",
    ):
        subject.build_collision_probe_result(
            request=request,
            authority_snapshots=authority,
            identity_center_snapshots=identity,
            provider_summary=provider,
            transcript_events=transcript,
            budget_summary=budget,
            budget_events=budget_events,
            sealed_at="2026-08-28T01:10:00Z",
        )


def test_repeated_page_token_preserves_durable_partial_evidence() -> None:
    request = _request()
    ledger = subject.CollisionCallLedger()
    budget = subject.CollisionProbeBudget(request)
    session_digest = _digest("authority-session-1")
    budget.record_session_bootstrap("sso:GetRoleCredentials")

    budget.reserve_provider_call("sts:GetCallerIdentity", is_page=False)
    sts = ledger.authorize(
        domain="authority",
        session_digest=session_digest,
        operation="sts:GetCallerIdentity",
        retries=0,
        started_at="2026-08-28T01:00:01Z",
    )
    budget.record_response(16)
    ledger.complete(sts, completed_at="2026-08-28T01:00:02Z")

    stream_digest = _digest("bucket-pagination-stream")
    repeated_token = _digest("repeated-page-token")
    budget.reserve_provider_call("s3:ListAllMyBuckets", is_page=True)
    first = ledger.authorize(
        domain="authority",
        session_digest=session_digest,
        operation="s3:ListAllMyBuckets",
        retries=0,
        pagination_key=stream_digest,
        started_at="2026-08-28T01:00:03Z",
    )
    budget.record_response(16)
    ledger.complete(
        first,
        complete=False,
        truncated=True,
        next_token=repeated_token,
        completed_at="2026-08-28T01:00:04Z",
    )

    budget.reserve_provider_call("s3:ListAllMyBuckets", is_page=True)
    second = ledger.authorize(
        domain="authority",
        session_digest=session_digest,
        operation="s3:ListAllMyBuckets",
        retries=0,
        page_token=repeated_token,
        pagination_key=stream_digest,
        started_at="2026-08-28T01:00:05Z",
    )
    budget.record_response(16)
    with pytest.raises(
        subject.CollisionProbeError,
        match="^COLLISION_PROVIDER_PAGE_TOKEN_REPEATED$",
    ):
        ledger.complete(
            second,
            complete=False,
            truncated=True,
            next_token=repeated_token,
            completed_at="2026-08-28T01:00:06Z",
        )

    calls, transcript_digest = ledger.partial_summary()
    transcript_events = ledger.partial_evidence_events()
    assert calls == 3
    assert transcript_events[-1]["outcome"] == "INCOMPLETE"
    provider_summary = {
        "provider_calls": calls,
        "aws_calls": None,
        "aws_mutations": 0,
        "live_provider_evidence": False,
        "transcript_digest": transcript_digest,
    }
    result = subject.build_collision_probe_failure_result(
        request=request,
        authority_snapshots=[],
        identity_center_snapshots=[],
        provider_summary=provider_summary,
        transcript_events=transcript_events,
        budget_summary=budget.summary(),
        budget_events=budget.partial_evidence_events(),
        blocker_code="COLLISION_PROVIDER_PAGE_TOKEN_REPEATED",
        sealed_at="2026-08-28T01:10:00Z",
    )
    assert result.public_receipt["status"] == "LIVE_READ_ONLY_PROBE_BLOCKED"


@pytest.mark.parametrize("failure", ["repeated_token", "over_page_cap"])
def test_transcript_replay_rejects_token_cycles_and_per_stream_over_cap(
    failure: str,
) -> None:
    request = _request()
    session_digest = _digest("authority-session-replay")
    stream_digest = _digest("authority-pagination-stream")
    events: list[dict[str, Any]] = [
        {
            "ordinal": 1,
            "domain": "authority",
            "session_digest": session_digest,
            "operation": "sts:GetCallerIdentity",
            "request_digest": _digest("sts-request"),
            "page_token_digest": None,
            "pagination_stream_digest": None,
            "started_at": "2026-08-28T01:00:01Z",
            "completed_at": "2026-08-28T01:00:01Z",
            "response_digest": _digest("sts-response"),
            "outcome": "SUCCESS",
            "complete": True,
            "truncated": False,
            "next_token_digest": None,
        }
    ]
    if failure == "repeated_token":
        token_a = _digest("page-token-a")
        token_b = _digest("page-token-b")
        next_tokens = [token_a, token_b, token_a, None]
    else:
        next_tokens = [
            _digest(f"page-token-{index}")
            for index in range(subject.MAX_PAGES)
        ] + [None]
    page_token: str | None = None
    for next_token in next_tokens:
        events.append(
            {
                "ordinal": len(events) + 1,
                "domain": "authority",
                "session_digest": session_digest,
                "operation": "s3:ListAllMyBuckets",
                "request_digest": _digest(
                    f"list-request-{len(events)}"
                ),
                "page_token_digest": page_token,
                "pagination_stream_digest": stream_digest,
                "started_at": "2026-08-28T01:00:01Z",
                "completed_at": "2026-08-28T01:00:01Z",
                "response_digest": _digest(
                    f"list-response-{len(events)}"
                ),
                "outcome": "SUCCESS",
                "complete": next_token is None,
                "truncated": next_token is not None,
                "next_token_digest": next_token,
            }
        )
        page_token = next_token
    summary = {
        "provider_calls": len(events),
        "aws_calls": None,
        "aws_mutations": 0,
        "live_provider_evidence": False,
        "transcript_digest": subject.canonical_digest(events),
    }

    with pytest.raises(
        subject.CollisionProbeError,
        match="^COLLISION_PROVIDER_TRANSCRIPT_INVALID$",
    ):
        subject._validate_provider_evidence(
            request,
            summary,
            events,
            sealed_at="2026-08-28T01:10:00Z",
            complete=False,
        )


def test_blocked_result_nulls_unbounded_aws_network_and_cost() -> None:
    request = _request()
    ledger = subject.CollisionCallLedger()
    budget = subject.CollisionProbeBudget(request)
    budget.record_session_bootstrap("sso:GetRoleCredentials")
    budget.reserve_provider_call("sts:GetCallerIdentity", is_page=False)
    ledger.authorize(
        domain="authority",
        session_digest=_digest("authority-session-1"),
        operation="sts:GetCallerIdentity",
        retries=0,
        request={"attempt": 1},
        started_at="2026-08-28T01:00:01Z",
    )
    calls, transcript_digest = ledger.partial_summary()
    transcript = ledger.partial_evidence_events()
    provider = {
        "provider_calls": calls,
        "aws_calls": None,
        "aws_mutations": 0,
        "live_provider_evidence": False,
        "transcript_digest": transcript_digest,
    }

    result = subject.build_collision_probe_failure_result(
        request=request,
        authority_snapshots=[],
        identity_center_snapshots=[],
        provider_summary=provider,
        transcript_events=transcript,
        budget_summary=budget.summary(),
        budget_events=budget.partial_evidence_events(),
        blocker_code="COLLISION_PROVIDER_READ_FAILED",
        sealed_at="2026-08-28T01:10:00Z",
    )

    assert result.private_evidence["execution_status"] == subject.EXECUTION_BLOCKED
    assert result.public_receipt["status"] == "LIVE_READ_ONLY_PROBE_BLOCKED"
    assert result.public_receipt["classification"] == subject.UNCERTAIN
    assert result.public_receipt["provider_calls"] == 1
    assert result.public_receipt["aws_calls"] is None
    assert result.public_receipt["network_calls"] is None
    assert result.public_receipt["modeled_cost_usd_upper"] is None
    assert result.public_receipt["cost_status"] == "INCOMPLETE_UNBOUNDED"


def test_source_reverification_failure_before_claim_leaves_no_orphan(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    private_root = tmp_path / "private"
    private_root.mkdir(mode=0o700)
    request = _request()
    request["private_custody_digest"] = subject.private_root_digest(
        private_root
    )
    request["operational_host_digest"] = subject.operational_host_digest()
    source_record = _verified_source_record(request)
    request["source_verification_digest"] = source_record[
        "verification_digest"
    ]
    _reseal(request, "request_digest")
    subject.persist_collision_probe_request(
        private_root=private_root,
        request=request,
    )
    verified = subject.VerifiedCollisionProbeSource(
        subject._VERIFIED_SOURCE_SENTINEL,
        source_record,
        tmp_path.resolve(),
    )
    calls = 0

    def reverify(self: subject.VerifiedCollisionProbeSource) -> None:
        nonlocal calls
        assert self is verified
        calls += 1
        if calls == 2:
            raise subject.CollisionProbeError(
                "COLLISION_SOURCE_REVERIFICATION_MISMATCH"
            )

    monkeypatch.setattr(
        subject.VerifiedCollisionProbeSource, "reverify", reverify
    )

    with pytest.raises(
        subject.CollisionProbeError,
        match="^COLLISION_SOURCE_REVERIFICATION_MISMATCH$",
    ):
        subject.read_and_claim_collision_probe_request(
            private_root=private_root,
            verified_source=verified,
            expected_request_digest=request["request_digest"],
            now=datetime(2026, 8, 28, 1, 5, tzinfo=UTC),
        )

    assert calls == 2
    assert not (private_root / subject.DEFAULT_CLAIM_FILE).exists()
    assert not (private_root / subject.DEFAULT_RESULT_FILE).exists()


def test_copied_request_on_another_host_is_rejected_before_claim(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    private_root = tmp_path / "private"
    private_root.mkdir(mode=0o700)
    materialization_host = _digest("materialization-host")
    request, verified = _persist_claimable_request(
        private_root,
        host_digest=materialization_host,
    )
    monkeypatch.setattr(
        subject.VerifiedCollisionProbeSource,
        "reverify",
        lambda self: None,
    )
    monkeypatch.setattr(
        subject,
        "operational_host_digest",
        lambda: _digest("different-execution-host"),
    )

    with pytest.raises(
        subject.CollisionProbeError,
        match="^COLLISION_HOST_BINDING_MISMATCH$",
    ):
        subject.read_and_claim_collision_probe_request(
            private_root=private_root,
            verified_source=verified,
            expected_request_digest=request["request_digest"],
            now=datetime(2026, 8, 28, 1, 5, tzinfo=UTC),
        )

    assert not (private_root / subject.DEFAULT_CLAIM_FILE).exists()
    assert not (private_root / subject.DEFAULT_RESULT_FILE).exists()


def test_live_capability_gate_rechecks_operational_host_before_provider_use(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    private_root = tmp_path / "private"
    private_root.mkdir(mode=0o700)
    materialization_host = _digest("materialization-host")
    monkeypatch.setattr(
        subject,
        "operational_host_digest",
        lambda: materialization_host,
    )
    request, verified = _persist_claimable_request(
        private_root,
        host_digest=materialization_host,
    )
    monkeypatch.setattr(
        subject.VerifiedCollisionProbeSource,
        "reverify",
        lambda self: None,
    )
    now = datetime(2026, 8, 28, 1, 5, tzinfo=UTC)
    capability = subject.read_and_claim_collision_probe_request(
        private_root=private_root,
        verified_source=verified,
        expected_request_digest=request["request_digest"],
        now=now,
        clock=lambda: now,
    )
    authority = request["profiles"]["authority"]
    identity = request["profiles"]["identity_center"]
    binding_arguments = {
        "sdk_runtime_root": request["sdk_runtime_root"],
        "authority_profile": authority["name"],
        "identity_center_profile": identity["name"],
        "authority_expected_account_id": authority["expected_account_id"],
        "authority_expected_principal_digest": authority[
            "expected_principal_digest"
        ],
        "authority_expected_sso_role_name_digest": authority[
            "expected_sso_role_name_digest"
        ],
        "identity_expected_account_id": identity["expected_account_id"],
        "identity_expected_principal_digest": identity[
            "expected_principal_digest"
        ],
        "identity_expected_sso_role_name_digest": identity[
            "expected_sso_role_name_digest"
        ],
        "authority_verification_digest": authority[
            "authority_verification_digest"
        ],
        "identity_authority_verification_digest": identity[
            "authority_verification_digest"
        ],
        "budget_digest": request["budget_digest"],
    }
    gate = subject.assert_collision_probe_provider_capability_bindings(
        capability,
        **binding_arguments,
    )

    subject.claim_collision_probe_execution(capability)
    gate()
    monkeypatch.setattr(
        subject,
        "operational_host_digest",
        lambda: _digest("different-execution-host"),
    )
    with pytest.raises(
        subject.CollisionProbeError,
        match="^COLLISION_HOST_BINDING_MISMATCH$",
    ):
        subject.assert_collision_probe_provider_capability_bindings(
            capability,
            **binding_arguments,
        )
    with pytest.raises(
        subject.CollisionProbeError,
        match="^COLLISION_HOST_BINDING_MISMATCH$",
    ):
        gate()


def test_atomic_result_persistence_round_trips_and_reprojects(
    tmp_path: Path,
) -> None:
    private_root = tmp_path / "private"
    private_root.mkdir(mode=0o700)
    request, claim = _write_result_custody(private_root)
    result = _build_success_result(request=request)

    subject.persist_collision_probe_result(
        private_root=private_root,
        result=result,
        expected_claim_digest=claim["claim_digest"],
    )

    assert {path.name for path in private_root.iterdir()} == {
        subject.DEFAULT_REQUEST_FILE,
        subject.DEFAULT_CLAIM_FILE,
        subject.DEFAULT_RESULT_FILE,
    }
    assert not (private_root / subject.DEFAULT_EVIDENCE_FILE).exists()
    assert not (private_root / subject.DEFAULT_RECEIPT_FILE).exists()
    assert subject.read_collision_probe_result(
        private_root=private_root
    ) == result
    bundle = subject.read_private_json(
        private_root, subject.DEFAULT_RESULT_FILE
    )
    assert bundle["private_root_digest"] == subject.private_root_digest(
        private_root
    )
    assert bundle["request_digest"] == request["request_digest"]
    assert bundle["claim_digest"] == claim["claim_digest"]

    collision = _build_success_result(
        authority_collisions=["artifact_bucket", "kms_key"],
        request=copy.deepcopy(request),
    )
    spliced = subject.CollisionProbeResult(
        private_evidence=result.private_evidence,
        public_receipt=collision.public_receipt,
    )
    other_root = tmp_path / "spliced"
    other_root.mkdir(mode=0o700)
    with pytest.raises(
        subject.CollisionProbeError,
        match="^COLLISION_RESULT_BINDING_MISMATCH$",
    ):
        subject.persist_collision_probe_result(
            private_root=other_root,
            result=spliced,
            expected_claim_digest=claim["claim_digest"],
        )
    assert list(other_root.iterdir()) == []


def test_result_bundle_requires_request_and_claim_in_the_exact_root(
    tmp_path: Path,
) -> None:
    source_root = tmp_path / "source"
    source_root.mkdir(mode=0o700)
    request, claim = _write_result_custody(source_root)
    result = _build_success_result(request=request)
    subject.persist_collision_probe_result(
        private_root=source_root,
        result=result,
        expected_claim_digest=claim["claim_digest"],
    )

    missing_root = tmp_path / "missing"
    missing_root.mkdir(mode=0o700)
    with pytest.raises(
        subject.CollisionProbeError,
        match="^COLLISION_RESULT_CUSTODY_MISMATCH$",
    ):
        subject.persist_collision_probe_result(
            private_root=missing_root,
            result=result,
            expected_claim_digest=claim["claim_digest"],
        )
    assert list(missing_root.iterdir()) == []

    copied_root = tmp_path / "copied"
    copied_root.mkdir(mode=0o700)
    subject.write_private_json(
        copied_root,
        subject.DEFAULT_RESULT_FILE,
        subject.read_private_json(source_root, subject.DEFAULT_RESULT_FILE),
    )
    with pytest.raises(
        subject.CollisionProbeError,
        match="^COLLISION_RESULT_CUSTODY_MISMATCH$",
    ):
        subject.read_collision_probe_result(private_root=copied_root)


def test_result_persistence_requires_the_capability_claim_digest(
    tmp_path: Path,
) -> None:
    private_root = tmp_path / "private"
    private_root.mkdir(mode=0o700)
    request, _ = _write_result_custody(private_root)
    result = _build_success_result(request=request)

    with pytest.raises(
        subject.CollisionProbeError,
        match="^COLLISION_RESULT_CUSTODY_MISMATCH$",
    ):
        subject.persist_collision_probe_result(
            private_root=private_root,
            result=result,
            expected_claim_digest=_digest("different-capability-claim"),
        )

    assert not (private_root / subject.DEFAULT_RESULT_FILE).exists()


def test_public_receipt_contains_only_digest_bindings_and_no_local_paths() -> None:
    request = _request()
    request["sdk_runtime_root"] = "/Users/private/runtime"
    request["sdk_runtime_root_digest"] = subject.canonical_digest(
        request["sdk_runtime_root"]
    )
    _reseal(request, "request_digest")
    authority, identity = _pairs()
    provider, transcript, budget, budget_events = (
        _successful_provider_and_budget_evidence(
            request,
            authority_snapshots=authority,
            identity_center_snapshots=identity,
        )
    )
    result = subject.build_collision_probe_result(
        request=request,
        authority_snapshots=authority,
        identity_center_snapshots=identity,
        provider_summary=provider,
        transcript_events=transcript,
        budget_summary=budget,
        budget_events=budget_events,
        sealed_at="2026-08-28T01:10:00Z",
    )

    encoded = subject.canonical_json(result.public_receipt)
    assert "AWSReadOnlyAccess" not in encoded
    assert "042360977644" not in encoded
    assert "839393571433" not in encoded
    assert "arn:aws:" not in encoded
    assert "/Users/" not in encoded
    subject.validate_public_collision_probe_receipt(result.public_receipt)
