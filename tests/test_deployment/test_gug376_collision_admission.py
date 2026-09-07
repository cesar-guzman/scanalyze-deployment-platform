from __future__ import annotations

import copy
from datetime import UTC, datetime, timedelta
import json
from pathlib import Path

import pytest

from tooling import platform_authority_gug376_collision_admission as subject
from tooling import (
    platform_authority_gug376_collision_atomic_admission as atomic_subject,
)
from tooling import (
    platform_authority_gug376_collision_admission_executor as transcript_executor,
)
from tooling import (
    platform_authority_gug376_collision_transcript_contract as transcript_contract,
)
from tooling import platform_authority_gug376_collision_catalog as catalog_contract
from tooling import platform_authority_gug376_collision_budget as budget_contract
from tooling import platform_authority_gug376_collision_policy as policy_contract
from tooling import platform_authority_plan_permission_repair_route_broker as broker


NOW = datetime(2026, 9, 1, 1, 0, tzinfo=UTC)
COMMIT = "a" * 40
TREE = "b" * 40
BOOTSTRAP_DIGEST = "sha256:" + "c" * 64
EFFECT_ROOT_DIGEST = "sha256:" + "e" * 64
ATOMIC_CONTEXT_DIGEST = "sha256:" + "d" * 64
IDENTITY_CENTER_INSTANCE_ARN = (
    "arn:aws:sso:::instance/ssoins-1234567890abcdef"
)
OPERATION = "foundation-create:dispatch"
EFFECT_REQUEST = {
    "record_type": "scanalyze.platform_authority.gug376_test_effect.v1",
    "change_set_type": "CREATE",
    "client_token": "gug376-test-effect",
}
EFFECT_DIGEST = subject.canonical_digest(EFFECT_REQUEST)


def test_session_mode_changes_only_after_both_readers_and_survives_route_revoke() -> None:
    assert subject.collision_session_mode_for_operation(
        "route:execute-change-set"
    ) == subject.LOCAL_DIRECT_SSO
    assert subject.collision_session_mode_for_operation(
        "broker:execute-change-set"
    ) == subject.LOCAL_DIRECT_SSO
    assert subject.collision_session_mode_for_operation(
        "broker-protection:create-change-set"
    ) == subject.LOCAL_DIRECT_SSO
    assert subject.collision_session_mode_for_operation(
        "route-revoke-execute-v1",
        execution_locus=subject.INLINE_BROKER_LAMBDA,
    ) == subject.POST_READER_RUNTIME
    for reducing_cleanup in (
        "bridge-cleanup-retire:dispatch",
        "bridge-cleanup-retire:execute",
    ):
        with pytest.raises(
            subject.RouteCollisionAdmissionError,
            match="PHASE_OPERATION_INVALID",
        ):
            subject.collision_session_mode_for_operation(reducing_cleanup)
    for operation in subject.INLINE_BROKER_LAMBDA_OPERATIONS:
        assert subject.collision_session_mode_for_operation(
            operation,
            execution_locus=subject.INLINE_BROKER_LAMBDA,
        ) == subject.POST_READER_RUNTIME
        with pytest.raises(
            subject.RouteCollisionAdmissionError,
            match="SESSION_MODE_UNREACHABLE",
        ):
            subject.collision_session_mode_for_operation(operation)

    route_revoke = json.loads(
        broker._RUNTIME_CONFIG_DICTIONARY_V3.splitlines()[0]  # noqa: SLF001
    )["creator_contracts"]["route-revoke-create-v1"]["expected_changes"]
    assert route_revoke == [
        {
            "action": "Remove",
            "details": [],
            "logical_resource_id": "BrokerInvokerAssignment",
            "replacement": None,
            "resource_type": "AWS::SSO::Assignment",
            "scope": [],
        }
    ]
    assert {
        "management.iam.collision-reader",
        "authority.iam.scanalyzegug376collisionreader",
    }.issubset(
        subject.OPERATION_PRESENT_OWNED_TARGET_IDS[
            "route-revoke-execute-v1"
        ]
    )


def _broker_identities(policy_digest: str) -> dict[str, dict[str, object]]:
    result: dict[str, dict[str, object]] = {}
    for domain, account in (
        ("authority", subject.AUTHORITY_ACCOUNT_ID),
        ("management", subject.MANAGEMENT_ACCOUNT_ID),
    ):
        result[domain] = {
            "account_id": account,
            "source": "BROKER_SERVICE_ROLE",
            "chain_depth": 1,
            "principal_digest": subject.canonical_digest(
                {"principal": domain}
            ),
            "sso_role_name_digest": subject.canonical_digest(
                {"role": domain}
            ),
            "role_arn_digest": subject.canonical_digest(
                {"role_arn": domain}
            ),
            "role_policy_digest": subject.canonical_digest(
                {"role_policy": domain}
            ),
            "session_policy_digest": subject.canonical_digest(
                {"session_policy": domain}
            ),
            "authority_verification_digest": subject.canonical_digest(
                {"verification": domain}
            ),
            "policy_digest": policy_digest,
        }
    return result


def _stamp(value: datetime) -> str:
    return value.isoformat().replace("+00:00", "Z")


def _reseal(value: dict[str, object], field: str) -> None:
    unsigned = dict(value)
    unsigned.pop(field, None)
    value[field] = subject.canonical_digest(unsigned)


def _root(tmp_path: Path) -> Path:
    root = tmp_path / "private"
    root.mkdir(mode=0o700, parents=True)
    root.chmod(0o700)
    return root


def _gug395_root(admission_root: Path) -> Path:
    root = admission_root.parent / "gug395-lineage"
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    root.chmod(0o700)
    return root


def _catalog() -> dict[str, object]:
    return catalog_contract.materialize_route_collision_catalog(
        source_commit_sha=COMMIT,
        source_tree_sha=TREE,
        bootstrap_intent_digest=BOOTSTRAP_DIGEST,
        not_before=_stamp(NOW - timedelta(minutes=1)),
        expires_at=_stamp(NOW + timedelta(minutes=10)),
        artifact_bucket_name=(
            "scanalyze-g376-art-aaaaaaaaaaaa-"
            "042360977644-us-east-1-an"
        ),
    )


def _candidate_policy_set(
    catalog: dict[str, object],
) -> dict[str, object]:
    domains: dict[str, dict[str, object]] = {}
    for domain in policy_contract.DOMAINS:
        domains[domain] = {}
        for kind in sorted(policy_contract._DYNAMIC_RESOURCE_KINDS[domain]):
            items: list[dict[str, object]] = []
            if kind == "sso_instance":
                items = [
                    {
                        "InstanceArn": IDENTITY_CENTER_INSTANCE_ARN,
                        "OwnerAccountId": subject.MANAGEMENT_ACCOUNT_ID,
                    }
                ]
            elif kind == "identity_center_kms_key":
                items = [
                    {
                        "BindingName": "identity_center_kms_key_arn",
                        "Mode": "AWS_OWNED_KMS_KEY",
                        "PrivateBindingDigest": "sha256:" + "e" * 64,
                    }
                ]
            domains[domain][kind] = {
                "operation": policy_contract._DISCOVERY_OPERATIONS[kind],
                "selector": policy_contract._expected_discovery_selector(
                    catalog,
                    domain=domain,
                    kind=kind,
                ),
                "pages": [
                    {
                        "page_index": 1,
                        "input_cursor_digest": None,
                        "output_cursor_digest": None,
                        "items": items,
                    }
                ],
            }
    discovery_evidence = {
        "schema_version": 1,
        "record_type": policy_contract.DISCOVERY_EVIDENCE_RECORD_TYPE,
        "catalog_digest": catalog["catalog_digest"],
        "domains": domains,
    }
    value = policy_contract._build_policy_set(
        catalog,
        discovery_evidence=discovery_evidence,
        discovery_provenance_digest="sha256:" + "d" * 64,
        identity_center_instance_arn=IDENTITY_CENTER_INSTANCE_ARN,
    )
    policy_contract.validate_route_collision_policy_set(
        value,
        catalog=catalog,
    )
    return value


def _gug395_result(
    root: Path,
    *,
    expires_at: datetime | None = None,
) -> tuple[dict[str, object], dict[str, object], dict[str, object]]:
    custody = subject._private_root_digest(root)
    request = {
        "source_verification_digest": "sha256:" + "e" * 64,
        "private_custody_digest": custody,
        "expires_at": _stamp(expires_at or (NOW + timedelta(minutes=10))),
        "targets": {
            "artifact_bucket": {
                "selector_kind": "ACCOUNT_REGIONAL_BUCKET_NAME_AND_TAG",
                "bucket_namespace": "account-regional",
                "name": (
                    "scanalyze-g376-art-aaaaaaaaaaaa-"
                    "042360977644-us-east-1-an"
                ),
            }
        },
        "profiles": {
            "authority": {
                "expected_account_id": subject.AUTHORITY_ACCOUNT_ID,
                "expected_principal_digest": subject.canonical_digest(
                    {"principal": "authority"}
                ),
                "expected_sso_role_name_digest": subject.canonical_digest(
                    {"role": "authority"}
                ),
                "authority_verification_digest": subject.canonical_digest(
                    {"verification": "authority"}
                ),
            },
            "identity_center": {
                "expected_account_id": subject.MANAGEMENT_ACCOUNT_ID,
                "expected_principal_digest": subject.canonical_digest(
                    {"principal": "management"}
                ),
                "expected_sso_role_name_digest": subject.canonical_digest(
                    {"role": "management"}
                ),
                "authority_verification_digest": subject.canonical_digest(
                    {"verification": "management"}
                ),
            },
        },
        "policy_digests": {
            "authority": subject.canonical_digest({"policy": "authority"}),
            "identity_center": subject.canonical_digest(
                {"policy": "management"}
            ),
        },
    }
    evidence = {
        "request": request,
        "request_digest": "sha256:" + "f" * 64,
        "provider_evidence_digest": "sha256:" + "1" * 64,
    }
    receipt = {
        "classification": subject.ABSENT_READY,
        "provider_implementation_gate": "READY_FOR_PROVIDER_IMPLEMENTATION",
        "status": "LIVE_READ_ONLY_PROBE_RECORDED",
        "evidence_complete": True,
        "evidence_stable": True,
        "live_provider_evidence": True,
        "aws_mutations": 0,
        "source_commit_sha": COMMIT,
        "source_tree_sha": TREE,
        "sealed_at": _stamp(NOW - timedelta(seconds=30)),
        "receipt_digest": "sha256:" + "2" * 64,
    }
    bundle = {
        "bundle_digest": "sha256:" + "3" * 64,
        "private_evidence": evidence,
        "public_receipt": receipt,
    }
    return bundle, evidence, receipt


def _request(
    monkeypatch: pytest.MonkeyPatch,
    root: Path,
    *,
    phase: str | None = None,
    expires_at: datetime | None = None,
    expected_gug395_request_digest: str = "sha256:" + "f" * 64,
    expected_identities: dict[str, object] | None = None,
    candidate_stage: bool = False,
) -> dict[str, object]:
    lineage_root = _gug395_root(root)
    monkeypatch.setattr(
        subject,
        "_gug395_bundle",
        lambda _root: _gug395_result(lineage_root, expires_at=expires_at),
    )
    catalog = _catalog()
    policy_set = (
        _candidate_policy_set(catalog)
        if candidate_stage
        else policy_contract.materialize_route_collision_policy_set(catalog)
    )
    return subject.materialize_route_collision_admission_request(
        private_root=root,
        gug395_private_root=lineage_root,
        catalog=catalog,
        collision_policy_set=policy_set,
        phase=phase or "artifact-foundation",
        operation=OPERATION,
        effect_request=EFFECT_REQUEST,
        source_commit_sha=COMMIT,
        source_tree_sha=TREE,
        bootstrap_intent_digest=BOOTSTRAP_DIGEST,
        effect_private_root_digest=EFFECT_ROOT_DIGEST,
        atomic_context_digest=ATOMIC_CONTEXT_DIGEST,
        expected_gug395_request_digest=expected_gug395_request_digest,
        expected_gug395_receipt_digest="sha256:" + "2" * 64,
        expected_gug395_bundle_digest="sha256:" + "3" * 64,
        expected_identities=expected_identities,
        not_before=_stamp(NOW - timedelta(minutes=1)),
        expires_at=_stamp(NOW + timedelta(minutes=10)),
        created_at=_stamp(NOW),
    )


def _legacy_v1_request(
    monkeypatch: pytest.MonkeyPatch,
    root: Path,
    *,
    candidate_stage: bool = False,
) -> dict[str, object]:
    request = copy.deepcopy(
        _request(
            monkeypatch,
            root,
            candidate_stage=candidate_stage,
        )
    )
    request.pop("expected_identity_center_kms_binding_digest")
    request["record_type"] = subject.REQUEST_TYPE_V1
    request["schema_version"] = 1
    request["collision_budget_digest"] = (
        budget_contract.collision_budget_digest_v1(
            session_mode=str(request["session_mode"]),
            operation=str(request["operation"]),
        )
    )
    request.pop("request_digest")
    request["request_digest"] = subject.canonical_digest(request)
    return request


def test_request_version_readers_preserve_v1_and_select_v2(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    current_root = _root(tmp_path / "current")
    legacy_root = _root(tmp_path / "legacy")
    current = _request(monkeypatch, current_root, candidate_stage=True)
    legacy = _legacy_v1_request(
        monkeypatch, legacy_root, candidate_stage=True
    )

    subject.validate_route_collision_admission_request_v1(legacy)
    subject.validate_route_collision_admission_request_v2(current)
    subject.validate_route_collision_admission_request(legacy)
    subject.validate_route_collision_admission_request(current)
    assert legacy["record_type"] == subject.REQUEST_TYPE_V1
    assert legacy["schema_version"] == 1
    assert "expected_identity_center_kms_binding_digest" not in legacy
    assert legacy["request_digest"] == subject.canonical_digest(
        {
            key: value
            for key, value in legacy.items()
            if key != "request_digest"
        }
    )
    with pytest.raises(
        subject.RouteCollisionAdmissionError,
        match="ROUTE_COLLISION_REQUEST_VERSION_UNSUPPORTED",
    ):
        subject.validate_route_collision_admission_request_v1(current)


def test_atomic_root_rejects_relative_and_symlink_paths(tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.mkdir(mode=0o700)
    target.chmod(0o700)
    link = tmp_path / "link"
    link.symlink_to(target, target_is_directory=True)

    with pytest.raises(
        atomic_subject.AtomicCollisionAdmissionError,
        match="ATOMIC_COLLISION_TEST_ROOT_INVALID",
    ):
        atomic_subject._root(  # noqa: SLF001
            Path("relative-root"),
            code="ATOMIC_COLLISION_TEST_ROOT_INVALID",
        )
    with pytest.raises(
        atomic_subject.AtomicCollisionAdmissionError,
        match="ATOMIC_COLLISION_TEST_ROOT_INVALID",
    ):
        atomic_subject._root(  # noqa: SLF001
            link,
            code="ATOMIC_COLLISION_TEST_ROOT_INVALID",
        )


def test_materialization_rejects_lineage_digest_changed_after_context(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    with pytest.raises(
        subject.RouteCollisionAdmissionError,
        match="ROUTE_COLLISION_GUG395_LINEAGE_CHANGED",
    ):
        _request(
            monkeypatch,
            _root(tmp_path),
            expected_gug395_request_digest="sha256:" + "9" * 64,
        )


def test_materialization_rejects_identity_projection_from_swapped_lineage(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    root = _root(tmp_path)
    lineage_root = _gug395_root(root)
    _bundle, evidence, _receipt = _gug395_result(lineage_root)
    catalog = _catalog()
    policy_set = policy_contract.materialize_route_collision_policy_set(
        catalog
    )
    identities = subject.expected_route_collision_identity_bindings(
        evidence["request"],
        collision_policy_set_digest=policy_set["policy_set_digest"],
    )
    identities["authority"]["principal_digest"] = "sha256:" + "9" * 64

    with pytest.raises(
        subject.RouteCollisionAdmissionError,
        match="ROUTE_COLLISION_GUG395_LINEAGE_CHANGED",
    ):
        _request(
            monkeypatch,
            root,
            expected_identities=identities,
        )


def _identity(
    request: dict[str, object],
    domain: str,
    capture_index: int,
    observed_at: str,
) -> dict[str, object]:
    identities = request["expected_identities"]
    assert isinstance(identities, dict)
    expected = identities[domain]
    assert isinstance(expected, dict)
    value = {
        "domain": domain,
        "account_id": expected["account_id"],
        "region": subject.REGION,
        "source": expected["source"],
        "chain_depth": expected["chain_depth"],
        "session_digest": subject.canonical_digest(
            {"domain": domain, "capture_index": capture_index}
        ),
        "principal_digest": expected["principal_digest"],
        "sso_role_name_digest": expected["sso_role_name_digest"],
        "observed_at": observed_at,
        "policy_digest": expected["policy_digest"],
        "authority_verification_digest": expected[
            "authority_verification_digest"
        ],
    }
    if expected["source"] == "BROKER_SERVICE_ROLE":
        value.update(
            {
                "role_arn_digest": expected["role_arn_digest"],
                "role_policy_digest": expected["role_policy_digest"],
                "session_policy_digest": expected[
                    "session_policy_digest"
                ],
            }
        )
    return value


def _inventory_operation(target: dict[str, object]) -> str:
    selector = target["selector"]
    assert isinstance(selector, dict)
    if (
        target["scope"] == "code_signing_config"
        and selector["kind"]
        in {
            "cloudformation_stack_resource",
            "cloudformation_ownership_tags",
        }
    ):
        return "cloudformation:DescribeStackResource"
    return {
        ("cloudformation", "stack"): "cloudformation:DescribeStacks",
        ("dynamodb", "table"): "dynamodb:DescribeTable",
        ("iam", "role"): "iam:GetRole",
        ("kms", "alias"): "kms:ListAliases",
        ("lambda", "alias"): "lambda:GetAlias",
        ("lambda", "code_signing_config"): "lambda:GetCodeSigningConfig",
        ("lambda", "function"): "lambda:GetFunction",
        ("logs", "log_group"): "logs:DescribeLogGroups",
        ("s3", "bucket"): "s3:ListAllMyBuckets",
        ("signer", "signing_profile"): "signer:GetSigningProfile",
        ("sso", "application"): "sso:DescribeApplication",
        ("sso", "permission_set"): "sso:DescribePermissionSet",
    }[(target["service"], target["scope"])]


def _ownership_operation(target: dict[str, object]) -> str:
    selector = target["selector"]
    assert isinstance(selector, dict)
    if selector["kind"] == "cloudformation_stack_resource":
        return "cloudformation:DescribeStackResource"
    return {
        "cloudformation": "cloudformation:DescribeStacks",
        "dynamodb": "dynamodb:ListTagsOfResource",
        "iam": "iam:ListRoleTags",
        "kms": "kms:ListResourceTags",
        "lambda": "lambda:ListTags",
        "logs": "logs:ListTagsForResource",
        "s3": "s3:GetBucketTagging",
        "signer": "signer:ListTagsForResource",
        "sso": "sso:ListTagsForResource",
    }[str(target["service"])]


_LIST_DISCOVERY_OPERATIONS = {
    "cloudformation:ListStacks",
    "kms:ListAliases",
    "lambda:ListAliases",
    "lambda:ListCodeSigningConfigs",
    "lambda:ListFunctions",
    "logs:DescribeLogGroups",
    "s3:ListAllMyBuckets",
    "signer:ListSigningProfiles",
    "sso:ListApplications",
    "sso:ListPermissionSets",
}


def _synthetic_described_instance_digest(
    request: dict[str, object],
) -> str:
    return subject.canonical_digest(
        {
            "record_type": "test.synthetic_identity_center_instance.v1",
            "request_digest": request["request_digest"],
        }
    )


def _transcript_events(
    request: dict[str, object],
    capture_index: int,
    observations: dict[str, object],
) -> list[dict[str, object]]:
    catalog = request["catalog"]
    dispositions = request["expected_dispositions"]
    assert isinstance(catalog, dict) and isinstance(dispositions, dict)
    targets = catalog["targets"]
    assert isinstance(targets, list)
    records: list[dict[str, object]] = []
    for domain in ("authority", "management"):
        identity = _identity(
            request,
            domain,
            capture_index,
            _stamp(NOW + timedelta(seconds=capture_index)),
        )
        operations: list[tuple[str, str, list[str]]] = [
            ("sts:GetCallerIdentity", "SUCCESS", [])
        ]
        kms_binding = request.get(
            "expected_identity_center_kms_binding_digest"
        )
        if domain == "management" and kms_binding is not None:
            operations.append(
                (
                    "sso:DescribeInstance",
                    "SUCCESS",
                    sorted(
                        str(target["target_id"])
                        for target in targets
                        if target["domain"] == "management"
                        and target["service"] == "sso"
                    ),
                )
            )
        for raw_target in targets:
            assert isinstance(raw_target, dict)
            if raw_target["domain"] != domain:
                continue
            target_id = str(raw_target["target_id"])
            discovery = _inventory_operation(raw_target)
            disposition = str(dispositions[target_id])
            operations.append(
                (
                    discovery,
                    (
                        "SUCCESS"
                        if disposition == "PRESENT_OWNED"
                        or discovery in _LIST_DISCOVERY_OPERATIONS
                        else "NOT_FOUND"
                    ),
                    [target_id],
                )
            )
            if dispositions[target_id] == "PRESENT_OWNED":
                ownership = _ownership_operation(raw_target)
                if ownership != discovery:
                    operations.append((ownership, "SUCCESS", [target_id]))
        for operation, outcome, target_ids in operations:
            if operation == "sso:DescribeInstance":
                page_item_digests = sorted(
                    [
                        str(kms_binding),
                        _synthetic_described_instance_digest(request),
                    ]
                )
            elif target_ids and outcome == "SUCCESS":
                page_item_digests = [
                    subject.canonical_digest(
                        {
                            "operation": operation,
                            "target_ids": target_ids,
                        }
                    )
                ]
            else:
                page_item_digests = []
            projection = {
                "page_item_digests": page_item_digests,
                "output_cursor_digest": None,
                "page_complete": True,
                "target_evidence_digests": {
                    target_id: subject.canonical_digest(observations[target_id])
                    for target_id in target_ids
                },
            }
            event: dict[str, object] = {
                    "ordinal": 0,
                    "capture_index": capture_index,
                    "domain": domain,
                    "account_id": identity["account_id"],
                    "region": subject.REGION,
                    "session_digest": identity["session_digest"],
                    "provider_implementation_digest": (
                        transcript_contract.COLLISION_PROVIDER_IMPLEMENTATION_DIGEST
                    ),
                    "operation": operation,
                    "outcome": outcome,
                    "request_digest": request["request_digest"],
                    "operation_request_digest": "",
                    "page_index": 1,
                    "input_cursor_digest": None,
                    "response_projection": projection,
                    "response_digest": subject.canonical_digest(projection),
                    "target_ids": target_ids,
                    "read_only": True,
                    "aws_mutations": 0,
            }
            event["operation_request_digest"] = subject.canonical_digest(
                transcript_contract.operation_request_descriptor(
                    request=request,
                    event=event,
                )
            )
            records.append(event)
    first_ordinal = (capture_index - 1) * len(records) + 1
    for ordinal, record in enumerate(records, first_ordinal):
        record["ordinal"] = ordinal
    return records


def _snapshot(
    request: dict[str, object],
    capture_index: int,
    *,
    facts_nonce: str = "stable",
) -> dict[str, object]:
    observed_at = _stamp(NOW + timedelta(seconds=capture_index))
    expected = request["expected_dispositions"]
    assert isinstance(expected, dict)
    observations = {
        target_id: {
            "disposition": disposition,
            "facts_digest": subject.canonical_digest(
                {"target_id": target_id, "facts_nonce": facts_nonce}
            ),
            "ownership_binding_digest": (
                subject.canonical_digest({"owner": target_id})
                if disposition == "PRESENT_OWNED"
                else None
            ),
        }
        for target_id, disposition in expected.items()
    }
    semantic = {
        "catalog_digest": request["catalog_digest"],
        "operation": request["operation"],
        "effect_request_digest": request["effect_request_digest"],
        "target_observations": observations,
    }
    value: dict[str, object] = {
        "record_type": subject.SNAPSHOT_TYPE,
        "schema_version": 1,
        "capture_index": capture_index,
        "request_digest": request["request_digest"],
        "catalog_digest": request["catalog_digest"],
        "operation": request["operation"],
        "effect_request_digest": request["effect_request_digest"],
        "identities": {
            "authority": _identity(
                request, "authority", capture_index, observed_at
            ),
            "management": _identity(
                request, "management", capture_index, observed_at
            ),
        },
        "target_observations": observations,
        "semantic_facts_digest": subject.canonical_digest(semantic),
        "transcript_digest": subject.canonical_digest(
            _transcript_events(request, capture_index, observations)
        ),
        "complete": True,
        "observed_at": observed_at,
    }
    value["snapshot_digest"] = subject.canonical_digest(value)
    return value


def _transcript_bundle(
    request: dict[str, object],
) -> tuple[list[dict[str, object]], list[dict[str, object]], dict[str, object]]:
    snapshots = [_snapshot(request, index) for index in (1, 2, 3)]
    events = [
        event
        for snapshot in snapshots
        for event in _transcript_events(
            request,
            int(snapshot["capture_index"]),
            snapshot["target_observations"],
        )
    ]
    summary: dict[str, object] = {
        "record_type": subject.TRANSCRIPT_SUMMARY_TYPE,
        "schema_version": 1,
        "request_digest": request["request_digest"],
        "snapshot_count": 3,
        "provider_calls": len(events),
        "aws_calls": len(events),
        "aws_mutations": 0,
        "read_only": True,
        "transcript_digest": subject.canonical_digest(events),
    }
    return snapshots, events, summary


def _rebind_transcript_bundle(
    *,
    request: dict[str, object],
    snapshots: list[dict[str, object]],
    events: list[dict[str, object]],
    summary: dict[str, object],
) -> None:
    for ordinal, event in enumerate(events, 1):
        event["ordinal"] = ordinal
        event["operation_request_digest"] = subject.canonical_digest(
            transcript_contract.operation_request_descriptor(
                request=request,
                event=event,
            )
        )
        event["response_digest"] = subject.canonical_digest(
            event["response_projection"]
        )
    for capture_index, snapshot in enumerate(snapshots, 1):
        snapshot["transcript_digest"] = subject.canonical_digest(
            [
                event
                for event in events
                if event["capture_index"] == capture_index
            ]
        )
    summary["provider_calls"] = len(events)
    summary["aws_calls"] = len(events)
    summary["transcript_digest"] = subject.canonical_digest(events)


def _claimed(
    monkeypatch: pytest.MonkeyPatch,
    root: Path,
) -> tuple[dict[str, object], subject.RouteCollisionAdmissionExecutionCapability]:
    request = _request(monkeypatch, root)
    subject.persist_route_collision_admission_request(
        private_root=root,
        request=request,
    )
    capability = subject.read_and_claim_route_collision_admission_request(
        private_root=root,
        expected_request_digest=str(request["request_digest"]),
        now=NOW,
    )
    return request, capability


def _transcript_sidecar(
    result: subject.RouteCollisionAdmissionResult,
) -> dict[str, object]:
    evidence = result.private_evidence
    receipt = result.public_receipt
    request = evidence["request"]
    events = [
        event
        for snapshot in evidence["snapshots"]
        for event in _transcript_events(
            request,
            int(snapshot["capture_index"]),
            snapshot["target_observations"],
        )
    ]
    events_digest = subject.canonical_digest(events)
    sidecar: dict[str, object] = {
        "record_type": subject.TRANSCRIPT_SIDECAR_TYPE,
        "schema_version": 1,
        "request_digest": evidence["request_digest"],
        "claim_digest": evidence["claim_digest"],
        "admission_digest": receipt["admission_digest"],
        "private_evidence_digest": evidence["private_evidence_digest"],
        "snapshot_transcript_digests": [
            snapshot["transcript_digest"]
            for snapshot in evidence["snapshots"]
        ],
        "events": events,
        "events_digest": events_digest,
        "summary": {
            "record_type": subject.TRANSCRIPT_SUMMARY_TYPE,
            "schema_version": 1,
            "request_digest": evidence["request_digest"],
            "snapshot_count": 3,
            "provider_calls": len(events),
            "aws_calls": len(events),
            "aws_mutations": 0,
            "read_only": True,
            "transcript_digest": events_digest,
        },
        "recorded_at": receipt["sealed_at"],
        "read_only": True,
        "aws_mutations": 0,
    }
    _reseal(sidecar, "sidecar_digest")
    return sidecar


def _persist_transcript_sidecar(
    root: Path,
    result: subject.RouteCollisionAdmissionResult,
) -> None:
    sidecar = _transcript_sidecar(result)
    subject.write_private_json(root, subject.DEFAULT_TRANSCRIPT_FILE, sidecar)


def test_materializes_strict_private_request_bound_to_gug395_and_catalog(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    root = _root(tmp_path)
    request = _request(monkeypatch, root)

    subject.validate_route_collision_admission_request(request)

    assert request["catalog_digest"] == request["catalog"]["catalog_digest"]
    assert request["bootstrap_intent_digest"] == BOOTSTRAP_DIGEST
    assert request["effect_request_digest"] == EFFECT_DIGEST
    assert request["gug395_result_bundle_digest"] == "sha256:" + "3" * 64
    policy = policy_contract.materialize_route_collision_policy_set(
        request["catalog"]
    )
    assert request["collision_policy_set_digest"] == policy[
        "policy_set_digest"
    ]
    assert request["collision_policy_digests"] == policy["policy_digests"]
    assert request["collision_policy_stage"] == policy["stage"]
    assert {
        value["policy_digest"]
        for value in request["expected_identities"].values()
    } == {policy["policy_set_digest"]}
    assert set(request["expected_dispositions"].values()) == {
        "ABSENT_AT_SNAPSHOT",
        "PRESENT_OWNED",
    }


def test_candidate_stage_request_materializes_and_validates(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    root = _root(tmp_path)
    lineage_root = _gug395_root(root)
    monkeypatch.setattr(
        subject,
        "_gug395_bundle",
        lambda _root: _gug395_result(lineage_root),
    )
    catalog = _catalog()
    candidate_policy = _candidate_policy_set(catalog)

    request = subject.materialize_route_collision_admission_request(
        private_root=root,
        gug395_private_root=lineage_root,
        catalog=catalog,
        collision_policy_set=candidate_policy,
        phase="artifact-foundation",
        operation=OPERATION,
        effect_request=EFFECT_REQUEST,
        source_commit_sha=COMMIT,
        source_tree_sha=TREE,
        bootstrap_intent_digest=BOOTSTRAP_DIGEST,
        effect_private_root_digest=EFFECT_ROOT_DIGEST,
        atomic_context_digest=ATOMIC_CONTEXT_DIGEST,
        expected_gug395_request_digest="sha256:" + "f" * 64,
        expected_gug395_receipt_digest="sha256:" + "2" * 64,
        expected_gug395_bundle_digest="sha256:" + "3" * 64,
        not_before=_stamp(NOW - timedelta(minutes=1)),
        expires_at=_stamp(NOW + timedelta(minutes=10)),
        created_at=_stamp(NOW),
    )

    assert request["collision_policy_stage"] == (
        "inventory-and-candidate-detail"
    )
    assert request["collision_discovery_provenance_digest"] == (
        candidate_policy["discovery_provenance_digest"]
    )
    subject.validate_route_collision_admission_request(request)


def test_candidate_transcript_binds_one_fresh_instance_read_per_snapshot(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    request = _request(
        monkeypatch,
        _root(tmp_path),
        candidate_stage=True,
    )
    snapshots, events, summary = _transcript_bundle(request)

    transcript_contract.validate_route_collision_transcript_bundle(
        events=events,
        summary=summary,
        request=request,
        snapshots=snapshots,
    )

    expected_binding = request["expected_identity_center_kms_binding_digest"]
    expected_instance = _synthetic_described_instance_digest(request)
    expected_targets = sorted(
        str(target["target_id"])
        for target in request["catalog"]["targets"]
        if target["domain"] == "management" and target["service"] == "sso"
    )
    described = [
        event
        for event in events
        if event["operation"] == "sso:DescribeInstance"
    ]
    assert [event["capture_index"] for event in described] == [1, 2, 3]
    for capture_index, event in enumerate(described, 1):
        assert event["target_ids"] == expected_targets
        assert event["response_projection"]["page_item_digests"] == sorted(
            [expected_binding, expected_instance]
        )
        segment = [
            candidate
            for candidate in events
            if candidate["capture_index"] == capture_index
        ]
        sts_index = next(
            index
            for index, candidate in enumerate(segment)
            if candidate["domain"] == "management"
            and candidate["operation"] == "sts:GetCallerIdentity"
        )
        describe_index = segment.index(event)
        first_other_sso = next(
            index
            for index, candidate in enumerate(segment)
            if candidate["domain"] == "management"
            and str(candidate["operation"]).startswith("sso:")
            and candidate["operation"] != "sso:DescribeInstance"
        )
        assert sts_index < describe_index < first_other_sso


@pytest.mark.parametrize(
    "tamper",
    [
        "missing",
        "duplicate",
        "wrong_order",
        "wrong_targets",
        "wrong_digest",
        "described_instance_drift",
    ],
)
def test_candidate_transcript_rejects_invalid_instance_attestation(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    tamper: str,
) -> None:
    request = _request(
        monkeypatch,
        _root(tmp_path),
        candidate_stage=True,
    )
    snapshots, events, summary = _transcript_bundle(request)
    describe_index = next(
        index
        for index, event in enumerate(events)
        if event["capture_index"] == 3
        and event["operation"] == "sso:DescribeInstance"
    )

    if tamper == "missing":
        events.pop(describe_index)
    elif tamper == "duplicate":
        events.insert(describe_index + 1, copy.deepcopy(events[describe_index]))
    elif tamper == "wrong_order":
        described = events.pop(describe_index)
        first_other_sso = next(
            index
            for index, event in enumerate(events)
            if event["capture_index"] == 3
            and event["domain"] == "management"
            and str(event["operation"]).startswith("sso:")
        )
        events.insert(first_other_sso + 1, described)
    elif tamper == "wrong_targets":
        event = events[describe_index]
        event["target_ids"] = event["target_ids"][:-1]
        projection = event["response_projection"]
        projection["target_evidence_digests"].pop(
            next(reversed(projection["target_evidence_digests"]))
        )
    elif tamper == "wrong_digest":
        events[describe_index]["response_projection"][
            "page_item_digests"
        ] = ["sha256:" + "9" * 64]
    else:
        events[describe_index]["response_projection"][
            "page_item_digests"
        ] = sorted(
            [
                str(
                    request[
                        "expected_identity_center_kms_binding_digest"
                    ]
                ),
                "sha256:" + "8" * 64,
            ]
        )

    _rebind_transcript_bundle(
        request=request,
        snapshots=snapshots,
        events=events,
        summary=summary,
    )
    with pytest.raises(
        transcript_contract.CollisionTranscriptContractError
    ) as rejected:
        transcript_contract.validate_route_collision_transcript_bundle(
            events=events,
            summary=summary,
            request=request,
            snapshots=snapshots,
        )
    assert rejected.value.code == "ROUTE_COLLISION_KMS_BINDING_INVALID"


def test_request_rejects_resealed_collision_policy_binding_drift(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    request = _request(monkeypatch, _root(tmp_path))
    request["collision_policy_set_digest"] = "sha256:" + "9" * 64
    _reseal(request, "request_digest")

    with pytest.raises(
        subject.RouteCollisionAdmissionError,
        match="ROUTE_COLLISION_POLICY_BINDING_INVALID",
    ):
        subject.validate_route_collision_admission_request(request)


def test_request_rejects_unknown_field_and_catalog_digest_drift(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    request = _request(monkeypatch, _root(tmp_path))
    request["unexpected"] = True
    request["request_digest"] = subject.canonical_digest(
        {key: value for key, value in request.items() if key != "request_digest"}
    )

    with pytest.raises(subject.RouteCollisionAdmissionError):
        subject.validate_route_collision_admission_request(request)


def test_claim_is_create_only_and_bound_before_connected_execution(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    root = _root(tmp_path)
    request, _capability = _claimed(monkeypatch, root)

    with pytest.raises(subject.RouteCollisionAdmissionError):
        subject.read_and_claim_route_collision_admission_request(
            private_root=root,
            expected_request_digest=str(request["request_digest"]),
            now=NOW,
        )


def test_request_cannot_be_claimed_before_its_created_at(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    root = _root(tmp_path)
    request = _request(monkeypatch, root)
    request["created_at"] = _stamp(NOW + timedelta(seconds=5))
    _reseal(request, "request_digest")
    subject.persist_route_collision_admission_request(
        private_root=root,
        request=request,
    )

    with pytest.raises(
        subject.RouteCollisionAdmissionError,
        match="ROUTE_COLLISION_REQUEST_NOT_ACTIVE",
    ):
        subject.read_and_claim_route_collision_admission_request(
            private_root=root,
            expected_request_digest=str(request["request_digest"]),
            now=NOW,
        )


def test_snapshots_captured_before_claim_are_rejected_as_replay(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    root = _root(tmp_path)
    request = _request(monkeypatch, root)
    subject.persist_route_collision_admission_request(
        private_root=root,
        request=request,
    )
    capability = subject.read_and_claim_route_collision_admission_request(
        private_root=root,
        expected_request_digest=str(request["request_digest"]),
        now=NOW + timedelta(seconds=5),
    )

    with pytest.raises(
        subject.RouteCollisionAdmissionError,
        match="ROUTE_COLLISION_SNAPSHOT_STABILITY_INVALID",
    ):
        subject.build_route_collision_admission_result(
            capability=capability,
            snapshots=[_snapshot(request, index) for index in (1, 2, 3)],
            sealed_at=NOW + timedelta(seconds=6),
        )


def test_snapshot_rejects_collision_or_uncertain_disposition(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    request = _request(monkeypatch, _root(tmp_path))
    snapshot = _snapshot(request, 1)
    target = next(iter(snapshot["target_observations"]))
    snapshot["target_observations"][target]["disposition"] = "PRESENT_FOREIGN"
    snapshot["semantic_facts_digest"] = subject.canonical_digest(
        {
            "catalog_digest": request["catalog_digest"],
            "operation": request["operation"],
            "effect_request_digest": request["effect_request_digest"],
            "target_observations": snapshot["target_observations"],
        }
    )
    snapshot["snapshot_digest"] = subject.canonical_digest(
        {key: value for key, value in snapshot.items() if key != "snapshot_digest"}
    )

    with pytest.raises(subject.RouteCollisionAdmissionError):
        subject.validate_route_collision_snapshot(
            snapshot,
            request=request,
            capture_index=1,
        )


def test_three_stable_snapshots_mint_exact_effect_admission(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    root = _root(tmp_path)
    request, capability = _claimed(monkeypatch, root)
    snapshots = [_snapshot(request, index) for index in (1, 2, 3)]

    result = subject.build_route_collision_admission_result(
        capability=capability,
        snapshots=snapshots,
        sealed_at=NOW + timedelta(seconds=4),
    )
    subject.persist_route_collision_admission_result(
        private_root=root,
        result=result,
    )
    _persist_transcript_sidecar(root, result)
    admission = subject.read_route_collision_admission(
        private_root=root,
        expected_admission_digest=result.public_receipt["admission_digest"],
        expected_operation=OPERATION,
        expected_effect_request_digest=EFFECT_DIGEST,
        expected_bootstrap_intent_digest=BOOTSTRAP_DIGEST,
        now=NOW + timedelta(seconds=5),
    )

    assert (
        subject.assert_route_collision_admission_active(
            admission,
            operation=OPERATION,
            effect_request_digest=EFFECT_DIGEST,
            bootstrap_intent_digest=BOOTSTRAP_DIGEST,
            now=NOW + timedelta(seconds=6),
        )
        == result.public_receipt["admission_digest"]
    )


def test_effect_grant_is_minimal_normalized_and_revalidated_pre_effect(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    root = _root(tmp_path)
    request, capability = _claimed(monkeypatch, root)
    result = subject.build_route_collision_admission_result(
        capability=capability,
        snapshots=[_snapshot(request, index) for index in (1, 2, 3)],
        sealed_at=NOW + timedelta(seconds=4),
    )
    subject.persist_route_collision_admission_result(
        private_root=root,
        result=result,
    )
    _persist_transcript_sidecar(root, result)
    admission = subject.read_route_collision_admission(
        private_root=root,
        expected_admission_digest=result.public_receipt["admission_digest"],
        expected_operation=OPERATION,
        expected_effect_request_digest=EFFECT_DIGEST,
        expected_bootstrap_intent_digest=BOOTSTRAP_DIGEST,
        now=NOW + timedelta(seconds=5),
    )

    grant = subject.consume_route_collision_admission(
        admission,
        operation=OPERATION,
        effect_request_digest=EFFECT_DIGEST,
        bootstrap_intent_digest=BOOTSTRAP_DIGEST,
        now=NOW + timedelta(seconds=6),
    )

    assert grant == subject.RouteCollisionAdmissionEffectGrant(
        admission_digest=result.public_receipt["admission_digest"],
        effect_private_root_digest=EFFECT_ROOT_DIGEST,
        atomic_context_digest=ATOMIC_CONTEXT_DIGEST,
        not_before=NOW - timedelta(minutes=1),
        expires_at=NOW + timedelta(minutes=10),
        sealed_at=NOW + timedelta(seconds=4),
    )
    assert not hasattr(grant, "__dict__")
    with pytest.raises(AttributeError):
        grant.expires_at = NOW + timedelta(hours=1)  # type: ignore[misc]
    assert (
        subject.revalidate_route_collision_admission_effect_grant(
            grant,
            now=NOW + timedelta(seconds=14),
        )
        == result.public_receipt["admission_digest"]
    )
    with pytest.raises(
        subject.RouteCollisionAdmissionError,
        match="ROUTE_COLLISION_ADMISSION_NOT_ACTIVE",
    ):
        subject.revalidate_route_collision_admission_effect_grant(
            grant,
            now=NOW + timedelta(seconds=15),
        )
    with pytest.raises(
        subject.RouteCollisionAdmissionError,
        match="ROUTE_COLLISION_ADMISSION_CAPABILITY_INVALID",
    ):
        subject.assert_route_collision_admission_active(
            admission,
            operation=OPERATION,
            effect_request_digest=EFFECT_DIGEST,
            bootstrap_intent_digest=BOOTSTRAP_DIGEST,
            now=NOW + timedelta(seconds=7),
        )


def test_action_time_snapshot_must_match_both_independent_snapshots(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    root = _root(tmp_path)
    request, capability = _claimed(monkeypatch, root)

    with pytest.raises(
        subject.RouteCollisionAdmissionError,
        match="ROUTE_COLLISION_SNAPSHOT_STABILITY_INVALID",
    ):
        subject.build_route_collision_admission_result(
            capability=capability,
            snapshots=[
                _snapshot(request, 1),
                _snapshot(request, 2),
                _snapshot(request, 3, facts_nonce="changed"),
            ],
            sealed_at=NOW + timedelta(seconds=4),
        )


def test_admission_rejects_wrong_operation_effect_or_expired_window(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    root = _root(tmp_path)
    request, capability = _claimed(monkeypatch, root)
    result = subject.build_route_collision_admission_result(
        capability=capability,
        snapshots=[_snapshot(request, index) for index in (1, 2, 3)],
        sealed_at=NOW + timedelta(seconds=4),
    )
    subject.persist_route_collision_admission_result(
        private_root=root,
        result=result,
    )
    _persist_transcript_sidecar(root, result)

    for operation, effect, observed in (
        ("wrong-operation-v1", EFFECT_DIGEST, NOW + timedelta(seconds=5)),
        (
            OPERATION,
            "sha256:" + "9" * 64,
            NOW + timedelta(seconds=5),
        ),
        (
            OPERATION,
            EFFECT_DIGEST,
            NOW + timedelta(minutes=11),
        ),
    ):
        with pytest.raises(subject.RouteCollisionAdmissionError):
            subject.read_route_collision_admission(
                private_root=root,
                expected_admission_digest=result.public_receipt[
                    "admission_digest"
                ],
                expected_operation=operation,
                expected_effect_request_digest=effect,
                expected_bootstrap_intent_digest=BOOTSTRAP_DIGEST,
                now=observed,
            )


def test_admission_rejects_resealed_transcript_not_bound_to_snapshots(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    root = _root(tmp_path)
    request, capability = _claimed(monkeypatch, root)
    result = subject.build_route_collision_admission_result(
        capability=capability,
        snapshots=[_snapshot(request, index) for index in (1, 2, 3)],
        sealed_at=NOW + timedelta(seconds=4),
    )
    subject.persist_route_collision_admission_result(
        private_root=root,
        result=result,
    )
    sidecar = _transcript_sidecar(result)
    events = sidecar["events"]
    summary = sidecar["summary"]
    assert isinstance(events, list) and isinstance(summary, dict)
    assert isinstance(events[0], dict)
    events[0]["forged_provider_fact"] = True
    events_digest = subject.canonical_digest(events)
    sidecar["events_digest"] = events_digest
    summary["transcript_digest"] = events_digest
    _reseal(sidecar, "sidecar_digest")
    subject.write_private_json(root, subject.DEFAULT_TRANSCRIPT_FILE, sidecar)

    with pytest.raises(
        subject.RouteCollisionAdmissionError,
        match="ROUTE_COLLISION_TRANSCRIPT_SIDECAR_INVALID",
    ):
        subject.read_route_collision_admission(
            private_root=root,
            expected_admission_digest=result.public_receipt[
                "admission_digest"
            ],
            expected_operation=OPERATION,
            expected_effect_request_digest=EFFECT_DIGEST,
            expected_bootstrap_intent_digest=BOOTSTRAP_DIGEST,
            now=NOW + timedelta(seconds=5),
        )


def test_present_owned_target_requires_successful_ownership_read(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    root = _root(tmp_path)
    request, capability = _claimed(monkeypatch, root)
    result = subject.build_route_collision_admission_result(
        capability=capability,
        snapshots=[_snapshot(request, index) for index in (1, 2, 3)],
        sealed_at=NOW + timedelta(seconds=4),
    )
    sidecar = _transcript_sidecar(result)
    events = sidecar["events"]
    summary = sidecar["summary"]
    assert isinstance(events, list) and isinstance(summary, dict)
    ownership_event = next(
        event
        for event in events
        if isinstance(event, dict)
        and event["operation"] == "iam:ListRoleTags"
    )
    ownership_event["outcome"] = "NOT_FOUND"
    snapshots = copy.deepcopy(result.private_evidence["snapshots"])
    for capture_index, snapshot in enumerate(snapshots, 1):
        snapshot["transcript_digest"] = subject.canonical_digest(
            [
                event
                for event in events
                if event["capture_index"] == capture_index
            ]
        )
    summary["transcript_digest"] = subject.canonical_digest(events)

    with pytest.raises(
        subject.RouteCollisionAdmissionError,
        match="ROUTE_COLLISION_INVENTORY_COVERAGE_INVALID",
    ):
        transcript_executor.validate_route_collision_transcript_bundle(
            events=events,
            summary=summary,
            request=request,
            snapshots=snapshots,
        )


def test_materialization_reuses_gug395_lineage_after_its_historical_window(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    root = _root(tmp_path)
    lineage_root = _gug395_root(root)
    monkeypatch.setattr(
        subject,
        "_gug395_bundle",
        lambda _root: _gug395_result(
            lineage_root,
            expires_at=NOW + timedelta(minutes=2),
        ),
    )

    catalog = _catalog()
    request = subject.materialize_route_collision_admission_request(
        private_root=root,
        gug395_private_root=lineage_root,
        catalog=catalog,
        collision_policy_set=(
            policy_contract.materialize_route_collision_policy_set(catalog)
        ),
        phase="artifact-foundation",
        operation=OPERATION,
        effect_request=EFFECT_REQUEST,
        source_commit_sha=COMMIT,
        source_tree_sha=TREE,
        bootstrap_intent_digest=BOOTSTRAP_DIGEST,
        effect_private_root_digest=EFFECT_ROOT_DIGEST,
        atomic_context_digest=ATOMIC_CONTEXT_DIGEST,
        expected_gug395_request_digest="sha256:" + "f" * 64,
        expected_gug395_receipt_digest="sha256:" + "2" * 64,
        expected_gug395_bundle_digest="sha256:" + "3" * 64,
        not_before=_stamp(NOW - timedelta(minutes=1)),
        expires_at=_stamp(NOW + timedelta(minutes=10)),
        created_at=_stamp(NOW),
    )
    assert request["gug395_private_root_digest"] == (
        subject._private_root_digest(lineage_root)
    )
    assert request["private_custody_digest"] == subject._private_root_digest(
        root
    )
    assert request["gug395_private_root_digest"] != request[
        "private_custody_digest"
    ]


def test_phase_operation_and_effect_request_are_closed_and_rederived(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    root = _root(tmp_path)
    lineage_root = _gug395_root(root)
    monkeypatch.setattr(
        subject,
        "_gug395_bundle",
        lambda _root: _gug395_result(lineage_root),
    )
    with pytest.raises(
        subject.RouteCollisionAdmissionError,
        match="ROUTE_COLLISION_PHASE_OPERATION_INVALID",
    ):
        catalog = _catalog()
        subject.materialize_route_collision_admission_request(
            private_root=root,
            gug395_private_root=lineage_root,
            catalog=catalog,
            collision_policy_set=(
                policy_contract.materialize_route_collision_policy_set(
                    catalog
                )
            ),
            phase="artifact-foundation",
            operation="delegation-create-v1",
            effect_request=EFFECT_REQUEST,
            source_commit_sha=COMMIT,
            source_tree_sha=TREE,
            bootstrap_intent_digest=BOOTSTRAP_DIGEST,
            effect_private_root_digest=EFFECT_ROOT_DIGEST,
            atomic_context_digest=ATOMIC_CONTEXT_DIGEST,
            expected_gug395_request_digest="sha256:" + "f" * 64,
            expected_gug395_receipt_digest="sha256:" + "2" * 64,
            expected_gug395_bundle_digest="sha256:" + "3" * 64,
            not_before=_stamp(NOW - timedelta(minutes=1)),
            expires_at=_stamp(NOW + timedelta(minutes=10)),
            created_at=_stamp(NOW),
        )

    request = _request(monkeypatch, root)
    request["effect_request"]["client_token"] = "resealed-drift"
    _reseal(request, "request_digest")
    with pytest.raises(
        subject.RouteCollisionAdmissionError,
        match="ROUTE_COLLISION_EFFECT_BINDING_INVALID",
    ):
        subject.validate_route_collision_admission_request(request)


def test_operation_lifecycle_catalog_is_exact_and_exhaustive() -> None:
    catalog = _catalog()
    route_created = {
        target["target_id"]
        for target in catalog["targets"]
        if target["lifecycle"] == "ROUTE_CREATED"
    }
    collision_only = {
        target["target_id"]
        for target in catalog["targets"]
        if target["lifecycle"] == "COLLISION_ONLY"
    }
    allowlisted_operations = set().union(
        *subject.PHASE_OPERATION_ALLOWLIST.values()
    )

    assert len(route_created) == 70
    assert len(collision_only) == 3
    assert route_created == subject.ROUTE_CREATED_TARGET_IDS
    assert collision_only == subject.COLLISION_ONLY_TARGET_IDS
    assert set(subject.OPERATION_PRESENT_OWNED_TARGET_IDS) == (
        allowlisted_operations
    )
    assert len(allowlisted_operations) == 41
    assert set().union(
        *subject.OPERATION_PRESENT_OWNED_TARGET_IDS.values()
    ) == route_created
    assert all(
        present <= route_created and present.isdisjoint(collision_only)
        for present in subject.OPERATION_PRESENT_OWNED_TARGET_IDS.values()
    )


@pytest.mark.parametrize(
    ("phase", "operation"),
    [
        (phase, operation)
        for phase, operations in subject.PHASE_OPERATION_ALLOWLIST.items()
        for operation in sorted(operations)
    ],
)
def test_each_operation_uses_its_exact_present_owned_target_set(
    phase: str,
    operation: str,
) -> None:
    actual = subject.expected_route_collision_dispositions(
        _catalog(), phase, operation
    )

    assert len(actual) == 73
    assert {
        target_id
        for target_id, disposition in actual.items()
        if disposition == "PRESENT_OWNED"
    } == subject.OPERATION_PRESENT_OWNED_TARGET_IDS[operation]
    assert all(
        actual[target_id] == "ABSENT_AT_SNAPSHOT"
        for target_id in subject.COLLISION_ONLY_TARGET_IDS
    )


def test_create_execute_reentry_protection_and_retirement_transitions() -> None:
    present = subject.OPERATION_PRESENT_OWNED_TARGET_IDS
    transitions = (
        (
            "bridge-create:dispatch",
            "bridge-create:execute",
            "management.cfn.artifact-bridge-stack",
        ),
        (
            "foundation-create:dispatch",
            "foundation-create:execute",
            "authority.cfn.artifact-foundation-stack",
        ),
        (
            "route:create-change-set",
            "route:execute-change-set",
            "management.cfn.temporary-route-stack",
        ),
        (
            "broker:create-change-set",
            "broker:execute-change-set",
            "authority.cfn.route-broker-stack",
        ),
        (
            "delegation-create-v1",
            "delegation-execute-v1",
            "management.cfn.plan-repair-delegation-stack",
        ),
        (
            "pep-create-v1",
            "pep-execute-v1",
            "authority.cfn.plan-repair-pep-stack",
        ),
    )
    for create_operation, execute_operation, stack_target in transitions:
        assert present[execute_operation] - present[create_operation] == {
            stack_target
        }

    assert present["route-reentry-preexecute:create-change-set"] == present[
        "route:execute-change-set"
    ]
    assert present["route-reentry-preexecute:execute-change-set"] == present[
        "route:execute-change-set"
    ]
    assert present["route-reentry-cleanup:create-change-set"] == present[
        "route:create-change-set"
    ]
    assert present["route-reentry-cleanup:execute-change-set"] == present[
        "route:execute-change-set"
    ]
    assert present["broker-reentry-preexecute:create-change-set"] == present[
        "broker:execute-change-set"
    ]
    assert present["broker-reentry-cleanup:create-change-set"] == present[
        "broker:create-change-set"
    ]
    assert present["broker-reentry-cleanup:execute-change-set"] == present[
        "broker:execute-change-set"
    ]

    broker_protection = present["broker-protection:create-change-set"]
    for operation in (
        "broker-protection:execute-change-set",
        "broker-protection-reentry-rollback:create-change-set",
        "broker-protection-reentry-rollback:execute-change-set",
        "seed-revoke-create-v1",
        "seed-revoke-execute-v1",
    ):
        assert present[operation] == broker_protection

    pep_protection = present["pep-protection-create-v1"]
    for operation in (
        "pep-protection-execute-v1",
        "closeout-gate-v1",
        "delegation-revoke-create-v1",
            "delegation-revoke-execute-v1",
            "route-revoke-create-v1",
            "route-revoke-execute-v1",
        ):
        assert present[operation] == pep_protection

    assert present["bridge-revoke:dispatch"] == present["publish-object"]
    assert present["bridge-revoke:execute"] == present["publish-object"]


def test_lifecycle_dispositions_ignore_phase_order_and_relevance(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    targets = copy.deepcopy(_catalog()["targets"])
    for index, target in enumerate(targets):
        target["phases"] = (
            ["retirement", "artifact-bridge"]
            if index % 2
            else ["pep"]
        )
    monkeypatch.setattr(subject, "_catalog_targets", lambda _catalog: targets)

    for phase, operations in subject.PHASE_OPERATION_ALLOWLIST.items():
        for operation in operations:
            actual = subject.expected_route_collision_dispositions(
                {}, phase, operation
            )
            assert {
                target_id
                for target_id, disposition in actual.items()
                if disposition == "PRESENT_OWNED"
            } == subject.OPERATION_PRESENT_OWNED_TARGET_IDS[operation]


@pytest.mark.parametrize("drift", ["missing", "unknown"])
def test_lifecycle_dispositions_fail_closed_on_target_drift(
    monkeypatch: pytest.MonkeyPatch,
    drift: str,
) -> None:
    targets = copy.deepcopy(_catalog()["targets"])
    if drift == "missing":
        targets.pop()
    else:
        targets[0]["target_id"] = "management.cfn.unknown-route-target"
    monkeypatch.setattr(subject, "_catalog_targets", lambda _catalog: targets)

    with pytest.raises(
        subject.RouteCollisionAdmissionError,
        match="ROUTE_COLLISION_LIFECYCLE_INVALID",
    ):
        subject.expected_route_collision_dispositions(
            {}, "artifact-foundation", OPERATION
        )


def test_snapshot_identity_is_bound_to_direct_sso_principal_and_policy(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    request = _request(monkeypatch, _root(tmp_path))
    snapshot = _snapshot(request, 1)
    snapshot["identities"]["authority"]["source"] = "ATTESTED_BROKER_ROLE"
    snapshot["identities"]["authority"]["chain_depth"] = 1
    _reseal(snapshot, "snapshot_digest")

    with pytest.raises(
        subject.RouteCollisionAdmissionError,
        match="ROUTE_COLLISION_SNAPSHOT_IDENTITY_INVALID",
    ):
        subject.validate_route_collision_snapshot(
            snapshot,
            request=request,
            capture_index=1,
        )


def test_result_rejects_resealed_zero_snapshot_forgery(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    root = _root(tmp_path)
    request, capability = _claimed(monkeypatch, root)
    valid = subject.build_route_collision_admission_result(
        capability=capability,
        snapshots=[_snapshot(request, index) for index in (1, 2, 3)],
        sealed_at=NOW + timedelta(seconds=4),
    )
    evidence = copy.deepcopy(valid.private_evidence)
    receipt = copy.deepcopy(valid.public_receipt)
    evidence["snapshots"] = []
    evidence["snapshot_digests"] = []
    _reseal(evidence, "private_evidence_digest")
    receipt["private_evidence_digest"] = evidence["private_evidence_digest"]
    receipt["snapshot_digests"] = []
    _reseal(receipt, "admission_digest")
    forged = subject.RouteCollisionAdmissionResult(evidence, receipt)

    with pytest.raises(subject.RouteCollisionAdmissionError):
        subject.persist_route_collision_admission_result(
            private_root=root,
            result=forged,
        )
    assert not (root / subject.DEFAULT_RESULT_FILE).exists()


def test_snapshots_must_be_strictly_ordered_and_immediately_sealed(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    first_root = _root(tmp_path / "first")
    request, capability = _claimed(monkeypatch, first_root)
    snapshots = [_snapshot(request, index) for index in (1, 2, 3)]
    snapshots[1]["observed_at"] = snapshots[0]["observed_at"]
    for identity in snapshots[1]["identities"].values():
        identity["observed_at"] = snapshots[0]["observed_at"]
    _reseal(snapshots[1], "snapshot_digest")
    with pytest.raises(
        subject.RouteCollisionAdmissionError,
        match="ROUTE_COLLISION_SNAPSHOT_STABILITY_INVALID",
    ):
        subject.build_route_collision_admission_result(
            capability=capability,
            snapshots=snapshots,
            sealed_at=NOW + timedelta(seconds=4),
        )

    second_root = _root(tmp_path / "second")
    request, capability = _claimed(monkeypatch, second_root)
    with pytest.raises(
        subject.RouteCollisionAdmissionError,
        match="ROUTE_COLLISION_SNAPSHOT_STABILITY_INVALID",
    ):
        subject.build_route_collision_admission_result(
            capability=capability,
            snapshots=[_snapshot(request, index) for index in (1, 2, 3)],
            sealed_at=NOW + timedelta(seconds=9),
        )


def test_admission_capability_is_fresh_and_one_shot(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    root = _root(tmp_path)
    request, capability = _claimed(monkeypatch, root)
    result = subject.build_route_collision_admission_result(
        capability=capability,
        snapshots=[_snapshot(request, index) for index in (1, 2, 3)],
        sealed_at=NOW + timedelta(seconds=4),
    )
    subject.persist_route_collision_admission_result(
        private_root=root,
        result=result,
    )
    _persist_transcript_sidecar(root, result)
    with pytest.raises(
        subject.RouteCollisionAdmissionError,
        match="ROUTE_COLLISION_ADMISSION_BINDING_INVALID",
    ):
        subject.read_route_collision_admission(
            private_root=root,
            expected_admission_digest=result.public_receipt["admission_digest"],
            expected_operation=OPERATION,
            expected_effect_request_digest=EFFECT_DIGEST,
            expected_bootstrap_intent_digest=BOOTSTRAP_DIGEST,
            now=NOW + timedelta(seconds=15),
        )

    admission = subject.read_route_collision_admission(
        private_root=root,
        expected_admission_digest=result.public_receipt["admission_digest"],
        expected_operation=OPERATION,
        expected_effect_request_digest=EFFECT_DIGEST,
        expected_bootstrap_intent_digest=BOOTSTRAP_DIGEST,
        now=NOW + timedelta(seconds=5),
    )
    with pytest.raises(subject.RouteCollisionAdmissionError):
        subject.read_route_collision_admission(
            private_root=root,
            expected_admission_digest=result.public_receipt["admission_digest"],
            expected_operation=OPERATION,
            expected_effect_request_digest=EFFECT_DIGEST,
            expected_bootstrap_intent_digest=BOOTSTRAP_DIGEST,
            now=NOW + timedelta(seconds=5),
        )
    subject.assert_route_collision_admission_active(
        admission,
        operation=OPERATION,
        effect_request_digest=EFFECT_DIGEST,
        bootstrap_intent_digest=BOOTSTRAP_DIGEST,
        now=NOW + timedelta(seconds=6),
    )
    with pytest.raises(
        subject.RouteCollisionAdmissionError,
        match="ROUTE_COLLISION_ADMISSION_CAPABILITY_INVALID",
    ):
        subject.assert_route_collision_admission_active(
            admission,
            operation=OPERATION,
            effect_request_digest=EFFECT_DIGEST,
            bootstrap_intent_digest=BOOTSTRAP_DIGEST,
            now=NOW + timedelta(seconds=7),
        )


def test_admission_rechecks_exact_transcript_before_effect(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    root = _root(tmp_path)
    request, execution = _claimed(monkeypatch, root)
    result = subject.build_route_collision_admission_result(
        capability=execution,
        snapshots=[_snapshot(request, index) for index in (1, 2, 3)],
        sealed_at=NOW + timedelta(seconds=4),
    )
    subject.persist_route_collision_admission_result(
        private_root=root,
        result=result,
    )
    _persist_transcript_sidecar(root, result)
    admission = subject.read_route_collision_admission(
        private_root=root,
        expected_admission_digest=result.public_receipt["admission_digest"],
        expected_operation=OPERATION,
        expected_effect_request_digest=EFFECT_DIGEST,
        expected_bootstrap_intent_digest=BOOTSTRAP_DIGEST,
        now=NOW + timedelta(seconds=5),
    )

    transcript_path = root / subject.DEFAULT_TRANSCRIPT_FILE
    replacement = subject.read_private_json(
        root, subject.DEFAULT_TRANSCRIPT_FILE
    )
    replacement["recorded_at"] = _stamp(NOW + timedelta(seconds=5))
    _reseal(replacement, "sidecar_digest")
    transcript_path.unlink()
    subject.write_private_json(
        root,
        subject.DEFAULT_TRANSCRIPT_FILE,
        replacement,
    )

    with pytest.raises(
        subject.RouteCollisionAdmissionError,
        match="ROUTE_COLLISION_ADMISSION_NOT_ACTIVE",
    ):
        subject.assert_route_collision_admission_active(
            admission,
            operation=OPERATION,
            effect_request_digest=EFFECT_DIGEST,
            bootstrap_intent_digest=BOOTSTRAP_DIGEST,
            now=NOW + timedelta(seconds=6),
        )
