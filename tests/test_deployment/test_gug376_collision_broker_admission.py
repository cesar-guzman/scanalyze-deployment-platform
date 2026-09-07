from __future__ import annotations

from collections import Counter
from datetime import UTC, datetime, timedelta
import gc
import json
from types import SimpleNamespace
from typing import Any, Mapping

import pytest

from tests.test_deployment import (
    test_gug376_collision_policy as policy_fixtures,
    test_gug376_plan_permission_repair_route_broker as route_fixtures,
)
from tooling import platform_authority_gug376_collision_admission as admission
from tooling import platform_authority_gug376_collision_broker_admission as subject
from tooling import platform_authority_gug376_collision_policy as collision_policy
from tooling import platform_authority_plan_permission_repair_route_broker as broker
from tooling.platform_authority_gug365_upstream_inventory import (
    canonical_digest,
    canonical_json,
)


INSTANCE_ARN = "arn:aws:sso:::instance/ssoins-1234567890abcdef"
PERMISSION_SET_ARN = (
    "arn:aws:sso:::permissionSet/"
    "ssoins-1234567890abcdef/ps-1234567890abcdef"
)
APPLICATION_ARN = (
    "arn:aws:sso::839393571433:application/"
    "ssoins-1234567890abcdef/apl-1234567890abcdef"
)


def _maximum_live_candidates(
    catalog: Mapping[str, Any],
) -> dict[str, dict[str, list[str]]]:
    candidates: dict[str, dict[str, list[str]]] = {
        domain: {} for domain in collision_policy.DOMAINS
    }
    for domain in collision_policy.DOMAINS:
        for kind in sorted(collision_policy._DYNAMIC_RESOURCE_KINDS[domain]):
            selector = collision_policy._expected_discovery_selector(
                catalog,
                domain=domain,
                kind=kind,
            )
            account_id = selector["account_id"]
            if kind == "cloudformation_stack":
                values = [
                    (
                        f"arn:aws:cloudformation:us-east-1:{account_id}:"
                        f"stack/{name}/{index:08d}-abcd-1234-abcd-1234567890ab"
                    )
                    for index, name in enumerate(
                        selector["stack_names"], start=1
                    )
                ]
            elif kind == "kms_key":
                values = [
                    (
                        f"arn:aws:kms:us-east-1:{account_id}:key/"
                        f"{index:08x}-abcd-1234-abcd-1234567890ab"
                    )
                    for index, _name in enumerate(
                        selector["alias_names"], start=1
                    )
                ]
            elif kind == "lambda_code_signing_config":
                values = [
                    (
                        f"arn:aws:lambda:us-east-1:{account_id}:"
                        f"code-signing-config:csc-{index:017d}"
                    )
                    for index, _selector in enumerate(
                        selector["stack_resources"], start=1
                    )
                ]
            elif kind == "identity_center_kms_key":
                values = [
                    f"arn:aws:kms:us-east-1:{account_id}:key/"
                    "00000001-abcd-1234-abcd-1234567890ab"
                ]
            elif kind == "sso_instance":
                values = [INSTANCE_ARN]
            elif kind == "sso_application":
                values = [
                    (
                        f"arn:aws:sso::{account_id}:application/"
                        f"ssoins-1234567890abcdef/apl-{index:016d}"
                    )
                    for index, _name in enumerate(
                        selector["application_names"], start=1
                    )
                ]
            elif kind == "sso_permission_set":
                values = [
                    (
                        "arn:aws:sso:::permissionSet/"
                        f"ssoins-1234567890abcdef/ps-{index:016d}"
                    )
                    for index, _name in enumerate(
                        selector["permission_set_names"], start=1
                    )
                ]
            else:  # pragma: no cover - catalog kind set is closed above.
                raise AssertionError(kind)
            candidates[domain][kind] = values
    return candidates


class _AwsNotFound(Exception):
    def __init__(self, code: str) -> None:
        self.response = {"Error": {"Code": code}}


class _FakeReadClient:
    def __init__(self, session: "_FakeSdkSession", service: str) -> None:
        self._session = session
        self._service = service
        self.meta = SimpleNamespace(
            region_name=broker.REGION,
            endpoint_url=(
                "https://" + broker._EXACT_SERVICE_ENDPOINT_HOSTS[service]
            ),
        )

    def _call(self, method: str, request: dict[str, Any]) -> dict[str, Any]:
        self._session.calls.append((self._service, method, request))
        if method == "get_caller_identity":
            return {
                "Account": self._session.account_id,
                "Arn": self._session.principal_arn,
                "UserId": "fake:" + self._session.session_name,
            }
        if method in {"describe_stacks", "describe_stack_resource"}:
            raise _AwsNotFound("ValidationError")
        if method == "describe_table":
            raise _AwsNotFound("ResourceNotFoundException")
        if method == "get_role":
            raise _AwsNotFound("NoSuchEntity")
        if method in {"get_alias", "get_function", "get_code_signing_config"}:
            raise _AwsNotFound("ResourceNotFoundException")
        if method == "get_signing_profile":
            raise _AwsNotFound("ResourceNotFoundException")
        if method == "list_stacks":
            return {"StackSummaries": []}
        if method == "list_aliases":
            return {"Aliases": [], "Truncated": False}
        if method == "describe_log_groups":
            return {"logGroups": []}
        if method == "list_buckets":
            return {"Buckets": []}
        if method == "list_instances":
            return {
                "Instances": [
                    {
                        "InstanceArn": INSTANCE_ARN,
                        "OwnerAccountId": broker.MANAGEMENT_ACCOUNT_ID,
                    }
                ]
            }
        if method == "describe_instance":
            return {
                "InstanceArn": INSTANCE_ARN,
                "IdentityStoreId": "d-1234567890",
                "OwnerAccountId": broker.MANAGEMENT_ACCOUNT_ID,
                "Status": "ACTIVE",
                "EncryptionConfigurationDetails": {
                    "KeyType": "AWS_OWNED_KMS_KEY",
                    "KmsKeyArn": None,
                    "EncryptionStatus": "ENABLED",
                },
            }
        if method == "list_applications":
            return {
                "Applications": [
                    {
                        "ApplicationArn": APPLICATION_ARN,
                        "Name": self._session.application_name,
                    }
                ]
            }
        if method == "list_permission_sets":
            return {"PermissionSets": [PERMISSION_SET_ARN]}
        if method == "describe_permission_set":
            return {
                "PermissionSet": {
                    "PermissionSetArn": PERMISSION_SET_ARN,
                    "Name": self._session.permission_set_name,
                }
            }
        raise AssertionError((self._service, method, request))

    def __getattr__(self, method: str) -> Any:
        return lambda **request: self._call(method, request)


class _FakeSdkSession:
    def __init__(
        self,
        *,
        account_id: str,
        role_name: str,
        session_name: str,
        permission_set_name: str,
        application_name: str,
    ) -> None:
        self.account_id = account_id
        self.role_name = role_name
        self.session_name = session_name
        self.permission_set_name = permission_set_name
        self.application_name = application_name
        self.principal_arn = (
            f"arn:aws:sts::{account_id}:assumed-role/"
            f"{role_name}/{session_name}"
        )
        self.calls: list[tuple[str, str, dict[str, Any]]] = []

    def client(
        self,
        service: str,
        *,
        region_name: str,
        config: object,
    ) -> _FakeReadClient:
        del config
        assert region_name == broker.REGION
        return _FakeReadClient(self, service)


class _FakeSts:
    def __init__(self) -> None:
        self.requests: list[dict[str, Any]] = []
        self.sessions_by_access_key: dict[str, dict[str, str]] = {}
        self.meta = SimpleNamespace(
            region_name=broker.REGION,
            endpoint_url="https://sts.us-east-1.amazonaws.com",
        )

    def assume_role(self, **request: Any) -> dict[str, Any]:
        self.requests.append(json.loads(json.dumps(request)))
        index = len(self.requests)
        role_arn = str(request["RoleArn"])
        account_id = role_arn.split(":", 5)[4]
        role_name = role_arn.rsplit("/", 1)[-1]
        session_name = str(request["RoleSessionName"])
        access_key = f"ASIAFAKE{index:012d}"
        self.sessions_by_access_key[access_key] = {
            "account_id": account_id,
            "role_name": role_name,
            "session_name": session_name,
        }
        return {
            "Credentials": {
                "AccessKeyId": access_key,
                "SecretAccessKey": f"secret-{index}",
                "SessionToken": f"token-{index}",
            },
            "AssumedRoleUser": {
                "Arn": (
                    f"arn:aws:sts::{account_id}:assumed-role/"
                    f"{role_name}/{session_name}"
                ),
                "AssumedRoleId": f"AROATEST{index:04d}:{session_name}",
            },
        }


class _AuthoritySession:
    def __init__(self, sts: _FakeSts) -> None:
        self._sts = sts

    def client(
        self,
        service: str,
        *,
        region_name: str,
        config: object,
    ) -> _FakeSts:
        del config
        assert service == "sts"
        assert region_name == broker.REGION
        return self._sts


class _FakeBoto3:
    def __init__(
        self,
        sts: _FakeSts,
        *,
        permission_set_name: str,
        application_name: str,
    ) -> None:
        self.gc_collect_count = 0
        owner = self

        class _SessionNamespace:
            @staticmethod
            def Session(**values: Any) -> _FakeSdkSession:
                owner.gc_collect_count += 1
                gc.collect()
                binding = sts.sessions_by_access_key[
                    values["aws_access_key_id"]
                ]
                assert values["region_name"] == broker.REGION
                return _FakeSdkSession(
                    **binding,
                    permission_set_name=permission_set_name,
                    application_name=application_name,
                )

        self.session = _SessionNamespace()


def _config() -> broker.BrokerConfig:
    value = route_fixtures._config_value()
    artifact_bucket = (
        f"scanalyze-g376-art-{value['source_commit'][:12]}-"
        f"{broker.AUTHORITY_ACCOUNT_ID}-{broker.REGION}-an"
    )
    parameters = value["requests"]["pep-create-v1"]["Parameters"]
    next(
        item for item in parameters if item["ParameterKey"] == "ArtifactBucket"
    )["ParameterValue"] = artifact_bucket
    value.pop("config_digest", None)
    return broker.BrokerConfig.from_mapping(broker.seal(value, "config_digest"))


def _identity_only_capture(
    *,
    factory: object,
    request: Mapping[str, Any],
    capture_index: int,
    purpose: str,
    clock: Any,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    snapshot = factory.open_snapshot(  # type: ignore[attr-defined]
        request=request,
        capture_index=capture_index,
        purpose=purpose,
    )
    identities = {
        domain: snapshot.read_identity(domain=domain)
        for domain in ("authority", "management")
    }
    observations = {
        target_id: {
            "target_id": target_id,
            "disposition": disposition,
            "evidence_digest": canonical_digest(
                {"target_id": target_id, "disposition": disposition}
            ),
        }
        for target_id, disposition in request[
            "expected_dispositions"
        ].items()
    }
    # The provider/session path is real; only the 73-target projections are
    # supplied from the already validated canonical disposition matrix so this
    # integration test stays compact.
    snapshot._observations = observations
    events = list(snapshot.transcript_events())
    semantic = {
        "catalog_digest": request["catalog_digest"],
        "operation": request["operation"],
        "effect_request_digest": request["effect_request_digest"],
        "target_observations": observations,
    }
    value = {
        "record_type": subject.SNAPSHOT_TYPE,
        "schema_version": 1,
        "capture_index": capture_index,
        "request_digest": request["request_digest"],
        "catalog_digest": request["catalog_digest"],
        "operation": request["operation"],
        "effect_request_digest": request["effect_request_digest"],
        "identities": identities,
        "target_observations": observations,
        "semantic_facts_digest": canonical_digest(semantic),
        "transcript_digest": canonical_digest(events),
        "complete": True,
        "observed_at": subject._stamp(clock()),
    }
    return subject._seal(value, "snapshot_digest"), events


def test_runtime_adapter_runs_inline_admission_with_ten_exact_sts_sessions(
    monkeypatch: Any,
) -> None:
    cfg = _config()
    kms_bindings = broker._collision_parameter_bindings(cfg)
    catalog = broker._InlineCollisionAdmissionAdapter(
        config=cfg,
        session_opener_for_policy=lambda *_args, **_kwargs: None,
        kms_bindings=kms_bindings,
        clock=lambda: datetime(2026, 8, 30, 19, 0, tzinfo=UTC),
    )._catalog
    permission_set_name = next(
        target["name"]
        for target in catalog["targets"]
        if target["service"] == "sso"
        and target["scope"] == "permission_set"
    )
    application_name = next(
        target["name"]
        for target in catalog["targets"]
        if target["service"] == "sso" and target["scope"] == "application"
    )
    sts = _FakeSts()
    boto3_module = _FakeBoto3(
        sts,
        permission_set_name=permission_set_name,
        application_name=application_name,
    )
    current = [datetime(2026, 8, 30, 19, 0, tzinfo=UTC)]
    budget_gates = [0]

    def clock() -> datetime:
        current[0] += timedelta(seconds=1)
        return current[0]

    def before_call() -> None:
        budget_gates[0] += 1

    monkeypatch.setattr(subject, "_capture", _identity_only_capture)
    monkeypatch.setattr(
        subject.transcript,
        "validate_route_collision_transcript_bundle",
        lambda **_kwargs: None,
    )
    adapter = broker._build_inline_collision_admission_adapter(
        config=cfg,
        authority_session=_AuthoritySession(sts),
        boto3_module=boto3_module,
        sdk_config=object(),
        clock=clock,
    )
    effect_request = {"exact": "delegation-create-v1"}
    capability = adapter.admit(
        phase="delegation",
        operation="delegation-create-v1",
        effect_request=effect_request,
        before_call=before_call,
    )
    manifest = adapter.manifest(capability)

    assert len(sts.requests) == 10
    assert boto3_module.gc_collect_count == 10
    assert budget_gates[0] > 20
    assert Counter(request["RoleArn"] for request in sts.requests) == {
        broker.AUTHORITY_COLLISION_READER_ROLE_ARN: 5,
        broker.MANAGEMENT_COLLISION_READER_ROLE_ARN: 5,
    }
    source_identity = f"gug376-collision-{cfg.source_commit}"
    for request in sts.requests:
        assert set(request) == {
            "RoleArn",
            "RoleSessionName",
            "SourceIdentity",
            "DurationSeconds",
            "Policy",
        }
        assert request["SourceIdentity"] == source_identity
        assert request["DurationSeconds"] == 900
        assert len(request["RoleSessionName"]) <= 64
        policy_json = request["Policy"]
        assert canonical_json(json.loads(policy_json)) == policy_json
        assert len(policy_json.encode("utf-8")) <= 2_048

    inventory_requests = sts.requests[:4]
    candidate_requests = sts.requests[4:]
    assert set(
        Counter(item["Policy"] for item in inventory_requests).values()
    ) == {2}
    assert set(
        Counter(item["Policy"] for item in candidate_requests).values()
    ) == {3}
    management_inventory = next(
        item["Policy"]
        for item in inventory_requests
        if item["RoleArn"] == broker.MANAGEMENT_COLLISION_READER_ROLE_ARN
    )
    assert "kms:" not in management_inventory
    assert "permissionSet/ssoins-1234567890abcdef/*" in management_inventory
    assert "permissionSet/ssoins-*/*" not in management_inventory
    management_candidate = next(
        item["Policy"]
        for item in candidate_requests
        if item["RoleArn"] == broker.MANAGEMENT_COLLISION_READER_ROLE_ARN
    )
    assert PERMISSION_SET_ARN not in management_candidate
    assert "permissionSet/ssoins-1234567890abcdef/*" in management_candidate
    assert APPLICATION_ARN in management_candidate
    assert "kms:" not in management_candidate
    assert {
        key: manifest["session_uniqueness_registry"][key]
        for key in (
            "session_count",
            "session_nonce_count",
            "sdk_session_count",
        )
    } == {
        "session_count": 10,
        "session_nonce_count": 10,
        "sdk_session_count": 10,
    }
    assert manifest["execution_locus"] == admission.INLINE_BROKER_LAMBDA
    assert manifest["session_mode"] == admission.POST_READER_RUNTIME
    budget_summary = manifest["collision_budget_summary"]
    assert {
        key: budget_summary[key]
        for key in (
            "session_mode",
            "session_open_count",
            "direct_sso_session_opens",
            "assume_role_opens",
            "assume_role_duration_seconds",
            "source_credential_bindings",
            "source_credential_vends",
        )
    } == {
        "session_mode": admission.POST_READER_RUNTIME,
        "session_open_count": 10,
        "direct_sso_session_opens": 0,
        "assume_role_opens": 10,
        "assume_role_duration_seconds": 900,
        "source_credential_bindings": 0,
        "source_credential_vends": 0,
    }
    assert manifest["collision_budget_events_digest"] == budget_summary[
        "events_digest"
    ]
    assert (
        manifest["collision_budget_transcript_events_digest"]
        == budget_summary["transcript_events_digest"]
    )
    assert manifest["manifest_digest"] == canonical_digest(
        {
            key: value
            for key, value in manifest.items()
            if key != "manifest_digest"
        }
    )
    for stage, requests in (
        ("inventory", inventory_requests),
        ("candidate", candidate_requests),
    ):
        field = f"{stage}_session_policy_digests"
        for domain, role_arn in (
            ("authority", broker.AUTHORITY_COLLISION_READER_ROLE_ARN),
            ("management", broker.MANAGEMENT_COLLISION_READER_ROLE_ARN),
        ):
            exact_policy = next(
                json.loads(item["Policy"])
                for item in requests
                if item["RoleArn"] == role_arn
            )
            assert manifest[field][domain] == canonical_digest(exact_policy)

    grant = adapter.consume(
        capability,
        operation="delegation-create-v1",
        effect_request_digest=canonical_digest(effect_request),
        expected_manifest_digest=manifest["manifest_digest"],
        now=current[0],
    )
    assert adapter.revalidate(grant, now=current[0]) == manifest[
        "manifest_digest"
    ]


def test_maximum_live_candidate_session_policies_keep_exact_headroom() -> None:
    catalog = policy_fixtures._catalog()
    candidates = _maximum_live_candidates(catalog)
    assert {
        kind: len(candidates["authority"][kind])
        for kind in (
            "cloudformation_stack",
            "kms_key",
            "lambda_code_signing_config",
        )
    } == {
        "cloudformation_stack": 3,
        "kms_key": 3,
        "lambda_code_signing_config": 3,
    }
    assert len(candidates["management"]["cloudformation_stack"]) == 3
    assert len(candidates["management"]["sso_permission_set"]) == 9
    evidence = policy_fixtures._discovery_evidence(catalog, candidates)
    policy_set = collision_policy._build_policy_set(
        catalog,
        discovery_evidence=evidence,
        discovery_provenance_digest=(
            policy_fixtures.DISCOVERY_PROVENANCE_DIGEST
        ),
        identity_center_instance_arn=INSTANCE_ARN,
        identity_center_kms_mode="CUSTOMER_MANAGED_KEY",
        identity_center_kms_key_arn=candidates["management"][
            "identity_center_kms_key"
        ][0],
    )
    collision_policy.validate_route_collision_policy_set(
        policy_set,
        catalog=catalog,
    )

    policies = {
        domain: subject.materialize_assume_role_session_policy(
            policy_set=policy_set,
            catalog=catalog,
            domain=domain,
        )
        for domain in collision_policy.DOMAINS
    }
    sizes = {
        domain: len(canonical_json(value).encode("utf-8"))
        for domain, value in policies.items()
    }
    assert sizes == {"authority": 1_654, "management": 1_599}
    assert all(
        size <= subject.MAX_MATERIALIZED_SESSION_POLICY_BYTES
        and subject.MAX_SESSION_POLICY_BYTES - size
        >= subject.MIN_SESSION_POLICY_HEADROOM_BYTES
        for size in sizes.values()
    )
    assert all(value["Version"] == "2012-10-17" for value in policies.values())

    compatible_resource_kinds = {
        "cloudformation:DescribeStacks": {"cloudformation_stack"},
        "cloudformation:DescribeStackResource": {"cloudformation_stack"},
        "kms:DescribeKey": {"kms_key"},
        "kms:Decrypt": {"kms_key"},
        "kms:ListResourceTags": {"kms_key"},
        "lambda:GetAlias": {"lambda_function"},
        "lambda:GetCodeSigningConfig": {"lambda_code_signing_config"},
        "lambda:GetFunction": {"lambda_function"},
        "lambda:ListTags": {
            "lambda_code_signing_config",
            "lambda_function",
        },
        "sso:DescribeApplication": {"sso_application"},
        "sso:DescribeInstance": {"sso_instance"},
        "sso:DescribePermissionSet": {
            "sso_instance",
            "sso_permission_set",
        },
        "sso:ListPermissionSets": {"sso_instance"},
        "sso:ListTagsForResource": {
            "sso_application",
            "sso_instance",
            "sso_permission_set",
        },
    }

    def resource_kind(resource: str) -> str:
        if ":cloudformation:" in resource and ":stack/" in resource:
            return "cloudformation_stack"
        if ":kms:" in resource and ":key/" in resource:
            return "kms_key"
        if ":lambda:" in resource and ":code-signing-config:" in resource:
            return "lambda_code_signing_config"
        if ":lambda:" in resource and ":function:" in resource:
            return "lambda_function"
        if ":sso::" in resource and ":application/" in resource:
            return "sso_application"
        if ":sso:::instance/" in resource:
            return "sso_instance"
        if ":sso:::permissionSet/" in resource:
            return "sso_permission_set"
        raise AssertionError(resource)

    for domain, session_policy in policies.items():
        candidate_document = policy_set["policies"][domain]["candidate_detail"]
        candidate_actions = {
            action
            for statement in candidate_document["Statement"]
            if statement["Effect"] == "Allow"
            for action in (
                statement["Action"]
                if isinstance(statement["Action"], list)
                else [statement["Action"]]
            )
            if action != "sts:GetCallerIdentity"
        }
        wildcard_actions = {
            action
            for statement in session_policy["Statement"]
            if statement["Resource"] == "*"
            for action in (
                statement["Action"]
                if isinstance(statement["Action"], list)
                else [statement["Action"]]
            )
        }
        assert candidate_actions.isdisjoint(wildcard_actions)

        reviewed_resources = {
            resource
            for kind, resources in candidates[domain].items()
            for resource in resources
        }
        if domain == "authority":
            reviewed_resources.add(
                "arn:aws:lambda:us-east-1:042360977644:function:*"
            )
            reviewed_resources.add(
                "arn:aws:cloudformation:us-east-1:042360977644:stack/*"
            )
        else:
            reviewed_resources.add(
                "arn:aws:sso:::permissionSet/"
                "ssoins-1234567890abcdef/*"
            )

        for statement in session_policy["Statement"]:
            resources = statement["Resource"]
            if resources == "*":
                continue
            resource_values = resources if isinstance(resources, list) else [resources]
            actions = (
                statement["Action"]
                if isinstance(statement["Action"], list)
                else [statement["Action"]]
            )
            for action in actions:
                compatible = compatible_resource_kinds[action]
                effective_resources = {
                    resource
                    for resource in resource_values
                    if action.split(":", 1)[0]
                    == resource.split(":", 3)[2]
                    and resource_kind(resource) in compatible
                }
                # Cross-service and wrong-resource-type pairs are inert in
                # IAM. Every compatible pair must stay inside the exact
                # candidate set or one reviewed attached-role intersection.
                assert effective_resources
                assert effective_resources <= reviewed_resources

        if domain == "management":
            decrypt = next(
                statement
                for statement in session_policy["Statement"]
                if statement["Action"] == "kms:Decrypt"
            )
            assert decrypt["Resource"] == candidates["management"][
                "identity_center_kms_key"
            ][0]
            assert decrypt["Condition"]["StringEquals"] == {
                "aws:PrincipalAccount": broker.MANAGEMENT_ACCOUNT_ID,
                "aws:RequestedRegion": broker.REGION,
                "kms:CallerAccount": broker.MANAGEMENT_ACCOUNT_ID,
                "kms:EncryptionContext:aws:sso:instance-arn": INSTANCE_ARN,
                "kms:ViaService": "sso.us-east-1.amazonaws.com",
            }

        rendered = canonical_json(session_policy)
        for kind, resources in candidates[domain].items():
            if kind == "sso_permission_set":
                continue
            assert all(resource in rendered for resource in resources)
        assert "permissionSet/ssoins-*/*" not in rendered
        assert ":key/*" not in rendered
        assert ":code-signing-config:*" not in rendered
        assert ":application/*" not in rendered


def test_inline_admission_rejects_kms_binding_digest_mismatch_before_sessions(
) -> None:
    with pytest.raises(subject.BrokerCollisionAdmissionError) as captured:
        subject.execute_inline_broker_collision_admission(
            catalog=policy_fixtures._catalog(),
            phase="delegation",
            operation="delegation-create-v1",
            effect_request={},
            identity_bindings={},
            identity_center_instance_arn=INSTANCE_ARN,
            identity_center_kms_mode="AWS_OWNED_KMS_KEY",
            identity_center_kms_key_arn=None,
            session_opener_for_policy=lambda *_args: None,
            expected_identity_center_kms_binding_digest=(
                "sha256:" + "0" * 64
            ),
            clock=lambda: datetime(2026, 9, 1, tzinfo=UTC),
            before_call=lambda: None,
        )
    assert captured.value.code == (
        "BROKER_COLLISION_IDENTITY_CENTER_BINDING_INVALID"
    )


def test_broker_lifecycle_uses_the_canonical_phase_for_every_operation() -> None:
    cfg = _config()
    catalog = broker._InlineCollisionAdmissionAdapter(
        config=cfg,
        session_opener_for_policy=lambda *_args, **_kwargs: None,
        kms_bindings=broker._collision_parameter_bindings(cfg),
        clock=lambda: datetime(2026, 8, 30, 19, 0, tzinfo=UTC),
    )._catalog
    operations = {
        operation
        for _phase, phase_operations in admission.PHASE_OPERATION_ALLOWLIST.items()
        for operation in phase_operations
    }
    assert len(operations) == 41
    for phase, phase_operations in admission.PHASE_OPERATION_ALLOWLIST.items():
        for operation in phase_operations:
            assert admission.route_collision_operation_phase(operation) == phase
            assert subject._expected_dispositions(
                catalog,
                operation,
            ) == admission.expected_route_collision_dispositions(
                catalog,
                phase,
                operation,
            )
