from __future__ import annotations

from collections import Counter
import copy
from dataclasses import dataclass
from pathlib import Path
import re
from typing import Any, Mapping

import pytest
import yaml
from yaml.nodes import MappingNode, ScalarNode, SequenceNode

from tooling import platform_authority_gug376_collision_catalog as subject


REPO_ROOT = Path(__file__).resolve().parents[2]
SOURCE_COMMIT = "a" * 40
SOURCE_TREE = "b" * 40
BOOTSTRAP_INTENT_DIGEST = "sha256:" + "c" * 64
ARTIFACT_BUCKET = (
    "scanalyze-g376-art-aaaaaaaaaaaa-042360977644-us-east-1-an"
)


@dataclass(frozen=True)
class _Intrinsic:
    tag: str
    value: object


class _CloudFormationLoader(yaml.SafeLoader):
    pass


def _construct_intrinsic(
    loader: yaml.SafeLoader,
    tag_suffix: str,
    node: ScalarNode | SequenceNode | MappingNode,
) -> _Intrinsic:
    if isinstance(node, ScalarNode):
        value: object = loader.construct_scalar(node)
    elif isinstance(node, SequenceNode):
        value = loader.construct_sequence(node, deep=True)
    else:
        value = loader.construct_mapping(node, deep=True)
    return _Intrinsic(tag_suffix, value)


_CloudFormationLoader.add_multi_constructor("!", _construct_intrinsic)


@dataclass(frozen=True)
class _RouteTemplate:
    relative_path: str
    stack_name: str
    domain: str
    account_id: str
    phase: str
    synthetic_parameters: Mapping[str, str]


_FOUNDATION_PARAMETERS = {
    "SourceCommit": SOURCE_COMMIT,
    "ArtifactBucketName": ARTIFACT_BUCKET,
    "ArtifactKmsAlias": (
        "alias/scanalyze-platform-authority-gug376-artifacts-"
        f"{SOURCE_COMMIT[:12]}"
    ),
    "SigningProfileName": f"ScanalyzeGug376ArtifactSigner_{SOURCE_COMMIT[:12]}",
}

_ROUTE_TEMPLATES = (
    _RouteTemplate(
        "bootstrap/cfn-platform-authority-gug376-artifact-bootstrap-bridge.yaml",
        subject.BRIDGE_STACK_NAME,
        "management",
        subject.MANAGEMENT_ACCOUNT_ID,
        "artifact-bridge",
        {},
    ),
    _RouteTemplate(
        "bootstrap/cfn-platform-authority-gug376-artifact-foundation.yaml",
        subject.FOUNDATION_STACK_NAME,
        "authority",
        subject.AUTHORITY_ACCOUNT_ID,
        "artifact-foundation",
        _FOUNDATION_PARAMETERS,
    ),
    _RouteTemplate(
        "bootstrap/cfn-platform-authority-gug376-temporary-change-set-route.yaml",
        subject.ROUTE_STACK_NAME,
        "management",
        subject.MANAGEMENT_ACCOUNT_ID,
        "route",
        {},
    ),
    _RouteTemplate(
        "bootstrap/cfn-platform-authority-gug376-route-broker-seed.template.yaml",
        subject.BROKER_STACK_NAME,
        "authority",
        subject.AUTHORITY_ACCOUNT_ID,
        "broker",
        {},
    ),
    _RouteTemplate(
        "bootstrap/cfn-platform-authority-bootstrap-plan-repair-delegation.yaml",
        subject.DELEGATION_STACK_NAME,
        "management",
        subject.MANAGEMENT_ACCOUNT_ID,
        "delegation",
        {},
    ),
    _RouteTemplate(
        "bootstrap/cfn-platform-authority-bootstrap-plan-repair-pep.yaml",
        subject.PEP_STACK_NAME,
        "authority",
        subject.AUTHORITY_ACCOUNT_ID,
        "pep",
        {},
    ),
)

_EXACT_PHYSICAL_PROPERTIES = {
    "AWS::DynamoDB::Table": ("dynamodb", "table", "TableName"),
    "AWS::KMS::Alias": ("kms", "alias", "AliasName"),
    "AWS::Lambda::Function": ("lambda", "function", "FunctionName"),
    "AWS::Logs::LogGroup": ("logs", "log_group", "LogGroupName"),
    "AWS::S3::Bucket": ("s3", "bucket", "BucketName"),
    "AWS::Signer::SigningProfile": (
        "signer",
        "signing_profile",
        "ProfileName",
    ),
    "AWS::SSO::Application": ("sso", "application", "Name"),
    "AWS::SSO::PermissionSet": ("sso", "permission_set", "Name"),
}

_NON_NAMED_RESOURCE_TYPES = {
    "AWS::KMS::Key",
    "AWS::Lambda::EventInvokeConfig",
    "AWS::Lambda::RuntimeManagementConfig",
    "AWS::Lambda::Version",
    "AWS::S3::BucketPolicy",
    "AWS::SSO::Assignment",
}

_OWNERSHIP_TAGS = {
    "managed_by": "cloudformation",
    "service": "scanalyze-platform-authority",
    "work_package": "GUG-376",
}


def _load_template(spec: _RouteTemplate) -> dict[str, Any]:
    source = (REPO_ROOT / spec.relative_path).read_text(encoding="utf-8")
    source = re.sub(
        r"@@([A-Z0-9_]+)@@",
        r"SYNTHETIC_\1",
        source,
    )
    loaded = yaml.load(
        source,
        Loader=_CloudFormationLoader,
    )
    assert isinstance(loaded, dict), spec.relative_path
    assert isinstance(loaded.get("Resources"), dict), spec.relative_path
    return loaded


def _resolve_resource_ref(
    logical_id: str,
    *,
    resources: Mapping[str, Any],
    parameters: Mapping[str, str],
    spec: _RouteTemplate,
) -> str:
    resource = resources.get(logical_id)
    assert isinstance(resource, Mapping), (
        spec.relative_path,
        logical_id,
        "unresolved resource Ref",
    )
    resource_type = resource.get("Type")
    properties = resource.get("Properties")
    assert isinstance(properties, Mapping), (spec.relative_path, logical_id)
    if resource_type == "AWS::IAM::Role":
        property_name = "RoleName"
    else:
        physical = _EXACT_PHYSICAL_PROPERTIES.get(str(resource_type))
        assert physical is not None, (
            spec.relative_path,
            logical_id,
            resource_type,
            "unsupported physical Ref",
        )
        property_name = physical[2]
    assert property_name in properties, (
        spec.relative_path,
        logical_id,
        property_name,
    )
    return _resolve_physical_value(
        properties[property_name],
        resources=resources,
        parameters=parameters,
        spec=spec,
    )


def _resolve_substitution(
    value: object,
    *,
    resources: Mapping[str, Any],
    parameters: Mapping[str, str],
    spec: _RouteTemplate,
) -> str:
    overrides: Mapping[str, Any] = {}
    if isinstance(value, str):
        template = value
    else:
        assert isinstance(value, list) and len(value) == 2
        template, raw_overrides = value
        assert isinstance(template, str) and isinstance(raw_overrides, Mapping)
        overrides = raw_overrides

    def replace(match: re.Match[str]) -> str:
        key = match.group(1)
        if key in overrides:
            return _resolve_physical_value(
                overrides[key],
                resources=resources,
                parameters=parameters,
                spec=spec,
            )
        return _resolve_physical_value(
            _Intrinsic("Ref", key),
            resources=resources,
            parameters=parameters,
            spec=spec,
        )

    return re.sub(r"\$\{([^}]+)\}", replace, template)


def _resolve_physical_value(
    value: object,
    *,
    resources: Mapping[str, Any],
    parameters: Mapping[str, str],
    spec: _RouteTemplate,
) -> str:
    if isinstance(value, str):
        return value
    assert isinstance(value, _Intrinsic), (
        spec.relative_path,
        value,
        "physical name must be a string or supported intrinsic",
    )
    if value.tag == "Ref":
        assert isinstance(value.value, str)
        if value.value in parameters:
            return parameters[value.value]
        pseudo_parameters = {
            "AWS::AccountId": spec.account_id,
            "AWS::Partition": "aws",
            "AWS::Region": subject.REGION,
        }
        if value.value in pseudo_parameters:
            return pseudo_parameters[value.value]
        return _resolve_resource_ref(
            value.value,
            resources=resources,
            parameters=parameters,
            spec=spec,
        )
    if value.tag == "Sub":
        return _resolve_substitution(
            value.value,
            resources=resources,
            parameters=parameters,
            spec=spec,
        )
    if value.tag == "Join":
        assert isinstance(value.value, list) and len(value.value) == 2
        delimiter, parts = value.value
        assert isinstance(delimiter, str) and isinstance(parts, list)
        return delimiter.join(
            _resolve_physical_value(
                part,
                resources=resources,
                parameters=parameters,
                spec=spec,
            )
            for part in parts
        )
    raise AssertionError(
        (spec.relative_path, value.tag, "unsupported physical-name intrinsic")
    )


def _binding(
    spec: _RouteTemplate,
    *,
    service: str,
    scope: str,
    name: str,
    selector: Mapping[str, Any],
) -> tuple[object, ...]:
    return (
        service,
        spec.domain,
        spec.account_id,
        subject.REGION,
        scope,
        name,
        subject.canonical_json(selector),
        (spec.phase,),
    )


def _iam_role_name(
    properties: Mapping[str, Any],
    *,
    resources: Mapping[str, Any],
    parameters: Mapping[str, str],
    spec: _RouteTemplate,
) -> str | None:
    if "RoleName" not in properties:
        return None
    role_name = _resolve_physical_value(
        properties["RoleName"],
        resources=resources,
        parameters=parameters,
        spec=spec,
    )
    path = _resolve_physical_value(
        properties.get("Path", "/"),
        resources=resources,
        parameters=parameters,
        spec=spec,
    )
    assert path.startswith("/") and path.endswith("/"), (
        spec.relative_path,
        path,
    )
    return f"{path.strip('/')}/{role_name}".lstrip("/")


def _code_signing_selector(
    logical_id: str,
    properties: Mapping[str, Any],
    *,
    resources: Mapping[str, Any],
    parameters: Mapping[str, str],
    spec: _RouteTemplate,
) -> dict[str, Any]:
    raw_tags = properties.get("Tags", [])
    assert isinstance(raw_tags, list), (spec.relative_path, logical_id)
    tags: dict[str, str] = {}
    for item in raw_tags:
        assert isinstance(item, Mapping) and set(item) == {"Key", "Value"}
        key = _resolve_physical_value(
            item["Key"],
            resources=resources,
            parameters=parameters,
            spec=spec,
        )
        tags[key] = _resolve_physical_value(
            item["Value"],
            resources=resources,
            parameters=parameters,
            spec=spec,
        )
    matching_tags = {
        key: tags[key] for key in _OWNERSHIP_TAGS if key in tags
    }
    assert not matching_tags or matching_tags == _OWNERSHIP_TAGS, (
        spec.relative_path,
        logical_id,
        "partial ownership tags cannot select a generated physical id",
    )
    selector: dict[str, Any] = {
        "kind": (
            "cloudformation_ownership_tags"
            if matching_tags
            else "cloudformation_stack_resource"
        ),
        "stack_name": spec.stack_name,
        "logical_resource_id": logical_id,
    }
    if matching_tags:
        selector["required_tags"] = _OWNERSHIP_TAGS
    return selector


def _template_physical_bindings() -> list[tuple[object, ...]]:
    bindings: list[tuple[object, ...]] = []
    for spec in _ROUTE_TEMPLATES:
        template = _load_template(spec)
        resources = template["Resources"]
        parameters = dict(spec.synthetic_parameters)
        bindings.append(
            _binding(
                spec,
                service="cloudformation",
                scope="stack",
                name=spec.stack_name,
                selector={"kind": "exact_name"},
            )
        )
        for logical_id, resource in resources.items():
            assert isinstance(logical_id, str) and isinstance(resource, Mapping)
            resource_type = resource.get("Type")
            properties = resource.get("Properties", {})
            assert isinstance(resource_type, str) and isinstance(
                properties, Mapping
            )
            if resource_type == "AWS::IAM::Role":
                name = _iam_role_name(
                    properties,
                    resources=resources,
                    parameters=parameters,
                    spec=spec,
                )
                if name is not None:
                    bindings.append(
                        _binding(
                            spec,
                            service="iam",
                            scope="role",
                            name=name,
                            selector={"kind": "exact_name"},
                        )
                    )
                continue
            if resource_type == "AWS::Lambda::Alias":
                assert {"FunctionName", "Name"} <= set(properties), (
                    spec.relative_path,
                    logical_id,
                )
                function_name = _resolve_physical_value(
                    properties["FunctionName"],
                    resources=resources,
                    parameters=parameters,
                    spec=spec,
                )
                alias_name = _resolve_physical_value(
                    properties["Name"],
                    resources=resources,
                    parameters=parameters,
                    spec=spec,
                )
                bindings.append(
                    _binding(
                        spec,
                        service="lambda",
                        scope="alias",
                        name=f"{function_name}:{alias_name}",
                        selector={
                            "kind": "lambda_alias",
                            "function_name": function_name,
                            "alias_name": alias_name,
                        },
                    )
                )
                continue
            if resource_type == "AWS::Lambda::CodeSigningConfig":
                selector = _code_signing_selector(
                    logical_id,
                    properties,
                    resources=resources,
                    parameters=parameters,
                    spec=spec,
                )
                bindings.append(
                    _binding(
                        spec,
                        service="lambda",
                        scope="code_signing_config",
                        name=f"{spec.stack_name}/{logical_id}",
                        selector=selector,
                    )
                )
                continue
            physical = _EXACT_PHYSICAL_PROPERTIES.get(resource_type)
            if physical is None:
                assert resource_type in _NON_NAMED_RESOURCE_TYPES, (
                    spec.relative_path,
                    logical_id,
                    resource_type,
                    "unclassified CloudFormation resource type",
                )
                continue
            if physical[2] not in properties:
                continue
            service, scope, property_name = physical
            name = _resolve_physical_value(
                properties[property_name],
                resources=resources,
                parameters=parameters,
                spec=spec,
            )
            bindings.append(
                _binding(
                    spec,
                    service=service,
                    scope=scope,
                    name=name,
                    selector={"kind": "exact_name"},
                )
            )
    return bindings


def _catalog_binding(target: Mapping[str, Any]) -> tuple[object, ...]:
    return (
        target["service"],
        target["domain"],
        target["account_id"],
        target["region"],
        target["scope"],
        target["name"],
        subject.canonical_json(target["selector"]),
        tuple(target["phases"]),
    )


def _catalog() -> dict[str, object]:
    return subject.materialize_route_collision_catalog(
        source_commit_sha=SOURCE_COMMIT,
        source_tree_sha=SOURCE_TREE,
        bootstrap_intent_digest=BOOTSTRAP_INTENT_DIGEST,
        not_before="2026-09-01T00:00:00Z",
        expires_at="2026-09-01T02:00:00Z",
        artifact_bucket_name=ARTIFACT_BUCKET,
    )


def _reseal(value: dict[str, object]) -> None:
    sealed = dict(value)
    sealed.pop("catalog_digest", None)
    value["catalog_digest"] = subject.canonical_digest(sealed)


def _target(value: dict[str, object], target_id: str) -> dict[str, object]:
    targets = value["targets"]
    assert isinstance(targets, list)
    return next(item for item in targets if item["target_id"] == target_id)


def test_catalog_is_stable_sorted_and_digest_sealed() -> None:
    first = _catalog()
    second = _catalog()

    assert first == second
    assert first["target_count"] == len(first["targets"])
    assert first["catalog_digest"] == subject.canonical_digest(
        {key: value for key, value in first.items() if key != "catalog_digest"}
    )
    unsigned = dict(first)
    digest = unsigned.pop("catalog_digest")
    assert digest == subject.canonical_digest(unsigned)

    targets = first["targets"]
    assert isinstance(targets, list)
    phase_indexes = [
        subject.PHASE_ORDER.index(item["phases"][0]) for item in targets
    ]
    assert phase_indexes == sorted(phase_indexes)
    assert len({item["target_id"] for item in targets}) == len(targets)
    assert subject.validate_route_collision_catalog(first) is None


def test_catalog_has_exact_top_and_target_schema() -> None:
    catalog = _catalog()
    assert set(catalog) == {
        "schema_version",
        "record_type",
        "source_commit_sha",
        "source_tree_sha",
        "bootstrap_intent_digest",
        "authority_account_id",
        "management_account_id",
        "region",
        "not_before",
        "expires_at",
        "artifact_bucket_name",
        "targets",
        "target_count",
        "catalog_digest",
    }
    target_fields = {
        "target_id",
        "service",
        "domain",
        "account_id",
        "region",
        "scope",
        "name",
        "selector",
        "phases",
        "lifecycle",
    }
    assert all(set(item) == target_fields for item in catalog["targets"])
    collision_only = {
        item["target_id"]
        for item in catalog["targets"]
        if item["lifecycle"] == "COLLISION_ONLY"
    }
    assert collision_only == {
        "management.sso.retirement-application",
        "management.sso.retirement-approver",
        "management.sso.retirement-classifier",
    }
    assert all(
        item["lifecycle"] == "ROUTE_CREATED"
        for item in catalog["targets"]
        if item["target_id"] not in collision_only
    )

    invalid = copy.deepcopy(catalog)
    invalid["unexpected"] = False
    _reseal(invalid)
    with pytest.raises(subject.CollisionCatalogError) as captured:
        subject.validate_route_collision_catalog(invalid)
    assert captured.value.code == "CATALOG_FIELDS_INVALID"

    invalid = copy.deepcopy(catalog)
    invalid["targets"][0]["unexpected"] = False
    _reseal(invalid)
    with pytest.raises(subject.CollisionCatalogError) as captured:
        subject.validate_route_collision_catalog(invalid)
    assert captured.value.code == "TARGET_FIELDS_INVALID"


def test_catalog_rejects_duplicate_missing_and_unknown_targets() -> None:
    catalog = _catalog()

    duplicate = copy.deepcopy(catalog)
    duplicate["targets"].append(copy.deepcopy(duplicate["targets"][0]))
    duplicate["target_count"] += 1
    _reseal(duplicate)
    with pytest.raises(subject.CollisionCatalogError) as captured:
        subject.validate_route_collision_catalog(duplicate)
    assert captured.value.code == "TARGET_DUPLICATE"

    missing = copy.deepcopy(catalog)
    missing["targets"].pop()
    missing["target_count"] -= 1
    _reseal(missing)
    with pytest.raises(subject.CollisionCatalogError) as captured:
        subject.validate_route_collision_catalog(missing)
    assert captured.value.code == "TARGET_SET_INVALID"

    unknown = copy.deepcopy(catalog)
    unknown["targets"][0]["target_id"] = "management.cfn.future-stack"
    _reseal(unknown)
    with pytest.raises(subject.CollisionCatalogError) as captured:
        subject.validate_route_collision_catalog(unknown)
    assert captured.value.code == "TARGET_SET_INVALID"


@pytest.mark.parametrize(
    ("field", "value", "code"),
    [
        ("account_id", subject.AUTHORITY_ACCOUNT_ID, "TARGET_ACCOUNT_INVALID"),
        ("region", "us-west-2", "TARGET_REGION_INVALID"),
        ("name", "future-${SOURCE_COMMIT}", "TARGET_NAME_AMBIGUOUS"),
    ],
)
def test_catalog_rejects_invalid_target_bindings(
    field: str, value: str, code: str
) -> None:
    invalid = _catalog()
    invalid["targets"][0][field] = value
    _reseal(invalid)

    with pytest.raises(subject.CollisionCatalogError) as captured:
        subject.validate_route_collision_catalog(invalid)
    assert captured.value.code == code


def test_catalog_rejects_top_account_region_and_digest_changes() -> None:
    catalog = _catalog()

    wrong_account = copy.deepcopy(catalog)
    wrong_account["authority_account_id"] = subject.MANAGEMENT_ACCOUNT_ID
    _reseal(wrong_account)
    with pytest.raises(subject.CollisionCatalogError) as captured:
        subject.validate_route_collision_catalog(wrong_account)
    assert captured.value.code == "CATALOG_ACCOUNT_INVALID"

    wrong_region = copy.deepcopy(catalog)
    wrong_region["region"] = "us-west-2"
    _reseal(wrong_region)
    with pytest.raises(subject.CollisionCatalogError) as captured:
        subject.validate_route_collision_catalog(wrong_region)
    assert captured.value.code == "CATALOG_REGION_INVALID"

    wrong_digest = copy.deepcopy(catalog)
    wrong_digest["catalog_digest"] = "sha256:" + "d" * 64
    with pytest.raises(subject.CollisionCatalogError) as captured:
        subject.validate_route_collision_catalog(wrong_digest)
    assert captured.value.code == "CATALOG_DIGEST_INVALID"


@pytest.mark.parametrize(
    "bucket_name",
    [
        "future-${SOURCE_COMMIT}",
        "192.168.0.1",
        "Scanalyze-GUG376",
        "scanalyze..gug376",
        "xn--scanalyze-gug376",
    ],
)
def test_materializer_rejects_ambiguous_or_invalid_bucket_names(
    bucket_name: str,
) -> None:
    with pytest.raises(subject.CollisionCatalogError) as captured:
        subject.materialize_route_collision_catalog(
            source_commit_sha=SOURCE_COMMIT,
            source_tree_sha=SOURCE_TREE,
            bootstrap_intent_digest=BOOTSTRAP_INTENT_DIGEST,
            not_before="2026-09-01T00:00:00Z",
            expires_at="2026-09-01T02:00:00Z",
            artifact_bucket_name=bucket_name,
        )
    assert captured.value.code in {
        "ARTIFACT_BUCKET_NAME_INVALID",
        "ARTIFACT_BUCKET_BINDING_INVALID",
    }


def test_catalog_rejects_valid_but_wrong_bucket_or_commit_binding() -> None:
    with pytest.raises(subject.CollisionCatalogError) as captured:
        subject.materialize_route_collision_catalog(
            source_commit_sha=SOURCE_COMMIT,
            source_tree_sha=SOURCE_TREE,
            bootstrap_intent_digest=BOOTSTRAP_INTENT_DIGEST,
            not_before="2026-09-01T00:00:00Z",
            expires_at="2026-09-01T02:00:00Z",
            artifact_bucket_name=(
                "scanalyze-g376-art-dddddddddddd-"
                "042360977644-us-east-1-an"
            ),
        )
    assert captured.value.code == "ARTIFACT_BUCKET_BINDING_INVALID"

    catalog = _catalog()
    catalog["artifact_bucket_name"] = (
        "scanalyze-g376-art-dddddddddddd-042360977644-us-east-1-an"
    )
    _reseal(catalog)
    with pytest.raises(subject.CollisionCatalogError) as captured:
        subject.validate_route_collision_catalog(catalog)
    assert captured.value.code == "ARTIFACT_BUCKET_BINDING_INVALID"


@pytest.mark.parametrize(
    ("not_before", "expires_at"),
    [
        ("2026-09-01T02:00:00Z", "2026-09-01T02:00:00Z"),
        ("2026-09-01T02:00:00Z", "2026-09-01T01:00:00Z"),
        ("2026-09-01T00:00:00Z", "2026-09-01T02:00:01Z"),
        ("2026-09-01T00:00:00+00:00", "2026-09-01T01:00:00Z"),
    ],
)
def test_materializer_rejects_invalid_or_ambiguous_window(
    not_before: str, expires_at: str
) -> None:
    with pytest.raises(subject.CollisionCatalogError) as captured:
        subject.materialize_route_collision_catalog(
            source_commit_sha=SOURCE_COMMIT,
            source_tree_sha=SOURCE_TREE,
            bootstrap_intent_digest=BOOTSTRAP_INTENT_DIGEST,
            not_before=not_before,
            expires_at=expires_at,
            artifact_bucket_name=ARTIFACT_BUCKET,
        )
    assert captured.value.code == "WINDOW_INVALID"


def test_code_signing_configs_use_closed_ownership_selectors() -> None:
    catalog = _catalog()
    configs = [
        item
        for item in catalog["targets"]
        if item["scope"] == "code_signing_config"
    ]
    assert {item["target_id"] for item in configs} == {
        "authority.lambda.artifact-code-signing-config",
        "authority.lambda.route-broker-code-signing-config",
        "authority.lambda.plan-repair-code-signing-config",
    }
    assert {
        item["selector"]["kind"] for item in configs
    } == {
        "cloudformation_ownership_tags",
        "cloudformation_stack_resource",
    }
    broker = next(
        item
        for item in configs
        if item["target_id"]
        == "authority.lambda.route-broker-code-signing-config"
    )
    assert broker["selector"] == {
        "kind": "cloudformation_stack_resource",
        "stack_name": subject.BROKER_STACK_NAME,
        "logical_resource_id": "BrokerCodeSigningConfig",
    }


def test_catalog_covers_six_stacks_and_gug395_identity_targets() -> None:
    catalog = _catalog()
    names = {item["name"] for item in catalog["targets"]}
    assert {
        subject.BRIDGE_STACK_NAME,
        subject.FOUNDATION_STACK_NAME,
        subject.ROUTE_STACK_NAME,
        subject.BROKER_STACK_NAME,
        subject.DELEGATION_STACK_NAME,
        subject.PEP_STACK_NAME,
    } <= names
    assert {
        "ScanalyzeAuthorityRetirement",
        "ScanalyzeAuthorityRetireClass",
        "ScanalyzeAuthorityRetireApprove",
    } <= names
    assert ARTIFACT_BUCKET in names


def test_templates_and_catalog_have_identical_physical_bindings() -> None:
    catalog = _catalog()
    targets = catalog["targets"]
    assert isinstance(targets, list)
    collision_only = [
        target for target in targets if target["lifecycle"] == "COLLISION_ONLY"
    ]
    route_created = [
        target for target in targets if target["lifecycle"] != "COLLISION_ONLY"
    ]
    assert all(target["lifecycle"] == "ROUTE_CREATED" for target in route_created)

    template_bindings = _template_physical_bindings()
    catalog_bindings = [_catalog_binding(target) for target in route_created]

    assert len(template_bindings) == len(catalog_bindings)
    assert len(template_bindings) == catalog["target_count"] - len(collision_only)
    assert Counter(template_bindings) == Counter(catalog_bindings)
