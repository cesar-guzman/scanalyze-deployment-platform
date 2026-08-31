"""Deterministic private broker configuration for the GUG-376 live route.

The materializer consumes only attested template/artifact coordinates plus a
closed, read-only Plan snapshot.  It performs no AWS call.  Dynamic provider
identifiers are deliberately represented by one reviewed sentinel and are
resolved by the broker from terminal AWS readback.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import re
from typing import Any, Mapping, Sequence

from tooling import platform_authority_plan_permission_repair as repair
from tooling import platform_authority_plan_permission_repair_artifact_bootstrap as artifact_bootstrap
from tooling import platform_authority_plan_permission_repair_broker_seed as seed
from tooling import platform_authority_plan_permission_repair_broker_signed_artifact as broker_artifact
from tooling import platform_authority_plan_permission_repair_deployment_route as route
from tooling import platform_authority_plan_permission_repair_route_broker as broker
from tooling import platform_authority_plan_permission_repair_signed_artifact as pep_artifact
from tooling import platform_authority_plan_permission_repair_template_readback as template_readback


RECORD_TYPE = (
    "scanalyze.platform_authority.plan_permission_repair_broker_config_input.v1"
)
PLAN_SNAPSHOT_RECORD_TYPE = (
    "scanalyze.platform_authority.plan_permission_repair_plan_seed_snapshot.v1"
)
EXACT_STACK_TAGS = [
    {"Key": "managed_by", "Value": "cloudformation"},
    {"Key": "service", "Value": "scanalyze-platform-authority"},
    {"Key": "work_package", "Value": "GUG-376"},
]
MIN_ROUTE_WINDOW_SECONDS = broker.MIN_ROUTE_WINDOW_SECONDS
DYNAMIC_IMMUTABLE_DIGEST_SENTINEL = "sha256:" + "0" * 64

_INPUT_FIELDS = frozenset(
    {
        "schema_version",
        "record_type",
        "source_commit",
        "route_not_before",
        "route_not_after",
        "repair_not_before",
        "repair_not_after",
        "bootstrap_change_set_name",
        "artifact_bootstrap_intent",
        "foundation_publish_binding",
        "plan_snapshot",
        "template_readbacks",
        "broker_artifact_handoff",
        "pep_signed_artifact_receipt",
        "production_authorized",
        "input_digest",
    }
)
_UNBOUND_INPUT_FIELDS = _INPUT_FIELDS - {"plan_snapshot"}
_PLAN_SNAPSHOT_FIELDS = frozenset(
    {
        "schema_version",
        "record_type",
        "source_commit",
        "bootstrap_change_set_name",
        "management_account_id",
        "authority_account_id",
        "region",
        "identity_center_instance_arn",
        "identity_store_id",
        "identity_store_arn",
        "principal_id",
        "principal_user_arn",
        "permission_set_arn",
        "permission_set_description",
        "permission_set_tags",
        "current_policy_digest",
        "desired_policy_digest",
        "generated_role_arn",
        "generated_role_name",
        "saml_provider_arn",
        "identity_center_kms_mode",
        "identity_center_kms_key_arn",
        "authority_verifier",
        "identity_center_verifier",
        "observed_at",
        "aws_calls",
        "aws_mutations",
        "production_status",
        "snapshot_digest",
    }
)
_VERIFIER_FIELDS = frozenset({"profile", "account_id", "caller_arn", "region"})
_POLICY_TEMPLATE_PATH = "policies/iam/platform-authority-bootstrap-plan-role.json"
_COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_INSTANCE_RE = re.compile(r"^arn:aws:sso:::instance/ssoins-[A-Za-z0-9]{16}$")
_STORE_RE = re.compile(r"^d-[a-z0-9]{10,}$")
_PRINCIPAL_RE = re.compile(
    r"^(?:[0-9a-f]{10}-)?[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$"
)
_PERMISSION_SET_RE = re.compile(
    r"^arn:aws:sso:::permissionSet/ssoins-[A-Za-z0-9]{16}/ps-[A-Za-z0-9]{16}$"
)
_ROLE_RE = re.compile(
    r"^arn:aws:iam::042360977644:role/aws-reserved/sso.amazonaws.com/"
    r"AWSReservedSSO_ScanalyzeAuthorityBootstrapPlan_[0-9A-Fa-f]{16}$"
)
_SAML_RE = re.compile(
    r"^arn:aws:iam::042360977644:saml-provider/"
    r"AWSSSO_[A-Za-z0-9+=,.@_-]+_DO_NOT_DELETE$"
)
_TIME_RE = re.compile(
    r"^20[0-9]{2}-(?:0[1-9]|1[0-2])-(?:[0-2][0-9]|3[01])T"
    r"(?:[01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]Z$"
)
_AUTHORITY_VERIFIER_RE = re.compile(
    r"^arn:aws:sts::042360977644:assumed-role/"
    r"AWSReservedSSO_AWSReadOnlyAccess_[0-9A-Fa-f]{16}/"
    r"[A-Za-z0-9+=,.@_-]{1,64}$"
)
_IDENTITY_CENTER_VERIFIER_RE = re.compile(
    r"^arn:aws:sts::839393571433:assumed-role/"
    r"AWSReservedSSO_ScanalyzeFounderPepIdentityAdmin_[0-9A-Fa-f]{16}/"
    r"[A-Za-z0-9+=,.@_-]{1,64}$"
)


class BrokerConfigMaterializationError(ValueError):
    """Stable failure from the private broker config materializer."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def _fail(code: str) -> None:
    raise BrokerConfigMaterializationError(code)


def _stamp(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        _fail("TIME_INVALID")
    return (
        value.astimezone(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def _time(value: Any, code: str) -> datetime:
    if not isinstance(value, str) or _TIME_RE.fullmatch(value) is None:
        _fail(code)
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise BrokerConfigMaterializationError(code) from exc
    if parsed.microsecond:
        _fail(code)
    return parsed


def _verify_seal(value: Mapping[str, Any], field: str, code: str) -> str:
    claimed = value.get(field)
    if (
        not isinstance(claimed, str)
        or _DIGEST_RE.fullmatch(claimed) is None
        or route.digest_value(
            {key: item for key, item in value.items() if key != field}
        )
        != claimed
    ):
        _fail(code)
    return claimed


def validate_plan_snapshot(
    value: Mapping[str, Any], *, source_commit: str, now: datetime | None = None
) -> dict[str, Any]:
    """Validate the private read-only seed snapshot consumed by this builder."""

    if not isinstance(value, Mapping) or set(value) != _PLAN_SNAPSHOT_FIELDS:
        _fail("PLAN_SNAPSHOT_FIELDS_INVALID")
    snapshot = json.loads(route.canonical_json(dict(value)))
    _verify_seal(snapshot, "snapshot_digest", "PLAN_SNAPSHOT_DIGEST_INVALID")
    try:
        change_set_name = repair.validate_bootstrap_change_set_name(
            snapshot.get("bootstrap_change_set_name")
        )
    except Exception as exc:
        raise BrokerConfigMaterializationError(
            "PLAN_SNAPSHOT_CHANGE_SET_INVALID"
        ) from exc
    authority = snapshot.get("authority_verifier")
    identity = snapshot.get("identity_center_verifier")
    tags = snapshot.get("permission_set_tags")
    if (
        snapshot.get("schema_version") != 1
        or snapshot.get("record_type") != PLAN_SNAPSHOT_RECORD_TYPE
        or snapshot.get("source_commit") != source_commit
        or snapshot.get("bootstrap_change_set_name") != change_set_name
        or snapshot.get("management_account_id") != route.MANAGEMENT_ACCOUNT_ID
        or snapshot.get("authority_account_id") != route.AUTHORITY_ACCOUNT_ID
        or snapshot.get("region") != route.REGION
        or _INSTANCE_RE.fullmatch(
            str(snapshot.get("identity_center_instance_arn", ""))
        )
        is None
        or _STORE_RE.fullmatch(str(snapshot.get("identity_store_id", ""))) is None
        or snapshot.get("identity_store_arn")
        != (
            f"arn:aws:identitystore::{route.MANAGEMENT_ACCOUNT_ID}:identitystore/"
            f"{snapshot.get('identity_store_id')}"
        )
        or _PRINCIPAL_RE.fullmatch(str(snapshot.get("principal_id", ""))) is None
        or snapshot.get("principal_user_arn")
        != f"arn:aws:identitystore:::user/{snapshot.get('principal_id')}"
        or _PERMISSION_SET_RE.fullmatch(str(snapshot.get("permission_set_arn", "")))
        is None
        or not isinstance(snapshot.get("permission_set_description"), str)
        or not 1 <= len(snapshot["permission_set_description"].encode("utf-8")) <= 700
        or not isinstance(tags, Mapping)
        or not tags
        or any(
            not isinstance(key, str)
            or not key
            or not isinstance(item, str)
            or not item
            for key, item in tags.items()
        )
        or any(
            _DIGEST_RE.fullmatch(str(snapshot.get(field, ""))) is None
            for field in ("current_policy_digest", "desired_policy_digest")
        )
        or snapshot.get("current_policy_digest")
        == snapshot.get("desired_policy_digest")
        or _ROLE_RE.fullmatch(str(snapshot.get("generated_role_arn", ""))) is None
        or not str(snapshot["generated_role_arn"]).endswith(
            "/" + str(snapshot.get("generated_role_name", ""))
        )
        or _SAML_RE.fullmatch(str(snapshot.get("saml_provider_arn", ""))) is None
        or snapshot.get("identity_center_kms_mode")
        not in {"AWS_OWNED_KMS_KEY", "CUSTOMER_MANAGED_KEY"}
        or not isinstance(authority, Mapping)
        or set(authority) != _VERIFIER_FIELDS
        or not isinstance(identity, Mapping)
        or set(identity) != _VERIFIER_FIELDS
        or authority.get("account_id") != route.AUTHORITY_ACCOUNT_ID
        or identity.get("account_id") != route.MANAGEMENT_ACCOUNT_ID
        or authority.get("region") != route.REGION
        or identity.get("region") != route.REGION
        or any(
            not isinstance(item.get(field), str) or not item.get(field)
            for item in (authority, identity)
            for field in ("profile", "caller_arn")
        )
        or authority.get("profile") != "042360977644_AWSReadOnlyAccess"
        or identity.get("profile")
        != "839393571433_ScanalyzeFounderPepIdentityAdmin"
        or _AUTHORITY_VERIFIER_RE.fullmatch(str(authority.get("caller_arn", "")))
        is None
        or _IDENTITY_CENTER_VERIFIER_RE.fullmatch(
            str(identity.get("caller_arn", ""))
        )
        is None
        or type(snapshot.get("aws_calls")) is not int
        or snapshot["aws_calls"] < 2
        or snapshot.get("aws_mutations") != 0
        or snapshot.get("production_status") != "NO-GO"
    ):
        _fail("PLAN_SNAPSHOT_INVALID")
    kms_key = snapshot.get("identity_center_kms_key_arn")
    if (
        snapshot["identity_center_kms_mode"] == "AWS_OWNED_KMS_KEY"
        and kms_key is not None
    ) or (
        snapshot["identity_center_kms_mode"] == "CUSTOMER_MANAGED_KEY"
        and (
            not isinstance(kms_key, str)
            or re.fullmatch(
                r"arn:aws:kms:us-east-1:839393571433:key/"
                r"[0-9a-fA-F-]{36}",
                kms_key,
            )
            is None
        )
    ):
        _fail("PLAN_SNAPSHOT_KMS_INVALID")
    evaluated = (now or datetime.now(timezone.utc)).astimezone(timezone.utc).replace(
        microsecond=0
    )
    observed = _time(snapshot.get("observed_at"), "PLAN_SNAPSHOT_TIME_INVALID")
    if observed > evaluated or (evaluated - observed).total_seconds() > 900:
        _fail("PLAN_SNAPSHOT_STALE")
    return snapshot


def bind_plan_snapshot(
    value: Mapping[str, Any],
    *,
    plan_snapshot: Mapping[str, Any],
    now: datetime | None = None,
) -> dict[str, Any]:
    """Join one independently captured snapshot to one sealed private draft.

    The product CLI deliberately accepts the connected snapshot only through
    its own owner-only file.  A draft that already embeds a snapshot is a
    second authority and is rejected rather than silently replaced.
    """

    if not isinstance(value, Mapping) or set(value) != _UNBOUND_INPUT_FIELDS:
        _fail("BROKER_CONFIG_DRAFT_FIELDS_INVALID")
    draft = json.loads(route.canonical_json(dict(value)))
    _verify_seal(
        draft, "input_digest", "BROKER_CONFIG_DRAFT_DIGEST_INVALID"
    )
    source_commit = draft.get("source_commit")
    if not isinstance(source_commit, str) or _COMMIT_RE.fullmatch(source_commit) is None:
        _fail("BROKER_CONFIG_DRAFT_INVALID")
    snapshot = validate_plan_snapshot(
        plan_snapshot,
        source_commit=source_commit,
        now=now,
    )
    if (
        draft.get("bootstrap_change_set_name")
        != snapshot.get("bootstrap_change_set_name")
    ):
        _fail("PLAN_SNAPSHOT_CHANGE_SET_MISMATCH")
    joined = {
        key: item for key, item in draft.items() if key != "input_digest"
    }
    joined["plan_snapshot"] = snapshot
    joined["input_digest"] = route.digest_value(joined)
    return joined


def _inventory(source: bytes) -> list[dict[str, str]]:
    try:
        return route._template_inventory(source)  # noqa: SLF001
    except route.RouteSeedError as exc:
        raise BrokerConfigMaterializationError("TEMPLATE_INVENTORY_INVALID") from exc


def _outputs(source: bytes) -> list[str]:
    try:
        lines = source.decode("utf-8").splitlines()
    except UnicodeDecodeError as exc:
        raise BrokerConfigMaterializationError("TEMPLATE_OUTPUTS_INVALID") from exc
    in_outputs = False
    values: list[str] = []
    for line in lines:
        if line == "Outputs:":
            in_outputs = True
            continue
        if not in_outputs:
            continue
        match = re.fullmatch(
            r"  ([A-Za-z][A-Za-z0-9]+):(?: .+)?",
            line,
        )
        if match:
            values.append(match.group(1))
    if not values or len(values) != len(set(values)):
        _fail("TEMPLATE_OUTPUTS_INVALID")
    return sorted(values)


def _changes(resources: Sequence[Mapping[str, str]], action: str) -> list[dict[str, Any]]:
    return [
        {
            "action": action,
            "logical_resource_id": item["logical_resource_id"],
            "resource_type": item["resource_type"],
            "replacement": None,
            "scope": [],
            "details": [],
        }
        for item in sorted(resources, key=lambda item: item["logical_resource_id"])
    ]


def _remove(inventory: Mapping[str, str], *logical_ids: str) -> list[dict[str, Any]]:
    try:
        resources = [
            {"logical_resource_id": logical_id, "resource_type": inventory[logical_id]}
            for logical_id in logical_ids
        ]
    except KeyError as exc:
        raise BrokerConfigMaterializationError("TEMPLATE_INVENTORY_INVALID") from exc
    return _changes(resources, "Remove")


def _direct_change_detail(
    *, target_attribute: str, target_name: str | None,
    requires_recreation: str | None,
) -> dict[str, Any]:
    return {
        "target_attribute": target_attribute,
        "target_name": target_name,
        "requires_recreation": requires_recreation,
        "evaluation": "Static",
        "change_source": "DirectModification",
        "causing_entity": None,
    }


def _pep_protection_changes(
    inventory: Mapping[str, str],
) -> list[dict[str, Any]]:
    lifecycle_ids = set(seed.PEP_LIFECYCLE_RESOURCE_IDS)
    if not lifecycle_ids.issubset(inventory):
        _fail("TEMPLATE_INVENTORY_INVALID")
    changes: list[dict[str, Any]] = []
    for logical_id in sorted(lifecycle_ids):
        details = [
            _direct_change_detail(
                target_attribute="DeletionPolicy",
                target_name=None,
                requires_recreation=None,
            )
        ]
        scope = ["DeletionPolicy", "UpdateReplacePolicy"]
        if logical_id == "RepairLedger":
            details.append(
                _direct_change_detail(
                    target_attribute="Properties",
                    target_name="DeletionProtectionEnabled",
                    requires_recreation="Never",
                )
            )
            scope.append("Properties")
        details.append(
            _direct_change_detail(
                target_attribute="UpdateReplacePolicy",
                target_name=None,
                requires_recreation=None,
            )
        )
        changes.append(
            {
                "action": "Modify",
                "logical_resource_id": logical_id,
                "resource_type": inventory[logical_id],
                "replacement": "False",
                "scope": sorted(scope),
                "details": details,
            }
        )
    return changes


def _parameters(values: Mapping[str, str]) -> list[dict[str, str]]:
    return [
        {"ParameterKey": key, "ParameterValue": item}
        for key, item in values.items()
    ]


def _update_parameters(
    keys: Sequence[str], explicit: Mapping[str, str]
) -> list[dict[str, Any]]:
    if not set(explicit).issubset(keys):
        _fail("UPDATE_PARAMETER_BINDING_INVALID")
    return [
        (
            {"ParameterKey": key, "ParameterValue": explicit[key]}
            if key in explicit
            else {"ParameterKey": key, "UsePreviousValue": True}
        )
        for key in keys
    ]


def _create_request(
    *,
    stack_name: str,
    change_set_name: str,
    change_set_type: str,
    parameters: list[dict[str, Any]],
    template_url: str,
) -> dict[str, Any]:
    return {
        "StackName": stack_name,
        "ChangeSetName": change_set_name,
        "ChangeSetType": change_set_type,
        "Parameters": parameters,
        "TemplateURL": template_url,
    }


def _validate_handoff(
    value: Mapping[str, Any], *, source_commit: str, now: datetime,
    bootstrap_intent: Mapping[str, Any],
    foundation_publish_binding: Mapping[str, Any],
) -> dict[str, Any]:
    expected = {
        "schema_version",
        "record_type",
        "source_commit",
        "observed_at",
        "broker_code",
        "pep_runtime_binding",
        "aws_calls",
        "aws_mutations",
        "deployment_authorized",
        "production_status",
        "handoff_digest",
    }
    if not isinstance(value, Mapping) or set(value) != expected:
        _fail("BROKER_ARTIFACT_HANDOFF_INVALID")
    handoff = json.loads(route.canonical_json(dict(value)))
    _verify_seal(handoff, "handoff_digest", "BROKER_ARTIFACT_HANDOFF_INVALID")
    if (
        handoff.get("record_type") != broker_artifact.HANDOFF_TYPE
        or handoff.get("schema_version") != 1
        or handoff.get("source_commit") != source_commit
        or handoff.get("aws_mutations") != 0
        or handoff.get("deployment_authorized") is not False
        or handoff.get("production_status") != "NO-GO"
    ):
        _fail("BROKER_ARTIFACT_HANDOFF_INVALID")
    try:
        handoff["broker_code"] = seed.validate_broker_signing_receipt(
            handoff["broker_code"],
            source_commit=source_commit,
            now=now,
            bootstrap_intent=bootstrap_intent,
            foundation_publish_binding=foundation_publish_binding,
        )
        handoff["pep_runtime_binding"] = seed.validate_pep_runtime_binding(
            handoff["pep_runtime_binding"], source_commit=source_commit
        )
    except seed.BrokerSeedError as exc:
        raise BrokerConfigMaterializationError(
            "BROKER_ARTIFACT_HANDOFF_INVALID"
        ) from exc
    return handoff


def materialize_broker_seed_input(
    value: Mapping[str, Any],
    *,
    git: route.GitPort,
    expected_storage_binding: Mapping[str, Any],
    now: datetime | None = None,
) -> dict[str, Any]:
    """Build and validate the exact broker seed input without provider I/O."""

    if not isinstance(value, Mapping) or set(value) != _INPUT_FIELDS:
        _fail("BROKER_CONFIG_INPUT_FIELDS_INVALID")
    _verify_seal(value, "input_digest", "BROKER_CONFIG_INPUT_DIGEST_INVALID")
    source_commit = value.get("source_commit")
    if (
        value.get("schema_version") != 1
        or value.get("record_type") != RECORD_TYPE
        or not isinstance(source_commit, str)
        or _COMMIT_RE.fullmatch(source_commit) is None
        or value.get("production_authorized") is not False
    ):
        _fail("BROKER_CONFIG_INPUT_INVALID")
    try:
        bootstrap_intent = artifact_bootstrap.validate_bootstrap_intent(
            value.get("artifact_bootstrap_intent")
        )
        publish_binding = artifact_bootstrap.validate_foundation_publish_binding(
            value.get("foundation_publish_binding"),
            bootstrap_intent=bootstrap_intent,
        )
    except Exception as exc:
        raise BrokerConfigMaterializationError(
            "FOUNDATION_PUBLISH_BINDING_INVALID"
        ) from exc
    if (
        bootstrap_intent.get("source_commit") != source_commit
        or publish_binding.get("source_commit") != source_commit
        or expected_storage_binding != publish_binding
    ):
        _fail("FOUNDATION_PUBLISH_BINDING_INVALID")
    evaluated = (now or datetime.now(timezone.utc)).astimezone(timezone.utc).replace(
        microsecond=0
    )
    route_before = _time(value.get("route_not_before"), "ROUTE_WINDOW_INVALID")
    route_after = _time(value.get("route_not_after"), "ROUTE_WINDOW_INVALID")
    recovery_not_after = _stamp(route_after + timedelta(hours=24))
    repair_before = _time(value.get("repair_not_before"), "REPAIR_WINDOW_INVALID")
    repair_after = _time(value.get("repair_not_after"), "REPAIR_WINDOW_INVALID")
    if (
        not route_before < route_after
        or not MIN_ROUTE_WINDOW_SECONDS
        <= (route_after - route_before).total_seconds()
        <= 7200
        or not repair_before < repair_after
        or (repair_after - repair_before).total_seconds() > 900
        or not route_before <= repair_before < repair_after <= route_after
    ):
        _fail("WINDOW_BINDING_INVALID")
    change_set_name = value.get("bootstrap_change_set_name")
    try:
        repair.validate_bootstrap_change_set_name(change_set_name)
    except Exception as exc:
        raise BrokerConfigMaterializationError("BOOTSTRAP_CHANGE_SET_INVALID") from exc
    snapshot = validate_plan_snapshot(
        value.get("plan_snapshot"), source_commit=source_commit, now=evaluated
    )
    templates = value.get("template_readbacks")
    if not isinstance(templates, Mapping) or set(templates) != {
        "route_template",
        "delegation_template",
        "pep_template",
        "pep_protection_template",
    }:
        _fail("TEMPLATE_READBACK_SET_INVALID")
    if not isinstance(expected_storage_binding, Mapping):
        _fail("UPSTREAM_STORAGE_BINDING_INVALID")
    storage_binding: Mapping[str, Any] = publish_binding
    validated_templates: dict[str, dict[str, Any]] = {}
    for kind in (
        "route_template",
        "delegation_template",
        "pep_template",
        "pep_protection_template",
    ):
        try:
            receipt = template_readback.validate_template_readback_receipt(
                templates[kind],
                artifact_kind=kind,
                source_commit=source_commit,
                now=evaluated,
                expected_storage_binding=storage_binding,
            )
        except template_readback.TemplateReadbackError as exc:
            raise BrokerConfigMaterializationError("TEMPLATE_READBACK_INVALID") from exc
        storage_binding = receipt["upstream_storage_binding"]
        validated_templates[kind] = receipt
    handoff = _validate_handoff(
        value.get("broker_artifact_handoff"),
        source_commit=source_commit,
        now=evaluated,
        bootstrap_intent=bootstrap_intent,
        foundation_publish_binding=publish_binding,
    )
    pep_receipt = value.get("pep_signed_artifact_receipt")
    try:
        pep_artifact.validate_signed_artifact_receipt(
            pep_receipt,
            now=evaluated,
            bootstrap_intent=bootstrap_intent,
            foundation_publish_binding=publish_binding,
        )
    except Exception as exc:
        raise BrokerConfigMaterializationError("PEP_ARTIFACT_RECEIPT_INVALID") from exc
    if (
        pep_receipt.get("source_commit") != source_commit
        or handoff["pep_runtime_binding"]["pep_signed_artifact_receipt_digest"]
        != pep_receipt.get("receipt_digest")
        or pep_receipt.get("upstream_storage_binding") != storage_binding
        or handoff["broker_code"].get("upstream_storage_binding")
        != storage_binding
        or handoff["pep_runtime_binding"].get(
            "upstream_storage_binding_digest"
        )
        != storage_binding.get("binding_digest")
    ):
        _fail("PEP_ARTIFACT_BINDING_INVALID")
    source_paths = {
        "route_template": route.ROUTE_TEMPLATE_PATH,
        "delegation_template": route.DELEGATION_TEMPLATE_PATH,
        "pep_template": "bootstrap/cfn-platform-authority-bootstrap-plan-repair-pep.yaml",
        "broker_source": seed.SOURCE_TEMPLATE_PATH.as_posix(),
        "policy_template": _POLICY_TEMPLATE_PATH,
    }
    sources = {
        name: git.read_at(source_commit, path)
        for name, path in source_paths.items()
    }
    for kind in ("route_template", "delegation_template"):
        if route.bytes_digest(sources[kind]) != validated_templates[kind]["source_sha256"]:
            _fail("TEMPLATE_GIT_BINDING_INVALID")
    pep_source_digest = route.bytes_digest(sources["pep_template"])
    if any(
        validated_templates[kind]["source_sha256"] != pep_source_digest
        for kind in ("pep_template", "pep_protection_template")
    ):
        _fail("TEMPLATE_GIT_BINDING_INVALID")
    try:
        policy_template = json.loads(sources["policy_template"].decode("utf-8"))
        if not isinstance(policy_template, dict):
            raise ValueError("policy template must be an object")
        target_policy = repair.render_bootstrap_iam_policy(
            policy_template=policy_template,
            binding=repair._bootstrap_binding(),  # noqa: SLF001
            change_set_name=change_set_name,
        )
        predecessor_policy = repair.render_predecessor_policy(target_policy)
    except (UnicodeError, json.JSONDecodeError, ValueError, repair.PlanPermissionRepairError) as exc:
        raise BrokerConfigMaterializationError("POLICY_SOURCE_INVALID") from exc
    if (
        snapshot["current_policy_digest"]
        != repair.canonical_digest(predecessor_policy)
        or snapshot["desired_policy_digest"]
        != repair.canonical_digest(target_policy)
    ):
        _fail("POLICY_SOURCE_BINDING_INVALID")
    route_inventory_list = _inventory(sources["route_template"])
    delegation_inventory_list = _inventory(sources["delegation_template"])
    pep_inventory_list = _inventory(sources["pep_template"])
    route_inventory = {
        item["logical_resource_id"]: item["resource_type"]
        for item in route_inventory_list
    }
    delegation_inventory = {
        item["logical_resource_id"]: item["resource_type"]
        for item in delegation_inventory_list
    }
    if set(route_inventory) != {
        "ManagementBrokerCreatorRole",
        "ManagementBrokerExecutorRole",
        "BrokerSeedCreatorPermissionSet",
        "BrokerSeedExecutorPermissionSet",
        "BrokerInvokerPermissionSet",
        "BrokerSeedCreatorAssignment",
        "BrokerSeedExecutorAssignment",
        "BrokerInvokerAssignment",
    } or set(delegation_inventory) != {
        "MutationServiceRole",
        "ReadbackServiceRole",
        "RepairInvokerPermissionSet",
        "RepairInvokerAssignment",
    } or len(pep_inventory_list) != 26:
        _fail("TEMPLATE_INVENTORY_INVALID")
    route_outputs = _outputs(sources["route_template"])
    delegation_outputs = _outputs(sources["delegation_template"])
    pep_outputs = _outputs(sources["pep_template"])
    if len(route_outputs) != 10 or len(delegation_outputs) != 6 or len(pep_outputs) != 11:
        _fail("TEMPLATE_OUTPUTS_INVALID")

    repair_seed = {
        "source_commit": source_commit,
        "route_window": [value["route_not_before"], value["route_not_after"]],
        "recovery_not_after": recovery_not_after,
        "repair_window": [value["repair_not_before"], value["repair_not_after"]],
        "bootstrap_change_set_name": change_set_name,
        "plan_snapshot_digest": snapshot["snapshot_digest"],
        "pep_receipt_digest": pep_receipt["receipt_digest"],
        "broker_handoff_digest": handoff["handoff_digest"],
    }
    repair_id = "gug376-plan-permission-repair-" + route.digest_value(repair_seed)[7:]
    binding_digest = route.digest_value(
        {"record_type": RECORD_TYPE, "repair_id": repair_id, **repair_seed}
    )
    initialization_digest = broker.digest_value(
        {
            "record_type": broker.LEDGER_RECORD_TYPE,
            "ledger_id": broker.ROUTE_LEDGER_ID,
            "source_commit": source_commit,
            "binding_digest": binding_digest,
            "initial_state": "READY",
            "initial_version": 0,
            "retry_permitted": False,
        }
    )
    template_urls = {
        kind: validated_templates[kind]["template_url"]
        for kind in validated_templates
    }
    route_update_keys = route.ROUTE_PARAMETER_KEYS
    delegation_values = {
        "ManagementAccountId": route.MANAGEMENT_ACCOUNT_ID,
        "AuthorityAccountId": route.AUTHORITY_ACCOUNT_ID,
        "SourceCommit": source_commit,
        "IdentityCenterInstanceArn": snapshot["identity_center_instance_arn"],
        "IdentityStoreArn": snapshot["identity_store_arn"],
        "RepairPrincipalId": snapshot["principal_id"],
        "RepairPrincipalUserArn": snapshot["principal_user_arn"],
        "RepairInvokerAssignmentEnabled": "true",
        "PlanPermissionSetArn": snapshot["permission_set_arn"],
        "UseIdentityCenterCustomerManagedKms": (
            "true"
            if snapshot["identity_center_kms_mode"] == "CUSTOMER_MANAGED_KEY"
            else "false"
        ),
        "IdentityCenterKmsKeyArn": snapshot["identity_center_kms_key_arn"] or "",
    }
    signed_parameters = {
        item["ParameterKey"]: item["ParameterValue"]
        for item in pep_receipt["cloudformation_parameters"]
    }
    pep_values = {
        "AuthorityAccountId": route.AUTHORITY_ACCOUNT_ID,
        "ManagementAccountId": route.MANAGEMENT_ACCOUNT_ID,
        **signed_parameters,
        "RepairId": repair_id,
        "PrincipalId": snapshot["principal_id"],
        "IdentityStoreId": snapshot["identity_store_id"],
        "IdentityCenterInstanceArn": snapshot["identity_center_instance_arn"],
        "PlanPermissionSetArn": snapshot["permission_set_arn"],
        "ExpectedPermissionSetDescription": snapshot[
            "permission_set_description"
        ],
        "RepairInvokerPermissionSetArn": (
            broker.REPAIR_INVOKER_PERMISSION_SET_SENTINEL
        ),
        "CurrentPolicyDigest": snapshot["current_policy_digest"],
        "DesiredPolicyDigest": snapshot["desired_policy_digest"],
        "ExpectedPlanPermissionSetTagsJson": route.canonical_json(
            snapshot["permission_set_tags"]
        ),
        "BootstrapChangeSetName": change_set_name,
        "RepairNotBefore": value["repair_not_before"],
        "RepairNotAfter": value["repair_not_after"],
        "PlanSamlProviderArn": snapshot["saml_provider_arn"],
        "IdentityCenterKmsMode": snapshot["identity_center_kms_mode"],
        "IdentityCenterKmsKeyArn": snapshot["identity_center_kms_key_arn"] or "",
        "ImmutableConfigurationDigest": DYNAMIC_IMMUTABLE_DIGEST_SENTINEL,
    }
    expected_pep_keys = {
        item for item in repair.IMMUTABLE_CONFIGURATION_PARAMETER_KEYS
    } | {
        "AuthorityAccountId",
        "ManagementAccountId",
        "ArtifactBucket",
        "ArtifactKey",
        "ArtifactVersion",
        "ImmutableConfigurationDigest",
    }
    if set(pep_values) != expected_pep_keys:
        _fail("PEP_PARAMETER_BINDING_INVALID")

    operations = {
        "seed-revoke": (
            "scanalyze-platform-authority-gug376-temporary-change-set-route",
            "gug376-temporary-route-seed-revoke",
            template_urls["route_template"],
            _update_parameters(
                route_update_keys,
                {"SeedAssignmentsEnabled": "false", "BrokerInvokerAssignmentEnabled": "true"},
            ),
        ),
        "delegation": (
            "scanalyze-platform-authority-bootstrap-plan-repair-delegation",
            "gug376-plan-repair-delegation-create",
            template_urls["delegation_template"],
            _parameters(delegation_values),
        ),
        "pep": (
            "scanalyze-platform-authority-bootstrap-plan-repair-pep",
            "gug376-plan-repair-pep-create",
            template_urls["pep_template"],
            _parameters(pep_values),
        ),
        "pep-protection": (
            "scanalyze-platform-authority-bootstrap-plan-repair-pep",
            "gug376-plan-repair-pep-protection-enable",
            template_urls["pep_protection_template"],
            _update_parameters(tuple(pep_values), {}),
        ),
        "delegation-revoke": (
            "scanalyze-platform-authority-bootstrap-plan-repair-delegation",
            "gug376-plan-repair-delegation-revoke",
            template_urls["delegation_template"],
            _update_parameters(
                tuple(delegation_values), {"RepairInvokerAssignmentEnabled": "false"}
            ),
        ),
        "route-revoke": (
            "scanalyze-platform-authority-gug376-temporary-change-set-route",
            "gug376-temporary-route-invoker-revoke",
            template_urls["route_template"],
            _update_parameters(
                route_update_keys,
                {"SeedAssignmentsEnabled": "false", "BrokerInvokerAssignmentEnabled": "false"},
            ),
        ),
    }
    requests: dict[str, dict[str, Any]] = {}
    for stem, (stack, name, url, parameters) in operations.items():
        creator = stem + "-create-v1"
        requests[creator] = _create_request(
            stack_name=stack,
            change_set_name=name,
            change_set_type=("CREATE" if stem in {"delegation", "pep"} else "UPDATE"),
            parameters=parameters,
            template_url=url,
        )

    route_after_seed = [
        item
        for item in route_inventory_list
        if item["logical_resource_id"]
        not in {"BrokerSeedCreatorAssignment", "BrokerSeedExecutorAssignment"}
    ]
    route_after_close = [
        item
        for item in route_after_seed
        if item["logical_resource_id"] != "BrokerInvokerAssignment"
    ]
    delegation_after_close = [
        item
        for item in delegation_inventory_list
        if item["logical_resource_id"] != "RepairInvokerAssignment"
    ]
    creator_contracts = {
        "seed-revoke-create-v1": {
            "template_digest": validated_templates["route_template"]["artifact_sha256"],
            "expected_changes": _remove(
                route_inventory,
                "BrokerSeedCreatorAssignment",
                "BrokerSeedExecutorAssignment",
            ),
        },
        "delegation-create-v1": {
            "template_digest": validated_templates["delegation_template"]["artifact_sha256"],
            "expected_changes": _changes(delegation_inventory_list, "Add"),
        },
        "pep-create-v1": {
            "template_digest": validated_templates["pep_template"]["artifact_sha256"],
            "expected_changes": _changes(pep_inventory_list, "Add"),
        },
        "pep-protection-create-v1": {
            "template_digest": validated_templates["pep_protection_template"][
                "artifact_sha256"
            ],
            "expected_changes": _pep_protection_changes(
                {
                    item["logical_resource_id"]: item["resource_type"]
                    for item in pep_inventory_list
                }
            ),
        },
        "delegation-revoke-create-v1": {
            "template_digest": validated_templates["delegation_template"]["artifact_sha256"],
            "expected_changes": _remove(delegation_inventory, "RepairInvokerAssignment"),
        },
        "route-revoke-create-v1": {
            "template_digest": validated_templates["route_template"]["artifact_sha256"],
            "expected_changes": _remove(route_inventory, "BrokerInvokerAssignment"),
        },
    }
    terminal_expectations = {
        "seed-revoke-execute-v1": {
            "account_id": route.MANAGEMENT_ACCOUNT_ID,
            "stack_name": operations["seed-revoke"][0],
            "terminal_statuses": ["UPDATE_COMPLETE"],
            "template_digest": validated_templates["route_template"]["artifact_sha256"],
            "expected_resources": route_after_seed,
            "expected_output_keys": route_outputs,
            "expected_static_outputs": {
                "SeedAssignmentMode": "false",
                "BrokerInvokerAssignmentMode": "true",
                "BrokerStackName": broker.ROUTE_BROKER_STACK_NAME,
                "ProductionAuthorized": "false",
            },
            "expected_tags": list(EXACT_STACK_TAGS),
        },
        "delegation-execute-v1": {
            "account_id": route.MANAGEMENT_ACCOUNT_ID,
            "stack_name": operations["delegation"][0],
            "terminal_statuses": ["CREATE_COMPLETE"],
            "template_digest": validated_templates["delegation_template"]["artifact_sha256"],
            "expected_resources": delegation_inventory_list,
            "expected_output_keys": delegation_outputs,
            "expected_static_outputs": {
                "RepairInvokerAssignmentMode": "true",
                "RepairPrincipalIdDigestRequired": "true",
                "ProductionAuthorized": "false",
            },
            "expected_tags": list(EXACT_STACK_TAGS),
        },
        "pep-execute-v1": {
            "account_id": route.AUTHORITY_ACCOUNT_ID,
            "stack_name": operations["pep"][0],
            "terminal_statuses": ["CREATE_COMPLETE"],
            "template_digest": validated_templates["pep_template"]["artifact_sha256"],
            "expected_resources": pep_inventory_list,
            "expected_output_keys": pep_outputs,
            "expected_static_outputs": {
                "LedgerDeletionProtectionMode": "false",
                "ProductionAuthorized": "false",
            },
            "expected_tags": list(EXACT_STACK_TAGS),
        },
        "pep-protection-execute-v1": {
            "account_id": route.AUTHORITY_ACCOUNT_ID,
            "stack_name": operations["pep-protection"][0],
            "terminal_statuses": ["UPDATE_COMPLETE"],
            "template_digest": validated_templates["pep_protection_template"][
                "artifact_sha256"
            ],
            "expected_resources": pep_inventory_list,
            "expected_output_keys": pep_outputs,
            "expected_static_outputs": {
                "LedgerDeletionProtectionMode": "true",
                "ProductionAuthorized": "false",
            },
            "expected_tags": list(EXACT_STACK_TAGS),
        },
        "delegation-revoke-execute-v1": {
            "account_id": route.MANAGEMENT_ACCOUNT_ID,
            "stack_name": operations["delegation-revoke"][0],
            "terminal_statuses": ["UPDATE_COMPLETE"],
            "template_digest": validated_templates["delegation_template"]["artifact_sha256"],
            "expected_resources": delegation_after_close,
            "expected_output_keys": delegation_outputs,
            "expected_static_outputs": {
                "RepairInvokerAssignmentMode": "false",
                "RepairPrincipalIdDigestRequired": "true",
                "ProductionAuthorized": "false",
            },
            "expected_tags": list(EXACT_STACK_TAGS),
        },
        "route-revoke-execute-v1": {
            "account_id": route.MANAGEMENT_ACCOUNT_ID,
            "stack_name": operations["route-revoke"][0],
            "terminal_statuses": ["UPDATE_COMPLETE"],
            "template_digest": validated_templates["route_template"]["artifact_sha256"],
            "expected_resources": route_after_close,
            "expected_output_keys": route_outputs,
            "expected_static_outputs": {
                "SeedAssignmentMode": "false",
                "BrokerInvokerAssignmentMode": "false",
                "BrokerStackName": broker.ROUTE_BROKER_STACK_NAME,
                "ProductionAuthorized": "false",
            },
            "expected_tags": list(EXACT_STACK_TAGS),
        },
    }
    config = {
        "schema_version": 1,
        "record_type": broker.CONFIG_RECORD_TYPE,
        "source_commit": source_commit,
        "ledger_id": broker.ROUTE_LEDGER_ID,
        "ledger_binding_digest": binding_digest,
        "initialization_digest": initialization_digest,
        "foundation_publish_binding_digest": publish_binding["binding_digest"],
        "repair_id": repair_id,
        "bootstrap_change_set_name": change_set_name,
        "identity_center_instance_arn": snapshot["identity_center_instance_arn"],
        "bootstrap_principal_id": snapshot["principal_id"],
        "route_not_before": value["route_not_before"],
        "route_not_after": value["route_not_after"],
        "recovery_not_after": recovery_not_after,
        "normal_plan_generated_role_arn": snapshot["generated_role_arn"],
        "normal_plan_generated_role_name": snapshot["generated_role_name"],
        "requests": requests,
        "creator_contracts": creator_contracts,
        "permission_set_output_contracts": {
            "route": {
                "account_id": route.MANAGEMENT_ACCOUNT_ID,
                "stack_name": operations["seed-revoke"][0],
                "permission_set_output_keys": [
                    "BrokerInvokerPermissionSetArn",
                    "BrokerSeedCreatorPermissionSetArn",
                    "BrokerSeedExecutorPermissionSetArn",
                ],
                "required_mode_outputs": {
                    "BrokerInvokerAssignmentMode": "true",
                    "SeedAssignmentMode": "true",
                },
            },
            "delegation": {
                "account_id": route.MANAGEMENT_ACCOUNT_ID,
                "stack_name": operations["delegation"][0],
                "permission_set_output_keys": ["RepairInvokerPermissionSetArn"],
                "required_mode_outputs": {"RepairInvokerAssignmentMode": "true"},
            },
        },
        "terminal_expectations": terminal_expectations,
        "revocation_assignment_scopes": {
            "seed-revoke-execute-v1": {
                "account_id": route.AUTHORITY_ACCOUNT_ID,
                "instance_arn": snapshot["identity_center_instance_arn"],
                "permission_set_sources": [
                    {"source": "route", "output_key": "BrokerSeedCreatorPermissionSetArn"},
                    {"source": "route", "output_key": "BrokerSeedExecutorPermissionSetArn"},
                ],
            },
            "delegation-revoke-execute-v1": {
                "account_id": route.AUTHORITY_ACCOUNT_ID,
                "instance_arn": snapshot["identity_center_instance_arn"],
                "permission_set_sources": [
                    {"source": "delegation", "output_key": "RepairInvokerPermissionSetArn"}
                ],
            },
            "route-revoke-execute-v1": {
                "account_id": route.AUTHORITY_ACCOUNT_ID,
                "instance_arn": snapshot["identity_center_instance_arn"],
                "permission_set_sources": [
                    {"source": "route", "output_key": "BrokerInvokerPermissionSetArn"}
                ],
            },
        },
        "retry_permitted": False,
        "production_authorized": False,
        "production_status": "NO-GO",
    }
    config = broker.seal(config, "config_digest")
    try:
        broker.BrokerConfig.from_mapping(config)
        envelope = broker.encode_runtime_config(config)
    except broker.RouteBrokerError as exc:
        raise BrokerConfigMaterializationError("BROKER_CONFIG_INVALID") from exc
    if len(broker.canonical_json(envelope).encode("utf-8")) > seed.MAX_BROKER_CONFIG_BYTES:
        _fail("BROKER_CONFIG_TOO_LARGE")
    pep_signed = pep_receipt["signed_artifact"]
    broker_seed_input = {
        "record_type": seed.RECORD_TYPE,
        "source_commit": source_commit,
        "management_account_id": route.MANAGEMENT_ACCOUNT_ID,
        "authority_account_id": route.AUTHORITY_ACCOUNT_ID,
        "region": route.REGION,
        "route_not_before": value["route_not_before"],
        "route_not_after": value["route_not_after"],
        "repair_id": repair_id,
        "artifact_bootstrap_intent": bootstrap_intent,
        "foundation_publish_binding": publish_binding,
        "foundation_publish_binding_digest": publish_binding["binding_digest"],
        "source_template": {
            "path": seed.SOURCE_TEMPLATE_PATH.as_posix(),
            "sha256": route.bytes_digest(sources["broker_source"]),
        },
        "broker_code": handoff["broker_code"],
        "pep_template": {
            "bucket": validated_templates["pep_template"]["bucket"],
            "key": validated_templates["pep_template"]["key"],
            "version": validated_templates["pep_template"]["version"],
            "url": validated_templates["pep_template"]["template_url"],
        },
        "pep_protection_template": {
            "bucket": validated_templates["pep_protection_template"]["bucket"],
            "key": validated_templates["pep_protection_template"]["key"],
            "version": validated_templates["pep_protection_template"]["version"],
            "url": validated_templates["pep_protection_template"]["template_url"],
        },
        "pep_artifact": {
            "bucket": pep_signed["bucket"],
            "key": pep_signed["key"],
            "version": pep_signed["version"],
        },
        "pep_runtime_binding": handoff["pep_runtime_binding"],
        "broker_config": config,
    }
    try:
        return seed.validate_input(broker_seed_input)
    except seed.BrokerSeedError as exc:
        raise BrokerConfigMaterializationError("BROKER_SEED_INPUT_INVALID") from exc


__all__ = [
    "BrokerConfigMaterializationError",
    "DYNAMIC_IMMUTABLE_DIGEST_SENTINEL",
    "EXACT_STACK_TAGS",
    "PLAN_SNAPSHOT_RECORD_TYPE",
    "RECORD_TYPE",
    "bind_plan_snapshot",
    "materialize_broker_seed_input",
    "validate_plan_snapshot",
]
