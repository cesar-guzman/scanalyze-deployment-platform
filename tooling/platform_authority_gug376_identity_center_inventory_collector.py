"""Inert GUG-385 Identity Center inventory contracts; callers inject typed fakes."""
from __future__ import annotations
from datetime import datetime, timedelta; from hashlib import sha256; import json, os, re
from pathlib import Path
from typing import Any, Callable, Mapping, Protocol
from tooling.platform_authority_gug365_upstream_inventory import canonical_digest, canonical_json, canonical_snapshot
from tooling.platform_authority_gug376_authority_inventory_collector import AuthorityAccessDenied, CollectorError, IDENTITY_FIELDS, _identity, _stamp, _time, private_target_absent, read_private_json, write_private_json
REPO_ROOT = Path(__file__).resolve().parents[1]
POLICY = REPO_ROOT / "policies/iam/platform-authority-gug376-identity-center-inventory-read-only.json"
POLICY_SHA256 = "6de56114672327b7fa39e65d00aa01d84abad2eec19c41990a13852dc083371d"
REGION, MAX_PAGES = "us-east-1", 50
NAMES = ("ScanalyzeAuthorityRetireApprove", "ScanalyzeAuthorityRetireClass")
PRIVATE_FIELDS = {"application_name", "approved_user_id", "approved_single_operator_user_arn", "authority_account_arn", "identity_center_kms_key_arn", "identity_store_arn", "identity_store_id"}
POLICY_TARGET_FIELDS = {"management_account_id", "authority_account_arn", "identity_center_instance_arn", "identity_store_arn", "approved_single_operator_user_arn", "identity_center_kms_key_arn", "identity_center_application_arn", "retire_approve_permission_set_arn", "retire_class_permission_set_arn"}
PLAN_FIELDS = {"private_targets", "not_before", "not_after", "expected_account_id", "expected_principal_arn", "authority_verification_digest", "expected_discovery_policy_digest", "expected_exact_policy_digest", "expected_target_digest", "expected_facts_digest"}
BINDING_FIELDS = PLAN_FIELDS - {"private_targets"} | {"private_target_digest", "identity_store_id_digest", "application_name_digest", "region"}
COUNTS = {"instances", "applications", "permission_sets", "assignments", "provisioning", "target_accounts", "operators"}
CLASSES = {"ABSENT_READY", "EXACT_PRESENT_NO_TOUCH", "DRIFT_BLOCKED_NO_REPAIR", "NOT_AUTHORIZED", "UNCERTAIN_RECONCILE_ONLY"}
_DIGEST, _ARN = re.compile(r"^sha256:[0-9a-f]{64}$"), re.compile(r"^arn:aws:[a-z0-9-]+:[a-z0-9-]*:[0-9]*:[A-Za-z0-9/.:_+=,@%-]+$")
def _fail(code: str) -> None: raise CollectorError(code)
def _parse(value: object) -> datetime:
    try: result = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except (TypeError, ValueError): _fail("PRIVATE_SNAPSHOT_INVALID")
    return result if _stamp(result) == value else _fail("PRIVATE_SNAPSHOT_INVALID")  # type: ignore[return-value]
class DiscoveryReader(Protocol):
    def list_instances(self, token: object | None) -> Mapping[str, Any]: ...
    def list_applications(self, instance_arn: str, application_name: str, token: object | None) -> Mapping[str, Any]: ...
    def list_permission_sets(self, instance_arn: str, names: tuple[str, str], token: object | None) -> Mapping[str, Any]: ...
class ExactReader(Protocol):
    def describe_instance(self, instance_arn: str) -> Mapping[str, Any]: ...
    def read_application(self, application_arn: str) -> Mapping[str, Any]: ...
    def read_permission_set(self, instance_arn: str, permission_set_arn: str) -> Mapping[str, Any]: ...
    def list_assignments(self, instance_arn: str, permission_set_arn: str, account_arn: str, token: object | None) -> Mapping[str, Any]: ...
    def list_provisioning(self, instance_arn: str, permission_set_arn: str, token: object | None) -> Mapping[str, Any]: ...
    def list_target_accounts(self, instance_arn: str, permission_set_arn: str, token: object | None) -> Mapping[str, Any]: ...
    def describe_approved_user(self, identity_store_id: str, user_id: str) -> Mapping[str, Any]: ...
class DirectSession(Protocol):
    def get_caller_identity(self) -> Mapping[str, Any]: ...
    def open_discovery(self) -> DiscoveryReader: ...
    def open_exact(self) -> ExactReader: ...
class DirectSessionFactory(Protocol):
    def open_sts(self, *, stage: str, policy: Mapping[str, Any], policy_digest: str, region: str) -> DirectSession: ...
def _validate_plan(plan: Mapping[str, Any]) -> Mapping[str, Any]:
    private = plan.get("private_targets")
    digests = ("authority_verification_digest", "expected_discovery_policy_digest", "expected_exact_policy_digest", "expected_target_digest", "expected_facts_digest")
    if set(plan) != PLAN_FIELDS or not isinstance(private, Mapping) or set(private) != PRIVATE_FIELDS or any(not isinstance(private[key], str) or not private[key] or "*" in private[key] for key in private) or any(_DIGEST.fullmatch(str(plan[key])) is None for key in digests) or not isinstance(plan["expected_account_id"], str) or re.fullmatch(r"[0-9]{12}", plan["expected_account_id"]) is None: _fail("IDENTITY_CENTER_PLAN_INVALID")
    account, store, user = str(plan["expected_account_id"]), private["identity_store_id"], private["approved_user_id"]
    if any(_ARN.fullmatch(str(private[key])) is None for key in ("approved_single_operator_user_arn", "authority_account_arn", "identity_center_kms_key_arn", "identity_store_arn")) or store not in private["identity_store_arn"] or store not in private["approved_single_operator_user_arn"] or not private["approved_single_operator_user_arn"].endswith("/" + user) or re.fullmatch(r"arn:aws:sso:::account/[0-9]{12}", private["authority_account_arn"]) is None or not private["identity_center_kms_key_arn"].startswith(f"arn:aws:kms:{REGION}:{account}:key/") or re.fullmatch(rf"arn:aws:sts::{account}:assumed-role/[A-Za-z0-9+=,.@_/-]+/[A-Za-z0-9+=,.@_-]+", str(plan["expected_principal_arn"])) is None: _fail("IDENTITY_CENTER_PRIVATE_TARGET_INVALID")
    return private
def _render(plan: Mapping[str, Any], targets: Mapping[str, Any] | None) -> tuple[dict[str, Any], str]:
    private = _validate_plan(plan); raw = POLICY.read_bytes()
    if sha256(raw).hexdigest() != POLICY_SHA256: _fail("IDENTITY_CENTER_POLICY_SOURCE_DRIFT")
    start, end = _time(plan["not_before"]), _time(plan["not_after"])
    if not start < end or (end - start).total_seconds() > 3600: _fail("IDENTITY_CENTER_POLICY_WINDOW_INVALID")
    policy = json.loads(raw)
    prefixes = ("Confirm", "Discover", "Deny") if targets is None else ("Confirm", "Read", "Decrypt", "Deny")
    policy["Statement"] = [item for item in policy["Statement"] if item["Sid"].startswith(prefixes)]
    values: dict[str, Any] = {"inventory_not_before": _stamp(start), "inventory_not_after": _stamp(end), "management_account_id": plan["expected_account_id"]}
    if targets is not None:
        if not isinstance(targets, Mapping) or set(targets) != POLICY_TARGET_FIELDS or targets.get("management_account_id") != plan["expected_account_id"] or any(key != "management_account_id" and _ARN.fullmatch(str(value)) is None for key, value in targets.items()): _fail("IDENTITY_CENTER_POLICY_TARGET_SET_INVALID")
        values.update(targets)
    rendered = canonical_json(policy)
    for key, value in values.items(): rendered = rendered.replace("${" + key + "}", json.dumps(value)[1:-1])
    if "${" in rendered: _fail("IDENTITY_CENTER_POLICY_PLACEHOLDER_REMAINS")
    result = json.loads(rendered); return result, canonical_digest(result)
def render_policy(plan: Mapping[str, Any], targets: Mapping[str, Any] | None = None) -> tuple[dict[str, Any], str]:
    policy, digest = _render(plan, targets); expected = plan["expected_discovery_policy_digest" if targets is None else "expected_exact_policy_digest"]
    if digest != expected or targets is not None and canonical_digest(targets) != plan["expected_target_digest"]: _fail("IDENTITY_CENTER_POLICY_DIGEST_NOT_VERIFIED")
    return policy, digest
def _pages(read: Callable[[object | None], Mapping[str, Any]]) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []; seen: set[str] = set(); token: object | None = None
    for _ in range(MAX_PAGES):
        page = read(token)
        if not isinstance(page, Mapping) or set(page) != {"items", "next_token", "truncated", "complete"} or not isinstance(page["items"], list) or type(page["truncated"]) is not bool or type(page["complete"]) is not bool: _fail("IDENTITY_CENTER_PAGE_INVALID")
        next_token, normalized = page["next_token"], canonical_snapshot(page["items"], code="IDENTITY_CENTER_PAGE_INVALID")
        if not all(isinstance(item, dict) for item in normalized) or next_token is not None and (not isinstance(next_token, str) or not next_token) or page["truncated"] != (next_token is not None) or page["complete"] != (next_token is None): _fail("IDENTITY_CENTER_PAGE_INCOMPLETE")
        items.extend(normalized)
        if next_token is None: return sorted(items, key=canonical_json)
        key = canonical_json(next_token)
        if key in seen: _fail("IDENTITY_CENTER_PAGE_TOKEN_REPEATED")
        seen.add(key); token = next_token
    _fail("IDENTITY_CENTER_PAGE_LIMIT_EXCEEDED")
def _one(value: Mapping[str, Any], required: set[str]) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != {"complete", "value"} or value["complete"] is not True or not isinstance(value["value"], Mapping): _fail("IDENTITY_CENTER_RESPONSE_INCOMPLETE")
    normalized = canonical_snapshot(value["value"], code="IDENTITY_CENTER_RESPONSE_INVALID")
    if not isinstance(normalized, dict) or not required <= set(normalized): _fail("IDENTITY_CENTER_RESPONSE_INVALID")
    return normalized
def _typed(items: object, required: set[str]) -> bool: return isinstance(items, list) and all(isinstance(item, Mapping) and required <= set(item) and all(isinstance(item[key], str) and item[key] and (not key.endswith("_arn") or _ARN.fullmatch(item[key]) is not None) for key in required) for item in items)
def _valid_discovery(value: object) -> bool: return isinstance(value, Mapping) and set(value) == {"instances", "applications", "permission_sets"} and _typed(value["instances"], {"identity_store_id", "instance_arn", "owner_account_id", "status"}) and _typed(value["applications"], {"application_arn", "name"}) and _typed(value["permission_sets"], {"name", "permission_set_arn"}) and all(re.fullmatch(r"d-[0-9a-f]{10}", item["identity_store_id"]) and re.fullmatch(r"[0-9]{12}", item["owner_account_id"]) and re.fullmatch(r"arn:aws:sso:::instance/ssoins-[A-Za-z0-9-]+", item["instance_arn"]) for item in value["instances"]) and all(re.fullmatch(r"arn:aws:sso::[0-9]{12}:application/ssoins-[A-Za-z0-9-]+/[A-Za-z0-9-]+", item["application_arn"]) for item in value["applications"]) and all(re.fullmatch(r"arn:aws:sso:::permissionSet/ssoins-[A-Za-z0-9-]+/[A-Za-z0-9-]+", item["permission_set_arn"]) for item in value["permission_sets"])
def _provider(call: Callable[[], Any]) -> tuple[Any, str | None]:
    try: return call(), None
    except AuthorityAccessDenied: return None, "NOT_AUTHORIZED"
    except Exception: return None, "UNCERTAIN_RECONCILE_ONLY"
def _checked_identity(session: DirectSession, plan: Mapping[str, Any], digest: str, now: datetime) -> dict[str, Any]:
    value = session.get_caller_identity(); (_fail("DIRECT_SESSION_BINDING_INVALID") if not isinstance(value, Mapping) or type(value.get("chain_depth")) is not int else _identity(value, plan, digest, _time(now)))
    return {key: (_stamp(item) if key.endswith("_at") else item) for key, item in value.items()}
def _discover(reader: DiscoveryReader, plan: Mapping[str, Any]) -> dict[str, list[dict[str, Any]]]:
    private = plan["private_targets"]; instances = _pages(reader.list_instances)
    instance = str(instances[0].get("instance_arn", "")) if len(instances) == 1 else ""
    return {"instances": instances, "applications": (_pages(lambda token: reader.list_applications(instance, private["application_name"], token)) if instance else []), "permission_sets": (_pages(lambda token: reader.list_permission_sets(instance, NAMES, token)) if instance else [])}
def _bind(plan: Mapping[str, Any], discovery: Mapping[str, list[dict[str, Any]]]) -> tuple[str, dict[str, str]]:
    private = plan["private_targets"]; instances, applications, permission_sets = (discovery[key] for key in ("instances", "applications", "permission_sets"))
    if not _valid_discovery(discovery): _fail("IDENTITY_CENTER_DISCOVERY_RESPONSE_INVALID")
    if len(instances) > 1 or len(applications) > 1 or len(permission_sets) > 2: return "DRIFT_BLOCKED_NO_REPAIR", {}
    names = [item.get("name") for item in permission_sets]
    if len(names) != len(set(names)) or not set(names) <= set(NAMES): return "DRIFT_BLOCKED_NO_REPAIR", {}
    if not instances and not applications and not permission_sets: return "ABSENT_READY", {}
    if not instances or not applications or set(names) < set(NAMES): return "DRIFT_BLOCKED_NO_REPAIR", {}
    instance, application = instances[0], applications[0]
    if instance.get("status") != "ACTIVE" or instance.get("owner_account_id") != plan["expected_account_id"] or instance.get("identity_store_id") != private["identity_store_id"] or application.get("name") != private["application_name"]: return "DRIFT_BLOCKED_NO_REPAIR", {}
    by_name = {str(item["name"]): str(item.get("permission_set_arn", "")) for item in permission_sets}
    targets = {"management_account_id": str(plan["expected_account_id"]), "authority_account_arn": private["authority_account_arn"], "identity_center_instance_arn": str(instance.get("instance_arn", "")), "identity_store_arn": private["identity_store_arn"], "approved_single_operator_user_arn": private["approved_single_operator_user_arn"], "identity_center_kms_key_arn": private["identity_center_kms_key_arn"], "identity_center_application_arn": str(application.get("application_arn", "")), "retire_approve_permission_set_arn": by_name[NAMES[0]], "retire_class_permission_set_arn": by_name[NAMES[1]]}
    instance_id = targets["identity_center_instance_arn"].rsplit("/", 1)[-1]
    if any(_ARN.fullmatch(value) is None for key, value in targets.items() if key != "management_account_id") or len(set(by_name.values())) != 2 or any(targets[key].split("/")[-2] != instance_id for key in ("identity_center_application_arn", "retire_approve_permission_set_arn", "retire_class_permission_set_arn")) or f"::{plan['expected_account_id']}:application/" not in targets["identity_center_application_arn"] or canonical_digest(targets) != plan["expected_target_digest"]: return "DRIFT_BLOCKED_NO_REPAIR", targets
    return "EXACT_PRESENT_NO_TOUCH", targets
def _bound_discovery(discovery: Mapping[str, Any], targets: Mapping[str, Any]) -> bool: return len(discovery["instances"]) == len(discovery["applications"]) == 1 and len(discovery["permission_sets"]) == 2 and discovery["instances"][0].get("instance_arn") == targets["identity_center_instance_arn"] and discovery["instances"][0].get("identity_store_id") == str(targets["identity_store_arn"]).rsplit("/", 1)[-1] and discovery["instances"][0].get("owner_account_id") == targets["management_account_id"] and discovery["instances"][0].get("status") == "ACTIVE" and discovery["applications"][0].get("application_arn") == targets["identity_center_application_arn"] and {item["name"]: item["permission_set_arn"] for item in discovery["permission_sets"]} == {name: targets["retire_approve_permission_set_arn" if name == NAMES[0] else "retire_class_permission_set_arn"] for name in NAMES}
def _valid_exact(facts: Mapping[str, Any], targets: Mapping[str, Any]) -> bool:
    arns = {name: targets["retire_approve_permission_set_arn" if name == NAMES[0] else "retire_class_permission_set_arn"] for name in NAMES}; application, discovery, instance, operator = facts["application"], facts["discovery"], facts["instance"], facts["operator"]
    if not _bound_discovery(discovery, targets) or instance.get("instance_arn") != targets["identity_center_instance_arn"] or instance.get("identity_store_id") != str(targets["identity_store_arn"]).rsplit("/", 1)[-1] or instance.get("owner_account_id") != targets["management_account_id"] or instance.get("status") != "ACTIVE" or application.get("application_arn") != targets["identity_center_application_arn"] or any(not isinstance(application.get(key), list) for key in ("grants", "scopes", "redirect_uris", "authentication_methods", "tags")) or any(not isinstance(application.get(key), Mapping) for key in ("assignment_configuration", "actor_policy")) or any(not isinstance(item, str) for key in ("grants", "scopes", "redirect_uris") for item in application[key]) or any(not isinstance(item, Mapping) or not item for key in ("authentication_methods", "tags") for item in application[key]) or operator.get("UserId") != str(targets["approved_single_operator_user_arn"]).rsplit("/", 1)[-1] or not isinstance(operator.get("UserName"), str) or not operator["UserName"] or not _typed(operator.get("Emails"), {"Value"}): return False
    for name, arn in arns.items():
        permission = facts["permission_sets"][name]
        if not isinstance(permission, Mapping) or permission.get("instance_arn") != targets["identity_center_instance_arn"] or permission.get("permission_set_arn") != arn or any(not isinstance(permission.get(key), list) or any(not isinstance(item, Mapping) or not item for item in permission[key]) for key in ("managed_policies", "customer_managed_policies", "tags")) or permission.get("inline_policy") is not None and not isinstance(permission.get("inline_policy"), (str, Mapping)) or permission.get("boundary") is not None and not isinstance(permission.get("boundary"), Mapping) or not _typed(facts["assignments"][name], {"account_arn", "permission_set_arn", "principal_id", "principal_type"}) or any(item["account_arn"] != targets["authority_account_arn"] or item["permission_set_arn"] != arn for item in facts["assignments"][name]) or not _typed(facts["provisioning"][name], {"permission_set_arn", "status"}) or any(item["permission_set_arn"] != arn for item in facts["provisioning"][name]) or not _typed(facts["target_accounts"][name], {"account_arn", "permission_set_arn"}) or any(item["permission_set_arn"] != arn for item in facts["target_accounts"][name]): return False
    return True
def _exact(reader: ExactReader, plan: Mapping[str, Any], targets: Mapping[str, str], discovery: Mapping[str, Any]) -> tuple[dict[str, Any], dict[str, int | None]]:
    instance, account = targets["identity_center_instance_arn"], targets["authority_account_arn"]
    permission_sets = {name: targets["retire_approve_permission_set_arn" if name == NAMES[0] else "retire_class_permission_set_arn"] for name in NAMES}
    facts: dict[str, Any] = {"discovery": discovery, "instance": _one(reader.describe_instance(instance), {"instance_arn", "identity_store_id", "owner_account_id", "status"}), "application": _one(reader.read_application(targets["identity_center_application_arn"]), {"application_arn", "grants", "scopes", "redirect_uris", "authentication_methods", "assignment_configuration", "actor_policy", "tags"}), "permission_sets": {}, "assignments": {}, "provisioning": {}, "target_accounts": {}}
    for name, arn in permission_sets.items():
        facts["permission_sets"][name] = _one(reader.read_permission_set(instance, arn), {"instance_arn", "permission_set_arn", "managed_policies", "customer_managed_policies", "inline_policy", "boundary", "tags"}); facts["assignments"][name] = _pages(lambda token, value=arn: reader.list_assignments(instance, value, account, token)); facts["provisioning"][name] = _pages(lambda token, value=arn: reader.list_provisioning(instance, value, token)); facts["target_accounts"][name] = _pages(lambda token, value=arn: reader.list_target_accounts(instance, value, token))
    facts["operator"] = _one(reader.describe_approved_user(plan["private_targets"]["identity_store_id"], plan["private_targets"]["approved_user_id"]), {"UserId", "UserName", "Emails"})
    if not _valid_exact(facts, targets): _fail("IDENTITY_CENTER_RESPONSE_INVALID")
    counts = {"instances": 1, "applications": 1, "permission_sets": 2, "assignments": sum(map(len, facts["assignments"].values())), "provisioning": sum(map(len, facts["provisioning"].values())), "target_accounts": sum(map(len, facts["target_accounts"].values())), "operators": 1}
    return facts, counts
def plan_binding(plan: Mapping[str, Any]) -> tuple[dict[str, Any], str]: private = _validate_plan(plan); value = {key: plan[key] for key in PLAN_FIELDS - {"private_targets", "not_before", "not_after"}}; value.update({"private_target_digest": canonical_digest(private), "identity_store_id_digest": canonical_digest(private["identity_store_id"]), "application_name_digest": canonical_digest(private["application_name"]), "not_before": _stamp(_time(plan["not_before"])), "not_after": _stamp(_time(plan["not_after"])), "region": REGION}); return value, canonical_digest(value)
def _receipt(classification: str, policy: str, target: str, facts: str, snapshots: list[str], counts: Mapping[str, Any], stable: bool) -> dict[str, Any]:
    value = {"record_type": "scanalyze.platform_authority.gug376_identity_center_inventory_receipt.v1", "status": "STOP_LIVE_ORCHESTRATOR_NOT_IMPLEMENTED", "live_status": "IDENTITY_CENTER_INVENTORY_LIVE_NOT_PROVEN", "classification": classification, "policy_binding_digest": policy, "target_digest": target, "facts_digest": facts, "snapshot_digests": snapshots, "surface_counts": dict(counts), "snapshot_count": len(snapshots), "stable": stable, "read_only": True, "aws_calls": 0, "aws_mutations": 0, "two_human_status": "NOT_PROVEN", "independent_approval_present": False, "deployment_authorized": False, "production_status": "NO-GO"}
    value["receipt_digest"] = canonical_digest(value); validate_public_receipt(value); return value
def validate_public_receipt(value: Mapping[str, Any]) -> None:
    if not isinstance(value, Mapping): _fail("PUBLIC_RECEIPT_INVALID")
    fields = {"record_type", "status", "live_status", "classification", "policy_binding_digest", "target_digest", "facts_digest", "snapshot_digests", "surface_counts", "snapshot_count", "stable", "read_only", "aws_calls", "aws_mutations", "two_human_status", "independent_approval_present", "deployment_authorized", "production_status", "receipt_digest"}
    fixed = (value.get("record_type") == "scanalyze.platform_authority.gug376_identity_center_inventory_receipt.v1" and value.get("status") == "STOP_LIVE_ORCHESTRATOR_NOT_IMPLEMENTED" and value.get("live_status") == "IDENTITY_CENTER_INVENTORY_LIVE_NOT_PROVEN" and value.get("read_only") is True and type(value.get("aws_calls")) is type(value.get("aws_mutations")) is int and value.get("aws_calls") == value.get("aws_mutations") == 0 and value.get("two_human_status") == "NOT_PROVEN" and value.get("independent_approval_present") is value.get("deployment_authorized") is False and value.get("production_status") == "NO-GO")
    snapshots, counts = value.get("snapshot_digests"), value.get("surface_counts")
    digests = [value.get(key) for key in ("policy_binding_digest", "target_digest", "facts_digest", "receipt_digest")] + (snapshots if isinstance(snapshots, list) else [])
    if set(value) != fields or not fixed or not isinstance(value.get("classification"), str) or value["classification"] not in CLASSES or not isinstance(snapshots, list) or len(set(map(str, snapshots))) != len(snapshots) or any(_DIGEST.fullmatch(str(item)) is None for item in digests) or not isinstance(counts, Mapping) or set(counts) != COUNTS or any(item is not None and (type(item) is not int or item < 0) for item in counts.values()) or type(value.get("snapshot_count")) is not int or value.get("snapshot_count") != len(snapshots) or value.get("snapshot_count") not in (1, 2) or type(value.get("stable")) is not bool or value.get("classification") in {"ABSENT_READY", "EXACT_PRESENT_NO_TOUCH", "DRIFT_BLOCKED_NO_REPAIR"} and (value.get("snapshot_count") != 2 or value.get("stable") is not True) or value.get("classification") in {"NOT_AUTHORIZED", "UNCERTAIN_RECONCILE_ONLY"} and value.get("stable") is not False or value.get("receipt_digest") != canonical_digest({key: item for key, item in value.items() if key != "receipt_digest"}): _fail("PUBLIC_RECEIPT_INVALID")
def _save(root: Path, name: str, plan: Mapping[str, Any], classification: str, policies: Mapping[str, Any], targets: Mapping[str, Any], facts: Mapping[str, Any], identities: list[Mapping[str, Any]], counts: Mapping[str, Any]) -> dict[str, Any]:
    binding, binding_digest = plan_binding(plan); policy_digest = canonical_digest({key: canonical_digest(item) for key, item in policies.items()}); target_digest, facts_digest = canonical_digest(targets), canonical_digest(facts)
    if len({item["session_id_digest"] for item in identities}) != len(identities): _fail("SESSIONS_NOT_INDEPENDENT")
    snapshot: dict[str, Any] = {"record_type": "scanalyze.platform_authority.gug376_identity_center_inventory_private.v1", "plan_binding": binding, "plan_binding_digest": binding_digest, "classification": classification, "policies": dict(policies), "policy_binding_digest": policy_digest, "targets": dict(targets), "target_digest": target_digest, "facts": dict(facts), "facts_digest": facts_digest, "identities": identities, "session_digests": [item["session_id_digest"] for item in identities], "surface_counts": dict(counts), "read_only": True, "aws_mutations": 0, "repository_persisted": False}
    snapshot["snapshot_digest"] = canonical_digest(snapshot); write_private_json(root, name, snapshot)
    provisional = "NOT_AUTHORIZED" if classification == "NOT_AUTHORIZED" else "UNCERTAIN_RECONCILE_ONLY"
    return _receipt(provisional, policy_digest, binding["expected_target_digest"], facts_digest, [snapshot["snapshot_digest"]], counts, False)
def capture(plan: Mapping[str, Any], factory: DirectSessionFactory, *, private_root: Path, artifact_name: str, now: datetime) -> dict[str, Any]:
    _validate_plan(plan); private_target_absent(private_root, artifact_name)
    if any(key.startswith("AWS_") or key in {"BOTO_CONFIG", "REQUESTS_CA_BUNDLE", "SSL_CERT_FILE", "SSL_CERT_DIR"} for key in os.environ): _fail("AMBIENT_AWS_OVERRIDE_FORBIDDEN")
    discovery_policy, discovery_digest = render_policy(plan); policies: dict[str, Any] = {"discovery": discovery_policy}; identities: list[Mapping[str, Any]] = []
    session = factory.open_sts(stage="discovery", policy=discovery_policy, policy_digest=discovery_digest, region=REGION); identities.append(_checked_identity(session, plan, discovery_digest, now))
    discovery, failure = _provider(lambda: _discover(session.open_discovery(), plan)); empty_counts = {key: None for key in COUNTS}
    if failure: return _save(private_root, artifact_name, plan, failure, policies, {}, {"classification": failure}, identities, empty_counts)
    counts = dict(empty_counts, instances=len(discovery["instances"]), applications=len(discovery["applications"]), permission_sets=len(discovery["permission_sets"]))
    bound, failure = _provider(lambda: _bind(plan, discovery))
    if failure: return _save(private_root, artifact_name, plan, failure, policies, {}, {"discovery": discovery, "classification": failure}, identities, counts)
    classification, targets = bound
    if classification != "EXACT_PRESENT_NO_TOUCH": return _save(private_root, artifact_name, plan, classification, policies, targets, {"discovery": discovery}, identities, counts)
    exact_policy, exact_digest = render_policy(plan, targets); policies["exact"] = exact_policy
    session = factory.open_sts(stage="exact", policy=exact_policy, policy_digest=exact_digest, region=REGION); identities.append(_checked_identity(session, plan, exact_digest, now)); result, failure = _provider(lambda: _exact(session.open_exact(), plan, targets, discovery))
    if failure: return _save(private_root, artifact_name, plan, failure, policies, targets, {"discovery": discovery, "classification": failure}, identities, counts)
    facts, counts = result; classification = "EXACT_PRESENT_NO_TOUCH" if canonical_digest(facts) == plan["expected_facts_digest"] else "DRIFT_BLOCKED_NO_REPAIR"
    return _save(private_root, artifact_name, plan, classification, policies, targets, facts, identities, counts)
def _outcome(value: Mapping[str, Any], binding: Mapping[str, Any]) -> tuple[str, dict[str, int | None]]:
    facts, targets = value["facts"], value["targets"]; counts: dict[str, int | None] = {key: None for key in COUNTS}
    if set(facts) == {"classification"} and isinstance(facts["classification"], str) and facts["classification"] in {"NOT_AUTHORIZED", "UNCERTAIN_RECONCILE_ONLY"} and not targets and set(value["policies"]) == {"discovery"}: return facts["classification"], counts
    discovery = facts.get("discovery")
    if not _valid_discovery(discovery): _fail("PRIVATE_SNAPSHOT_INVALID")
    counts.update(instances=len(discovery["instances"]), applications=len(discovery["applications"]), permission_sets=len(discovery["permission_sets"])); keys = set(facts)
    if keys == {"discovery", "classification"} and isinstance(facts["classification"], str) and facts["classification"] in {"NOT_AUTHORIZED", "UNCERTAIN_RECONCILE_ONLY"}: return facts["classification"], counts
    if keys == {"discovery"}:
        names = [item["name"] for item in discovery["permission_sets"]]; bounded = len(discovery["instances"]) <= 1 and len(discovery["applications"]) <= 1 and len(names) <= 2 and len(names) == len(set(names)) and set(names) <= set(NAMES); complete = len(discovery["instances"]) == len(discovery["applications"]) == 1 and len(names) == 2 and set(names) == set(NAMES) and discovery["instances"][0]["status"] == "ACTIVE" and discovery["instances"][0]["owner_account_id"] == binding["expected_account_id"] and canonical_digest(discovery["instances"][0]["identity_store_id"]) == binding["identity_store_id_digest"] and canonical_digest(discovery["applications"][0]["name"]) == binding["application_name_digest"]; absence = bounded and not discovery["instances"] and not discovery["applications"] and not names
        if value["classification"] == "ABSENT_READY" and absence and not targets and set(value["policies"]) == {"discovery"}: return "ABSENT_READY", counts
        if value["classification"] == "DRIFT_BLOCKED_NO_REPAIR" and set(value["policies"]) == {"discovery"} and (not targets and not complete and not absence or value["target_digest"] != binding["expected_target_digest"] and set(targets) == POLICY_TARGET_FIELDS and isinstance(targets.get("management_account_id"), str) and re.fullmatch(r"[0-9]{12}", targets["management_account_id"]) is not None and all(key == "management_account_id" or _ARN.fullmatch(str(item)) is not None for key, item in targets.items()) and _bound_discovery(discovery, targets)): return "DRIFT_BLOCKED_NO_REPAIR", counts
        _fail("PRIVATE_SNAPSHOT_INVALID")
    full = {"discovery", "instance", "application", "permission_sets", "assignments", "provisioning", "target_accounts", "operator"}
    surfaces = [facts.get(key) for key in ("permission_sets", "assignments", "provisioning", "target_accounts")]
    if keys != full or set(value["policies"]) != {"discovery", "exact"} or set(targets) != POLICY_TARGET_FIELDS or value["target_digest"] != binding["expected_target_digest"] or not isinstance(targets.get("management_account_id"), str) or re.fullmatch(r"[0-9]{12}", targets["management_account_id"]) is None or any(key != "management_account_id" and _ARN.fullmatch(str(item)) is None for key, item in targets.items()) or any(not isinstance(item, Mapping) or set(item) != set(NAMES) for item in surfaces) or any(not isinstance(facts.get(key), Mapping) for key in ("instance", "application", "operator")): _fail("PRIVATE_SNAPSHOT_INVALID")
    if not _valid_exact(facts, targets): _fail("PRIVATE_SNAPSHOT_INVALID")
    counts.update(assignments=sum(map(len, facts["assignments"].values())), provisioning=sum(map(len, facts["provisioning"].values())), target_accounts=sum(map(len, facts["target_accounts"].values())), operators=1)
    exact = value["target_digest"] == binding["expected_target_digest"] and value["facts_digest"] == binding["expected_facts_digest"]
    return ("EXACT_PRESENT_NO_TOUCH" if exact else "DRIFT_BLOCKED_NO_REPAIR"), counts
def _snapshot(value: Mapping[str, Any]) -> dict[str, Any]:
    try: value = json.loads(canonical_json(value))
    except Exception as exc: raise CollectorError("PRIVATE_SNAPSHOT_INVALID") from exc
    fields = {"record_type", "plan_binding", "plan_binding_digest", "classification", "policies", "policy_binding_digest", "targets", "target_digest", "facts", "facts_digest", "identities", "session_digests", "surface_counts", "read_only", "aws_mutations", "repository_persisted", "snapshot_digest"}
    nested = (value.get("plan_binding"), value.get("policies"), value.get("targets"), value.get("facts"), value.get("surface_counts")) if isinstance(value, Mapping) else ()
    if not isinstance(value, Mapping) or set(value) != fields or any(not isinstance(item, Mapping) for item in nested) or value["record_type"] != "scanalyze.platform_authority.gug376_identity_center_inventory_private.v1" or not isinstance(value["classification"], str) or value["classification"] not in CLASSES or value["read_only"] is not True or type(value["aws_mutations"]) is not int or value["aws_mutations"] != 0 or value["repository_persisted"] is not False: _fail("PRIVATE_SNAPSHOT_INVALID")
    binding, policies, targets, counts = value["plan_binding"], value["policies"], value["targets"], value["surface_counts"]
    digest_keys = {"authority_verification_digest", "expected_discovery_policy_digest", "expected_exact_policy_digest", "expected_target_digest", "expected_facts_digest", "private_target_digest", "identity_store_id_digest", "application_name_digest"}
    if set(binding) != BINDING_FIELDS or any(_DIGEST.fullmatch(str(binding.get(key))) is None for key in digest_keys) or binding.get("region") != REGION or not isinstance(binding.get("expected_account_id"), str) or re.fullmatch(r"[0-9]{12}", binding["expected_account_id"]) is None or re.fullmatch(rf"arn:aws:sts::{binding.get('expected_account_id')}:assumed-role/[A-Za-z0-9+=,.@_/-]+/[A-Za-z0-9+=,.@_-]+", str(binding.get("expected_principal_arn"))) is None or value["plan_binding_digest"] != canonical_digest(binding): _fail("PRIVATE_SNAPSHOT_INVALID")
    if not _parse(binding["not_before"]) < _parse(binding["not_after"]) or (_parse(binding["not_after"]) - _parse(binding["not_before"])).total_seconds() > 3600 or set(policies) not in ({"discovery"}, {"discovery", "exact"}) or any(not isinstance(policy, Mapping) or "${" in canonical_json(policy) for policy in policies.values()): _fail("PRIVATE_SNAPSHOT_INVALID")
    stages = ["discovery"] + (["exact"] if "exact" in policies else []); expected = [binding["expected_discovery_policy_digest"]] + ([binding["expected_exact_policy_digest"]] if "exact" in policies else [])
    if any(canonical_digest(policies[stage]) != digest for stage, digest in zip(stages, expected)) or value["policy_binding_digest"] != canonical_digest({key: canonical_digest(item) for key, item in policies.items()}) or value["target_digest"] != canonical_digest(targets) or value["facts_digest"] != canonical_digest(value["facts"]) or set(counts) != COUNTS or any(item is not None and (type(item) is not int or item < 0) for item in counts.values()): _fail("PRIVATE_SNAPSHOT_INVALID")
    identities = value["identities"]
    if not isinstance(identities, list) or len(identities) != len(stages) or any(not isinstance(item, Mapping) or set(item) != IDENTITY_FIELDS for item in identities): _fail("PRIVATE_SNAPSHOT_INVALID")
    for identity, digest in zip(identities, expected):
        started, observed, expires = (_parse(identity[key]) for key in ("started_at", "observed_at", "expires_at"))
        if identity["source"] != "DIRECT_SSO" or type(identity["chain_depth"]) is not int or identity["chain_depth"] != 0 or identity["account_id"] != binding["expected_account_id"] or identity["region"] != REGION or identity["principal_arn"] != binding["expected_principal_arn"] or identity["policy_digest"] != digest or identity["authority_verification_digest"] != binding["authority_verification_digest"] or _DIGEST.fullmatch(str(identity["session_id_digest"])) is None or not started <= _parse(binding["not_before"]) <= observed < _parse(binding["not_after"]) <= expires or expires - started > timedelta(hours=1): _fail("PRIVATE_SNAPSHOT_INVALID")
    classification, derived_counts = _outcome(value, binding)
    if value["classification"] != classification or counts != derived_counts or value["session_digests"] != [item["session_id_digest"] for item in identities] or len(set(value["session_digests"])) != len(value["session_digests"]) or value["snapshot_digest"] != canonical_digest({key: item for key, item in value.items() if key != "snapshot_digest"}): _fail("PRIVATE_SNAPSHOT_INVALID")
    return dict(value)
def certify(first: Mapping[str, Any], second: Mapping[str, Any], *, expected_plan_binding_digest: str) -> dict[str, Any]:
    first, second = _snapshot(first), _snapshot(second)
    if _DIGEST.fullmatch(str(expected_plan_binding_digest)) is None or any(item["plan_binding_digest"] != expected_plan_binding_digest for item in (first, second)): _fail("IDENTITY_CENTER_PLAN_BINDING_INVALID")
    first_times, second_times = ([_parse(item["observed_at"]) for item in value["identities"]] for value in (first, second))
    if set(first["session_digests"]) & set(second["session_digests"]) or max(first_times) >= min(second_times): _fail("SESSIONS_NOT_INDEPENDENT")
    bound = ("plan_binding_digest", "policy_binding_digest", "target_digest", "facts_digest", "classification", "surface_counts"); stable = all(first[key] == second[key] for key in bound)
    if not stable: classification = "UNCERTAIN_RECONCILE_ONLY"
    elif second["classification"] in {"NOT_AUTHORIZED", "UNCERTAIN_RECONCILE_ONLY"}: classification, stable = second["classification"], False
    else: classification = second["classification"]
    binding = second["plan_binding"]
    return _receipt(classification, second["policy_binding_digest"], binding["expected_target_digest"], second["facts_digest"], [first["snapshot_digest"], second["snapshot_digest"]], second["surface_counts"], stable)
