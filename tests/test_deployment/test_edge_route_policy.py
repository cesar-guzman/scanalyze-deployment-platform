"""Real offline verifier and CLI; synthetic publication decisions, no app imports."""
from copy import deepcopy
import ast
import json
from pathlib import Path
import subprocess
import sys

import pytest

from tooling import edge_route_policy as verifier
from tooling.authorize_deployment_backend import canonical_digest
from tooling.policy_digest import compute_policy_digest

ROOT = Path(__file__).resolve().parents[2]
SOURCE_FILES = [
    verifier.APP / name for name in (
        "main.py", "enterprise_authorization.py", "authorization.py", "api/health.py", "api/v1/router.py",
        "api/v1/documents.py", "api/v1/batches.py", "api/v1/analytics.py",
        "api/v1/addons/employee_profiles.py", "api/v1/user_lifecycle.py",
        "api/v2/router.py", "authentication_assurance.py",
    )
] + [verifier.AUTH_POLICY, verifier.OPENAPI, verifier.REWRITE]
SELECTED = [
    ("GET", "/api/v2/documents/{documentId}/result", ["results.read_full"], "read"),
    ("GET", "/api/v1/documents/{document_id}/artifacts", ["artifacts.list_metadata"], "read"),
    ("GET", "/api/v1/addons/employee-profiles", ["employee_profiles.list_masked"], "read"),
    ("POST", "/api/v2/operations/{operation}/reconciliation", ["batches.create", "documents.create"], "write"),
    ("POST", "/api/v1/admin/invitations", ["authorization_administration.invitations.create"], "admin"),
    ("GET", "/api/v1/admin/roles", ["authorization_administration.roles.read"], "read"),
    ("GET", "/api/v1/analytics/docs", ["documents.read_metadata"], "read"),
    ("GET", "/api/v1/analytics/export-bank", ["exports.execute"], "read"),
]


@pytest.fixture
def source(tmp_path):
    target = tmp_path / "source"
    for relative in SOURCE_FILES:
        destination = target / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes((ROOT / relative).read_bytes())
    return target


def seal(policy):
    policy["record_digest"] = canonical_digest({key: value for key, value in policy.items() if key != "record_digest"})
    return policy


def artifact(source):
    _, _, observed = verifier.inspect_sources(source)
    pins = {"source_commit": "a" * 40, **observed}
    routes = [{"method": method, "path": path, "operation_ids": ops,
               "prefilter_scope": "scanalyze.api.v1/" + scope} for method, path, ops, scope in SELECTED]
    policy = seal({"schema_version": "edge-route-policy.v1", **pins, "routes": routes})
    return policy, deepcopy(pins)


def cli(tmp_path, source, policy, pins, *, expected=None, raw=None, extra=()):
    policy_file, pins_file = tmp_path / "policy.json", tmp_path / "pins.json"
    policy_file.write_bytes(raw if raw is not None else json.dumps(policy).encode())
    pins_file.write_text(json.dumps(pins))
    return subprocess.run([
        sys.executable, "-m", "tooling.edge_route_policy", "verify",
        "--policy-path", str(policy_file), "--expected-record-digest", expected or policy["record_digest"],
        "--expected-pins-path", str(pins_file), "--source-root", str(source), *extra,
    ], cwd=ROOT, capture_output=True, text=True, check=False)


def assert_rejected(result):
    assert result.returncode == 2
    assert result.stdout == ""
    assert result.stderr.strip() == "EDGE_ROUTE_POLICY_REJECTED"


def test_real_inventory_preserves_54_routes_50_protected_and_reconciliation(source):
    inventory, requirements, _ = verifier.inspect_sources(source)
    assert len(inventory) == 54
    assert sum(bool(row["operation_ids"]) for row in inventory) == 50
    assert len(requirements) == 30
    assert {
        (row["method"], row["path"]): row["operation_ids"]
        for row in inventory
        if row["path"] in {"/api/v1/analytics/docs", "/api/v1/analytics/export-bank"}
    } == {
        ("GET", "/api/v1/analytics/docs"): ["documents.read_metadata"],
        ("GET", "/api/v1/analytics/export-bank"): ["exports.execute"],
    }
    assert next(row for row in inventory if "reconciliation" in row["path"])["operation_ids"] == ["batches.create", "documents.create"]
    assert {row["path"] for row in inventory if not row["operation_ids"]} == {
        "/health", "/api/v1/health", "/api/v1/auth/passkey/initiate", "/api/v1/auth/passkey/respond",
    }


def test_cli_projects_exact_explicit_subset_without_starting_application(source, tmp_path):
    # If this main were imported, the deliberate guard would fail immediately.
    main = source / verifier.APP / "main.py"
    main.write_text("raise RuntimeError('must never execute application')\n" + main.read_text())
    policy, pins = artifact(source)
    result = cli(tmp_path, source, policy, pins)
    assert result.returncode == 0, result.stderr
    assert result.stderr == ""
    assert json.loads(result.stdout) == {"api_authorization_routes": {
        method + " " + path: ["scanalyze.api.v1/" + scope] for method, path, _, scope in SELECTED
    }}


def test_resealed_policy_cannot_replace_independent_outer_digest(source, tmp_path):
    policy, pins = artifact(source)
    original = policy["record_digest"]
    policy["routes"].pop()
    seal(policy)
    assert_rejected(cli(tmp_path, source, policy, pins, expected=original))


@pytest.mark.parametrize("field", sorted(verifier.PIN_FIELDS))
def test_resealed_artifact_cannot_replace_each_independent_pin(source, tmp_path, field):
    policy, pins = artifact(source)
    policy[field] = "b" * 40 if field == "source_commit" else "2.0.0" if field == "authorization_policy_version" else "sha256:" + "f" * 64
    seal(policy)
    assert_rejected(cli(tmp_path, source, policy, pins))


@pytest.mark.parametrize("relative", [verifier.OPENAPI, verifier.REWRITE, verifier.AUTH_SOURCE, verifier.AUTH_DEPENDENCIES, verifier.APP / "api/v1/documents.py"])
def test_changed_source_bytes_fail_with_all_pins_unchanged(source, tmp_path, relative):
    policy, pins = artifact(source)
    file = source / relative
    file.write_bytes(file.read_bytes() + b"\n")
    assert_rejected(cli(tmp_path, source, policy, pins))


def test_published_policy_uses_rfc8785_not_python_source_or_json_whitespace(source, tmp_path):
    policy, pins = artifact(source)
    published = json.loads((source / verifier.AUTH_POLICY).read_text())
    assert pins["authorization_policy_digest"] == compute_policy_digest(published)
    assert pins["authorization_policy_digest"] != pins["authorization_source_digest"]
    (source / verifier.AUTH_POLICY).write_text(json.dumps(published, indent=4))
    assert cli(tmp_path, source, policy, pins).returncode == 0
    published["policy_version"] = "2.0.0"
    (source / verifier.AUTH_POLICY).write_text(json.dumps(published))
    assert_rejected(cli(tmp_path, source, policy, pins))


@pytest.mark.parametrize("mode", ["duplicate", "nan", "unknown", "no_record", "empty", "or_array"])
def test_closed_schema_and_json_parser_fail_without_output(source, tmp_path, mode):
    policy, pins = artifact(source)
    raw = None
    if mode == "duplicate": raw = json.dumps(policy).replace('"schema_version":', '"schema_version":"wrong","schema_version":').encode()
    elif mode == "nan": raw = json.dumps(policy).replace('"routes":', '"untrusted":NaN,"routes":').encode()
    elif mode == "unknown": policy["unreviewed"] = True
    elif mode == "no_record": del policy["record_digest"]
    elif mode == "empty": policy["routes"] = []
    else: policy["routes"][0]["prefilter_scope"] = ["scanalyze.api.v1/read", "scanalyze.api.v1/admin"]
    if mode not in {"duplicate", "nan", "no_record"}: seal(policy)
    assert_rejected(cli(tmp_path, source, policy, pins, expected="sha256:" + "a" * 64 if mode == "no_record" else None, raw=raw))


def test_caller_cannot_supply_a_permissive_schema(source, tmp_path):
    policy, pins = artifact(source)
    fake = tmp_path / "permissive.json"
    fake.write_text("{}")
    result = cli(tmp_path, source, policy, pins, extra=("--schema-path", str(fake)))
    assert result.returncode == 2 and result.stdout == ""


@pytest.mark.parametrize("index,scope,accepted", [
    (0, "admin", True), (0, "write", False), (1, "admin", False),
    (2, "admin", False), (3, "read", False), (4, "read", False), (4, "admin", True),
    (6, "read", True), (6, "write", False), (6, "admin", False),
    (7, "read", True), (7, "write", False), (7, "admin", True),
])
def test_prefilter_is_necessary_for_every_allowed_principal_and_alternative(source, tmp_path, index, scope, accepted):
    policy, pins = artifact(source)
    policy["routes"][index]["prefilter_scope"] = "scanalyze.api.v1/" + scope
    seal(policy)
    result = cli(tmp_path, source, policy, pins)
    if accepted: assert result.returncode == 0, result.stderr
    else: assert_rejected(result)


@pytest.mark.parametrize("scope", ["read", "write"])
def test_alternative_operations_without_a_common_scope_cannot_be_projected(source, tmp_path, scope):
    # Exercise the actual AST parser after an independently pinned source change:
    # reconciliation can create either a batch (R here) or a document (W).
    target = source / verifier.AUTH_SOURCE
    original = '''OperationId.BATCHES_CREATE: OperationPolicy(
        OperationId.BATCHES_CREATE,
        (_permission(ResourceType.BATCHES, (Action.WRITE,), (DataClass.METADATA,)),),
        _WRITE,
    ),'''
    replacement = original.replace("Action.WRITE", "Action.READ").replace("_WRITE", "_READ")
    text = target.read_text()
    assert text.count(original) == 1
    target.write_text(text.replace(original, replacement))
    policy, pins = artifact(source)
    policy["routes"][3]["prefilter_scope"] = "scanalyze.api.v1/" + scope
    seal(policy)
    assert_rejected(cli(tmp_path, source, policy, pins))


@pytest.mark.parametrize("mode", ["duplicate", "phantom", "missing_metadata", "wrong_operation", "wildcard", "greedy", "query", "double_slash", "parent", "trailing_slash"])
def test_route_selection_is_exact_and_cannot_widen(source, tmp_path, mode):
    policy, pins = artifact(source)
    if mode == "duplicate": policy["routes"].append(deepcopy(policy["routes"][0]))
    elif mode == "missing_metadata": policy["routes"][0].update(path="/health", operation_ids=[])
    elif mode == "wrong_operation": policy["routes"][3]["operation_ids"] = ["batches.create"]
    else:
        policy["routes"][0]["path"] = {
            "phantom": "/api/v1/documents", "wildcard": "/api/*", "greedy": "/api/{proxy+}",
            "query": "/health?public=true", "double_slash": "/api//v1/health",
            "parent": "/api/../health", "trailing_slash": "/api/v1/admin/roles/",
        }[mode]
    seal(policy)
    assert_rejected(cli(tmp_path, source, policy, pins))


@pytest.mark.parametrize("mode", ["conditional", "nested", "dynamic_prefix", "shadow_import", "early_return", "unknown_receiver", "duplicate_mount", "router_rebound", "dynamic_route"])
def test_ambiguous_mount_graph_fails_even_when_caller_attempts_reanchoring(source, mode):
    main = source / verifier.APP / "main.py"
    text = main.read_text()
    if mode == "conditional": text = text.replace("    app.include_router(health_router)", "    if False:\n        app.include_router(health_router)")
    elif mode == "nested": text = text.replace("    app.include_router(health_router)", "    def unused():\n        app.include_router(health_router)")
    elif mode == "shadow_import": text = text.replace("    app.include_router(health_router)", "    health_router = FastAPI()\n    app.include_router(health_router)")
    elif mode == "early_return": text = text.replace("    # Routers", "    if s.env:\n        return app\n    # Routers")
    elif mode == "unknown_receiver": text = text.replace("app.include_router(health_router)", "foreign.include_router(health_router)")
    elif mode == "duplicate_mount": text = text.replace("    app.include_router(health_router)", "    app.include_router(health_router)\n    app.include_router(health_router)")
    elif mode == "dynamic_route": text = text.replace("    # Routers", "    app.add_api_route('/hidden', lambda: {})\n    # Routers")
    else:
        target = source / verifier.APP / "api/v1/router.py"
        changed = target.read_text()
        if mode == "dynamic_prefix": changed = changed.replace('prefix="/api/v1"', 'prefix=PREFIX')
        else: changed += '\nrouter = APIRouter(prefix="/foreign")\n'
        target.write_text(changed)
    main.write_text(text)
    with pytest.raises((ValueError, KeyError)):
        verifier.inspect_sources(source)


def test_unmounted_router_is_excluded_and_cannot_be_published(source, tmp_path):
    target = source / verifier.APP / "api/v1/documents.py"
    target.write_text(target.read_text() + '''
unused = APIRouter()
@unused.get("/unmounted")
async def not_mounted(auth=Depends(_READ_DOCUMENT_ACCESS)):
    return {}
''')
    policy, pins = artifact(source)
    inventory, _, _ = verifier.inspect_sources(source)
    assert len(inventory) == 54 and not any("unmounted" in row["path"] for row in inventory)
    policy["routes"].append({"method":"GET", "path":"/api/v1/documents/unmounted",
        "operation_ids":["documents.read_metadata"], "prefilter_scope":"scanalyze.api.v1/read"})
    seal(policy)
    assert_rejected(cli(tmp_path, source, policy, pins))


@pytest.mark.parametrize("symbol", ["APIRouter", "Depends", "require_operation", "OperationId"])
def test_import_shadowing_cannot_change_the_semantics_of_parsed_names(source, symbol):
    target = source / verifier.APP / "api/v1/documents.py"
    target.write_text(target.read_text() + "\nfrom ignored import " + symbol + "\n")
    with pytest.raises(ValueError):
        verifier.inspect_sources(source)


@pytest.mark.parametrize("statement", [
    "from ...auth import get_auth_context as _READ_DOCUMENT_ACCESS",
    "from ignored import _READ_DOCUMENT_ACCESS",
    "import ignored as _READ_DOCUMENT_ACCESS",
    "def _READ_DOCUMENT_ACCESS():\n    return None",
    "async def _READ_DOCUMENT_ACCESS():\n    return None",
    "class _READ_DOCUMENT_ACCESS:\n    pass",
])
def test_dependency_replacement_before_decorator_is_rejected(source, tmp_path, statement):
    policy, pins = artifact(source)
    target = source / verifier.APP / "api/v1/documents.py"
    text = target.read_text()
    assert "@router." in text
    target.write_text(text.replace("@router.", statement + "\n\n@router.", 1))
    # Existing custody rejects changed bytes, and fresh pins cannot make this
    # ambiguous dependency look like the require_operation binding it replaced.
    assert_rejected(cli(tmp_path, source, policy, pins))
    with pytest.raises(ValueError):
        verifier.inspect_sources(source)


@pytest.mark.parametrize("mutation", [
    "if True:\n    _READ_DOCUMENT_ACCESS = lambda: None\n",
    'register = router.get\n@register("/hidden")\nasync def hidden():\n    return {}\n',
])
def test_dependency_rebinding_and_aliased_route_registration_fail_closed(source, mutation):
    target = source / verifier.APP / "api/v1/documents.py"
    target.write_text(target.read_text() + "\n" + mutation)
    with pytest.raises(ValueError):
        verifier.inspect_sources(source)


def test_alias_actions_are_resolved_from_ast_without_name_inference(source):
    source_text = (source / verifier.AUTH_SOURCE).read_text()
    published = json.loads((source / verifier.AUTH_POLICY).read_text())
    renamed = source_text.replace("_READ_ADMIN", "_EXPLICIT_READ_AND_ADMIN")
    _, requirements = verifier.operation_requirements(ast.parse(renamed), published)
    assert requirements["results.read_full"][:2] == ({"scanalyze.api.v1/read", "scanalyze.api.v1/admin"},) * 2
    with pytest.raises(ValueError):
        verifier.operation_requirements(ast.parse(source_text.replace("_READ_ADMIN = frozenset({Action.READ.value, Action.ADMIN.value})", "_READ_ADMIN = unknown_action_set()")), published)


def test_duplicate_parameter_shape_is_rejected_without_silent_dedup(source):
    target = source / verifier.APP / "api/v1/documents.py"
    target.write_text(target.read_text() + '''
@router.get("/{renamed_parameter}")
async def ambiguous(auth=Depends(_READ_DOCUMENT_ACCESS)):
    return {}
''')
    with pytest.raises(ValueError): verifier.inspect_sources(source)
