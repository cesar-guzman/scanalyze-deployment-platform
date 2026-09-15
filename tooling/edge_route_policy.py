"""Offline verification of a reviewed route subset; never imports the application."""
from __future__ import annotations

import argparse
import ast
import hashlib
import json
from pathlib import Path
import re
import sys

import jsonschema

from tooling.authorize_deployment_backend import canonical_digest
from tooling.policy_digest import compute_policy_digest
from tooling.validate_enterprise_authorization import validate_enterprise_authorization

ROOT = Path(__file__).resolve().parents[1]
APP = Path("backend/workers/scanalyze-ingest-api/app")
AUTH_SOURCE = APP / "enterprise_authorization.py"
AUTH_DEPENDENCIES = APP / "authorization.py"
AUTH_POLICY = Path("policies/authorization/enterprise-authorization.v1.json")
OPENAPI = Path("schemas/scanalyze-document-journey.openapi.v1.json")
REWRITE = Path("modules/edge/api_path_rewrite.js")
METHODS = frozenset({"GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"})
PIN_FIELDS = frozenset({
    "source_commit", "source_tree_digest", "inventory_digest", "openapi_digest",
    "authorization_policy_digest", "authorization_policy_version",
    "authorization_source_digest", "rewrite_source_digest",
})
DIGEST = re.compile(r"sha256:[a-f0-9]{64}\Z")
PATH = re.compile(r"/(?:[A-Za-z0-9_-]+|\{[A-Za-z][A-Za-z0-9_]*\})(?:/(?:[A-Za-z0-9_-]+|\{[A-Za-z][A-Za-z0-9_]*\}))*\Z")


def require(condition: bool) -> None:
    if not condition:
        raise ValueError("edge route policy rejected")


def strict_json(data: bytes):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result)
            result[key] = value
        return result

    def invalid(_):
        raise ValueError("invalid JSON constant")

    return json.loads(data, object_pairs_hook=pairs, parse_constant=invalid)


def read_bytes(path: Path) -> bytes:
    require(not path.is_symlink() and path.is_file())
    require(path.stat().st_size <= 1_048_576)
    return path.read_bytes()


def byte_digest(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def schema_validate(value, name: str) -> None:
    # The caller cannot replace either verifier schema.
    schema = strict_json(read_bytes(ROOT / "schemas" / name))
    jsonschema.Draft202012Validator(schema).validate(value)


def assignments(tree):
    result = {}
    for node in tree.body:
        target = node.target if isinstance(node, ast.AnnAssign) else (
            node.targets[0] if isinstance(node, ast.Assign) and len(node.targets) == 1 else None
        )
        if isinstance(target, ast.Name):
            require(target.id not in result)
            result[target.id] = node.value
    return result


def literal(node, expected_type):
    value = ast.literal_eval(node)
    require(type(value) is expected_type)
    return value


def enum_values(tree, name):
    classes = [node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == name]
    require(len(classes) == 1)
    values = {key: literal(value, str) for key, value in assignments(classes[0]).items()}
    require(bool(values) and len(set(values.values())) == len(values))
    return values


def member(node, enum_name, values):
    require(isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name)
            and node.value.id == enum_name and node.attr in values)
    return values[node.attr]


def call_named(node, name):
    return isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == name


def operation_requirements(tree, published):
    values = assignments(tree)
    actions, operations = enum_values(tree, "Action"), enum_values(tree, "OperationId")
    require(literal(values["POLICY_DIGEST"], str) == compute_policy_digest(published))
    require(literal(values["POLICY_VERSION"], str) == published["policy_version"])
    scope_ast = values["_ACTION_SCOPES"]
    require(isinstance(scope_ast, ast.Dict))
    scopes = {}
    for key, value in zip(scope_ast.keys, scope_ast.values):
        action = member(key, "Action", actions)
        require(action not in scopes)
        scopes[action] = literal(value, str)
    require(scopes == {item["id"]: item["scope"] for item in published["actions"]})

    def action_set(node, seen=frozenset()):
        if isinstance(node, ast.Name):
            require(node.id in values and node.id not in seen)
            return action_set(values[node.id], seen | {node.id})
        if call_named(node, "frozenset"):
            require(not node.keywords and len(node.args) <= 1)
            return action_set(node.args[0], seen) if node.args else set()
        require(isinstance(node, (ast.Tuple, ast.Set)))
        result = set()
        for item in node.elts:
            if isinstance(item, ast.Attribute) and item.attr == "value":
                item = item.value
            action = member(item, "Action", actions)
            require(action not in result)
            result.add(action)
        return result

    table = values["OPERATION_POLICIES"]
    require(isinstance(table, ast.Dict))
    requirements = {}
    for key, value in zip(table.keys, table.values):
        operation = member(key, "OperationId", operations)
        require(operation not in requirements and call_named(value, "OperationPolicy") and len(value.args) == 3)
        require(member(value.args[0], "OperationId", operations) == operation)
        require(isinstance(value.args[1], ast.Tuple) and bool(value.args[1].elts))
        human = set()
        for permission in value.args[1].elts:
            require(call_named(permission, "_permission") and len(permission.args) == 3 and not permission.keywords)
            human.update(action_set(permission.args[1]))
        keywords = {}
        for kw in value.keywords:
            require(kw.arg in {"m2m_allowed", "step_up_required", "temporary_grant_allowed"} and kw.arg not in keywords)
            keywords[kw.arg] = literal(kw.value, bool)
        m2m = action_set(value.args[2])
        allowed = keywords.get("m2m_allowed", True)
        require(bool(human) and (bool(m2m) if allowed else not m2m))
        requirements[operation] = ({scopes[a] for a in human}, {scopes[a] for a in m2m}, allowed)
    require(set(requirements) == set(operations.values()))
    return operations, requirements


class MountedInventory:
    """Accept the explicit router/factory syntax in this release; deny ambiguity."""

    def __init__(self, source_root: Path, operations):
        self.root = source_root.resolve()
        self.app = self.root / APP
        self.operations = operations
        self.sources = {}
        self.stack = set()

    def tree(self, path):
        require(path.resolve().is_relative_to(self.app) and path.resolve() == path.absolute())
        data = read_bytes(path)
        self.sources[str(path.relative_to(self.root))] = byte_digest(data)
        return ast.parse(data)

    def imported_router(self, tree, path, name):
        matches = []
        for node in tree.body:
            if isinstance(node, ast.ImportFrom):
                for alias in node.names:
                    if (alias.asname or alias.name) == name:
                        require(node.level > 0 and node.module is not None)
                        directory = path.parent
                        for _ in range(node.level - 1):
                            directory = directory.parent
                        target = directory / (node.module.replace(".", "/") + ".py")
                        require(target.is_file())
                        matches.append((target, alias.name))
        require(len(matches) == 1)
        return matches[0]

    def validate_bindings(self, tree, path, dependencies):
        origins = {
            "FastAPI": "fastapi", "APIRouter": "fastapi", "Depends": "fastapi",
            "require_operation": self.app / "authorization.py",
            "ROUTE_OPERATION_POLICY_ATTRIBUTE": self.app / "authorization.py",
            "OperationId": self.app / "enterprise_authorization.py",
            "authorize_operation": self.app / "enterprise_authorization.py",
        }
        imports = {}
        top_level = {id(node) for node in tree.body}
        dependency_values = assignments(tree)
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                require(all(alias.name != "*" for alias in node.names))
                for alias in node.names:
                    name = alias.asname or alias.name
                    require(name not in dependencies)
                    if name not in origins:
                        continue
                    require(id(node) in top_level and name not in imports and alias.name == name
                            and alias.asname is None)
                    if node.level == 0:
                        origin = node.module
                    else:
                        require(node.module is not None)
                        origin = path.parent
                        for _ in range(node.level - 1):
                            origin = origin.parent
                        origin = origin / (node.module.replace(".", "/") + ".py")
                    require(origin == origins[name])
                    imports[name] = origin
            if isinstance(node, ast.Import):
                require(not any((alias.asname or alias.name.split(".")[0]) in origins.keys() | dependencies.keys()
                                for alias in node.names))
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                require(node.name not in origins)
                if node.name in dependencies:
                    require(node.name not in dependency_values and id(node) in top_level
                            and not isinstance(node, ast.ClassDef)
                            and sum(isinstance(other, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
                                    and other.name == node.name for other in ast.walk(tree)) == 1)
            if isinstance(node, ast.arg):
                require(node.arg not in origins.keys() | dependencies.keys())
            if isinstance(node, (ast.ExceptHandler, ast.MatchAs, ast.MatchStar)):
                require(node.name not in origins.keys() | dependencies.keys())
            if isinstance(node, ast.MatchMapping):
                require(node.rest not in origins.keys() | dependencies.keys())
            if isinstance(node, ast.Name):
                if node.id in origins:
                    require(isinstance(node.ctx, ast.Load))
                if node.id in dependencies and isinstance(node.ctx, (ast.Store, ast.Del)):
                    require(any(isinstance(statement, (ast.Assign, ast.AnnAssign))
                                and statement.value is dependency_values.get(node.id)
                                and any(child is node for child in ast.walk(statement)) for statement in tree.body))
        used = {node.id for node in ast.walk(tree) if isinstance(node, ast.Name) and node.id in origins}
        require(used <= imports.keys())

    def dependency_operations(self, tree):
        values = assignments(tree)
        deps = {}
        for name, value in values.items():
            if call_named(value, "require_operation"):
                require(len(value.args) == 1 and all(kw.arg == "auth_dependency" for kw in value.keywords))
                deps[name] = [member(value.args[0], "OperationId", self.operations)]
        functions = {node.name: node for node in tree.body if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))}
        for node in tree.body:
            call = node.value if isinstance(node, ast.Expr) else None
            if not call_named(call, "setattr") or len(call.args) != 3:
                continue
            target, attr, payload = call.args
            if not (isinstance(attr, ast.Name) and attr.id == "ROUTE_OPERATION_POLICY_ATTRIBUTE"):
                continue
            require(isinstance(target, ast.Name) and target.id in functions and target.id not in deps)
            require(call_named(payload, "frozenset") and len(payload.args) == 1 and not payload.keywords
                    and isinstance(payload.args[0], ast.Set))
            ops = [member(item, "OperationId", self.operations) for item in payload.args[0].elts]
            require(bool(ops) and len(set(ops)) == len(ops))
            body = functions[target.id]
            require(any(call_named(item, "authorize_operation") for item in ast.walk(body)))
            selected = {member(item, "OperationId", self.operations) for item in ast.walk(body)
                        if isinstance(item, ast.Attribute) and isinstance(item.value, ast.Name) and item.value.id == "OperationId"}
            require(selected == set(ops))
            deps[target.id] = sorted(ops)
        return deps

    @staticmethod
    def prefix(call):
        require(not any(kw.arg is None or kw.arg in {"dependencies", "routes", "route_class"} for kw in call.keywords))
        prefixes = [kw.value for kw in call.keywords if kw.arg == "prefix"]
        require(len(prefixes) <= 1)
        prefix = literal(prefixes[0], str) if prefixes else ""
        require(prefix == "" or (PATH.fullmatch(prefix) is not None and "{" not in prefix))
        return prefix

    def collect(self, path, receiver, inherited="", *, root=False):
        identity = (path, receiver)
        require(identity not in self.stack)
        self.stack.add(identity)
        tree = self.tree(path)
        scope = tree
        allowed_calls = set()
        allowed_assignments = set()
        if root:
            exports = assignments(tree)
            factory = exports[receiver]
            require(isinstance(factory, ast.Call) and isinstance(factory.func, ast.Name) and not factory.args and not factory.keywords)
            definitions = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == factory.func.id]
            require(len(definitions) == 1)
            scope = definitions[0]
            require(not scope.decorator_list)
            require(not scope.args.args and not scope.args.kwonlyargs and not scope.args.vararg and not scope.args.kwarg)
            require(isinstance(scope.body[-1], ast.Return) and isinstance(scope.body[-1].value, ast.Name)
                    and scope.body[-1].value.id == receiver)
            allowed_assignments.add(id(factory))
            def check_returns(body):
                for statement in body:
                    if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                        continue
                    if isinstance(statement, ast.Return):
                        require(statement is scope.body[-1])
                    for field in ("body", "orelse", "finalbody"):
                        nested = getattr(statement, field, [])
                        if isinstance(nested, list):
                            check_returns(nested)
                    for handler in getattr(statement, "handlers", []):
                        check_returns(handler.body)
            check_returns(scope.body)
        values = assignments(scope)
        reserved = {"APIRouter", "FastAPI", "Depends", "require_operation", "OperationId"}
        require(not reserved.intersection(assignments(tree)))
        require(not any(isinstance(node, (ast.FunctionDef, ast.ClassDef)) and node.name in reserved for node in tree.body))
        constructor = values[receiver]
        require(call_named(constructor, "FastAPI" if root else "APIRouter") and not constructor.args)
        expected_import = "FastAPI" if root else "APIRouter"
        require(any(isinstance(node, ast.ImportFrom) and node.module == "fastapi" and node.level == 0
                    and any(alias.name == expected_import and alias.asname is None for alias in node.names) for node in tree.body))
        allowed_calls.add(id(constructor))
        allowed_assignments.add(id(constructor))
        active = inherited + self.prefix(constructor)
        deps = self.dependency_operations(tree)
        self.validate_bindings(tree, path, deps)
        rows = []
        local_routers = {name for name, value in values.items() if call_named(value, "APIRouter") or call_named(value, "FastAPI")}
        for value in values.values():
            if call_named(value, "APIRouter") or call_named(value, "FastAPI"):
                allowed_calls.add(id(value))
        for node in scope.body:
            if isinstance(node, ast.Expr) and isinstance(node.value, ast.Call):
                call = node.value
                if isinstance(call.func, ast.Attribute) and call.func.attr == "include_router":
                    require(isinstance(call.func.value, ast.Name) and call.func.value.id in local_routers)
                    allowed_calls.add(id(call))
                    if call.func.value.id != receiver:
                        continue
                    require(len(call.args) == 1 and isinstance(call.args[0], ast.Name))
                    require(call.args[0].id not in values)
                    child, child_receiver = self.imported_router(tree, path, call.args[0].id)
                    rows.extend(self.collect(child, child_receiver, active + self.prefix(call)))
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            for decorator in node.decorator_list:
                if not (isinstance(decorator, ast.Call) and isinstance(decorator.func, ast.Attribute)
                        and decorator.func.attr.upper() in METHODS):
                    continue
                require(isinstance(decorator.func.value, ast.Name) and decorator.func.value.id in local_routers)
                allowed_calls.add(id(decorator))
                if decorator.func.value.id != receiver:
                    continue
                require(len(decorator.args) == 1 and not any(kw.arg is None or kw.arg == "dependencies" for kw in decorator.keywords))
                suffix = literal(decorator.args[0], str)
                require(suffix == "" or PATH.fullmatch(suffix) is not None)
                full_path = active + suffix
                require(PATH.fullmatch(full_path) is not None)
                ops = []
                for default in [*node.args.defaults, *node.args.kw_defaults]:
                    if call_named(default, "Depends"):
                        require(len(default.args) == 1)
                        dependency = default.args[0]
                        if isinstance(dependency, ast.Name):
                            ops.extend(deps.get(dependency.id, []))
                        elif call_named(dependency, "require_operation"):
                            require(len(dependency.args) == 1)
                            ops.append(member(dependency.args[0], "OperationId", self.operations))
                        else:
                            raise ValueError("unsupported dependency")
                require(len(ops) == len(set(ops)))
                rows.append({"method": decorator.func.attr.upper(), "path": full_path, "operation_ids": sorted(ops)})
        for node in ast.walk(tree):
            if isinstance(node, ast.Attribute):
                routing_attribute = node.attr in {"include_router", "add_api_route", "api_route", "mount"}
                routing_attribute |= isinstance(node.value, ast.Name) and node.value.id in local_routers and node.attr.upper() in METHODS
                require(not routing_attribute or any(isinstance(call, ast.Call) and call.func is node
                                                     and id(call) in allowed_calls for call in ast.walk(tree)))
            if isinstance(node, ast.Call):
                func = node.func
                routing = call_named(node, "APIRouter") or call_named(node, "FastAPI")
                if isinstance(func, ast.Attribute):
                    routing |= func.attr in {"include_router", "add_api_route", "api_route", "mount"}
                    routing |= (isinstance(func.value, ast.Name) and func.value.id in local_routers and func.attr.upper() in METHODS)
                    routing |= isinstance(func.value, ast.Attribute) and func.value.attr == "routes"
                require(not routing or id(node) in allowed_calls)
            if isinstance(node, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                for target in targets:
                    if isinstance(target, ast.Name) and target.id == receiver:
                        require(id(node.value) in allowed_assignments)
                    if isinstance(target, ast.Attribute) and isinstance(target.value, ast.Name) and target.value.id == receiver:
                        require(target.attr not in {"prefix", "routes", "route_class"})
        self.stack.remove(identity)
        return rows

    def inventory(self):
        rows = self.collect(self.app / "main.py", "app", root=True)
        seen = set()
        for row in rows:
            key = (row["method"], re.sub(r"\{[^}]+\}", "{}", row["path"]))
            require(key not in seen)
            seen.add(key)
        return sorted(rows, key=lambda row: (row["method"], row["path"]))


def inspect_sources(source_root: Path):
    source_root = source_root.resolve()
    published = strict_json(read_bytes(source_root / AUTH_POLICY))
    schema_validate(published, "enterprise-authorization.v1.schema.json")
    require(not validate_enterprise_authorization(published))
    auth_bytes = read_bytes(source_root / AUTH_SOURCE)
    operations, requirements = operation_requirements(ast.parse(auth_bytes), published)
    collector = MountedInventory(source_root, operations)
    inventory = collector.inventory()
    collector.sources[str(AUTH_SOURCE)] = byte_digest(auth_bytes)
    # require_operation owns the metadata attached to dependency functions.
    collector.sources[str(AUTH_DEPENDENCIES)] = byte_digest(read_bytes(source_root / AUTH_DEPENDENCIES))
    openapi_bytes = read_bytes(source_root / OPENAPI)
    openapi = strict_json(openapi_bytes)
    mounted = {(row["method"], row["path"]) for row in inventory}
    require(isinstance(openapi.get("paths"), dict) and bool(openapi["paths"]))
    for path, item in openapi["paths"].items():
        for method in item:
            if method.upper() in METHODS:
                require((method.upper(), path) in mounted)
    pins = {
        "source_tree_digest": canonical_digest(collector.sources),
        "inventory_digest": canonical_digest(inventory),
        "authorization_source_digest": byte_digest(auth_bytes),
        "authorization_policy_digest": compute_policy_digest(published),
        "authorization_policy_version": published["policy_version"],
        "openapi_digest": byte_digest(openapi_bytes),
        "rewrite_source_digest": byte_digest(read_bytes(source_root / REWRITE)),
    }
    return inventory, requirements, pins


def verify_policy(policy, expected_record_digest, expected_pins, source_root: Path):
    schema_validate(policy, "edge-route-policy.v1.schema.json")
    require(isinstance(expected_pins, dict) and set(expected_pins) == PIN_FIELDS)
    require(isinstance(expected_record_digest, str) and DIGEST.fullmatch(expected_record_digest) is not None)
    require(policy["record_digest"] == expected_record_digest == canonical_digest({key: value for key, value in policy.items() if key != "record_digest"}))
    require({key: policy[key] for key in PIN_FIELDS} == expected_pins)
    inventory, requirements, observed = inspect_sources(source_root)
    require(all(policy[key] == value for key, value in observed.items()))
    routes = {(row["method"], row["path"]): row for row in inventory}
    output = {}
    for row in policy["routes"]:
        key = (row["method"], row["path"])
        require(PATH.fullmatch(row["path"]) is not None and key in routes)
        require(row["operation_ids"] == routes[key]["operation_ids"] and bool(row["operation_ids"]))
        route_key = " ".join(key)
        require(route_key not in output)
        candidates = None
        for operation in row["operation_ids"]:
            human, m2m, m2m_allowed = requirements[operation]
            necessary = human & m2m if m2m_allowed else human
            candidates = necessary if candidates is None else candidates & necessary
        require(row["prefilter_scope"] in candidates)
        output[route_key] = [row["prefilter_scope"]]
    return {"api_authorization_routes": dict(sorted(output.items()))}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["verify"])
    parser.add_argument("--policy-path", required=True, type=Path)
    parser.add_argument("--expected-record-digest", required=True)
    parser.add_argument("--expected-pins-path", required=True, type=Path)
    parser.add_argument("--source-root", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        output = verify_policy(strict_json(read_bytes(args.policy_path)), args.expected_record_digest,
                               strict_json(read_bytes(args.expected_pins_path)), args.source_root)
    except (ValueError, TypeError, KeyError, AttributeError, OSError, SyntaxError, RecursionError, jsonschema.ValidationError):
        print("EDGE_ROUTE_POLICY_REJECTED", file=sys.stderr)
        return 2
    print(json.dumps(output, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
