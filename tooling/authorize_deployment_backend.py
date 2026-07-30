#!/usr/bin/env python3
"""Authorize and render one Terraform backend from trusted deployment records.

Request values are assertions only. The approved deployment target, an
independently retrieved target anchor, ACCOUNT_READY v2, the canonical layer
catalog, and a held deployment execution lock all have to agree exactly.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import tempfile
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Any

import jsonschema
import yaml


REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_SCHEMA_DIR = REPO_ROOT / "schemas"
EXECUTABLE_STATUSES = frozenset({"READY", "ACTIVE"})
EXPECTED_CONTROLS = {
    "state_versioning_enabled": True,
    "state_default_encryption": "aws:kms",
    "state_bucket_key_enabled": True,
    "state_public_access_blocked": True,
    "state_object_lock_enabled": False,
    "native_lockfile_enabled": True,
}
KMS_ARN = re.compile(
    r"^arn:aws(?:-[a-z]+)*:kms:(?P<region>[a-z0-9-]+):"
    r"(?P<account>[0-9]{12}):key/[A-Za-z0-9-]+$"
)
S3_ARN = re.compile(
    r"^arn:aws(?:-[a-z]+)*:s3:::(?P<bucket>[a-z0-9][a-z0-9.-]{1,61}[a-z0-9])$"
)


class AuthorizationError(ValueError):
    """A deployment target or backend could not be proven safe."""


def canonical_digest(document: dict[str, Any]) -> str:
    """Return the SHA-256 digest of canonical JSON."""
    canonical = json.dumps(
        document,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )
    return "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise AuthorizationError(f"duplicate JSON key is forbidden: {key}")
        result[key] = value
    return result


def load_json_strict(path: Path) -> dict[str, Any]:
    """Load a JSON object while rejecting duplicate keys and non-objects."""
    try:
        value = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=_reject_duplicate_pairs,
        )
    except (OSError, json.JSONDecodeError) as exc:
        raise AuthorizationError(f"invalid JSON document: {path.name}") from exc
    if not isinstance(value, dict):
        raise AuthorizationError(f"JSON document must be an object: {path.name}")
    return value


class _UniqueKeyLoader(yaml.SafeLoader):
    pass


def _construct_unique_mapping(
    loader: yaml.SafeLoader,
    node: yaml.nodes.MappingNode,
    deep: bool = False,
) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in result:
            raise AuthorizationError(f"duplicate YAML key is forbidden: {key}")
        result[key] = loader.construct_object(value_node, deep=deep)
    return result


_UniqueKeyLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_unique_mapping,
)


def load_yaml_strict(path: Path) -> dict[str, Any]:
    """Load a YAML mapping while rejecting duplicate keys."""
    try:
        value = yaml.load(path.read_text(encoding="utf-8"), Loader=_UniqueKeyLoader)
    except (OSError, yaml.YAMLError) as exc:
        raise AuthorizationError(f"invalid YAML document: {path.name}") from exc
    if not isinstance(value, dict):
        raise AuthorizationError(f"YAML document must be a mapping: {path.name}")
    return value


def _schema(schema_dir: Path, name: str) -> dict[str, Any]:
    return load_json_strict(schema_dir / name)


def _validate_schema(
    document: dict[str, Any],
    schema_dir: Path,
    schema_name: str,
    label: str,
) -> None:
    validator = jsonschema.Draft202012Validator(
        _schema(schema_dir, schema_name),
        format_checker=jsonschema.FormatChecker(),
    )
    errors = sorted(validator.iter_errors(document), key=lambda error: list(error.path))
    if errors:
        first = errors[0]
        path = ".".join(str(part) for part in first.absolute_path) or "(root)"
        raise AuthorizationError(f"{label} schema validation failed at {path}")


def _digest_matches(document: dict[str, Any], field: str, label: str) -> None:
    claimed = document.get(field)
    computed = canonical_digest({key: value for key, value in document.items() if key != field})
    if claimed != computed:
        raise AuthorizationError(f"{label} digest mismatch")


def _parse_time(value: str, label: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise AuthorizationError(f"invalid {label} timestamp") from exc
    if parsed.tzinfo is None:
        raise AuthorizationError(f"{label} timestamp must be timezone-aware")
    return parsed.astimezone(UTC)


def _exact_bindings(
    manifest: dict[str, Any],
    target: dict[str, Any],
    account_ready: dict[str, Any],
) -> None:
    comparisons = {
        "customer_id": (manifest.get("customer_id"), target.get("customer_id"), account_ready.get("customer_id")),
        "deployment_id": (manifest.get("deployment_id"), target.get("deployment_id"), account_ready.get("deployment_id")),
        "account_id": (manifest.get("aws_account_id"), target.get("account_id"), account_ready.get("account_id")),
        "region": (manifest.get("aws_region"), target.get("region"), account_ready.get("region")),
        "environment": (manifest.get("environment"), target.get("environment"), account_ready.get("environment")),
    }
    for field, values in comparisons.items():
        if any(value is None or value == "" for value in values) or len(set(values)) != 1:
            raise AuthorizationError(f"conflicting {field} binding")


def _validate_roles(account_ready: dict[str, Any]) -> None:
    account_id = account_ready["account_id"]
    customer_id = account_ready["customer_id"]
    deployment_id = account_ready["deployment_id"]
    for role_name, role in account_ready["roles"].items():
        arn = role["arn"]
        if f"::{account_id}:role/" not in arn:
            raise AuthorizationError(f"role account binding mismatch: {role_name}")
        if role["customer_id_tag"] != customer_id:
            raise AuthorizationError(f"role customer binding mismatch: {role_name}")
        if role["deployment_id_tag"] != deployment_id:
            raise AuthorizationError(f"role deployment binding mismatch: {role_name}")
        if role["account_id_tag"] != account_id:
            raise AuthorizationError(f"role account tag mismatch: {role_name}")
        if role["region_tag"] != account_ready["region"]:
            raise AuthorizationError(f"role region binding mismatch: {role_name}")
        if role["environment_tag"] != account_ready["environment"]:
            raise AuthorizationError(f"role environment binding mismatch: {role_name}")


def _validate_state_binding(
    target: dict[str, Any],
    account_ready: dict[str, Any],
) -> tuple[str, str]:
    infrastructure = account_ready["state_infrastructure"]
    state_bucket_arn = infrastructure["state_bucket"]
    state_kms_key = infrastructure["state_kms_key"]
    if target["state_binding"] != {
        "state_bucket": state_bucket_arn,
        "state_kms_key": state_kms_key,
    }:
        raise AuthorizationError("registry and ACCOUNT_READY state binding mismatch")
    kms_match = KMS_ARN.fullmatch(state_kms_key)
    if not kms_match:
        raise AuthorizationError("state KMS key ARN is malformed")
    if kms_match.group("account") != target["account_id"]:
        raise AuthorizationError("state KMS key account binding mismatch")
    if kms_match.group("region") != target["region"]:
        raise AuthorizationError("state KMS key region binding mismatch")
    bucket_match = S3_ARN.fullmatch(state_bucket_arn)
    if not bucket_match:
        raise AuthorizationError("state bucket ARN is malformed")
    bucket = bucket_match.group("bucket")
    return bucket, state_kms_key


def _state_key(
    layer_catalog: dict[str, Any],
    layer: str,
    deployment_id: str,
    region: str,
) -> str:
    stages = [stage for stage in layer_catalog.get("layers", []) if stage.get("layer") == layer]
    if len(stages) != 1:
        raise AuthorizationError("layer is missing or ambiguous in canonical catalog")
    stage = stages[0]
    if stage.get("kind") != "terraform" or not stage.get("root"):
        raise AuthorizationError("backend authorization is limited to Terraform layers")
    template = stage.get("state_key")
    if not isinstance(template, str) or not template:
        raise AuthorizationError("Terraform layer has no state key")
    try:
        key = template.format(deployment_id=deployment_id, region=region)
    except (KeyError, ValueError) as exc:
        raise AuthorizationError("state key template is invalid") from exc
    path = PurePosixPath(key)
    if (
        path.is_absolute()
        or ".." in path.parts
        or "//" in key
        or not key.startswith(f"{deployment_id}/")
        or not key.endswith("/terraform.tfstate")
        or key.endswith(".tflock")
    ):
        raise AuthorizationError("derived state key is unsafe")
    if stage.get("scope") == "regional" and f"/{region}/" not in f"/{key}":
        raise AuthorizationError("regional state key is not region-bound")
    return key


def _validate_execution_lock(
    execution_lock: dict[str, Any],
    target: dict[str, Any],
    now: datetime,
) -> None:
    _digest_matches(execution_lock, "lock_digest", "execution lock")
    if execution_lock["status"] != "HELD":
        raise AuthorizationError("execution lock is not held")
    exact = {
        "deployment_id": target["deployment_id"],
        "account_id": target["account_id"],
        "region": target["region"],
        "registry_record_digest": target["record_digest"],
    }
    for field, expected in exact.items():
        if execution_lock.get(field) != expected:
            raise AuthorizationError(f"execution lock {field} mismatch")
    acquired_at = _parse_time(execution_lock["acquired_at"], "lock acquired_at")
    expires_at = _parse_time(execution_lock["expires_at"], "lock expires_at")
    if acquired_at >= expires_at:
        raise AuthorizationError("execution lock interval is invalid")
    duration_seconds = (expires_at - acquired_at).total_seconds()
    if not 300 <= duration_seconds <= 3600:
        raise AuthorizationError("execution lock duration is outside the approved range")
    if acquired_at > now.astimezone(UTC):
        raise AuthorizationError("execution lock was acquired in the future")
    if now.astimezone(UTC) >= expires_at:
        raise AuthorizationError("execution lock is expired")


def authorize_backend(
    *,
    manifest: dict[str, Any],
    target: dict[str, Any],
    anchor: dict[str, Any],
    account_ready: dict[str, Any],
    execution_lock: dict[str, Any],
    layer_catalog: dict[str, Any],
    layer: str,
    now: datetime,
    schema_dir: Path = DEFAULT_SCHEMA_DIR,
) -> dict[str, Any]:
    """Return a content-addressed backend binding or fail closed."""
    _validate_schema(manifest, schema_dir, "deployment-manifest.v2.schema.json", "manifest v2")
    _validate_schema(target, schema_dir, "deployment-target.v1.schema.json", "deployment target")
    _validate_schema(anchor, schema_dir, "deployment-target-anchor.v1.schema.json", "registry anchor")
    _validate_schema(account_ready, schema_dir, "account-ready.v2.schema.json", "ACCOUNT_READY v2")
    _validate_schema(execution_lock, schema_dir, "deployment-execution-lock.v1.schema.json", "execution lock")

    _digest_matches(target, "record_digest", "deployment target record")
    _digest_matches(account_ready, "contract_digest", "ACCOUNT_READY contract")

    if anchor != {
        "schema_version": "1",
        "deployment_id": target["deployment_id"],
        "registry_version": target["registry_version"],
        "record_digest": target["record_digest"],
    }:
        raise AuthorizationError("registry anchor does not exactly match target record")
    if target["status"] not in EXECUTABLE_STATUSES:
        raise AuthorizationError("deployment target status is not executable")
    if target["account_ready"] != {
        "schema_version": "2",
        "baseline_version": account_ready["baseline_version"],
        "contract_digest": account_ready["contract_digest"],
    }:
        raise AuthorizationError("registry and ACCOUNT_READY contract binding mismatch")
    if account_ready["controls"] != EXPECTED_CONTROLS:
        raise AuthorizationError("ACCOUNT_READY state controls are not approved")

    _exact_bindings(manifest, target, account_ready)
    _validate_roles(account_ready)
    bucket, kms_key = _validate_state_binding(target, account_ready)
    _validate_execution_lock(execution_lock, target, now)
    key = _state_key(
        layer_catalog,
        layer,
        target["deployment_id"],
        target["region"],
    )

    binding: dict[str, Any] = {
        "schema_version": "1",
        "customer_id": target["customer_id"],
        "deployment_id": target["deployment_id"],
        "account_id": target["account_id"],
        "region": target["region"],
        "environment": target["environment"],
        "layer": layer,
        "execution_id": execution_lock["execution_id"],
        "registry_version": target["registry_version"],
        "registry_record_digest": target["record_digest"],
        "account_ready_digest": account_ready["contract_digest"],
        "execution_lock_digest": execution_lock["lock_digest"],
        "backend": {
            "bucket": bucket,
            "key": key,
            "region": target["region"],
            "encrypt": True,
            "kms_key_id": kms_key,
            "use_lockfile": True,
            "allowed_account_ids": [target["account_id"]],
        },
    }
    binding["binding_digest"] = canonical_digest(binding)
    _validate_schema(
        binding,
        schema_dir,
        "terraform-backend-binding.v1.schema.json",
        "backend binding",
    )
    return binding


def render_backend_hcl(binding: dict[str, Any]) -> str:
    """Render only the reviewed S3 backend attributes."""
    backend = binding["backend"]
    quoted = lambda value: json.dumps(value, ensure_ascii=True)  # noqa: E731
    return "\n".join(
        [
            f"bucket = {quoted(backend['bucket'])}",
            f"key = {quoted(backend['key'])}",
            f"region = {quoted(backend['region'])}",
            "encrypt = true",
            f"kms_key_id = {quoted(backend['kms_key_id'])}",
            "use_lockfile = true",
            f"allowed_account_ids = [{quoted(backend['allowed_account_ids'][0])}]",
            "",
        ]
    )


def write_private_file(path: Path, content: str) -> None:
    """Atomically write a mode-0600 file and reject symlink destinations."""
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_symlink():
        raise AuthorizationError("refusing to replace a symlink destination")
    fd, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary_path = Path(temporary_name)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_path, path)
        path.chmod(0o600)
    except Exception:
        temporary_path.unlink(missing_ok=True)
        raise


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--target", type=Path, required=True)
    parser.add_argument("--target-anchor", type=Path, required=True)
    parser.add_argument("--account-ready", type=Path, required=True)
    parser.add_argument("--execution-lock", type=Path, required=True)
    parser.add_argument("--layer-catalog", type=Path, required=True)
    parser.add_argument("--layer", required=True)
    parser.add_argument("--backend-out", type=Path, required=True)
    parser.add_argument("--binding-out", type=Path, required=True)
    parser.add_argument("--expected-customer-id", required=True)
    parser.add_argument("--expected-deployment-id", required=True)
    parser.add_argument("--expected-account-id", required=True)
    parser.add_argument("--expected-region", required=True)
    parser.add_argument("--expected-execution-id", required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        binding = authorize_backend(
            manifest=load_yaml_strict(args.manifest),
            target=load_json_strict(args.target),
            anchor=load_json_strict(args.target_anchor),
            account_ready=load_json_strict(args.account_ready),
            execution_lock=load_json_strict(args.execution_lock),
            layer_catalog=load_yaml_strict(args.layer_catalog),
            layer=args.layer,
            now=datetime.now(UTC),
        )
        expected = {
            "customer_id": args.expected_customer_id,
            "deployment_id": args.expected_deployment_id,
            "account_id": args.expected_account_id,
            "region": args.expected_region,
            "execution_id": args.expected_execution_id,
        }
        for field, value in expected.items():
            if binding.get(field) != value:
                raise AuthorizationError(f"request assertion does not match {field}")
        write_private_file(args.backend_out, render_backend_hcl(binding))
        write_private_file(
            args.binding_out,
            json.dumps(binding, sort_keys=True, indent=2) + "\n",
        )
    except (AuthorizationError, OSError, KeyError) as exc:
        print(f"DENY: backend authorization failed: {exc}", file=sys.stderr)
        return 2
    print("PASS: registry, account baseline, execution lock, and backend binding verified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
