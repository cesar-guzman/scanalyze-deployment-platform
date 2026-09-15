"""Render the reviewed GUG-215 factory policies without provider I/O.

The pure renderer accepts independently pinned bytes only. Repo-path
loading for the PREPARED offline plan lives in
prepare_workforce_factory_policy_plan (still non-authorizing).

Byte pins must come from an independent review boundary. Matching pins establish
integrity only: a captured DescribeKey request/response does not authenticate
the provider or prove that alias/aws/dynamodb resolves to the supplied key.
DescribeKey on a predefined AWS alias can itself materialize its managed key;
this module neither performs nor authorizes that call.

The internal semantic pins constrain the two reviewed policy documents, not
source provenance or CI. A future installer still needs authenticated current
readbacks, reviewed signed runtime/version binding, and verified revocation of
the distinct factory role before broker activation. No returned object is an
installation grant, creation receipt, or deployment authorization.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import json
import math
import re
from typing import Any


_ACCOUNT = "042360977644"
_REGION = "us-east-1"
_ALIAS = "alias/aws/dynamodb"
_ACTIVE_SEMANTIC_SHA256 = "d91076d8d283d17404e0a9aba82528f36069da785b989ae181347811506869ac"
_INERT_SEMANTIC_SHA256 = "f99b4daa06151c7633ba372e345a672b8cde01fbe64811f5898abf9e521b2b54"
_MAX_JSON_BYTES = 32768
_MAX_NODES = 2048
_MAX_DEPTH = 16
_PIN = re.compile(r"[0-9a-f]{64}")
_KEY_ID = re.compile(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}")
_TIMESTAMP = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z")
_PLACEHOLDERS = {
    "${ledger_kms_key_arn}", "${factory_not_before}", "${factory_not_after}",
}


class WorkforceFactoryPolicyRejected(ValueError):
    """Sanitized rejection; raw input values never appear in diagnostics."""

    code = "WORKFORCE_FACTORY_POLICY_REJECTED"

    def __init__(self) -> None:
        super().__init__(self.code)


def _reject() -> None:
    raise WorkforceFactoryPolicyRejected()


def _canonical(document: Any) -> str:
    return json.dumps(document, sort_keys=True, ensure_ascii=True,
                      separators=(",", ":"), allow_nan=False)


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            _reject()
        result[key] = value
    return result


def _invalid_constant(_: str) -> None:
    _reject()


def _pinned_json(data: bytes, pin: str) -> dict[str, Any]:
    if (type(data) is not bytes or not 0 < len(data) <= _MAX_JSON_BYTES
            or type(pin) is not str or _PIN.fullmatch(pin) is None
            or _sha256(data) != pin):
        _reject()
    document = json.loads(data.decode("utf-8"), object_pairs_hook=_unique,
                          parse_constant=_invalid_constant)
    if type(document) is not dict:
        _reject()
    nodes = 0

    def inspect(value: Any, depth: int) -> None:
        nonlocal nodes
        nodes += 1
        if nodes > _MAX_NODES or depth > _MAX_DEPTH:
            _reject()
        if type(value) is dict:
            for key, item in value.items():
                key.encode("utf-8", errors="strict")
                inspect(item, depth + 1)
        elif type(value) is list:
            for item in value:
                inspect(item, depth + 1)
        elif type(value) is str:
            value.encode("utf-8", errors="strict")
        elif type(value) is float and not math.isfinite(value):
            _reject()

    inspect(document, 0)
    return document


def _timestamp(value: str) -> datetime:
    if type(value) is not str or _TIMESTAMP.fullmatch(value) is None:
        _reject()
    parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    # strptime accepts some noncanonical forms; the regex and round trip fix it.
    if parsed.isoformat(timespec="seconds").replace("+00:00", "Z") != value:
        _reject()
    return parsed


def _metadata(readback: dict[str, Any], now: datetime) -> tuple[dict[str, Any], datetime]:
    if set(readback) != {"schema_version", "account_id", "region", "observed_at",
                         "describe_key_request", "key_metadata"}:
        _reject()
    if (type(readback["schema_version"]) is not int or readback["schema_version"] != 1
            or readback["account_id"] != _ACCOUNT or readback["region"] != _REGION
            or readback["describe_key_request"] != {"KeyId": _ALIAS}):
        _reject()
    observed = _timestamp(readback["observed_at"])
    if not timedelta(0) <= now - observed <= timedelta(seconds=300):
        _reject()
    metadata = readback["key_metadata"]
    required = {"AWSAccountId", "Arn", "KeyId", "Enabled", "KeyUsage", "KeyState",
                "Origin", "KeyManager", "KeySpec", "MultiRegion", "EncryptionAlgorithms"}
    optional = {"CustomerMasterKeySpec", "CreationDate", "Description", "CurrentKeyMaterialId"}
    if type(metadata) is not dict or not required <= set(metadata) <= required | optional:
        _reject()
    key_id = metadata["KeyId"]
    if (type(key_id) is not str or _KEY_ID.fullmatch(key_id) is None
            or metadata["AWSAccountId"] != _ACCOUNT
            or metadata["Arn"] != f"arn:aws:kms:{_REGION}:{_ACCOUNT}:key/{key_id}"
            or metadata["Enabled"] is not True or metadata["KeyUsage"] != "ENCRYPT_DECRYPT"
            or metadata["KeyState"] != "Enabled" or metadata["Origin"] != "AWS_KMS"
            or metadata["KeyManager"] != "AWS" or metadata["KeySpec"] != "SYMMETRIC_DEFAULT"
            or metadata["MultiRegion"] is not False
            or metadata["EncryptionAlgorithms"] != ["SYMMETRIC_DEFAULT"]
            or metadata.get("CustomerMasterKeySpec") not in (None, "SYMMETRIC_DEFAULT")):
        _reject()
    if "Description" in metadata and (type(metadata["Description"]) is not str
                                     or len(metadata["Description"]) > 8192):
        _reject()
    if "CurrentKeyMaterialId" in metadata and (type(metadata["CurrentKeyMaterialId"]) is not str
                                              or _PIN.fullmatch(metadata["CurrentKeyMaterialId"]) is None):
        _reject()
    if "CreationDate" in metadata:
        created = metadata["CreationDate"]
        # AWS JSON timestamps are numbers; captured SDK/CLI output can be ISO UTC.
        if type(created) in (int, float):
            if not math.isfinite(created) or created < 0:
                _reject()
            datetime.fromtimestamp(created, timezone.utc)
        elif type(created) is str and len(created) <= 40:
            parsed = datetime.fromisoformat(created.replace("Z", "+00:00"))
            if parsed.tzinfo is None or parsed.utcoffset() != timedelta(0):
                _reject()
        else:
            _reject()
    return metadata, observed


def _template(data: bytes, pin: str, expected: str, placeholders: set[str]) -> dict[str, Any]:
    document = _pinned_json(data, pin)
    if _sha256(_canonical(document).encode("ascii")) != expected:
        _reject()
    found: set[str] = set()

    def inspect(value: Any) -> None:
        if type(value) is dict:
            for key, item in value.items():
                if "${" in key:
                    _reject()
                inspect(item)
        elif type(value) is list:
            for item in value:
                inspect(item)
        elif type(value) is str and "${" in value:
            if value not in _PLACEHOLDERS:
                _reject()
            found.add(value)

    inspect(document)
    if found != placeholders:
        _reject()
    return document


def _policy(document: dict[str, Any], replacements: dict[str, str]) -> dict[str, Any]:
    def expand(value: Any) -> Any:
        if type(value) is dict:
            return {key: expand(item) for key, item in value.items()}
        if type(value) is list:
            return [expand(item) for item in value]
        return replacements.get(value, value) if type(value) is str else value

    rendered = expand(document)
    serialized = _canonical(rendered)
    if len(serialized) > 6144:
        _reject()
    digest = _sha256(serialized.encode("ascii"))
    return {"document": rendered, "json": serialized, "sha256": digest,
            "iam_size_chars": len(serialized), "intended_attached_policy_sha256": digest,
            "intended_permissions_boundary_sha256": digest}


def render_workforce_factory_policies(
    *, active_template_bytes: bytes, expected_active_template_sha256: str,
    deny_only_template_bytes: bytes, expected_deny_only_template_sha256: str,
    key_readback_bytes: bytes, expected_key_readback_sha256: str,
    factory_not_before: str, factory_not_after: str, evaluated_at: datetime,
) -> dict[str, Any]:
    """Return a non-authorizing offline plan from three independently pinned blobs.

    Key readback schema1 is closed: account_id, region, observed_at (whole-second
    canonical UTC), describe_key_request={KeyId: alias/aws/dynamodb}, key_metadata.
    Pin format is exactly 64 lowercase hex characters over the original bytes.
    Evaluation must be aware UTC. It is never rounded; captured age is <=300s.
    The whole-second UTC window may be future but must not be expired, and lasts
    at most900s. The API selects no window, role ID, function version or profile.
    """
    try:
        if (type(evaluated_at) is not datetime or evaluated_at.tzinfo is None
                or evaluated_at.utcoffset() != timedelta(0)):
            _reject()
        start, end = _timestamp(factory_not_before), _timestamp(factory_not_after)
        if not timedelta(0) < end - start <= timedelta(seconds=900) or evaluated_at >= end:
            _reject()
        active = _template(active_template_bytes, expected_active_template_sha256,
                           _ACTIVE_SEMANTIC_SHA256, _PLACEHOLDERS)
        inert = _template(deny_only_template_bytes, expected_deny_only_template_sha256,
                          _INERT_SEMANTIC_SHA256, set())
        readback = _pinned_json(key_readback_bytes, expected_key_readback_sha256)
        metadata, _ = _metadata(readback, evaluated_at)
        replacements = {"${ledger_kms_key_arn}": metadata["Arn"],
                        "${factory_not_before}": factory_not_before,
                        "${factory_not_after}": factory_not_after}
        return {
            "schema_version": 1,
            "record_type": "scanalyze.platform_authority.workforce_ledger_factory_policy_plan.v1",
            "status": "CAPTURED_NOT_AUTHENTICATED", "decision": "NO-GO",
            "deployment_authorized": False,
            "source_ci_status": "PENDING_CONNECTED_REVALIDATION",
            "runtime_binding_status": "PENDING_SIGNED_ARTIFACT_AND_NUMERIC_VERSION_READBACK",
            "revocation_status": "REQUIRED_BEFORE_BROKER_ACTIVATION",
            "account_id": _ACCOUNT, "region": _REGION,
            "evaluated_at": evaluated_at.isoformat().replace("+00:00", "Z"),
            "factory_window": {"not_before": factory_not_before, "not_after": factory_not_after},
            "key_binding": {"key_arn": metadata["Arn"], "key_id": metadata["KeyId"],
                            "describe_key_request": readback["describe_key_request"],
                            "observed_at": readback["observed_at"],
                            "readback_sha256": expected_key_readback_sha256,
                            "alias_binding_status": "CAPTURED_NOT_AUTHENTICATED"},
            "source_pins": {"active_template_sha256": expected_active_template_sha256,
                            "active_semantic_sha256": _ACTIVE_SEMANTIC_SHA256,
                            "deny_only_template_sha256": expected_deny_only_template_sha256,
                            "deny_only_semantic_sha256": _INERT_SEMANTIC_SHA256},
            "policies": {"active": _policy(active, replacements), "deny_only": _policy(inert, {})},
        }
    except Exception:
        raise WorkforceFactoryPolicyRejected() from None


# Canonical repo-relative sources for the PREPARED offline factory plan.
# Callers must not substitute alternate deny-all documents.
WORKFORCE_FACTORY_ACTIVE_POLICY_RELPATH = (
    "policies/iam/platform-authority-gug215-workforce-ledger-factory-boundary.json"
)
WORKFORCE_FACTORY_DENY_ALL_POLICY_RELPATH = (
    "policies/iam/platform-authority-gug215-workforce-ledger-factory-deny-all.json"
)


def prepare_workforce_factory_policy_plan(
    *,
    repo_root: Any,
    key_readback_bytes: bytes,
    expected_key_readback_sha256: str,
    factory_not_before: str,
    factory_not_after: str,
    evaluated_at: datetime,
) -> dict[str, Any]:
    """Load the reviewed active + deny-all policy files into a PREPARED plan.

    Reads only the two canonical relative paths under repo_root. Does not
    install IAM, invent RoleIds, or authorize deployment. Pins are the SHA-256
    of the exact on-disk bytes so a substituted deny-all still fails closed
    against the semantic digest inside render_workforce_factory_policies.
    """
    from pathlib import Path

    root = Path(repo_root)
    if not isinstance(repo_root, (str, Path)) or not root.is_dir():
        _reject()
    active_path = (root / WORKFORCE_FACTORY_ACTIVE_POLICY_RELPATH).resolve()
    deny_path = (root / WORKFORCE_FACTORY_DENY_ALL_POLICY_RELPATH).resolve()
    try:
        active_path.relative_to(root.resolve())
        deny_path.relative_to(root.resolve())
    except ValueError:
        _reject()
    if (active_path.name != Path(WORKFORCE_FACTORY_ACTIVE_POLICY_RELPATH).name
            or deny_path.name != Path(WORKFORCE_FACTORY_DENY_ALL_POLICY_RELPATH).name
            or not active_path.is_file() or not deny_path.is_file()):
        _reject()
    active = active_path.read_bytes()
    deny_only = deny_path.read_bytes()
    plan = render_workforce_factory_policies(
        active_template_bytes=active,
        expected_active_template_sha256=_sha256(active),
        deny_only_template_bytes=deny_only,
        expected_deny_only_template_sha256=_sha256(deny_only),
        key_readback_bytes=key_readback_bytes,
        expected_key_readback_sha256=expected_key_readback_sha256,
        factory_not_before=factory_not_before,
        factory_not_after=factory_not_after,
        evaluated_at=evaluated_at,
    )
    # Explicit PREPARED markers for installers; never flip authorization.
    plan = dict(plan)
    plan["preparation_status"] = "PREPARED_DENY_ALL_AND_ACTIVE_BOUND_OFFLINE"
    plan["installation_performed"] = False
    plan["deny_all_source"] = WORKFORCE_FACTORY_DENY_ALL_POLICY_RELPATH
    plan["active_boundary_source"] = WORKFORCE_FACTORY_ACTIVE_POLICY_RELPATH
    return plan
