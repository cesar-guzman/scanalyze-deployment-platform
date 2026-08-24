"""Inert-by-default, injected GUG-384 authority inventory collector."""
from __future__ import annotations
from datetime import UTC, datetime, timedelta; from hashlib import sha256; import json, os, re, stat
from pathlib import Path
from typing import Any, Callable, Mapping, Protocol
from tooling.platform_authority_gug365_upstream_inventory import canonical_digest, canonical_json, canonical_snapshot
REPO_ROOT = Path(__file__).resolve().parents[1]
POLICY = REPO_ROOT / "policies/iam/platform-authority-gug376-authority-inventory-read-only.json"
POLICY_SHA256 = "7e0de088559d9c13d28e446cc97d246e58eafe45c71d2e261893dc0ce235ddf0"
REGION, MAX_PAGES = "us-east-1", 50
SURFACES = ("s3", "kms", "signer", "lambda_code_signing", "lambda_runtime", "iam_roles", "artifact_objects")
TARGETS = frozenset({"artifact_bucket_arn", "broker_signed_object_arn", "broker_unsigned_object_arn", "ledger_factory_signed_object_arn", "ledger_factory_unsigned_object_arn", "artifact_kms_key_arn", "signing_profile_arn", "code_signing_config_arn", "runtime_source_function_arn", "runtime_source_function_version_arn", "retire_approve_generated_role_arn", "retire_class_generated_role_arn"})
PLAN_FIELDS = {"targets", "not_before", "not_after", "expected_policy_digest", "expected_account_id", "expected_principal_arn", "authority_verification_digest"}
IDENTITY_FIELDS = {"source", "chain_depth", "account_id", "region", "principal_arn", "session_id_digest", "started_at", "expires_at", "observed_at", "policy_digest", "authority_verification_digest"}
CLASSES = frozenset({"ABSENT_READY", "EXACT_PRESENT_NO_TOUCH", "PREEXISTING_NO_TOUCH", "DRIFT_BLOCKED_NO_REPAIR", "UNCERTAIN_RECONCILE_ONLY", "NOT_AUTHORIZED"})
_DIGEST, _TOKEN, _ARN, _STAMP = re.compile(r"^sha256:[0-9a-f]{64}$"), re.compile(r"^[A-Z][A-Z0-9_]{2,95}$"), re.compile(r"^arn:aws:[a-z0-9-]+:[a-z0-9-]*:[0-9]*:[A-Za-z0-9/.:_+=,@%-]+$"), re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")
_NAME, _SYNC = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,126}\.json$"), ("cloudstorage", "mobile documents", "fileprovider", "dropbox", "onedrive")
class CollectorError(RuntimeError):
    def __init__(self, code: str) -> None:
        self.code = code if _TOKEN.fullmatch(code) else "AUTHORITY_INVENTORY_BLOCKED"
        super().__init__(self.code)
class AuthorityAccessDenied(RuntimeError): pass
class AuthorityReader(Protocol):
    s3: Callable[[object | None], Mapping[str, Any]]
    kms: Callable[[object | None], Mapping[str, Any]]
    signer: Callable[[object | None], Mapping[str, Any]]
    lambda_code_signing: Callable[[object | None], Mapping[str, Any]]
    lambda_runtime: Callable[[object | None], Mapping[str, Any]]
    iam_roles: Callable[[object | None], Mapping[str, Any]]
    artifact_objects: Callable[[object | None], Mapping[str, Any]]
class StsFirstSession(Protocol):
    def get_caller_identity(self) -> Mapping[str, Any]: ...
    def open_reader(self) -> AuthorityReader: ...
class DirectSessionFactory(Protocol):
    def open_sts(self, *, policy: Mapping[str, Any], policy_digest: str, region: str) -> StsFirstSession: ...
class ExternalCertificationVerifier(Protocol):
    def verify(self, first: Mapping[str, Any], second: Mapping[str, Any]) -> Mapping[str, Any]: ...
def _fail(code: str) -> None: raise CollectorError(code)
def _time(value: object) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None: _fail("INVENTORY_TIME_INVALID")
    return value.astimezone(UTC).replace(microsecond=0)
def _stamp(value: object) -> str: return _time(value).isoformat().replace("+00:00", "Z")
def render_policy(plan: Mapping[str, Any]) -> tuple[dict[str, Any], str]:
    raw = POLICY.read_bytes()
    if set(plan) != PLAN_FIELDS or sha256(raw).hexdigest() != POLICY_SHA256: _fail("POLICY_INPUT_INVALID")
    targets, account, principal = plan["targets"], plan["expected_account_id"], plan["expected_principal_arn"]
    if not isinstance(targets, Mapping) or set(targets) != TARGETS or not isinstance(account, str) or re.fullmatch(r"[0-9]{12}", account) is None: _fail("POLICY_TARGET_SET_INVALID")
    if any(not isinstance(v, str) or _ARN.fullmatch(v) is None for v in targets.values()): _fail("POLICY_TARGET_NOT_EXACT")
    base, version = targets["runtime_source_function_arn"], targets["runtime_source_function_version_arn"]
    objects = [targets[key] for key in TARGETS if key.endswith("_object_arn")]
    regional = ("artifact_kms_key_arn", "signing_profile_arn", "code_signing_config_arn", "runtime_source_function_arn", "runtime_source_function_version_arn")
    if re.fullmatch(re.escape(base) + r":[1-9][0-9]*", version) is None or len(set(objects)) != 4 or any(not value.startswith(targets["artifact_bucket_arn"] + "/") for value in objects): _fail("POLICY_TARGET_BINDING_INVALID")
    exact = {"artifact_kms_key_arn": rf"arn:aws:kms:{REGION}:{account}:key/[0-9a-f-]+", "signing_profile_arn": rf"arn:aws:signer:{REGION}:{account}:/signing-profiles/[A-Za-z0-9_.-]+", "code_signing_config_arn": rf"arn:aws:lambda:{REGION}:{account}:code-signing-config:csc-[A-Za-z0-9]+", "runtime_source_function_arn": rf"arn:aws:lambda:{REGION}:{account}:function:[A-Za-z0-9_-]+"}
    if any(f":{REGION}:{account}:" not in targets[key] for key in regional) or any(re.fullmatch(pattern, targets[key]) is None for key, pattern in exact.items()) or any(f"::{account}:role/aws-reserved/sso.amazonaws.com/" not in targets[key] for key in ("retire_approve_generated_role_arn", "retire_class_generated_role_arn")) or not isinstance(principal, str) or re.fullmatch(rf"arn:aws:sts::{account}:assumed-role/[A-Za-z0-9+=,.@_/-]+/[A-Za-z0-9+=,.@_-]+", principal) is None: _fail("POLICY_TARGET_BINDING_INVALID")
    start, end = _time(plan["not_before"]), _time(plan["not_after"])
    if not start < end or end - start > timedelta(hours=1): _fail("POLICY_WINDOW_INVALID")
    values = dict(targets, inventory_not_before=_stamp(start), inventory_not_after=_stamp(end)); rendered = raw.decode()
    for key, value in values.items(): rendered = rendered.replace("${" + key + "}", json.dumps(value)[1:-1])
    if "${" in rendered: _fail("POLICY_PLACEHOLDER_REMAINS")
    try: result = json.loads(rendered)
    except json.JSONDecodeError as exc: raise CollectorError("POLICY_RENDER_INVALID") from exc
    digest = "sha256:" + sha256(canonical_json(result).encode("utf-8")).hexdigest()
    if digest != plan["expected_policy_digest"] or _DIGEST.fullmatch(str(plan["authority_verification_digest"])) is None: _fail("POLICY_DIGEST_NOT_VERIFIED")
    return result, digest
def _root(root: Path) -> int:
    if not root.is_absolute(): _fail("PRIVATE_ROOT_NOT_ABSOLUTE")
    try:
        before, resolved = root.lstat(), root.resolve(strict=True)
        if resolved == REPO_ROOT or REPO_ROOT in resolved.parents or any(marker in str(resolved).casefold() for marker in _SYNC) or any((parent / ".git").exists() for parent in (resolved, *resolved.parents)): _fail("PRIVATE_ROOT_LOCATION_INVALID")
        nofollow, directory = getattr(os, "O_NOFOLLOW", 0), getattr(os, "O_DIRECTORY", 0)
        if not nofollow or not directory: _fail("PRIVATE_ROOT_NOFOLLOW_UNAVAILABLE")
        descriptor = os.open(resolved, os.O_RDONLY | nofollow | directory); opened = os.fstat(descriptor)
    except CollectorError: raise
    except OSError as exc: raise CollectorError("PRIVATE_ROOT_INVALID") from exc
    if (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino) or not stat.S_ISDIR(opened.st_mode) or opened.st_uid != os.geteuid() or stat.S_IMODE(opened.st_mode) != 0o700:
        os.close(descriptor); _fail("PRIVATE_ROOT_CUSTODY_INVALID")
    return descriptor
def _target(root: Path, name: str) -> tuple[int, str]:
    if not isinstance(name, str) or _NAME.fullmatch(name) is None: _fail("PRIVATE_ARTIFACT_NAME_INVALID")
    return _root(root), name
def private_target_absent(root: Path, name: str) -> None:
    directory, target = _target(root, name)
    try:
        try: os.stat(target, dir_fd=directory, follow_symlinks=False)
        except FileNotFoundError: return
        _fail("PRIVATE_ARTIFACT_EXISTS")
    finally: os.close(directory)
def write_private_json(root: Path, name: str, value: Mapping[str, Any]) -> None:
    directory, target = _target(root, name); payload = (canonical_json(value) + "\n").encode()
    temporary, descriptor = f".{target}.{canonical_digest(value)[7:23]}.tmp", None
    try:
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory); remaining = payload
        while remaining:
            written = os.write(descriptor, remaining)
            if written <= 0: _fail("PRIVATE_OUTPUT_WRITE_FAILED")
            remaining = remaining[written:]
        os.fchmod(descriptor, 0o600); os.fsync(descriptor); item = os.fstat(descriptor)
        if not stat.S_ISREG(item.st_mode) or item.st_uid != os.geteuid() or item.st_nlink != 1 or stat.S_IMODE(item.st_mode) != 0o600: _fail("PRIVATE_OUTPUT_CUSTODY_INVALID")
        os.link(temporary, target, src_dir_fd=directory, dst_dir_fd=directory, follow_symlinks=False); published = os.stat(target, dir_fd=directory, follow_symlinks=False)
        if (published.st_dev, published.st_ino) != (item.st_dev, item.st_ino): _fail("PRIVATE_OUTPUT_CUSTODY_INVALID")
        os.fsync(directory)
        os.unlink(temporary, dir_fd=directory); os.fsync(directory)
        if os.stat(target, dir_fd=directory, follow_symlinks=False).st_nlink != 1: _fail("PRIVATE_OUTPUT_CUSTODY_INVALID")
    except CollectorError: raise
    except OSError as exc: raise CollectorError("PRIVATE_OUTPUT_WRITE_FAILED") from exc
    finally:
        if descriptor is not None: os.close(descriptor)
        os.close(directory)
def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result: _fail("PRIVATE_INPUT_DUPLICATE_KEY")
        result[key] = value
    return result
def read_private_json(root: Path, name: str) -> dict[str, Any]:
    directory, target = _target(root, name); descriptor = None
    try:
        descriptor = os.open(target, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=directory)
        opened, path_item = os.fstat(descriptor), os.stat(target, dir_fd=directory, follow_symlinks=False)
        if not stat.S_ISREG(opened.st_mode) or opened.st_uid != os.geteuid() or opened.st_nlink != 1 or stat.S_IMODE(opened.st_mode) != 0o600 or not 0 < opened.st_size <= 4 * 1024 * 1024 or (opened.st_dev, opened.st_ino) != (path_item.st_dev, path_item.st_ino): _fail("PRIVATE_INPUT_CUSTODY_INVALID")
        raw = b""
        while len(raw) <= opened.st_size:
            chunk = os.read(descriptor, min(65536, opened.st_size + 1 - len(raw)))
            if not chunk: break
            raw += chunk
        after, path_after = os.fstat(descriptor), os.stat(target, dir_fd=directory, follow_symlinks=False)
        if len(raw) != opened.st_size or (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns, opened.st_ctime_ns) != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns) or (after.st_dev, after.st_ino) != (path_after.st_dev, path_after.st_ino): _fail("PRIVATE_INPUT_CHANGED_DURING_READ")
        value = json.loads(raw, object_pairs_hook=_pairs)
        if not isinstance(value, dict): _fail("PRIVATE_INPUT_INVALID")
        return value
    except CollectorError: raise
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc: raise CollectorError("PRIVATE_INPUT_INVALID") from exc
    finally:
        if descriptor is not None: os.close(descriptor)
        os.close(directory)
def _collect(name: str, read: Callable[[object | None], Mapping[str, Any]], runtime_arn: str) -> dict[str, Any]:
    items: list[dict[str, Any]] = []; seen: set[str] = set(); cursor: object | None = None
    try:
        for page_count in range(1, MAX_PAGES + 1):
            page = read(cursor)
            if not isinstance(page, Mapping) or set(page) != {"items", "next_cursor", "truncated"} or not isinstance(page["items"], list) or not isinstance(page["truncated"], bool): _fail("INVENTORY_PAGE_INVALID")
            next_cursor = page["next_cursor"]
            if page["truncated"] != (next_cursor is not None): _fail("INVENTORY_TRUNCATION_CONFLICT")
            normalized = canonical_snapshot(page["items"], code="INVENTORY_PAGE_INVALID")
            if not all(isinstance(item, dict) for item in normalized): _fail("INVENTORY_PAGE_INVALID")
            items.extend(normalized)
            if next_cursor is None:
                items.sort(key=canonical_json)
                if name == "lambda_runtime" and (len(items) != 1 or items[0].get("function_arn") != runtime_arn or str(items[0].get("version")) != runtime_arn.rsplit(":", 1)[-1] or items[0].get("runtime") != "python3.12" or items[0].get("architectures") != ["x86_64"] or items[0].get("update_runtime_on") != "Manual" or re.fullmatch(r"arn:aws:lambda:us-east-1::runtime:[0-9a-f]{64}", str(items[0].get("runtime_version_arn"))) is None): _fail("STOP_RUNTIME_PIN_SOURCE_NOT_PROVEN")
                return {"complete": True, "count": len(items), "page_count": page_count, "items": items, "evidence_digest": canonical_digest(items)}
            key = canonical_json(next_cursor)
            if key in seen: _fail("INVENTORY_PAGINATION_CYCLE")
            seen.add(key); cursor = next_cursor
        _fail("INVENTORY_PAGE_LIMIT_EXCEEDED")
    except AuthorityAccessDenied: classification = "NOT_AUTHORIZED"
    except Exception: classification = "UNCERTAIN_RECONCILE_ONLY"
    return {"complete": False, "classification": classification, "count": None, "page_count": None, "evidence_digest": canonical_digest({"surface": name, "classification": classification})}
def _identity(value: Mapping[str, Any], plan: Mapping[str, Any], policy_digest: str, now: datetime) -> None:
    if not isinstance(value, Mapping) or set(value) != IDENTITY_FIELDS: _fail("SESSION_IDENTITY_INVALID")
    start, end, observed, expires = _time(plan["not_before"]), _time(plan["not_after"]), _time(value["observed_at"]), _time(value["expires_at"])
    if value["source"] != "DIRECT_SSO" or value["chain_depth"] != 0 or value["account_id"] != plan["expected_account_id"] or value["region"] != REGION or value["principal_arn"] != plan["expected_principal_arn"] or value["policy_digest"] != policy_digest or value["authority_verification_digest"] != plan["authority_verification_digest"] or _DIGEST.fullmatch(str(value["session_id_digest"])) is None or not _time(value["started_at"]) <= start <= observed <= now < end <= expires or expires - _time(value["started_at"]) > timedelta(hours=1): _fail("DIRECT_SESSION_BINDING_INVALID")
def _receipt(classification: str, policy_digest: str, facts_digest: str, runtime_target_digest: str, snapshots: list[str], counts: Mapping[str, Any], stable: bool, external: tuple[str, str, str] | None = None) -> dict[str, Any]:
    if classification not in CLASSES: _fail("INVENTORY_CLASSIFICATION_INVALID")
    certification, verifier, trust = external or (None, None, None)
    if any(_DIGEST.fullmatch(str(value)) is None for value in (policy_digest, facts_digest, runtime_target_digest, *snapshots)) or len(snapshots) not in (1, 2) or len(set(snapshots)) != len(snapshots) or set(counts) != set(SURFACES) or any(value is not None and (type(value) is not int or value < 0) for value in counts.values()) or type(stable) is not bool or any(value is not None and _DIGEST.fullmatch(str(value)) is None for value in (certification, verifier, trust)) or ((classification == "EXACT_PRESENT_NO_TOUCH") != (external is not None)): _fail("PUBLIC_RECEIPT_INPUT_INVALID")
    result = {"record_type": "scanalyze.platform_authority.gug376_authority_inventory_receipt.v1", "status": "AUTHORITY_INVENTORY_LIVE_NOT_PROVEN", "classification": classification, "policy_digest": policy_digest, "facts_digest": facts_digest, "runtime_target_digest": runtime_target_digest, "snapshot_digests": snapshots, "surface_counts_digest": canonical_digest(dict(counts)), "external_certification_digest": certification, "external_verifier_identity_digest": verifier, "external_trust_anchor_digest": trust, "session_count": len(snapshots), "stable": stable, "read_only": True, "aws_mutations": 0, "two_human_status": "NOT_PROVEN", "independent_approval_present": False, "deployment_authorized": False, "production_status": "NO-GO"}
    result["receipt_digest"] = canonical_digest(result); return result
def capture(plan: Mapping[str, Any], factory: DirectSessionFactory, *, private_root: Path, artifact_name: str, now: datetime) -> dict[str, Any]:
    policy, policy_digest = render_policy(plan); private_target_absent(private_root, artifact_name)
    if any(key.startswith("AWS_") or key in {"BOTO_CONFIG", "REQUESTS_CA_BUNDLE", "SSL_CERT_FILE", "SSL_CERT_DIR"} for key in os.environ): _fail("AMBIENT_AWS_OVERRIDE_FORBIDDEN")
    session = factory.open_sts(policy=policy, policy_digest=policy_digest, region=REGION); identity = session.get_caller_identity()
    _identity(identity, plan, policy_digest, _time(now)); reader = session.open_reader()
    calls = (("s3", reader.s3), ("kms", reader.kms), ("signer", reader.signer), ("lambda_code_signing", reader.lambda_code_signing), ("lambda_runtime", reader.lambda_runtime), ("iam_roles", reader.iam_roles), ("artifact_objects", reader.artifact_objects))
    surfaces = {name: _collect(name, method, plan["targets"]["runtime_source_function_version_arn"]) for name, method in calls}
    facts = {name: (item["items"] if item["complete"] else {"classification": item["classification"]}) for name, item in surfaces.items()}; facts_digest = canonical_digest(facts)
    failures = {item.get("classification") for item in surfaces.values() if not item["complete"]}; classification = "NOT_AUTHORIZED" if "NOT_AUTHORIZED" in failures else "UNCERTAIN_RECONCILE_ONLY"
    private_identity = {key: (_stamp(value) if key.endswith("_at") else value) for key, value in identity.items()}
    snapshot: dict[str, Any] = {"record_type": "scanalyze.platform_authority.gug376_authority_inventory_private.v1", "policy_digest": policy_digest, "runtime_target_digest": canonical_digest({"policy_digest": policy_digest, "runtime_source_function_version_arn": plan["targets"]["runtime_source_function_version_arn"]}), "classification": classification, "identity": private_identity, "surfaces": surfaces, "facts_digest": facts_digest, "read_only": True, "aws_mutations": 0, "repository_persisted": False}
    snapshot["snapshot_digest"] = canonical_digest(snapshot); write_private_json(private_root, artifact_name, snapshot)
    return _receipt(classification, policy_digest, facts_digest, snapshot["runtime_target_digest"], [snapshot["snapshot_digest"]], {name: item["count"] for name, item in surfaces.items()}, False)
def _snapshot(value: Mapping[str, Any]) -> dict[str, Any]:
    try: value = json.loads(canonical_json(value))
    except Exception as exc: raise CollectorError("PRIVATE_SNAPSHOT_INVALID") from exc
    expected = {"record_type", "policy_digest", "runtime_target_digest", "classification", "identity", "surfaces", "facts_digest", "read_only", "aws_mutations", "repository_persisted", "snapshot_digest"}
    if not isinstance(value, Mapping) or set(value) != expected or value["record_type"] != "scanalyze.platform_authority.gug376_authority_inventory_private.v1" or not isinstance(value["identity"], Mapping) or not isinstance(value["surfaces"], Mapping) or set(value["surfaces"]) != set(SURFACES) or value["read_only"] is not True or value["aws_mutations"] != 0 or value["repository_persisted"] is not False or value["classification"] not in {"NOT_AUTHORIZED", "UNCERTAIN_RECONCILE_ONLY"}: _fail("PRIVATE_SNAPSHOT_INVALID")
    identity = value["identity"]
    if set(identity) != IDENTITY_FIELDS or identity["source"] != "DIRECT_SSO" or identity["chain_depth"] != 0 or identity["region"] != REGION or re.fullmatch(r"[0-9]{12}", str(identity["account_id"])) is None or re.fullmatch(rf"arn:aws:sts::{identity['account_id']}:assumed-role/[A-Za-z0-9+=,.@_/-]+/[A-Za-z0-9+=,.@_-]+", str(identity["principal_arn"])) is None or any(_DIGEST.fullmatch(str(identity[key])) is None for key in ("session_id_digest", "policy_digest", "authority_verification_digest")) or any(_STAMP.fullmatch(str(identity[key])) is None for key in ("started_at", "expires_at", "observed_at")) or identity["policy_digest"] != value["policy_digest"]: _fail("PRIVATE_SNAPSHOT_INVALID")
    try: started, observed, expires = (datetime.fromisoformat(str(identity[key]).replace("Z", "+00:00")) for key in ("started_at", "observed_at", "expires_at"))
    except ValueError as exc: raise CollectorError("PRIVATE_SNAPSHOT_INVALID") from exc
    if not started <= observed < expires or expires - started > timedelta(hours=1): _fail("PRIVATE_SNAPSHOT_INVALID")
    facts: dict[str, Any] = {}
    for name, item in value["surfaces"].items():
        if not isinstance(item, Mapping): _fail("PRIVATE_SNAPSHOT_INVALID")
        if item.get("complete") is True:
            if set(item) != {"complete", "count", "page_count", "items", "evidence_digest"} or not isinstance(item["items"], list) or not all(isinstance(raw, dict) for raw in item["items"]) or type(item["count"]) is not int or item["count"] < 0 or item["count"] != len(item["items"]) or type(item["page_count"]) is not int or not 1 <= item["page_count"] <= MAX_PAGES or item["evidence_digest"] != canonical_digest(item["items"]): _fail("PRIVATE_SNAPSHOT_INVALID")
            if name == "lambda_runtime" and (len(runtime := item["items"]) != 1 or re.fullmatch(rf"arn:aws:lambda:{REGION}:{identity['account_id']}:function:[A-Za-z0-9_-]+:[1-9][0-9]*", str(runtime[0].get("function_arn"))) is None or str(runtime[0].get("version")) != str(runtime[0].get("function_arn")).rsplit(":", 1)[-1] or runtime[0].get("runtime") != "python3.12" or runtime[0].get("architectures") != ["x86_64"] or runtime[0].get("update_runtime_on") != "Manual" or re.fullmatch(r"arn:aws:lambda:us-east-1::runtime:[0-9a-f]{64}", str(runtime[0].get("runtime_version_arn"))) is None or value["runtime_target_digest"] != canonical_digest({"policy_digest": value["policy_digest"], "runtime_source_function_version_arn": runtime[0].get("function_arn")})): _fail("PRIVATE_SNAPSHOT_RUNTIME_PIN_INVALID")
            facts[name] = item["items"]
        elif item.get("complete") is False:
            if set(item) != {"complete", "classification", "count", "page_count", "evidence_digest"} or item["classification"] not in {"NOT_AUTHORIZED", "UNCERTAIN_RECONCILE_ONLY"} or item["count"] is not None or item["page_count"] is not None or item["evidence_digest"] != canonical_digest({"surface": name, "classification": item["classification"]}): _fail("PRIVATE_SNAPSHOT_INVALID")
            facts[name] = {"classification": item["classification"]}
        else: _fail("PRIVATE_SNAPSHOT_INVALID")
    failures = {item.get("classification") for item in value["surfaces"].values() if not item["complete"]}; expected = "NOT_AUTHORIZED" if "NOT_AUTHORIZED" in failures else "UNCERTAIN_RECONCILE_ONLY"
    if value["classification"] != expected or value["facts_digest"] != canonical_digest(facts) or value["snapshot_digest"] != canonical_digest({key: item for key, item in value.items() if key != "snapshot_digest"}): _fail("PRIVATE_SNAPSHOT_INVALID")
    return dict(value)
def certify(first: Mapping[str, Any], second: Mapping[str, Any], *, expected_runtime_target_digest: str, expected_facts_digest: str | None = None, external_verifier: ExternalCertificationVerifier | None = None) -> dict[str, Any]:
    first, second = _snapshot(first), _snapshot(second)
    bound = ("source", "chain_depth", "account_id", "region", "principal_arn", "policy_digest", "authority_verification_digest")
    if any(first["identity"][key] != second["identity"][key] for key in bound) or first["identity"]["session_id_digest"] == second["identity"]["session_id_digest"] or first["identity"]["observed_at"] >= second["identity"]["observed_at"]: _fail("SESSIONS_NOT_INDEPENDENT")
    if (target_invalid := _DIGEST.fullmatch(str(expected_runtime_target_digest)) is None or any(snapshot["runtime_target_digest"] != expected_runtime_target_digest for snapshot in (first, second))) or expected_facts_digest is not None and _DIGEST.fullmatch(str(expected_facts_digest)) is None: _fail("RUNTIME_TARGET_BINDING_INVALID" if target_invalid else "EXPECTED_FACTS_DIGEST_INVALID")
    counts = {name: second["surfaces"][name]["count"] for name in SURFACES}
    external = None
    if first["policy_digest"] != second["policy_digest"] or first["facts_digest"] != second["facts_digest"]: classification, stable = "UNCERTAIN_RECONCILE_ONLY", False
    elif any(not item["complete"] for snapshot in (first, second) for item in snapshot["surfaces"].values()): classification, stable = ("NOT_AUTHORIZED" if any(item.get("classification") == "NOT_AUTHORIZED" for snapshot in (first, second) for item in snapshot["surfaces"].values()) else "UNCERTAIN_RECONCILE_ONLY"), False
    elif not any(counts[name] for name in SURFACES if name != "lambda_runtime"): classification, stable = "ABSENT_READY", True
    elif expected_facts_digest is not None and second["facts_digest"] != expected_facts_digest: classification, stable = "DRIFT_BLOCKED_NO_REPAIR", True
    elif expected_facts_digest == second["facts_digest"] and external_verifier is not None:
        try: certificate = external_verifier.verify(json.loads(canonical_json(first)), json.loads(canonical_json(second)))
        except Exception as exc: raise CollectorError("CAUSAL_VERIFICATION_FAILED") from exc
        bindings = {"policy_digest": second["policy_digest"], "facts_digest": second["facts_digest"], "runtime_target_digest": second["runtime_target_digest"], "first_snapshot_digest": first["snapshot_digest"], "second_snapshot_digest": second["snapshot_digest"], "first_session_digest": first["identity"]["session_id_digest"], "second_session_digest": second["identity"]["session_id_digest"], "authority_verification_digest": second["identity"]["authority_verification_digest"]}
        fields = {"record_type", "verifier_identity_digest", "trust_anchor_digest", "certification_digest", *bindings}
        if not isinstance(certificate, Mapping) or set(certificate) != fields or certificate.get("record_type") != "scanalyze.platform_authority.gug376_external_inventory_certification.v1" or any(certificate.get(key) != value for key, value in bindings.items()) or certificate.get("trust_anchor_digest") != second["identity"]["authority_verification_digest"] or any(_DIGEST.fullmatch(str(certificate.get(key))) is None for key in fields - {"record_type"}) or certificate.get("certification_digest") != canonical_digest({key: value for key, value in certificate.items() if key != "certification_digest"}): _fail("CAUSAL_VERIFICATION_INVALID")
        external = (str(certificate["certification_digest"]), str(certificate["verifier_identity_digest"]), str(certificate["trust_anchor_digest"]))
        classification, stable = "EXACT_PRESENT_NO_TOUCH", True
    else: classification, stable = "PREEXISTING_NO_TOUCH", True
    return _receipt(classification, second["policy_digest"], second["facts_digest"], second["runtime_target_digest"], [first["snapshot_digest"], second["snapshot_digest"]], counts, stable, external)
