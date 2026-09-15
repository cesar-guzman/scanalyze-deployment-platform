"""One-operation PKCE receiver with a pinned, optional public OIDC exchange."""
from __future__ import annotations

import base64
from dataclasses import dataclass, field
from datetime import UTC, datetime
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import secrets
import select
import socket
import stat
import subprocess
import sys
import time
from typing import Callable, Sequence
from urllib.parse import parse_qsl, urlencode, urlsplit

from tooling.platform_authority_bootstrap import BootstrapAuthorizationError, SingleOwnerPolicy
from tooling.platform_authority_bootstrap_jwt_grant import (
    JWT_BEARER_GRANT, JwtBearerBinding, JwtBearerGrantError, validate_claims,
)
from tooling.platform_authority_bootstrap_oidc_client import OidcClientError, OidcPublicClient


AUTHORITY_ACCOUNT = "042360977644"
REGION = "us-east-1"
CALLBACK_PORT = 38271
REDIRECT_URI = "http://127.0.0.1:38271/callback"
AUTHORIZE_ENDPOINT = "https://oidc.us-east-1.amazonaws.com/authorize"
MAX_REQUEST_BYTES = 12 * 1024
MAX_GRANT_BYTES = 12 * 1024
CALLBACK_TIMEOUT = 300.0
READINESS_TIMEOUT = 900.0
CHILD_COMPLETION_TIMEOUT = 1800.0
OPERATIONS = frozenset({"plan", "approve", "apply"})
BINDING_FIELDS = frozenset({
    "schema_version", "record_type", "authority_account_id", "region",
    "application_arn", "instance_arn", "redirect_uri",
})
JWT_BINDING_FIELDS = BINDING_FIELDS | {
    "trusted_token_issuer_arn", "issuer_url", "audience",
    "authorization_endpoint", "token_endpoint",
}
SINGLE_OWNER_BINDING_FIELDS = JWT_BINDING_FIELDS | {
    "single_owner_authorized_at", "single_owner_expires_at",
}

# This fixed stdlib-only program is part of the reviewed helper Git blob. It
# receives public source bytes over a separate anonymous pipe, authenticates
# transport custody, and never asks the filesystem to execute repository code.
CHILD_BOOTSTRAP = r'''
import base64, hashlib, importlib.abc, importlib.util, json, os, sys
from pathlib import Path
fd = int(sys.argv[1])
expected = sys.argv[2]
root = Path(sys.argv[3])
raw = bytearray()
while True:
    chunk = os.read(fd, 65536)
    if not chunk:
        break
    raw.extend(chunk)
    if len(raw) > 4 * 1024 * 1024:
        raise SystemExit(2)
os.close(fd)
if hashlib.sha256(raw).hexdigest() != expected:
    raise SystemExit(2)
sources = {name: base64.b64decode(value, validate=True) for name, value in json.loads(raw).items()}
raw.clear()
class SourceFinder(importlib.abc.MetaPathFinder, importlib.abc.Loader):
    def find_spec(self, fullname, path=None, target=None):
        if fullname != 'tooling' and not fullname.startswith('tooling.'):
            return None
        relative = fullname.replace('.', '/')
        package = relative + '/__init__.py'
        module = relative + '.py'
        selected = package if package in sources else module
        if selected not in sources:
            raise ImportError('SNAPSHOT_MODULE_UNAVAILABLE')
        spec = importlib.util.spec_from_loader(fullname, self, is_package=selected == package)
        spec.loader_state = selected
        return spec
    def create_module(self, spec):
        return None
    def exec_module(self, module):
        relative = module.__spec__.loader_state
        module.__file__ = str(root / relative)
        exec(compile(sources[relative], module.__file__, 'exec'), module.__dict__)
def install_snapshot(source_root):
    if source_root != root:
        raise ValueError('SNAPSHOT_ROOT_INVALID')
    sys.dont_write_bytecode = True
    sys.meta_path.insert(0, SourceFinder())
entry = 'scripts/deployment/platform-authority-bootstrap.py'
sys.argv = [str(root / entry), *sys.argv[4:]]
namespace = {'__file__': str(root / entry), '__name__': '__main__',
             '_GUG274_SNAPSHOT_IMPORTER': install_snapshot}
exec(compile(sources[entry], namespace['__file__'], 'exec'), namespace)
'''


class IdentityGrantError(ValueError):
    """Only static public reason codes may cross the process boundary."""


def _closed_object(raw: bytes) -> dict:
    def unique(pairs: list[tuple[str, object]]) -> dict:
        value: dict = {}
        for key, item in pairs:
            if key in value:
                raise IdentityGrantError("DUPLICATE_FIELD")
            value[key] = item
        return value
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=unique)
    except (ValueError, UnicodeError):
        raise IdentityGrantError("INVALID_JSON") from None
    if type(value) is not dict:
        raise IdentityGrantError("INVALID_JSON")
    return value


@dataclass(frozen=True)
class ApplicationBinding:
    application_arn: str = field(repr=False)
    instance_arn: str = field(repr=False)
    jwt_bearer: JwtBearerBinding | None = field(default=None, repr=False)
    oidc_client: OidcPublicClient | None = field(default=None, repr=False)
    single_owner: SingleOwnerPolicy | None = field(default=None, repr=False)

    def __post_init__(self) -> None:
        if self.single_owner is not None and (
            not isinstance(self.single_owner, SingleOwnerPolicy)
            or self.jwt_bearer is None or self.oidc_client is None
        ):
            raise IdentityGrantError("BINDING_TOPOLOGY_INVALID")

    @property
    def grant_version(self) -> str:
        return "2" if self.jwt_bearer is not None else "1"

    @classmethod
    def from_bytes(cls, raw: bytes, expected_sha256: str) -> "ApplicationBinding":
        if (
            re.fullmatch(r"[a-f0-9]{64}", expected_sha256) is None
            or not 2 <= len(raw) <= 4096
            or not hmac.compare_digest(hashlib.sha256(raw).hexdigest(), expected_sha256)
        ):
            raise IdentityGrantError("BINDING_PIN_MISMATCH")
        value = _closed_object(raw)
        version = value.get("schema_version")
        if type(version) is not str:
            raise IdentityGrantError("BINDING_CONTRACT_INVALID")
        expected_fields = {
            "1": BINDING_FIELDS, "2": JWT_BINDING_FIELDS, "3": SINGLE_OWNER_BINDING_FIELDS,
        }.get(version, BINDING_FIELDS)
        if set(value) != expected_fields or any(type(item) is not str for item in value.values()):
            raise IdentityGrantError("BINDING_CONTRACT_INVALID")
        if (
            version not in ("1", "2", "3")
            or value["record_type"] != {
                "1": "platform_authority_bootstrap_pkce_binding",
                "2": "platform_authority_bootstrap_jwt_binding",
                "3": "platform_authority_bootstrap_single_owner_binding",
            }.get(version)
            or value["authority_account_id"] != AUTHORITY_ACCOUNT
            or value["region"] != REGION
            or value["redirect_uri"] != REDIRECT_URI
        ):
            raise IdentityGrantError("BINDING_TOPOLOGY_INVALID")
        match = re.fullmatch(
            rf"arn:aws:sso::{AUTHORITY_ACCOUNT}:application/(ssoins-[a-f0-9]{{16}})/apl-[a-f0-9]{{16}}",
            value["application_arn"],
        )
        if match is None or value["instance_arn"] != "arn:aws:sso:::instance/" + match[1]:
            raise IdentityGrantError("BINDING_TOPOLOGY_INVALID")
        if version in ("2", "3"):
            try:
                jwt = JwtBearerBinding(
                    authority_account_id=AUTHORITY_ACCOUNT,
                    identity_center_instance_arn=value["instance_arn"],
                    trusted_token_issuer_arn=value["trusted_token_issuer_arn"],
                    issuer_url=value["issuer_url"], audience=value["audience"],
                )
                client = OidcPublicClient(
                    issuer_url=value["issuer_url"], audience=value["audience"],
                    authorization_endpoint=value["authorization_endpoint"],
                    token_endpoint=value["token_endpoint"],
                )
                policy = SingleOwnerPolicy(
                    authorized_at=value["single_owner_authorized_at"],
                    expires_at=value["single_owner_expires_at"],
                ) if version == "3" else None
            except (BootstrapAuthorizationError, JwtBearerGrantError, OidcClientError):
                raise IdentityGrantError("BINDING_TOPOLOGY_INVALID") from None
            return cls(value["application_arn"], value["instance_arn"], jwt, client, policy)
        return cls(value["application_arn"], value["instance_arn"])


def read_binding(path: Path, expected_sha256: str) -> ApplicationBinding:
    try:
        if not path.is_absolute() or path.parent.resolve(strict=True) != path.parent:
            raise IdentityGrantError("BINDING_PATH_INVALID")
        parent = path.parent.stat()
        if parent.st_uid != os.geteuid() or stat.S_IMODE(parent.st_mode) & 0o077:
            raise IdentityGrantError("BINDING_PATH_INVALID")
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            metadata = os.fstat(fd)
            if (
                not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.geteuid()
                or stat.S_IMODE(metadata.st_mode) & 0o077 or metadata.st_nlink != 1
            ):
                raise IdentityGrantError("BINDING_PATH_INVALID")
            raw = os.read(fd, 4097)
        finally:
            os.close(fd)
    except OSError:
        raise IdentityGrantError("BINDING_PATH_INVALID") from None
    return ApplicationBinding.from_bytes(raw, expected_sha256)


@dataclass
class PendingGrant:
    state: str = field(default_factory=lambda: secrets.token_urlsafe(32), repr=False)
    verifier: str = field(default_factory=lambda: secrets.token_urlsafe(48), repr=False)
    _consumed: bool = field(default=False, init=False, repr=False)
    _binding: ApplicationBinding | None = field(default=None, init=False, repr=False)
    _nonce: str | None = field(default=None, init=False, repr=False)

    def authorization_url(self, binding: ApplicationBinding, operation_binding_digest: str | None = None) -> str:
        if self._consumed:
            raise IdentityGrantError("GRANT_ALREADY_CONSUMED")
        challenge = base64.urlsafe_b64encode(hashlib.sha256(self.verifier.encode("ascii")).digest()).rstrip(b"=").decode("ascii")
        if binding.jwt_bearer is not None:
            if (
                binding.oidc_client is None
                or type(operation_binding_digest) is not str
                or re.fullmatch(r"sha256:[a-f0-9]{64}", operation_binding_digest) is None
            ):
                raise IdentityGrantError("OPERATION_BINDING_INVALID")
            self._binding, self._nonce = binding, operation_binding_digest
            return binding.oidc_client.authorization_endpoint + "?" + urlencode({
                "response_type": "code", "client_id": binding.oidc_client.audience,
                "redirect_uri": REDIRECT_URI, "state": self.state,
                "code_challenge_method": "S256", "scope": "openid",
                "code_challenge": challenge, "nonce": operation_binding_digest,
                "prompt": "login", "max_age": "0",
            })
        if operation_binding_digest is not None or binding.oidc_client is not None:
            raise IdentityGrantError("OPERATION_BINDING_INVALID")
        return AUTHORIZE_ENDPOINT + "?" + urlencode({
            "response_type": "code", "client_id": binding.application_arn,
            "redirect_uri": REDIRECT_URI, "state": self.state,
            "code_challenge_method": "S256", "scopes": "sts:identity_context",
            "code_challenge": challenge,
        })

    def consume_request(self, request: bytes) -> bytes:
        if self._consumed:
            raise IdentityGrantError("GRANT_ALREADY_CONSUMED")
        self._consumed = True
        assertion = ""
        try:
            code, received_state = _parse_callback(request)
            if not hmac.compare_digest(received_state, self.state):
                raise IdentityGrantError("CALLBACK_STATE_MISMATCH")
            if self._binding is not None:
                try:
                    if self._binding.single_owner is not None:
                        self._binding.single_owner.require_active(datetime.now(UTC))
                    assertion = self._binding.oidc_client.exchange_code(
                        code=code, verifier=self.verifier, redirect_uri=REDIRECT_URI,
                    )
                    validate_claims(assertion, self._binding.jwt_bearer, self._nonce, datetime.now(UTC))
                except (OidcClientError, BootstrapAuthorizationError):
                    raise IdentityGrantError("OIDC_GRANT_REJECTED_OR_UNCERTAIN") from None
                payload = json.dumps({
                    "schema_version": "2", "record_type": "platform_authority_bootstrap_identity_grant",
                    "grant_type": JWT_BEARER_GRANT, "assertion": assertion,
                }, separators=(",", ":")).encode("utf-8")
            else:
                payload = json.dumps({
                    "schema_version": "1", "record_type": "platform_authority_bootstrap_identity_grant",
                    "authorization_code": code, "code_verifier": self.verifier,
                }, separators=(",", ":")).encode("utf-8")
            if len(payload) > MAX_GRANT_BYTES:
                raise IdentityGrantError("GRANT_SIZE_INVALID")
            return payload
        finally:
            assertion = ""
            self.clear()

    def clear(self) -> None:
        self._consumed = True
        self.state = ""
        self.verifier = ""
        self._binding = None
        self._nonce = None


def _parse_callback(request: bytes) -> tuple[str, str]:
    if not 1 <= len(request) <= MAX_REQUEST_BYTES or not request.endswith(b"\r\n\r\n"):
        raise IdentityGrantError("CALLBACK_REQUEST_INVALID")
    try:
        lines = request.decode("ascii").split("\r\n")
        method, target, protocol = lines[0].split(" ")
        if method != "GET" or protocol != "HTTP/1.1":
            raise ValueError
        headers: dict[str, str] = {}
        for line in lines[1:-2]:
            name, value = line.split(":", 1)
            name = name.lower()
            if not re.fullmatch(r"[a-z0-9-]+", name) or name in headers:
                raise ValueError
            headers[name] = value.strip(" \t")
        if (
            headers.get("host") != "127.0.0.1:38271"
            or headers.get("content-length", "0") != "0"
            or "transfer-encoding" in headers
            or any(ord(char) < 32 or ord(char) == 127 for char in target)
            or not target.startswith("/callback?")
            or re.search(r"%(?![0-9a-fA-F]{2})", target)
        ):
            raise ValueError
        parsed = urlsplit(target)
        if parsed.scheme or parsed.netloc or parsed.path != "/callback" or parsed.fragment:
            raise ValueError
        pairs = parse_qsl(parsed.query, keep_blank_values=True, strict_parsing=True,
                          encoding="utf-8", errors="strict", max_num_fields=2)
        if len(pairs) != 2 or {pair[0] for pair in pairs} != {"code", "state"}:
            raise ValueError
        values = dict(pairs)
        code, state = values["code"], values["state"]
        if (
            not 8 <= len(code) <= 4096 or not code.isascii()
            or any(ord(char) <= 32 or ord(char) == 127 for char in code)
            or re.fullmatch(r"[A-Za-z0-9_-]{43}", state) is None
        ):
            raise ValueError
        return code, state
    except (ValueError, UnicodeError):
        raise IdentityGrantError("CALLBACK_REQUEST_INVALID") from None


def open_listener() -> socket.socket:
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        # Reuse a closed connection's TIME_WAIT address across separate human
        # operations, never a live listener (SO_REUSEPORT is deliberately absent).
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.1", CALLBACK_PORT))
        listener.listen(1)
        listener.setblocking(False)
        return listener
    except OSError:
        listener.close()
        raise IdentityGrantError("CALLBACK_PORT_UNAVAILABLE") from None


def receive_callback(listener: socket.socket, pending: PendingGrant, *,
                     child_alive: Callable[[], bool], timeout: float = CALLBACK_TIMEOUT) -> bytes:
    deadline = time.monotonic() + timeout
    connection: socket.socket | None = None
    try:
        while True:
            if not child_alive():
                raise IdentityGrantError("CHILD_EXITED_BEFORE_GRANT")
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise IdentityGrantError("CALLBACK_TIMEOUT")
            if select.select([listener], [], [], min(remaining, 0.1))[0]:
                connection, peer = listener.accept()
                if peer[0] != "127.0.0.1":
                    raise IdentityGrantError("CALLBACK_PEER_INVALID")
                break
        connection.settimeout(min(2.0, max(0.001, deadline - time.monotonic())))
        raw = bytearray()
        while b"\r\n\r\n" not in raw:
            chunk = connection.recv(min(4096, MAX_REQUEST_BYTES + 1 - len(raw)))
            if not chunk:
                raise IdentityGrantError("CALLBACK_REQUEST_INVALID")
            raw.extend(chunk)
            if len(raw) > MAX_REQUEST_BYTES or time.monotonic() >= deadline:
                raise IdentityGrantError("CALLBACK_REQUEST_INVALID")
        payload = pending.consume_request(bytes(raw))
        raw.clear()
        connection.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 28\r\nContent-Type: text/plain\r\nCache-Control: no-store\r\nReferrer-Policy: no-referrer\r\nConnection: close\r\n\r\nAuthorization step received.\n")
        return payload
    except (OSError, ValueError) as exc:
        pending.clear()
        if connection is not None:
            try:
                connection.sendall(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n")
            except OSError:
                pass
        if isinstance(exc, IdentityGrantError):
            raise
        raise IdentityGrantError("CALLBACK_FAILED") from None
    finally:
        if connection is not None:
            connection.close()
        listener.close()


def wait_ready(fd: int, *, operation: str, child: subprocess.Popen,
               timeout: float = READINESS_TIMEOUT, version: str = "1") -> str | None:
    deadline = time.monotonic() + timeout
    raw = bytearray()
    while True:
        if child.poll() is not None:
            raise IdentityGrantError("CHILD_EXITED_BEFORE_READY")
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise IdentityGrantError("READINESS_TIMEOUT")
        if not select.select([fd], [], [], min(remaining, 0.1))[0]:
            continue
        chunk = os.read(fd, 513 - len(raw))
        if not chunk:
            break
        raw.extend(chunk)
        if len(raw) > 512:
            raise IdentityGrantError("READINESS_INVALID")
    expected = {"schema_version": version, "record_type": "platform_authority_bootstrap_grant_ready",
                "operation": operation, "pid": child.pid}
    if not raw:
        raise IdentityGrantError("CHILD_CLOSED_BEFORE_READY")
    value = _closed_object(bytes(raw))
    nonce = value.pop("operation_binding_digest", None) if version == "2" else None
    if (
        version not in ("1", "2") or value != expected
        or (version == "2" and (type(nonce) is not str or re.fullmatch(r"sha256:[a-f0-9]{64}", nonce) is None))
    ):
        raise IdentityGrantError("READINESS_INVALID")
    return nonce


def write_pipe(fd: int, payload: bytes, *, child_alive: Callable[[], bool], timeout: float = 10.0) -> None:
    """Bound pipe writes even if the isolated child stops consuming input."""
    os.set_blocking(fd, False)
    deadline = time.monotonic() + timeout
    view = memoryview(payload)
    while view:
        if not child_alive():
            raise IdentityGrantError("CHILD_EXITED_DURING_TRANSPORT")
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise IdentityGrantError("PIPE_WRITE_TIMEOUT")
        if not select.select([], [fd], [], min(remaining, 0.1))[1]:
            continue
        try:
            written = os.write(fd, view[:65536])
        except BlockingIOError:
            continue
        if written <= 0:
            raise IdentityGrantError("PIPE_WRITE_FAILED")
        view = view[written:]


def child_arguments(operation: str, arguments: Sequence[str]) -> list[str]:
    value_flags = {
        "plan": {"--initiator-id", "--change-set-name", "--plan-out"},
        "approve": {"--plan", "--approver-id", "--approval-out"},
        "apply": {"--plan", "--approval", "--verification-out", "--backend-config-out"},
    }
    bool_flags = {"plan": {"--allow-change-set-write"}, "approve": set(), "apply": {"--allow-bootstrap-apply"}}
    if operation not in OPERATIONS:
        raise IdentityGrantError("OPERATION_INVALID")
    seen: set[str] = set()
    result: list[str] = []
    index = 0
    destinations: set[str] = set()
    while index < len(arguments):
        name = arguments[index]
        index += 1
        if name in seen and name != "--destination-account-id":
            raise IdentityGrantError("COMMAND_ARGUMENTS_INVALID")
        seen.add(name)
        if name in bool_flags[operation]:
            result.append(name)
            continue
        if name not in value_flags[operation] | {"--destination-account-id"} or index == len(arguments):
            raise IdentityGrantError("COMMAND_ARGUMENTS_INVALID")
        value = arguments[index]
        index += 1
        if not value or len(value) > 4096 or value.startswith("-") or any(ord(char) < 32 or ord(char) == 127 for char in value):
            raise IdentityGrantError("COMMAND_ARGUMENTS_INVALID")
        if name == "--destination-account-id":
            if re.fullmatch(r"[0-9]{12}", value) is None or value in {AUTHORITY_ACCOUNT, "000000000000"} or value in destinations:
                raise IdentityGrantError("COMMAND_ARGUMENTS_INVALID")
            destinations.add(value)
        result.extend([name, value])
    if not destinations or not (value_flags[operation] | bool_flags[operation]) <= seen:
        raise IdentityGrantError("COMMAND_ARGUMENTS_INVALID")
    return result


def open_browser(url: str) -> None:
    """Use the fixed macOS system launcher; no BROWSER/shell override or output."""
    executable = Path("/usr/bin/open")
    try:
        metadata = executable.lstat()
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != 0 or stat.S_IMODE(metadata.st_mode) & 0o022:
            raise IdentityGrantError("BROWSER_LAUNCHER_INVALID")
        subprocess.run([str(executable), url], check=True, timeout=10,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                       env={"PATH": "/usr/bin:/bin"})
    except (OSError, subprocess.SubprocessError):
        raise IdentityGrantError("BROWSER_LAUNCH_FAILED") from None


def launch(*, source_root: Path, source_snapshot: dict[str, bytes],
           binding: ApplicationBinding, operation: str,
           arguments: Sequence[str], revalidate_source: Callable[[], None],
           browser: Callable[[str], None] = open_browser) -> int:
    args = child_arguments(operation, arguments)
    def require_policy() -> None:
        if binding.single_owner is not None:
            try:
                binding.single_owner.require_active(datetime.now(UTC))
            except BootstrapAuthorizationError:
                raise IdentityGrantError("SINGLE_OWNER_AUTHORIZATION_INACTIVE") from None

    require_policy()
    if binding.single_owner is not None:
        destinations = [args[index + 1] for index, name in enumerate(args) if name == "--destination-account-id"]
        actor_flag = {"plan": "--initiator-id", "approve": "--approver-id"}.get(operation)
        if destinations != ["905418363887"] or (
            actor_flag is not None and args[args.index(actor_flag) + 1] != binding.single_owner.owner_operator_id
        ):
            raise IdentityGrantError("SINGLE_OWNER_SCOPE_INVALID")
    # Take a private immutable byte snapshot before any supplied revalidation
    # callback or child can run. The operational launcher supplies Git blobs.
    if (
        type(source_snapshot) is not dict
        or "scripts/deployment/platform-authority-bootstrap.py" not in source_snapshot
        or "tooling/__init__.py" not in source_snapshot
        or any(type(name) is not str or type(value) is not bytes for name, value in source_snapshot.items())
    ):
        raise IdentityGrantError("SOURCE_SNAPSHOT_INVALID")
    source_bytes = json.dumps({name: base64.b64encode(value).decode("ascii")
                              for name, value in source_snapshot.items()}, sort_keys=True, separators=(",", ":")).encode("ascii")
    if len(source_bytes) > 4 * 1024 * 1024:
        raise IdentityGrantError("SOURCE_SNAPSHOT_INVALID")
    listener = open_listener()
    pending = PendingGrant()
    descriptors: list[int] = []
    child: subprocess.Popen | None = None
    payload = b""
    try:
        grant_read, grant_write = os.pipe()
        descriptors.extend([grant_read, grant_write])
        ready_read, ready_write = os.pipe()
        descriptors.extend([ready_read, ready_write])
        source_read, source_write = os.pipe()
        descriptors.extend([source_read, source_write])
        revalidate_source()
        require_policy()
        command = [sys.executable, "-I", "-S", "-c", CHILD_BOOTSTRAP, str(source_read),
                   hashlib.sha256(source_bytes).hexdigest(), str(source_root),
                   operation, "--authority-account-id", AUTHORITY_ACCOUNT, "--region", REGION,
                   *args, "--identity-grant-fd", str(grant_read), "--identity-grant-ready-fd", str(ready_write)]
        if binding.grant_version == "2":
            command.extend(["--identity-grant-version", "2"])
        if binding.single_owner is not None:
            command.extend([
                "--operator-policy-mode", "single_owner_v1",
                "--single-owner-authorized-at", binding.single_owner.authorized_at,
                "--single-owner-expires-at", binding.single_owner.expires_at,
            ])
        child = subprocess.Popen(command, pass_fds=(grant_read, ready_write, source_read), close_fds=True,
                                 stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                 stderr=subprocess.DEVNULL, cwd=source_root)
        for fd in (grant_read, ready_write, source_read):
            os.close(fd)
            descriptors.remove(fd)
        write_pipe(source_write, source_bytes, child_alive=lambda: child.poll() is None, timeout=30.0)
        os.close(source_write)
        descriptors.remove(source_write)
        nonce = (
            wait_ready(ready_read, operation=operation, child=child, version="2")
            if binding.grant_version == "2"
            else wait_ready(ready_read, operation=operation, child=child)
        )
        os.close(ready_read)
        descriptors.remove(ready_read)
        revalidate_source()
        require_policy()
        browser(pending.authorization_url(binding, nonce))
        payload = receive_callback(listener, pending, child_alive=lambda: child.poll() is None)
        require_policy()
        write_pipe(grant_write, payload, child_alive=lambda: child.poll() is None)
        payload = b""
        os.close(grant_write)
        descriptors.remove(grant_write)
        try:
            result = child.wait(timeout=CHILD_COMPLETION_TIMEOUT)
        except subprocess.TimeoutExpired:
            raise IdentityGrantError("CHILD_COMPLETION_UNCERTAIN") from None
        if result != 0:
            raise IdentityGrantError("CHILD_OPERATION_REJECTED_OR_UNCERTAIN")
        return 0
    except OSError:
        raise IdentityGrantError("GRANT_TRANSPORT_FAILED") from None
    finally:
        payload = b""
        pending.clear()
        listener.close()
        for fd in descriptors:
            os.close(fd)
        if child is not None and child.poll() is None:
            child.terminate()
            try:
                child.wait(timeout=5)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait(timeout=5)
