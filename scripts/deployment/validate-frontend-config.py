#!/usr/bin/env python3
"""Validate and render the public frontend-config/v3 contract offline.

The renderer consumes captured ``terraform output -json`` bytes. It never
executes Terraform or AWS, never logs configuration values, and writes only to
an explicitly selected path outside this repository.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import re
import stat
import sys
import tempfile
from pathlib import Path
from typing import Any
from urllib.parse import SplitResult, urlsplit

from jsonschema import Draft202012Validator, FormatChecker


REPO_ROOT = Path(__file__).resolve().parents[2]
SCHEMA_PATH = REPO_ROOT / "schemas" / "frontend-config.v3.schema.json"
MAX_INPUT_BYTES = 1_048_576
MAX_CONFIG_BYTES = 65_536
SAFE_SECRET_MARKER = "client_secret_embedded"
SECRET_LIKE_KEYS = {
    "access_key",
    "access_token",
    "api_key",
    "authorization_code",
    "client_secret",
    "credential",
    "credentials",
    "database_password",
    "id_token",
    "password",
    "private_key",
    "refresh_token",
    "secret",
    "secret_key",
    "session_token",
    "token",
}


class FrontendConfigError(ValueError):
    """A deterministic error that is safe to expose without rejected values."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise FrontendConfigError("FRONTEND_CONFIG_DUPLICATE_KEY")
        result[key] = value
    return result


def _reject_non_finite(_: str) -> None:
    raise FrontendConfigError("FRONTEND_CONFIG_NON_FINITE_JSON")


def _parse_finite_float(serialized: str) -> float:
    value = float(serialized)
    if not math.isfinite(value):
        raise FrontendConfigError("FRONTEND_CONFIG_NON_FINITE_JSON")
    return value


def parse_json_strict(serialized: str) -> Any:
    """Parse strict JSON while rejecting empty, duplicate and non-finite input."""

    if serialized.strip() == "":
        raise FrontendConfigError("FRONTEND_CONFIG_EMPTY_JSON")
    try:
        return json.loads(
            serialized,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_non_finite,
            parse_float=_parse_finite_float,
        )
    except FrontendConfigError:
        raise
    except (TypeError, ValueError, json.JSONDecodeError) as exc:
        raise FrontendConfigError("FRONTEND_CONFIG_INVALID_JSON") from exc


def load_json_strict(path: Path) -> Any:
    """Load bounded UTF-8 JSON without echoing its path or contents."""

    try:
        size = path.stat().st_size
        if size == 0:
            raise FrontendConfigError("FRONTEND_CONFIG_EMPTY_JSON")
        if size > MAX_INPUT_BYTES:
            raise FrontendConfigError("FRONTEND_CONFIG_INPUT_TOO_LARGE")
        serialized = path.read_text(encoding="utf-8")
    except FrontendConfigError:
        raise
    except (OSError, UnicodeError) as exc:
        raise FrontendConfigError("FRONTEND_CONFIG_INPUT_UNAVAILABLE") from exc
    return parse_json_strict(serialized)


def _normalized_key(key: str) -> str:
    snake_case = re.sub(r"(?<!^)(?=[A-Z])", "_", key)
    return "_".join(
        part for part in re.sub(r"[^A-Za-z0-9]+", "_", snake_case).lower().split("_") if part
    )


def _reject_secret_like_keys(value: Any) -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            normalized = _normalized_key(key)
            if normalized != SAFE_SECRET_MARKER and (
                normalized in SECRET_LIKE_KEYS
                or normalized.endswith("_secret")
                or normalized.endswith("_password")
                or normalized.endswith("_token")
                or normalized.endswith("_private_key")
            ):
                raise FrontendConfigError("FRONTEND_CONFIG_SECRET_LIKE_KEY")
            _reject_secret_like_keys(child)
    elif isinstance(value, list):
        for child in value:
            _reject_secret_like_keys(child)


def _runtime_url(
    value: str,
    *,
    exact_path: str,
    allow_sandbox_loopback: bool,
) -> SplitResult:
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except (TypeError, ValueError) as exc:
        raise FrontendConfigError("FRONTEND_CONFIG_URL_INVALID") from exc
    if (
        not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or parsed.path != exact_path
    ):
        raise FrontendConfigError("FRONTEND_CONFIG_URL_INVALID")
    is_public_https = parsed.scheme == "https" and port is None
    is_sandbox_loopback = (
        allow_sandbox_loopback
        and parsed.scheme == "http"
        and parsed.hostname in {"localhost", "127.0.0.1"}
        and port is not None
        and 1 <= port <= 65_535
    )
    if not (is_public_https or is_sandbox_loopback):
        raise FrontendConfigError("FRONTEND_CONFIG_URL_INVALID")
    return parsed


def _origin(url: SplitResult) -> tuple[str, str, int | None]:
    return (url.scheme, url.hostname or "", url.port)


def validate_runtime_config(value: Any) -> dict[str, Any]:
    """Validate schema plus cross-field deployment and OIDC bindings."""

    if not isinstance(value, dict):
        raise FrontendConfigError("FRONTEND_CONFIG_SCHEMA_INVALID")
    _reject_secret_like_keys(value)

    try:
        schema = load_json_strict(SCHEMA_PATH)
        Draft202012Validator.check_schema(schema)
        errors = list(
            Draft202012Validator(
                schema,
                format_checker=FormatChecker(),
            ).iter_errors(value)
        )
    except FrontendConfigError:
        raise
    except Exception as exc:  # jsonschema exceptions must never echo instances.
        raise FrontendConfigError("FRONTEND_CONFIG_SCHEMA_UNAVAILABLE") from exc
    if errors:
        raise FrontendConfigError("FRONTEND_CONFIG_SCHEMA_INVALID")

    region = value["region"]
    deployment_id = value["deployment_id"]
    cognito = value["cognito"]
    if cognito["region"] != region or not cognito["user_pool_id"].startswith(f"{region}_"):
        raise FrontendConfigError("FRONTEND_CONFIG_REGION_BINDING_INVALID")

    aws_dns_suffix = "amazonaws.com.cn" if region.startswith("cn-") else "amazonaws.com"
    expected_issuer = (
        f"https://cognito-idp.{region}.{aws_dns_suffix}/{cognito['user_pool_id']}"
    )
    if cognito["issuer_url"] != expected_issuer:
        raise FrontendConfigError("FRONTEND_CONFIG_ISSUER_BINDING_INVALID")

    hosted_suffix = "amazoncognito.com.cn" if region.startswith("cn-") else "amazoncognito.com"
    hosted_prefix = deployment_id.lower().replace("_", "-") + "-identity"
    expected_hosted_ui = (
        f"https://{hosted_prefix}.auth.{region}.{hosted_suffix}"
    )
    if cognito["hosted_ui_domain"] != expected_hosted_ui:
        raise FrontendConfigError("FRONTEND_CONFIG_HOSTED_UI_BINDING_INVALID")

    allow_sandbox_loopback = value["environment"] == "sandbox"
    api_url = _runtime_url(
        value["api_endpoint"],
        exact_path="/api",
        allow_sandbox_loopback=allow_sandbox_loopback,
    )
    redirect_url = _runtime_url(
        cognito["redirect_uri"],
        exact_path="/callback",
        allow_sandbox_loopback=allow_sandbox_loopback,
    )
    logout_url = _runtime_url(
        cognito["post_logout_redirect_uri"],
        exact_path="/",
        allow_sandbox_loopback=allow_sandbox_loopback,
    )
    if not (_origin(api_url) == _origin(redirect_url) == _origin(logout_url)):
        raise FrontendConfigError("FRONTEND_CONFIG_ORIGIN_BINDING_INVALID")

    if len(render_config_bytes(value)) > MAX_CONFIG_BYTES:
        raise FrontendConfigError("FRONTEND_CONFIG_TOO_LARGE")
    return value


def _public_terraform_output(document: dict[str, Any], name: str) -> Any:
    selected = document.get(name)
    if (
        not isinstance(selected, dict)
        or selected.get("sensitive") is not False
        or "value" not in selected
    ):
        raise FrontendConfigError("FRONTEND_CONFIG_TERRAFORM_OUTPUT_INVALID")
    return selected["value"]


def extract_terraform_runtime_config(document: Any) -> tuple[dict[str, Any], bytes]:
    """Verify and select the exact digest-bound bytes from Terraform outputs."""

    if not isinstance(document, dict):
        raise FrontendConfigError("FRONTEND_CONFIG_TERRAFORM_OUTPUT_INVALID")
    config_value = _public_terraform_output(document, "frontend_runtime_config")
    json_value = _public_terraform_output(document, "frontend_runtime_config_json")
    digest_value = _public_terraform_output(document, "frontend_runtime_config_sha256")
    if not isinstance(json_value, str) or not isinstance(digest_value, str):
        raise FrontendConfigError("FRONTEND_CONFIG_TERRAFORM_OUTPUT_INVALID")
    exact_bytes = json_value.encode("utf-8")
    if len(exact_bytes) == 0:
        raise FrontendConfigError("FRONTEND_CONFIG_TERRAFORM_OUTPUT_INVALID")
    if len(exact_bytes) > MAX_CONFIG_BYTES:
        raise FrontendConfigError("FRONTEND_CONFIG_TOO_LARGE")
    parsed_json = parse_json_strict(json_value)
    config = validate_runtime_config(config_value)
    if parsed_json != config:
        raise FrontendConfigError("FRONTEND_CONFIG_TERRAFORM_VALUE_MISMATCH")
    if render_config_bytes(config) != exact_bytes:
        raise FrontendConfigError("FRONTEND_CONFIG_TERRAFORM_BYTES_NONCANONICAL")
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", digest_value):
        raise FrontendConfigError("FRONTEND_CONFIG_TERRAFORM_DIGEST_INVALID")
    if _digest(exact_bytes) != digest_value:
        raise FrontendConfigError("FRONTEND_CONFIG_TERRAFORM_DIGEST_MISMATCH")
    return config, exact_bytes


def render_config_bytes(config: dict[str, Any]) -> bytes:
    return json.dumps(
        config,
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _digest(content: bytes) -> str:
    return "sha256:" + hashlib.sha256(content).hexdigest()


def _inside_repo(path: Path) -> bool:
    try:
        path.relative_to(REPO_ROOT.resolve())
        return True
    except ValueError:
        return False


def write_config_outside_repo(
    output_path: Path,
    content: bytes,
    *,
    overwrite: bool = False,
) -> None:
    """Write mode 0600 outside the checkout, fail-closed on existing targets."""

    expanded = output_path.expanduser()
    if expanded.is_symlink():
        raise FrontendConfigError("FRONTEND_CONFIG_OUTPUT_UNSAFE")
    resolved = expanded.resolve(strict=False)
    if _inside_repo(resolved):
        raise FrontendConfigError("FRONTEND_CONFIG_OUTPUT_INSIDE_REPOSITORY")
    parent = resolved.parent
    if not parent.is_dir():
        raise FrontendConfigError("FRONTEND_CONFIG_OUTPUT_PARENT_UNAVAILABLE")
    if not overwrite:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            descriptor = os.open(resolved, flags, 0o600)
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(content)
                stream.flush()
                os.fsync(stream.fileno())
            os.chmod(resolved, 0o600)
            return
        except FileExistsError as exc:
            raise FrontendConfigError("FRONTEND_CONFIG_OUTPUT_EXISTS") from exc
        except OSError as exc:
            raise FrontendConfigError("FRONTEND_CONFIG_OUTPUT_WRITE_FAILED") from exc

    temporary_name: str | None = None
    try:
        descriptor, temporary_name = tempfile.mkstemp(
            dir=parent,
            prefix=".frontend-config-",
        )
        os.fchmod(descriptor, stat.S_IRUSR | stat.S_IWUSR)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary_name, resolved)
        os.chmod(resolved, 0o600)
    except OSError as exc:
        raise FrontendConfigError("FRONTEND_CONFIG_OUTPUT_WRITE_FAILED") from exc
    finally:
        if temporary_name and os.path.exists(temporary_name):
            os.unlink(temporary_name)


def artifact_tree_digest(artifact_dir: Path) -> str:
    """Hash one immutable build tree without reading external runtime configs."""

    root = artifact_dir.resolve(strict=False)
    if not root.is_dir():
        raise FrontendConfigError("FRONTEND_BUILD_ARTIFACT_UNAVAILABLE")
    entries: list[tuple[str, bytes]] = []
    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            raise FrontendConfigError("FRONTEND_BUILD_ARTIFACT_UNSAFE")
        if path.is_file():
            relative = path.relative_to(root).as_posix()
            if relative == "config.json":
                raise FrontendConfigError("FRONTEND_BUILD_CONTAINS_RUNTIME_CONFIG")
            entries.append((relative, path.read_bytes()))
    if not entries:
        raise FrontendConfigError("FRONTEND_BUILD_ARTIFACT_UNAVAILABLE")
    digest = hashlib.sha256()
    for relative, content in entries:
        encoded_path = relative.encode("utf-8")
        digest.update(len(encoded_path).to_bytes(8, "big"))
        digest.update(encoded_path)
        digest.update(len(content).to_bytes(8, "big"))
        digest.update(content)
    return "sha256:" + digest.hexdigest()


def prove_build_once(artifact_dir: Path, config_a: Path, config_b: Path) -> str:
    """Prove two distinct external configs share one unchanged build tree."""

    artifact_root = artifact_dir.resolve(strict=False)
    for config_path in (config_a, config_b):
        candidate = config_path.resolve(strict=False)
        try:
            candidate.relative_to(artifact_root)
        except ValueError:
            pass
        else:
            raise FrontendConfigError("FRONTEND_BUILD_CONFIG_NOT_EXTERNAL")

    before = artifact_tree_digest(artifact_root)
    rendered_a = render_config_bytes(validate_runtime_config(load_json_strict(config_a)))
    rendered_b = render_config_bytes(validate_runtime_config(load_json_strict(config_b)))
    if _digest(rendered_a) == _digest(rendered_b):
        raise FrontendConfigError("FRONTEND_BUILD_CONFIGS_NOT_DISTINCT")
    after = artifact_tree_digest(artifact_root)
    if before != after:
        raise FrontendConfigError("FRONTEND_BUILD_ARTIFACT_CHANGED")
    return before


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subcommands = parser.add_subparsers(dest="command", required=True)

    validate = subcommands.add_parser("validate")
    validate.add_argument("config", type=Path)

    render = subcommands.add_parser("render")
    render.add_argument("--terraform-output", required=True, type=Path)
    render.add_argument("--output", required=True, type=Path)
    render.add_argument("--overwrite", action="store_true")

    proof = subcommands.add_parser("prove-build-once")
    proof.add_argument("--artifact-dir", required=True, type=Path)
    proof.add_argument("--config-a", required=True, type=Path)
    proof.add_argument("--config-b", required=True, type=Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "validate":
            config = validate_runtime_config(load_json_strict(args.config))
            print(f"FRONTEND_CONFIG_VALID {_digest(render_config_bytes(config))}")
            return 0
        if args.command == "render":
            terraform_output = load_json_strict(args.terraform_output)
            _config, rendered = extract_terraform_runtime_config(terraform_output)
            write_config_outside_repo(args.output, rendered, overwrite=args.overwrite)
            print(f"FRONTEND_CONFIG_WRITTEN {_digest(rendered)}")
            return 0
        if args.command == "prove-build-once":
            digest = prove_build_once(args.artifact_dir, args.config_a, args.config_b)
            print(f"FRONTEND_BUILD_ONCE_VERIFIED {digest}")
            return 0
    except FrontendConfigError as exc:
        print(exc.code, file=sys.stderr)
        return 2
    except Exception:
        print("FRONTEND_CONFIG_INTERNAL_ERROR", file=sys.stderr)
        return 2
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
