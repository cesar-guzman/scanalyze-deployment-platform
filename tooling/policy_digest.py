#!/usr/bin/env python3
"""Reproducible digest verification for reviewed authorization policies.

The enterprise authorization policy currently uses the RFC 8785 data model
subset made of objects, arrays, strings, booleans, null, and safe integers.
Floating-point values are rejected rather than normalized ambiguously. Object
member names are sorted by UTF-16 code units as required by JSON Canonicalization
Scheme (JCS), and the resulting UTF-8 bytes are hashed with SHA-256.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any

try:
    from tooling.validate_enterprise_authorization import load_json_without_duplicates
except ModuleNotFoundError:  # Direct execution from tooling/.
    from validate_enterprise_authorization import (  # type: ignore[no-redef]
        load_json_without_duplicates,
    )


SHA256_PATTERN = re.compile(r"^sha256:[0-9a-f]{64}$")
MAX_SAFE_INTEGER = (2**53) - 1


class CanonicalizationError(ValueError):
    """Raised when policy JSON is outside the reviewed JCS subset."""


def _validate_unicode(value: str) -> None:
    if any(0xD800 <= ord(character) <= 0xDFFF for character in value):
        raise CanonicalizationError("policy strings must not contain lone surrogates")


def _quote(value: str) -> str:
    _validate_unicode(value)
    return json.dumps(value, ensure_ascii=False, allow_nan=False)


def _utf16_sort_key(value: str) -> bytes:
    _validate_unicode(value)
    return value.encode("utf-16-be")


def _canonical_text(value: Any) -> str:
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, int):
        if abs(value) > MAX_SAFE_INTEGER:
            raise CanonicalizationError("policy integers must be IEEE-754 safe")
        return str(value)
    if isinstance(value, float):
        raise CanonicalizationError("floating-point policy values are unsupported")
    if isinstance(value, str):
        return _quote(value)
    if isinstance(value, list):
        return "[" + ",".join(_canonical_text(item) for item in value) + "]"
    if isinstance(value, dict):
        if any(not isinstance(key, str) for key in value):
            raise CanonicalizationError("policy object keys must be strings")
        members = (
            f"{_quote(key)}:{_canonical_text(value[key])}"
            for key in sorted(value, key=_utf16_sort_key)
        )
        return "{" + ",".join(members) + "}"
    raise CanonicalizationError("policy contains an unsupported JSON value")


def canonicalize_rfc8785(policy: dict[str, Any]) -> bytes:
    """Return deterministic RFC 8785-compatible UTF-8 bytes."""

    if not isinstance(policy, dict):
        raise CanonicalizationError("policy root must be an object")
    return _canonical_text(policy).encode("utf-8")


def compute_policy_digest(policy: dict[str, Any]) -> str:
    """Return the versioned lowercase SHA-256 digest for one policy."""

    canonical = canonicalize_rfc8785(policy)
    return f"sha256:{hashlib.sha256(canonical).hexdigest()}"


def load_digest(path: Path) -> str:
    """Read one strict digest file without accepting comments or aliases."""

    lines = path.read_text(encoding="utf-8").splitlines()
    if len(lines) != 1 or SHA256_PATTERN.fullmatch(lines[0]) is None:
        raise ValueError("digest file must contain one sha256 lowercase hex value")
    return lines[0]


def verify_policy_digest(policy_path: Path, digest_path: Path) -> tuple[bool, str]:
    """Verify a reviewed policy against its tracked digest file."""

    policy = load_json_without_duplicates(policy_path)
    computed = compute_policy_digest(policy)
    expected = load_digest(digest_path)
    return computed == expected, computed


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Compute or verify an RFC 8785-compatible policy digest"
    )
    parser.add_argument("policy", type=Path)
    parser.add_argument("--digest-file", type=Path)
    parser.add_argument(
        "--check",
        action="store_true",
        help="fail unless the tracked digest matches the reviewed policy",
    )
    args = parser.parse_args(argv)

    try:
        policy = load_json_without_duplicates(args.policy)
        computed = compute_policy_digest(policy)
        if not args.check:
            print(computed)
            return 0
        if args.digest_file is None:
            parser.error("--check requires --digest-file")
        expected = load_digest(args.digest_file)
    except (CanonicalizationError, OSError, ValueError) as error:
        print(f"FAIL: {error}", file=sys.stderr)
        return 1

    if computed != expected:
        print("FAIL: tracked policy digest does not match", file=sys.stderr)
        return 1
    print("PASS: reviewed policy digest matches")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
