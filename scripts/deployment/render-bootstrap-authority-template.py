#!/usr/bin/env python3
"""Render the fixed GUG-274 template to reviewed JSON; perform no cloud action."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat

import yaml


SOURCE = Path(__file__).resolve().parents[2] / "bootstrap/cfn-platform-authority-bootstrap-artifact-authority.yaml"


class TemplateError(ValueError):
    pass


class TemplateLoader(yaml.SafeLoader):
    def construct_mapping(self, node: yaml.Node, deep: bool = False) -> dict:
        result = {}
        for key_node, value_node in node.value:
            key = self.construct_object(key_node, deep=deep)
            if not isinstance(key, str) or key in result:
                raise TemplateError("template keys must be unique strings")
            result[key] = self.construct_object(value_node, deep=deep)
        return result


def _intrinsic(loader: TemplateLoader, suffix: str, node: yaml.Node) -> dict:
    if suffix not in {"Ref", "Sub", "GetAtt", "Equals", "Not", "Join", "If"}:
        raise TemplateError("unreviewed template intrinsic")
    if isinstance(node, yaml.ScalarNode):
        value = loader.construct_scalar(node)
    elif isinstance(node, yaml.SequenceNode):
        value = loader.construct_sequence(node, deep=True)
    else:
        raise TemplateError("unsupported template intrinsic shape")
    if suffix == "GetAtt" and isinstance(value, str):
        value = value.split(".", 1)
        if len(value) != 2 or not all(value):
            raise TemplateError("invalid GetAtt reference")
    return {suffix if suffix == "Ref" else "Fn::" + suffix: value}


TemplateLoader.add_multi_constructor("!", _intrinsic)


def render(source: bytes, expected_source_sha256: str) -> bytes:
    if not re.fullmatch(r"[0-9a-f]{64}", expected_source_sha256):
        raise TemplateError("expected source SHA-256 must be independently reviewed")
    if hashlib.sha256(source).hexdigest() != expected_source_sha256:
        raise TemplateError("reviewed template source digest mismatch")
    if not source or len(source) > 1_048_576:
        raise TemplateError("template source size invalid")
    try:
        template = yaml.load(source.decode("utf-8"), Loader=TemplateLoader)
        if not isinstance(template, dict) or not isinstance(template.get("Resources"), dict):
            raise TemplateError("template Resources must be a mapping")
        return (json.dumps(template, sort_keys=True, separators=(",", ":"),
                           ensure_ascii=True, allow_nan=False) + "\n").encode("ascii")
    except (UnicodeError, yaml.YAMLError, TypeError, RecursionError, ValueError) as exc:
        if isinstance(exc, TemplateError):
            raise
        raise TemplateError("template is not strict renderable JSON") from None


def write_private(output: Path, payload: bytes) -> None:
    if not output.is_absolute() or output.parent.resolve(strict=True) != output.parent:
        raise TemplateError("output requires a canonical private directory")
    parent = output.parent.stat()
    if parent.st_uid != os.geteuid() or stat.S_IMODE(parent.st_mode) & 0o077:
        raise TemplateError("output directory must be private and caller-owned")
    descriptor = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(payload)
        stream.flush()
        os.fsync(stream.fileno())


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--expected-source-sha256", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        if SOURCE.is_symlink() or not SOURCE.is_file():
            raise TemplateError("fixed source template is unavailable")
        rendered = render(SOURCE.read_bytes(), args.expected_source_sha256)
        write_private(args.output, rendered)
    except (TemplateError, OSError):
        parser.exit(1, "ERROR: template render rejected; no installation authorized\n")
    print(json.dumps({
        "status": "LOCAL_RENDER_ONLY",
        "source_sha256": args.expected_source_sha256,
        "rendered_sha256": hashlib.sha256(rendered).hexdigest(),
        "output": str(args.output),
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
