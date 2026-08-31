#!/usr/bin/env python3
"""Attest one exact GUG-376 versioned template using read-only AWS calls."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import re
import stat
import sys
from typing import Sequence


REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from tooling import (  # noqa: E402
    platform_authority_plan_permission_repair_broker_seed as seed,
)
from tooling import (  # noqa: E402
    platform_authority_plan_permission_repair_template_readback as readback,
)


class _Parser(argparse.ArgumentParser):
    def error(self, _message: str) -> None:
        raise readback.TemplateReadbackError("CLI_ARGUMENTS_INVALID")


def _parser() -> argparse.ArgumentParser:
    parser = _Parser(
        description=(
            "Read STS, bucket versioning, and one exact S3 object version. "
            "The artifact bucket and KMS key are derived from validated "
            "GUG-376 foundation publication evidence and cannot be supplied "
            "manually."
        )
    )
    parser.add_argument(
        "--artifact-kind",
        choices=(
            "route_template",
            "delegation_template",
            "pep_template",
            "pep_protection_template",
            "broker_template",
            "broker_protection_template",
        ),
        required=True,
    )
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--private-root", type=Path, required=True)
    parser.add_argument("--bootstrap-intent-name", required=True)
    parser.add_argument("--foundation-publish-binding-name", required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--output-name")
    parser.add_argument("--pep-template-name")
    parser.add_argument("--pep-materialization-receipt-name")
    parser.add_argument("--pep-protection-template-name")
    parser.add_argument("--pep-protection-materialization-receipt-name")
    parser.add_argument("--broker-template-name")
    parser.add_argument("--broker-materialization-receipt-name")
    parser.add_argument("--broker-protection-template-name")
    parser.add_argument("--broker-protection-materialization-receipt-name")
    parser.add_argument("--aws-profile", required=True)
    parser.add_argument("--expected-account-id", required=True)
    parser.add_argument("--region", required=True)
    return parser


def _absolute(path: Path) -> Path:
    return Path(os.path.abspath(os.path.expanduser(os.fspath(path))))


def _read_private_bytes(
    *, private_root: Path, name: str, maximum: int
) -> bytes:
    if not re.fullmatch(
        r"[A-Za-z0-9][A-Za-z0-9._-]{0,126}", name
    ):
        raise readback.TemplateReadbackError("PRIVATE_ARTIFACT_NAME_INVALID")
    try:
        root_fd = seed._private_root(private_root)  # noqa: SLF001
    except seed.BrokerSeedError as exc:
        raise readback.TemplateReadbackError(exc.code) from exc
    try:
        try:
            descriptor = os.open(
                name,
                os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=root_fd,
            )
        except OSError as exc:
            raise readback.TemplateReadbackError(
                "PRIVATE_ARTIFACT_INVALID"
            ) from exc
        try:
            before = os.fstat(descriptor)
            if (
                not stat.S_ISREG(before.st_mode)
                or before.st_uid != os.geteuid()
                or before.st_nlink != 1
                or stat.S_IMODE(before.st_mode) != 0o600
                or not 0 < before.st_size <= maximum
            ):
                raise readback.TemplateReadbackError(
                    "PRIVATE_ARTIFACT_INVALID"
                )
            chunks: list[bytes] = []
            total = 0
            while total <= maximum:
                chunk = os.read(descriptor, min(65_536, maximum + 1 - total))
                if not chunk:
                    break
                chunks.append(chunk)
                total += len(chunk)
            after = os.fstat(descriptor)
            if (
                total != before.st_size
                or total > maximum
                or (
                    after.st_dev,
                    after.st_ino,
                    after.st_size,
                    after.st_mtime_ns,
                    after.st_ctime_ns,
                    after.st_mode,
                    after.st_uid,
                    after.st_nlink,
                )
                != (
                    before.st_dev,
                    before.st_ino,
                    before.st_size,
                    before.st_mtime_ns,
                    before.st_ctime_ns,
                    before.st_mode,
                    before.st_uid,
                    before.st_nlink,
                )
            ):
                raise readback.TemplateReadbackError(
                    "PRIVATE_ARTIFACT_CHANGED"
                )
        finally:
            os.close(descriptor)
    finally:
        os.close(root_fd)
    return b"".join(chunks)


def main(argv: Sequence[str] | None = None) -> int:
    try:
        args = _parser().parse_args(argv)
        source_root = _absolute(args.source_root)
        private_root = _absolute(args.private_root)
        try:
            private_root.relative_to(source_root)
            raise readback.TemplateReadbackError("PRIVATE_ROOT_INSIDE_SOURCE")
        except ValueError:
            pass
        bootstrap_intent = seed.load_private_input(
            private_root=private_root, name=args.bootstrap_intent_name
        )
        foundation_publish_binding = seed.load_private_input(
            private_root=private_root,
            name=args.foundation_publish_binding_name,
        )
        private_artifact = None
        materialization_receipt = None
        private_names = {
            "pep_template": (
                args.pep_template_name,
                args.pep_materialization_receipt_name,
            ),
            "pep_protection_template": (
                args.pep_protection_template_name,
                args.pep_protection_materialization_receipt_name,
            ),
            "broker_template": (
                args.broker_template_name,
                args.broker_materialization_receipt_name,
            ),
            "broker_protection_template": (
                args.broker_protection_template_name,
                args.broker_protection_materialization_receipt_name,
            ),
        }
        supplied_private_names = {
            args.pep_template_name,
            args.pep_materialization_receipt_name,
            args.pep_protection_template_name,
            args.pep_protection_materialization_receipt_name,
            args.broker_template_name,
            args.broker_materialization_receipt_name,
            args.broker_protection_template_name,
            args.broker_protection_materialization_receipt_name,
        } - {None}
        if args.artifact_kind in private_names:
            template_name, materialization_name = private_names[
                args.artifact_kind
            ]
            if (
                template_name is None
                or materialization_name is None
                or len(supplied_private_names) != 2
            ):
                raise readback.TemplateReadbackError(
                    "TEMPLATE_MATERIALIZED_ARTIFACT_REQUIRED"
                )
            private_artifact = _read_private_bytes(
                private_root=private_root,
                name=template_name,
                maximum=readback.MAX_TEMPLATE_BYTES,
            )
            materialization_receipt = seed.load_private_input(
                private_root=private_root,
                name=materialization_name,
            )
        elif supplied_private_names:
            raise readback.TemplateReadbackError(
                "PUBLIC_TEMPLATE_PRIVATE_INPUT_FORBIDDEN"
            )
        receipt = readback.attest_template_readback(
            source_root=source_root,
            upstream_source_root=None,
            source_commit=args.source_commit,
            artifact_kind=args.artifact_kind,
            version=args.version,
            gug363_plan=None,
            gug365_plan=None,
            aws_profile=args.aws_profile,
            expected_account_id=args.expected_account_id,
            region=args.region,
            private_artifact=private_artifact,
            materialization_receipt=materialization_receipt,
            bootstrap_intent=bootstrap_intent,
            foundation_publish_binding=foundation_publish_binding,
        )
        output_name = args.output_name or readback.DEFAULT_OUTPUT_NAMES[
            args.artifact_kind
        ]
        destination = readback.write_private_receipt(
            private_root=private_root,
            output_name=output_name,
            receipt=receipt,
        )
        # Bucket, key, version, caller ARN, KMS ARN, and embedded private
        # materialization evidence intentionally never reach stdout.
        summary = {
            "record_type": receipt["record_type"],
            "source_commit": receipt["source_commit"],
            "source_path": receipt["source_path"],
            "output_name": destination.name,
            "receipt_digest": receipt["receipt_digest"],
            "aws_calls": receipt["aws_calls"],
            "aws_mutations": 0,
            "deployment_authorized": False,
            "production_status": "NO-GO",
        }
        sys.stdout.write(seed.canonical_json(summary) + "\n")
        return 0
    except (seed.BrokerSeedError, readback.TemplateReadbackError) as exc:
        code = exc.code
        sys.stderr.write(seed.canonical_json({"error": code}) + "\n")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
