#!/usr/bin/env python3
"""Materialize the parameterless GUG-376 route-broker seed offline."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import sys
from typing import Sequence


REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from tooling.platform_authority_plan_permission_repair_broker_seed import (  # noqa: E402
    BrokerSeedError,
    MATERIALIZATION_RECEIPT_OUTPUT_NAME,
    PACKAGE_RECEIPT_OUTPUT_NAME,
    PEP_MATERIALIZATION_RECEIPT_OUTPUT_NAME,
    PEP_PROTECTION_MATERIALIZATION_RECEIPT_OUTPUT_NAME,
    PROTECTION_MATERIALIZATION_RECEIPT_OUTPUT_NAME,
    build_private_broker_package,
    canonical_json,
    load_private_input,
    materialize_broker_seed_pair,
    materialize_pep_template_pair,
    write_private_receipt,
)


class _Parser(argparse.ArgumentParser):
    def error(self, _message: str) -> None:
        raise BrokerSeedError("CLI_ARGUMENTS_INVALID")


def _parser() -> argparse.ArgumentParser:
    parser = _Parser(
        description=(
            "Render the reviewed GUG-376 broker seed into an owner-only "
            "directory. This command performs no AWS call."
        )
    )
    commands = parser.add_subparsers(dest="command", required=True)
    build = commands.add_parser(
        "build-package",
        help="build the deterministic unsigned broker ZIP without cloud coordinates",
    )
    build.add_argument("--source-root", type=Path, required=True)
    build.add_argument("--private-root", type=Path, required=True)
    build.add_argument("--source-commit", required=True)
    materialize = commands.add_parser(
        "materialize-template",
        help="bind the attested signed object into the parameterless template",
    )
    materialize.add_argument("--source-root", type=Path, required=True)
    materialize.add_argument("--private-root", type=Path, required=True)
    materialize.add_argument("--input-name", required=True)
    pep = commands.add_parser(
        "materialize-pep-templates",
        help=(
            "render the reviewed PEP source into immutable CREATE/protection "
            "lifecycle variants"
        ),
    )
    pep.add_argument("--source-root", type=Path, required=True)
    pep.add_argument("--private-root", type=Path, required=True)
    pep.add_argument("--source-commit", required=True)
    return parser


def _absolute(path: Path) -> Path:
    return Path(os.path.abspath(os.path.expanduser(os.fspath(path))))


def main(argv: Sequence[str] | None = None) -> int:
    try:
        args = _parser().parse_args(argv)
        source_root = _absolute(args.source_root)
        private_root = _absolute(args.private_root)
        try:
            private_root.relative_to(source_root)
        except ValueError:
            pass
        else:
            raise BrokerSeedError("PRIVATE_ROOT_INSIDE_SOURCE")
        if args.command == "build-package":
            _path, receipt = build_private_broker_package(
                source_root=source_root,
                private_root=private_root,
                source_commit=args.source_commit,
            )
            receipt_name = PACKAGE_RECEIPT_OUTPUT_NAME
        elif args.command == "materialize-template":
            private_input = load_private_input(
                private_root=private_root,
                name=args.input_name,
            )
            materialized = materialize_broker_seed_pair(
                source_root=source_root,
                private_root=private_root,
                private_input=private_input,
            )
            create_receipt = materialized["broker_template"][1]
            protection_receipt = materialized["broker_protection_template"][1]
            for receipt_name, variant_receipt in (
                (MATERIALIZATION_RECEIPT_OUTPUT_NAME, create_receipt),
                (
                    PROTECTION_MATERIALIZATION_RECEIPT_OUTPUT_NAME,
                    protection_receipt,
                ),
            ):
                write_private_receipt(
                    private_root=private_root,
                    name=receipt_name,
                    receipt=variant_receipt,
                )
            summary = {
                "record_type": create_receipt["record_type"],
                "source_commit": create_receipt["source_commit"],
                "receipts": {
                    "broker_template": {
                        "receipt_name": MATERIALIZATION_RECEIPT_OUTPUT_NAME,
                        "receipt_digest": create_receipt["receipt_digest"],
                        "template_sha256": create_receipt["template_sha256"],
                        "template_bytes": create_receipt["template_bytes"],
                    },
                    "broker_protection_template": {
                        "receipt_name": (
                            PROTECTION_MATERIALIZATION_RECEIPT_OUTPUT_NAME
                        ),
                        "receipt_digest": protection_receipt["receipt_digest"],
                        "template_sha256": protection_receipt["template_sha256"],
                        "template_bytes": protection_receipt["template_bytes"],
                    },
                },
                "aws_calls": 0,
                "aws_mutations": 0,
                "deployment_authorized": False,
                "production_status": create_receipt["production_status"],
            }
            sys.stdout.write(canonical_json(summary) + "\n")
            return 0
        else:
            materialized = materialize_pep_template_pair(
                source_root=source_root,
                private_root=private_root,
                source_commit=args.source_commit,
            )
            create_receipt = materialized["pep_template"][1]
            protection_receipt = materialized["pep_protection_template"][1]
            for receipt_name, variant_receipt in (
                (PEP_MATERIALIZATION_RECEIPT_OUTPUT_NAME, create_receipt),
                (
                    PEP_PROTECTION_MATERIALIZATION_RECEIPT_OUTPUT_NAME,
                    protection_receipt,
                ),
            ):
                write_private_receipt(
                    private_root=private_root,
                    name=receipt_name,
                    receipt=variant_receipt,
                )
            summary = {
                "record_type": create_receipt["record_type"],
                "source_commit": create_receipt["source_commit"],
                "receipts": {
                    "pep_template": {
                        "receipt_name": PEP_MATERIALIZATION_RECEIPT_OUTPUT_NAME,
                        "receipt_digest": create_receipt["receipt_digest"],
                        "template_sha256": create_receipt["template_sha256"],
                        "template_bytes": create_receipt["template_bytes"],
                    },
                    "pep_protection_template": {
                        "receipt_name": (
                            PEP_PROTECTION_MATERIALIZATION_RECEIPT_OUTPUT_NAME
                        ),
                        "receipt_digest": protection_receipt["receipt_digest"],
                        "template_sha256": protection_receipt["template_sha256"],
                        "template_bytes": protection_receipt["template_bytes"],
                    },
                },
                "aws_calls": 0,
                "aws_mutations": 0,
                "deployment_authorized": False,
                "production_status": create_receipt["production_status"],
            }
            sys.stdout.write(canonical_json(summary) + "\n")
            return 0
        write_private_receipt(
            private_root=private_root,
            name=receipt_name,
            receipt=receipt,
        )
        summary = {
            "record_type": receipt["record_type"],
            "source_commit": receipt["source_commit"],
            "receipt_name": receipt_name,
            "receipt_digest": receipt["receipt_digest"],
            "aws_calls": receipt["aws_calls"],
            "aws_mutations": receipt["aws_mutations"],
            "deployment_authorized": receipt["deployment_authorized"],
            "production_status": receipt["production_status"],
        }
        if args.command == "build-package":
            summary.update(
                {
                    "package_sha256": receipt["package_sha256"],
                    "package_bytes": receipt["package_bytes"],
                    "signed": receipt["signed"],
                }
            )
        else:
            summary.update(
                {
                    "template_sha256": receipt["template_sha256"],
                    "template_bytes": receipt["template_bytes"],
                    "effective_policy_projection_digest": receipt[
                        "effective_policy_projection_digest"
                    ],
                }
            )
        sys.stdout.write(canonical_json(summary) + "\n")
        return 0
    except BrokerSeedError as exc:
        sys.stderr.write(canonical_json({"error": exc.code}) + "\n")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
