#!/usr/bin/env python3
"""Produce the read-only GUG-376 broker signed-artifact handoff."""

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
    canonical_json,
    load_private_input,
)
from tooling.platform_authority_plan_permission_repair_broker_signed_artifact import (  # noqa: E402
    BrokerSignedArtifactError,
    DEFAULT_OUTPUT_NAME,
    EXPECTED_PROFILE,
    attest_broker_signed_artifact,
    write_private_handoff,
)


class _Parser(argparse.ArgumentParser):
    def error(self, _message: str) -> None:
        raise BrokerSignedArtifactError("CLI_ARGUMENTS_INVALID")


def _parser() -> argparse.ArgumentParser:
    parser = _Parser(
        description=(
            "Read back the exact GUG-376 broker source/signing/output chain. "
            "This command performs read-only AWS calls and no deployment."
        )
    )
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--private-root", type=Path, required=True)
    parser.add_argument("--output-name", default=DEFAULT_OUTPUT_NAME)
    parser.add_argument(
        "--aws-profile", required=True, choices=(EXPECTED_PROFILE,)
    )
    parser.add_argument("--expected-account-id", required=True)
    parser.add_argument("--region", required=True)
    parser.add_argument("--unsigned-bucket", required=True)
    parser.add_argument("--unsigned-key", required=True)
    parser.add_argument("--unsigned-version", required=True)
    parser.add_argument("--signing-job-id", required=True)
    parser.add_argument("--signed-version", required=True)
    parser.add_argument("--pep-signed-artifact-receipt-name", required=True)
    parser.add_argument("--bootstrap-intent-name", required=True)
    parser.add_argument("--foundation-publish-binding-name", required=True)
    return parser


def _absolute(value: Path) -> Path:
    return Path(os.path.abspath(os.path.expanduser(os.fspath(value))))


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
            raise BrokerSignedArtifactError("PRIVATE_ROOT_INSIDE_SOURCE")
        pep_receipt = load_private_input(
            private_root=private_root,
            name=args.pep_signed_artifact_receipt_name,
        )
        bootstrap_intent = load_private_input(
            private_root=private_root,
            name=args.bootstrap_intent_name,
        )
        foundation_publish_binding = load_private_input(
            private_root=private_root,
            name=args.foundation_publish_binding_name,
        )
        handoff = attest_broker_signed_artifact(
            source_root=source_root,
            source_commit=args.source_commit,
            aws_profile=args.aws_profile,
            expected_account_id=args.expected_account_id,
            region=args.region,
            unsigned_bucket=args.unsigned_bucket,
            unsigned_key=args.unsigned_key,
            unsigned_version=args.unsigned_version,
            signing_job_id=args.signing_job_id,
            signed_version=args.signed_version,
            pep_signed_artifact_receipt=pep_receipt,
            bootstrap_intent=bootstrap_intent,
            foundation_publish_binding=foundation_publish_binding,
        )
        destination = write_private_handoff(
            private_root=private_root,
            output_name=args.output_name,
            handoff=handoff,
        )
        summary = {
            "record_type": handoff["record_type"],
            "source_commit": handoff["source_commit"],
            "output_name": destination.name,
            "handoff_digest": handoff["handoff_digest"],
            "aws_calls": handoff["aws_calls"],
            "aws_mutations": 0,
            "deployment_authorized": False,
            "production_status": "NO-GO",
        }
        sys.stdout.write(canonical_json(summary) + "\n")
        return 0
    except (BrokerSeedError, BrokerSignedArtifactError) as exc:
        sys.stderr.write(canonical_json({"error": exc.code}) + "\n")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
