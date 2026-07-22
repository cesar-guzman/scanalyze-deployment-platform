#!/usr/bin/env python3
"""Two-phase, read-only-verifiable GUG-221 Change Set handoff."""

from __future__ import annotations

import argparse
from pathlib import Path
import sys
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tooling.platform_authority_lambda_audit_repair_change_set import (  # noqa: E402
    DELEGATION_TEMPLATE_PATH,
    EXPECTED_MANAGEMENT_PROFILE,
    EXPECTED_PROFILE,
    REGION,
    TEMPLATE_PATH,
    ChangeSetHandoffError,
    _reviewed_template_bytes,
    build_delegation_parameter_handoff,
    collect_gug220_live_evidence_read_only,
    prepare_pep_parameter_handoff,
    read_private_json,
    readback_delegation_live,
    verify_delegation_change_set_read_only,
    verify_pep_change_set_read_only,
    write_private_json,
)
from tooling.platform_authority_lambda_audit_repair_package import canonical_json  # noqa: E402


def _chain_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--deployment-contract", required=True, type=Path)
    parser.add_argument("--gug220-intent", required=True, type=Path)
    parser.add_argument("--gug220-ledger", required=True, type=Path)
    parser.add_argument("--gug220-receipt", required=True, type=Path)


def _profiles(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--authority-profile", required=True, choices=(EXPECTED_PROFILE,))
    parser.add_argument(
        "--management-profile", required=True, choices=(EXPECTED_MANAGEMENT_PROFILE,)
    )
    parser.add_argument("--region", default=REGION, choices=(REGION,))


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Derive and verify the two strictly ordered GUG-221 CREATE Change Sets; "
            "this tool exposes no mutation operation"
        )
    )
    commands = parser.add_subparsers(dest="command", required=True)

    phase_a_prepare = commands.add_parser(
        "prepare-delegation",
        help="fresh-read GUG-220 and derive only the 10 Phase A parameters",
    )
    _profiles(phase_a_prepare)
    _chain_arguments(phase_a_prepare)
    phase_a_prepare.add_argument("--output-gug220-evidence", required=True, type=Path)
    phase_a_prepare.add_argument("--output-parameters", required=True, type=Path)

    phase_a_verify = commands.add_parser(
        "verify-delegation", help="verify the already-created Phase A Change Set"
    )
    _profiles(phase_a_verify)
    _chain_arguments(phase_a_verify)
    phase_a_verify.add_argument("--gug220-evidence", required=True, type=Path)
    phase_a_verify.add_argument("--parameter-handoff", required=True, type=Path)
    phase_a_verify.add_argument("--change-set-arn", required=True)
    phase_a_verify.add_argument("--output-receipt", required=True, type=Path)

    phase_a_live = commands.add_parser(
        "readback-delegation",
        help="prove the separately executed Phase A stack and effective identities",
    )
    _profiles(phase_a_live)
    _chain_arguments(phase_a_live)
    phase_a_live.add_argument("--gug220-evidence", required=True, type=Path)
    phase_a_live.add_argument("--parameter-handoff", required=True, type=Path)
    phase_a_live.add_argument(
        "--delegation-change-set-receipt", required=True, type=Path
    )
    phase_a_live.add_argument(
        "--output-execution-receipt", required=True, type=Path
    )
    phase_a_live.add_argument("--output-live-receipt", required=True, type=Path)

    phase_b_prepare = commands.add_parser(
        "prepare-pep", help="derive Phase B only after a valid Phase A live receipt"
    )
    _chain_arguments(phase_b_prepare)
    phase_b_prepare.add_argument("--gug220-evidence", required=True, type=Path)
    phase_b_prepare.add_argument("--signed-receipt", required=True, type=Path)
    phase_b_prepare.add_argument("--delegation-live-receipt", required=True, type=Path)
    phase_b_prepare.add_argument("--output-parameters", required=True, type=Path)

    phase_b_verify = commands.add_parser(
        "verify-pep",
        help="fresh-read artifacts and Phase A state, then verify the Phase B Change Set",
    )
    _profiles(phase_b_verify)
    _chain_arguments(phase_b_verify)
    phase_b_verify.add_argument("--gug220-evidence", required=True, type=Path)
    phase_b_verify.add_argument("--signed-receipt", required=True, type=Path)
    phase_b_verify.add_argument("--delegation-parameter-handoff", required=True, type=Path)
    phase_b_verify.add_argument("--delegation-live-receipt", required=True, type=Path)
    phase_b_verify.add_argument("--pep-parameter-handoff", required=True, type=Path)
    phase_b_verify.add_argument("--change-set-arn", required=True)
    phase_b_verify.add_argument("--output-receipt", required=True, type=Path)
    return parser.parse_args()


def _aws_clients(args: argparse.Namespace) -> tuple[dict[str, Any], dict[str, Any]]:
    try:
        import boto3
        from botocore.config import Config
    except ImportError as exc:
        raise ChangeSetHandoffError("AWS_SDK_UNAVAILABLE") from exc
    config = Config(
        connect_timeout=3,
        read_timeout=8,
        retries={"total_max_attempts": 1, "mode": "standard"},
    )
    authority_session = boto3.Session(
        profile_name=args.authority_profile, region_name=args.region
    )
    management_session = boto3.Session(
        profile_name=args.management_profile, region_name=args.region
    )
    authority = {
        service: authority_session.client(service, config=config)
        for service in ("sts", "iam", "cloudformation", "cloudtrail", "signer", "s3")
    }
    management = {
        service: management_session.client(service, config=config)
        for service in (
            "sts",
            "sso-admin",
            "identitystore",
            "kms",
            "organizations",
            "iam",
            "cloudformation",
            "cloudtrail",
        )
    }
    return authority, management


def _read_chain(args: argparse.Namespace) -> tuple[dict, dict, dict, dict]:
    return tuple(  # type: ignore[return-value]
        dict(read_private_json(path, source_root=ROOT))
        for path in (
            args.deployment_contract,
            args.gug220_intent,
            args.gug220_ledger,
            args.gug220_receipt,
        )
    )


def _fresh_evidence(
    args: argparse.Namespace,
    *,
    contract: dict,
    intent: dict,
    ledger: dict,
    receipt: dict,
    authority: dict[str, Any],
    management: dict[str, Any],
) -> dict:
    return dict(
        collect_gug220_live_evidence_read_only(
            source_root=ROOT,
            deployment_contract=contract,
            gug220_intent=intent,
            gug220_ledger=ledger,
            gug220_receipt=receipt,
            management_profile_name=args.management_profile,
            authority_profile_name=args.authority_profile,
            region=args.region,
            management_sts_client=management["sts"],
            management_sso_admin_client=management["sso-admin"],
            management_identitystore_client=management["identitystore"],
            management_kms_client=management["kms"],
            management_organizations_client=management["organizations"],
            authority_sts_client=authority["sts"],
            authority_iam_client=authority["iam"],
        )
    )


def main() -> int:
    args = parse_args()
    try:
        contract, intent, ledger, receipt = _read_chain(args)
        if args.command == "prepare-pep":
            handoff = prepare_pep_parameter_handoff(
                source_root=ROOT,
                signed_receipt_path=args.signed_receipt,
                delegation_live_receipt_path=args.delegation_live_receipt,
                deployment_contract_path=args.deployment_contract,
                gug220_intent_path=args.gug220_intent,
                gug220_ledger_path=args.gug220_ledger,
                gug220_receipt_path=args.gug220_receipt,
                gug220_evidence_path=args.gug220_evidence,
                output_path=args.output_parameters,
            )
            result = {
                "phase": "B_PEP_PARAMETERS",
                "parameter_count": len(handoff["parameters"]),
                "authority_status": handoff["authority_status"],
                "production_status": handoff["production_status"],
            }
        else:
            authority, management = _aws_clients(args)
            if args.command == "prepare-delegation":
                evidence = _fresh_evidence(
                    args,
                    contract=contract,
                    intent=intent,
                    ledger=ledger,
                    receipt=receipt,
                    authority=authority,
                    management=management,
                )
                template = _reviewed_template_bytes(
                    source_root=ROOT,
                    source_commit=contract["source_commit"],
                    template_path=DELEGATION_TEMPLATE_PATH,
                )
                handoff = build_delegation_parameter_handoff(
                    source_root=ROOT,
                    deployment_contract=contract,
                    gug220_intent=intent,
                    gug220_ledger=ledger,
                    gug220_receipt=receipt,
                    gug220_evidence=evidence,
                    delegation_template_bytes=template,
                )
                write_private_json(
                    value=evidence,
                    output_path=args.output_gug220_evidence,
                    source_root=ROOT,
                )
                write_private_json(
                    value=handoff,
                    output_path=args.output_parameters,
                    source_root=ROOT,
                )
                result = {
                    "phase": "A_DELEGATION_PARAMETERS",
                    "parameter_count": len(handoff["parameters"]),
                    "evidence_status": evidence["evidence_status"],
                    "production_status": "NO-GO",
                }
            else:
                evidence = dict(read_private_json(args.gug220_evidence, source_root=ROOT))
                delegation_handoff = dict(
                    read_private_json(args.parameter_handoff, source_root=ROOT)
                ) if args.command != "verify-pep" else dict(
                    read_private_json(args.delegation_parameter_handoff, source_root=ROOT)
                )
                delegation_template = _reviewed_template_bytes(
                    source_root=ROOT,
                    source_commit=contract["source_commit"],
                    template_path=DELEGATION_TEMPLATE_PATH,
                )
                common = {
                    "source_root": ROOT,
                    "profile_name": args.management_profile,
                    "authority_profile_name": args.authority_profile,
                    "region": args.region,
                    "deployment_contract": contract,
                    "gug220_intent": intent,
                    "gug220_ledger": ledger,
                    "gug220_receipt": receipt,
                    "gug220_evidence": evidence,
                    "reviewed_template_bytes": delegation_template,
                    "sts_client": management["sts"],
                    "management_sso_admin_client": management["sso-admin"],
                    "management_identitystore_client": management["identitystore"],
                    "management_kms_client": management["kms"],
                    "management_organizations_client": management["organizations"],
                    "authority_sts_client": authority["sts"],
                    "authority_iam_client": authority["iam"],
                }
                if args.command == "verify-delegation":
                    result_receipt = verify_delegation_change_set_read_only(
                        **common,
                        change_set_arn=args.change_set_arn,
                        parameter_handoff=delegation_handoff,
                        cloudformation_client=management["cloudformation"],
                        cloudtrail_client=management["cloudtrail"],
                    )
                    output = args.output_receipt
                elif args.command == "readback-delegation":
                    if (
                        args.output_execution_receipt.resolve()
                        == args.output_live_receipt.resolve()
                    ):
                        raise ChangeSetHandoffError(
                            "DELEGATION_RECEIPT_OUTPUT_PATHS_MUST_DIFFER"
                        )
                    delegation_change_set_receipt = dict(
                        read_private_json(
                            args.delegation_change_set_receipt,
                            source_root=ROOT,
                        )
                    )
                    result_receipt = readback_delegation_live(
                        source_root=ROOT,
                        profile_name=args.management_profile,
                        authority_profile_name=args.authority_profile,
                        region=args.region,
                        deployment_contract=contract,
                        gug220_intent=intent,
                        gug220_ledger=ledger,
                        gug220_receipt=receipt,
                        gug220_evidence=evidence,
                        delegation_handoff=delegation_handoff,
                        delegation_change_set_receipt=(
                            delegation_change_set_receipt
                        ),
                        reviewed_template_bytes=delegation_template,
                        sts_client=management["sts"],
                        cloudformation_client=management["cloudformation"],
                        cloudtrail_client=management["cloudtrail"],
                        sso_admin_client=management["sso-admin"],
                        identitystore_client=management["identitystore"],
                        kms_client=management["kms"],
                        organizations_client=management["organizations"],
                        iam_client=management["iam"],
                        authority_sts_client=authority["sts"],
                        authority_iam_client=authority["iam"],
                    )
                    write_private_json(
                        value=result_receipt["delegation_execution_receipt"],
                        output_path=args.output_execution_receipt,
                        source_root=ROOT,
                    )
                    output = args.output_live_receipt
                else:
                    local_signed = dict(
                        read_private_json(args.signed_receipt, source_root=ROOT)
                    )
                    live = dict(
                        read_private_json(args.delegation_live_receipt, source_root=ROOT)
                    )
                    pep_handoff = dict(
                        read_private_json(args.pep_parameter_handoff, source_root=ROOT)
                    )
                    pep_template = _reviewed_template_bytes(
                        source_root=ROOT,
                        source_commit=local_signed["source_commit"],
                        template_path=TEMPLATE_PATH,
                    )
                    result_receipt = verify_pep_change_set_read_only(
                        source_root=ROOT,
                        profile_name=args.authority_profile,
                        management_profile_name=args.management_profile,
                        region=args.region,
                        change_set_arn=args.change_set_arn,
                        signed_receipt=local_signed,
                        deployment_contract=contract,
                        gug220_intent=intent,
                        gug220_ledger=ledger,
                        gug220_receipt=receipt,
                        gug220_evidence=evidence,
                        delegation_handoff=delegation_handoff,
                        delegation_live_receipt=live,
                        pep_handoff=pep_handoff,
                        reviewed_template_bytes=pep_template,
                        reviewed_delegation_template_bytes=delegation_template,
                        authority_sts_client=authority["sts"],
                        authority_signer_client=authority["signer"],
                        authority_s3_client=authority["s3"],
                        authority_cloudformation_client=authority["cloudformation"],
                        authority_cloudtrail_client=authority["cloudtrail"],
                        management_sts_client=management["sts"],
                        management_cloudformation_client=management["cloudformation"],
                        management_cloudtrail_client=management["cloudtrail"],
                        management_sso_admin_client=management["sso-admin"],
                        management_identitystore_client=management["identitystore"],
                        management_kms_client=management["kms"],
                        management_organizations_client=management["organizations"],
                        management_iam_client=management["iam"],
                        authority_iam_client=authority["iam"],
                    )
                    output = args.output_receipt
                write_private_json(value=result_receipt, output_path=output, source_root=ROOT)
                result = {
                    "phase": result_receipt["phase"],
                    "evidence_status": result_receipt["evidence_status"],
                    "authority_status": result_receipt["authority_status"],
                    "production_status": result_receipt["production_status"],
                }
    except (OSError, ValueError) as exc:
        print(f"GUG221_CHANGE_SET_BLOCKED:{exc}", file=sys.stderr)
        return 2
    print(canonical_json(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
