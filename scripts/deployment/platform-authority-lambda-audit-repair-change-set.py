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
    PHASE_B_PRECONDITION_TEMPLATE_PATH,
    REGION,
    TEMPLATE_PATH,
    ChangeSetHandoffError,
    _reviewed_template_bytes,
    build_phase_b_precondition_parameter_handoff,
    build_delegation_parameter_handoff,
    collect_gug220_live_evidence_read_only,
    prepare_pep_parameter_handoff,
    read_private_json,
    readback_delegation_live,
    readback_pep_execution_with_effective_state_read_only,
    verify_delegation_change_set_read_only,
    verify_phase_b_precondition_change_set_read_only,
    verify_pep_change_set_read_only,
    write_private_json,
    write_private_json_pair_atomic,
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


def _authority_profile(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--authority-profile", required=True, choices=(EXPECTED_PROFILE,))
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
    phase_b_prepare.add_argument(
        "--phase-b-identity-materialization-receipt",
        required=True,
        type=Path,
    )
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
    phase_b_verify.add_argument(
        "--phase-b-identity-materialization-receipt",
        required=True,
        type=Path,
    )
    phase_b_verify.add_argument("--pep-parameter-handoff", required=True, type=Path)
    phase_b_verify.add_argument("--change-set-arn", required=True)
    phase_b_verify.add_argument("--output-receipt", required=True, type=Path)

    phase_b_readback = commands.add_parser(
        "readback-pep",
        help=(
            "prove the separately executed Phase B stack using read-only "
            "CloudFormation and CloudTrail APIs"
        ),
    )
    _authority_profile(phase_b_readback)
    _chain_arguments(phase_b_readback)
    phase_b_readback.add_argument("--gug220-evidence", required=True, type=Path)
    phase_b_readback.add_argument("--signed-receipt", required=True, type=Path)
    phase_b_readback.add_argument(
        "--delegation-live-receipt", required=True, type=Path
    )
    phase_b_readback.add_argument(
        "--pep-parameter-handoff", required=True, type=Path
    )
    phase_b_readback.add_argument(
        "--pep-change-set-receipt", required=True, type=Path
    )
    phase_b_readback.add_argument(
        "--phase-b-identity-materialization-receipt",
        required=True,
        type=Path,
    )
    phase_b_readback.add_argument(
        "--phase-b-precondition-parameter-handoff",
        required=True,
        type=Path,
    )
    phase_b_readback.add_argument(
        "--phase-b-precondition-change-set-receipt",
        required=True,
        type=Path,
    )
    phase_b_readback.add_argument(
        "--broker-effect-receipt", required=True, type=Path
    )
    phase_b_readback.add_argument(
        "--output-cloudformation-trace-receipt", required=True, type=Path
    )
    phase_b_readback.add_argument(
        "--output-effective-state-receipt", required=True, type=Path
    )

    phase_b_precondition_prepare = commands.add_parser(
        "prepare-phase-b-precondition",
        help=(
            "derive PRE_B broker parameters only from identity materialization "
            "and the reviewed PEP Change Set receipt"
        ),
    )
    _chain_arguments(phase_b_precondition_prepare)
    phase_b_precondition_prepare.add_argument(
        "--signed-receipt", required=True, type=Path
    )
    phase_b_precondition_prepare.add_argument(
        "--phase-b-identity-materialization-receipt",
        required=True,
        type=Path,
    )
    phase_b_precondition_prepare.add_argument(
        "--pep-parameter-handoff", required=True, type=Path
    )
    phase_b_precondition_prepare.add_argument(
        "--pep-change-set-receipt", required=True, type=Path
    )
    phase_b_precondition_prepare.add_argument(
        "--output-parameters", required=True, type=Path
    )

    phase_b_precondition_verify = commands.add_parser(
        "verify-phase-b-precondition",
        help="verify the already-created PRE_B broker Change Set",
    )
    _authority_profile(phase_b_precondition_verify)
    _chain_arguments(phase_b_precondition_verify)
    phase_b_precondition_verify.add_argument(
        "--signed-receipt", required=True, type=Path
    )
    phase_b_precondition_verify.add_argument(
        "--phase-b-identity-materialization-receipt",
        required=True,
        type=Path,
    )
    phase_b_precondition_verify.add_argument(
        "--pep-parameter-handoff", required=True, type=Path
    )
    phase_b_precondition_verify.add_argument(
        "--pep-change-set-receipt", required=True, type=Path
    )
    phase_b_precondition_verify.add_argument(
        "--phase-b-precondition-parameter-handoff",
        required=True,
        type=Path,
    )
    phase_b_precondition_verify.add_argument("--change-set-arn", required=True)
    phase_b_precondition_verify.add_argument(
        "--output-receipt", required=True, type=Path
    )
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
    authority = {
        service: authority_session.client(service, config=config)
        for service in (
            "sts",
            "iam",
            "cloudformation",
            "cloudtrail",
            "signer",
            "s3",
            "lambda",
            "dynamodb",
            "kms",
            "logs",
        )
    }
    management: dict[str, Any] = {}
    if hasattr(args, "management_profile"):
        management_session = boto3.Session(
            profile_name=args.management_profile, region_name=args.region
        )
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


def _validate_readback_output_paths(
    cloudformation_trace_path: Path,
    effective_state_path: Path,
) -> None:
    if cloudformation_trace_path.resolve() == effective_state_path.resolve():
        raise ChangeSetHandoffError("PEP_READBACK_OUTPUT_PATHS_MUST_DIFFER")


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
                phase_b_identity_materialization_receipt_path=(
                    args.phase_b_identity_materialization_receipt
                ),
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
        elif args.command == "prepare-phase-b-precondition":
            signed = dict(
                read_private_json(args.signed_receipt, source_root=ROOT)
            )
            identity_materialization_receipt = dict(
                read_private_json(
                    args.phase_b_identity_materialization_receipt,
                    source_root=ROOT,
                )
            )
            pep_handoff = dict(
                read_private_json(
                    args.pep_parameter_handoff,
                    source_root=ROOT,
                )
            )
            pep_change_set_receipt = dict(
                read_private_json(
                    args.pep_change_set_receipt,
                    source_root=ROOT,
                )
            )
            precondition_template = _reviewed_template_bytes(
                source_root=ROOT,
                source_commit=str(signed["source_commit"]),
                template_path=PHASE_B_PRECONDITION_TEMPLATE_PATH,
            )
            handoff = build_phase_b_precondition_parameter_handoff(
                source_root=ROOT,
                signed_receipt=signed,
                deployment_contract=contract,
                phase_b_identity_materialization_receipt=(
                    identity_materialization_receipt
                ),
                pep_parameter_handoff=pep_handoff,
                pep_change_set_receipt=pep_change_set_receipt,
                reviewed_template_bytes=precondition_template,
            )
            write_private_json(
                value=handoff,
                output_path=args.output_parameters,
                source_root=ROOT,
            )
            result = {
                "phase": "PRE_B_BROKER_PARAMETERS",
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
            elif args.command == "verify-phase-b-precondition":
                signed = dict(
                    read_private_json(args.signed_receipt, source_root=ROOT)
                )
                identity_materialization_receipt = dict(
                    read_private_json(
                        args.phase_b_identity_materialization_receipt,
                        source_root=ROOT,
                    )
                )
                pep_handoff = dict(
                    read_private_json(
                        args.pep_parameter_handoff,
                        source_root=ROOT,
                    )
                )
                pep_change_set_receipt = dict(
                    read_private_json(
                        args.pep_change_set_receipt,
                        source_root=ROOT,
                    )
                )
                precondition_handoff = dict(
                    read_private_json(
                        args.phase_b_precondition_parameter_handoff,
                        source_root=ROOT,
                    )
                )
                precondition_template = _reviewed_template_bytes(
                    source_root=ROOT,
                    source_commit=str(signed["source_commit"]),
                    template_path=PHASE_B_PRECONDITION_TEMPLATE_PATH,
                )
                result_receipt = (
                    verify_phase_b_precondition_change_set_read_only(
                        source_root=ROOT,
                        profile_name=args.authority_profile,
                        region=args.region,
                        change_set_arn=args.change_set_arn,
                        parameter_handoff=precondition_handoff,
                        signed_receipt=signed,
                        deployment_contract=contract,
                        phase_b_identity_materialization_receipt=(
                            identity_materialization_receipt
                        ),
                        pep_parameter_handoff=pep_handoff,
                        pep_change_set_receipt=pep_change_set_receipt,
                        reviewed_template_bytes=precondition_template,
                        sts_client=authority["sts"],
                        cloudformation_client=authority["cloudformation"],
                        cloudtrail_client=authority["cloudtrail"],
                    )
                )
                write_private_json(
                    value=result_receipt,
                    output_path=args.output_receipt,
                    source_root=ROOT,
                )
                result = {
                    "phase": result_receipt["phase"],
                    "evidence_status": result_receipt["evidence_status"],
                    "production_status": result_receipt["production_status"],
                }
            else:
                evidence = dict(read_private_json(args.gug220_evidence, source_root=ROOT))
                if args.command == "verify-pep":
                    delegation_handoff = dict(
                        read_private_json(
                            args.delegation_parameter_handoff, source_root=ROOT
                        )
                    )
                elif args.command in ("verify-delegation", "readback-delegation"):
                    delegation_handoff = dict(
                        read_private_json(args.parameter_handoff, source_root=ROOT)
                    )
                else:
                    delegation_handoff = {}
                delegation_template = _reviewed_template_bytes(
                    source_root=ROOT,
                    source_commit=contract["source_commit"],
                    template_path=DELEGATION_TEMPLATE_PATH,
                )
                common = {}
                if args.command not in (
                    "readback-pep",
                    "verify-phase-b-precondition",
                ):
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
                        "management_identitystore_client": management[
                            "identitystore"
                        ],
                        "management_kms_client": management["kms"],
                        "management_organizations_client": management[
                            "organizations"
                        ],
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
                elif args.command == "verify-pep":
                    local_signed = dict(
                        read_private_json(args.signed_receipt, source_root=ROOT)
                    )
                    live = dict(
                        read_private_json(args.delegation_live_receipt, source_root=ROOT)
                    )
                    identity_materialization_receipt = dict(
                        read_private_json(
                            args.phase_b_identity_materialization_receipt,
                            source_root=ROOT,
                        )
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
                        phase_b_identity_materialization_receipt=(
                            identity_materialization_receipt
                        ),
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
                else:
                    local_signed = dict(
                        read_private_json(args.signed_receipt, source_root=ROOT)
                    )
                    live = dict(
                        read_private_json(
                            args.delegation_live_receipt, source_root=ROOT
                        )
                    )
                    identity_materialization_receipt = dict(
                        read_private_json(
                            args.phase_b_identity_materialization_receipt,
                            source_root=ROOT,
                        )
                    )
                    pep_handoff = dict(
                        read_private_json(
                            args.pep_parameter_handoff, source_root=ROOT
                        )
                    )
                    pep_change_set_receipt = dict(
                        read_private_json(
                            args.pep_change_set_receipt, source_root=ROOT
                        )
                    )
                    precondition_handoff = dict(
                        read_private_json(
                            args.phase_b_precondition_parameter_handoff,
                            source_root=ROOT,
                        )
                    )
                    precondition_change_set_receipt = dict(
                        read_private_json(
                            args.phase_b_precondition_change_set_receipt,
                            source_root=ROOT,
                        )
                    )
                    broker_effect_receipt = dict(
                        read_private_json(
                            args.broker_effect_receipt, source_root=ROOT
                        )
                    )
                    _validate_readback_output_paths(
                        args.output_cloudformation_trace_receipt,
                        args.output_effective_state_receipt,
                    )
                    pep_template = _reviewed_template_bytes(
                        source_root=ROOT,
                        source_commit=local_signed["source_commit"],
                        template_path=TEMPLATE_PATH,
                    )
                    precondition_template = _reviewed_template_bytes(
                        source_root=ROOT,
                        source_commit=local_signed["source_commit"],
                        template_path=PHASE_B_PRECONDITION_TEMPLATE_PATH,
                    )
                    chained_receipts = (
                        readback_pep_execution_with_effective_state_read_only(
                            source_root=ROOT,
                            profile_name=args.authority_profile,
                            region=args.region,
                            signed_receipt=local_signed,
                            deployment_contract=contract,
                            gug220_intent=intent,
                            gug220_ledger=ledger,
                            gug220_receipt=receipt,
                            gug220_evidence=evidence,
                            delegation_live_receipt=live,
                            phase_b_identity_materialization_receipt=(
                                identity_materialization_receipt
                            ),
                            pep_handoff=pep_handoff,
                            pep_change_set_receipt=pep_change_set_receipt,
                            phase_b_precondition_parameter_handoff=(
                                precondition_handoff
                            ),
                            phase_b_precondition_change_set_receipt=(
                                precondition_change_set_receipt
                            ),
                            broker_effect_receipt=broker_effect_receipt,
                            reviewed_template_bytes=pep_template,
                            reviewed_phase_b_precondition_template_bytes=(
                                precondition_template
                            ),
                            sts_client=authority["sts"],
                            cloudformation_client=authority["cloudformation"],
                            cloudtrail_client=authority["cloudtrail"],
                            iam_client=authority["iam"],
                            lambda_client=authority["lambda"],
                            dynamodb_client=authority["dynamodb"],
                            kms_client=authority["kms"],
                            logs_client=authority["logs"],
                        )
                    )
                    write_private_json_pair_atomic(
                        first_value=chained_receipts[
                            "cloudformation_trace_receipt"
                        ],
                        first_output_path=args.output_cloudformation_trace_receipt,
                        second_value=chained_receipts[
                            "effective_state_receipt"
                        ],
                        second_output_path=args.output_effective_state_receipt,
                        source_root=ROOT,
                    )
                    result_receipt = chained_receipts[
                        "effective_state_receipt"
                    ]
                    output = None
                if output is not None:
                    write_private_json(
                        value=result_receipt,
                        output_path=output,
                        source_root=ROOT,
                    )
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
