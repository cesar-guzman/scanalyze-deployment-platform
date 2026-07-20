"""Lambda Function URL entrypoint for the GUG-217 proof-only PEP."""
from __future__ import annotations

import json
import os
from datetime import UTC, datetime
from typing import Any, Mapping

from tooling.platform_authority_change_set_retirement_broker import (
    BotoClients,
    BrokerConfig,
    BrokerError,
    RetirementBroker,
    _alias_from_context,
)
from tooling.platform_authority_identity_context_pep import (
    IdentityContextPep,
    IdentityContextPepBinding,
    IdentityContextProofVerifier,
    ProofBoundaryError,
)


def _required(env: Mapping[str, str], name: str) -> str:
    value = env.get(name)
    if not isinstance(value, str) or not value:
        raise ProofBoundaryError("CONFIGURATION_INCOMPLETE")
    return value


def binding_from_environment(
    broker_config: BrokerConfig,
    env: Mapping[str, str] | None = None,
) -> IdentityContextPepBinding:
    source = os.environ if env is None else env
    return IdentityContextPepBinding(
        authority_account_id=broker_config.authority_account_id,
        region=broker_config.region,
        identity_center_application_arn=broker_config.identity_center_application_arn,
        identity_center_instance_arn=broker_config.identity_center_instance_arn,
        identity_store_arn=broker_config.identity_store_arn,
        redirect_uri=_required(source, "IDENTITY_CENTER_REDIRECT_URI"),
        broker_execution_role_arn=broker_config.execution_role_arn,
        classifier_user_id=broker_config.classifier_identity_store_user_id,
        approver_user_id=broker_config.approver_identity_store_user_id,
        classifier_proof_role_arn=broker_config.classifier_proof_role_arn,
        approver_proof_role_arn=broker_config.approver_proof_role_arn,
    )


def _response(status_code: int, value: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "statusCode": status_code,
        "headers": {
            "cache-control": "no-store",
            "content-type": "application/json",
            "pragma": "no-cache",
            "x-content-type-options": "nosniff",
        },
        "isBase64Encoded": False,
        "body": json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ),
    }


def handler(event: object, context: object) -> dict[str, Any]:
    """Verify one human proof and execute one synchronous broker operation."""

    try:
        config = BrokerConfig.from_environment()
        binding = binding_from_environment(config)
        clients = BotoClients.create(config.region)
        pep = IdentityContextPep(
            verifier=IdentityContextProofVerifier(
                oidc_client=clients.sso_oidc,
                sts_client=clients.sts,
                clock=lambda: datetime.now(tz=UTC),
            ),
            broker=RetirementBroker(config=config, clients=clients),
        )
        result = pep.execute(
            alias=_alias_from_context(context),
            event=event,
            binding=binding,
            now=datetime.now(tz=UTC),
        )
        return _response(200, result)
    except (ProofBoundaryError, BrokerError) as exc:
        return _response(403, {"status": "DENY", "reason_code": exc.code})
    except Exception:
        return _response(
            500,
            {"status": "DENY", "reason_code": "IDENTITY_CONTEXT_PEP_INTERNAL_ERROR"},
        )
