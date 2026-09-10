"""Authentication Assurance (WebAuthn/Passkeys) Adapter.

Implements native passkey authentication against Cognito User Pools using
InitiateAuth(USER_AUTH) -> RespondToAuthChallenge(WEB_AUTHN).
"""

from typing import Any, Dict, Optional
import time

import boto3
import jwt
from fastapi import APIRouter, Depends, HTTPException, Header, Request
from pydantic import BaseModel

from .config import get_settings
from .errors import AppError
from .logging import get_logger
from .auth import AuthContext, get_auth_context
from .aws_clients import dynamodb_resource

logger = get_logger()

# Boto3 client initialized lazily
_cognito_client = None

def get_cognito_client(settings: Any):
    global _cognito_client
    if _cognito_client is None:
        _cognito_client = boto3.client("cognito-idp", region_name=settings.cognito_region)
    return _cognito_client

class InitiateAuthRequest(BaseModel):
    username: str

class InitiateAuthResponse(BaseModel):
    challenge_name: str
    session: str
    challenge_parameters: Dict[str, str]

class RespondToAuthChallengeRequest(BaseModel):
    username: str
    session: str
    challenge_responses: Dict[str, str]

class RespondToAuthChallengeResponse(BaseModel):
    access_token: Optional[str] = None
    id_token: Optional[str] = None
    refresh_token: Optional[str] = None
    challenge_name: Optional[str] = None
    session: Optional[str] = None

router = APIRouter(prefix="/api/v1/auth/passkey", tags=["auth"])

@router.post("/initiate", response_model=InitiateAuthResponse)
def initiate_passkey_auth(
    req: InitiateAuthRequest,
    settings: Any = Depends(get_settings),
):
    client = get_cognito_client(settings)
    try:
        response = client.initiate_auth(
            AuthFlow="USER_AUTH",
            AuthParameters={
                "USERNAME": req.username,
            },
            ClientId=settings.cognito_client_id,
        )
        challenge_name = response.get("ChallengeName")
        if challenge_name != "WEB_AUTHN":
            logger.warning(
                "unexpected_challenge",
                challenge_name=challenge_name,
            )
            raise AppError(
                code="UNAUTHORIZED",
                message="Expected WEB_AUTHN challenge.",
                status_code=401,
                details={}
            )
        return InitiateAuthResponse(
            challenge_name=challenge_name,
            session=response.get("Session", ""),
            challenge_parameters=response.get("ChallengeParameters", {})
        )
    except client.exceptions.UserNotFoundException:
        raise AppError(
            code="UNAUTHORIZED",
            message="User not found",
            status_code=401,
            details={}
        )
    except client.exceptions.NotAuthorizedException:
        raise AppError(
            code="UNAUTHORIZED",
            message="Not authorized",
            status_code=401,
            details={}
        )
    except Exception as e:
        logger.error("initiate_auth_failed", error=str(e))
        raise AppError(
            code="INTERNAL_ERROR",
            message="Failed to initiate authentication",
            status_code=500,
            details={}
        )

@router.post("/respond", response_model=RespondToAuthChallengeResponse)
def respond_passkey_auth(
    req: RespondToAuthChallengeRequest,
    settings: Any = Depends(get_settings),
):
    client = get_cognito_client(settings)
    try:
        response = client.respond_to_auth_challenge(
            ClientId=settings.cognito_client_id,
            ChallengeName="WEB_AUTHN",
            Session=req.session,
            ChallengeResponses=req.challenge_responses
        )
        auth_result = response.get("AuthenticationResult")
        if auth_result:
            access_token = auth_result.get("AccessToken")
            
            # Decode token without verification to extract identity for binding
            # (Token comes directly from Cognito TLS connection, so it's trusted here)
            claims = jwt.decode(access_token, options={"verify_signature": False})
            jti = claims.get("jti")
            sub = claims.get("sub")
            auth_time = claims.get("auth_time", int(time.time()))
            customer_id = claims.get("custom:customerId")
            deployment_id = claims.get("custom:deployment_id")
            
            if not jti or not sub:
                logger.error("invalid_token_claims_from_provider")
                raise AppError(code="INTERNAL_ERROR", message="Invalid token claims", status_code=500, details={})

            ledger_table_name = getattr(settings, "operation_ledger_table_name", None)
            if ledger_table_name:
                table = dynamodb_resource().Table(ledger_table_name)
                # Persist durable audit event BEFORE returning the token (fail-closed)
                table.put_item(
                    Item={
                        "pk": f"AUTH_EVENT#{jti}",
                        "sk": "META",
                        "record_type": "scanalyze.platform_authority.authentication_event.v1",
                        "jti": jti,
                        "subject": sub,
                        "customer_id": customer_id,
                        "deployment_id": deployment_id,
                        "auth_time": auth_time,
                        "assurance": "phishing_resistant_mfa",
                        "assurance_source": "authoritative_authentication_event_v1",
                        "assurance_version": "phishing-resistant-mfa.v1",
                        "expires_at": auth_time + 300,
                        "created_at": int(time.time()),
                    },
                    ConditionExpression="attribute_not_exists(pk) AND attribute_not_exists(sk)"
                )
            else:
                logger.warning("missing_operation_ledger_table_name", reason="cannot_persist_auth_event")
                # Fail-closed: do not return token if we cannot persist the audit log
                raise AppError(code="INTERNAL_ERROR", message="Durable audit storage unavailable", status_code=500, details={})

            return RespondToAuthChallengeResponse(
                access_token=access_token,
                id_token=auth_result.get("IdToken"),
                refresh_token=auth_result.get("RefreshToken"),
            )
        else:
            return RespondToAuthChallengeResponse(
                challenge_name=response.get("ChallengeName"),
                session=response.get("Session")
            )
    except client.exceptions.NotAuthorizedException:
        raise AppError(
            code="UNAUTHORIZED",
            message="Invalid passkey response",
            status_code=401,
            details={}
        )
    except Exception as e:
        logger.error("respond_to_auth_challenge_failed", error=str(e))
        raise AppError(
            code="INTERNAL_ERROR",
            message="Failed to respond to auth challenge",
            status_code=500,
            details={}
        )
