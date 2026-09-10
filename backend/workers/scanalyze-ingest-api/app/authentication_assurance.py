"""Authentication Assurance (WebAuthn/Passkeys) Adapter.

Implements native passkey authentication against Cognito User Pools using
InitiateAuth(USER_AUTH) -> RespondToAuthChallenge(WEB_AUTHN).
"""

from typing import Any, Dict, Optional
import boto3
from fastapi import APIRouter, Depends, HTTPException, Header, Request
from pydantic import BaseModel

from .config import get_settings
from .errors import AppError
from .logging import get_logger
from .auth import AuthContext, get_auth_context

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

router = APIRouter(prefix="/auth/passkey", tags=["auth"])

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
            return RespondToAuthChallengeResponse(
                access_token=auth_result.get("AccessToken"),
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
