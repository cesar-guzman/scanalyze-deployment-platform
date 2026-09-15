"""Explicit, one-attempt KMS adapter for the release VSA signing port.

No client is created and no cloud request occurs on import. Authority pins must
be delivered by the protected caller; this module installs no signing grant.
"""
from __future__ import annotations

import base64
from copy import deepcopy
import hashlib
import json
import re
from threading import Lock

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from tooling import release_policy_gate as gate
from tooling.release_vsa_producer import SigningRequest

ACCOUNT_ID = "042360977644"
REGION = "us-east-1"
AUTHORITY_FIELDS = {"schema_version", "account_id", "region", "key_arn", "caller_role_arn",
                    "caller_role_id", "signer_digest", "public_jwk_digest"}
SIGNER_FIELDS = {"key_id", "issuer", "identity", "public_key_jwk"}
SHA256 = re.compile(r"sha256:[a-f0-9]{64}\Z")
KEY_ARN = re.compile(r"arn:aws:kms:us-east-1:042360977644:key/"
                     r"(?!00000000-0000-0000-0000-000000000000$)[a-f0-9]{8}-(?:[a-f0-9]{4}-){3}[a-f0-9]{12}\Z")
ROLE_ARN = re.compile(r"arn:aws:iam::042360977644:role/(?:[A-Za-z0-9_+=,.@-]+/)*[A-Za-z0-9_+=,.@-]{1,64}\Z")


class KMSSigningRejected(ValueError):
    """Fixed failure codes without AWS exception, credential or payload details."""


def _require(value: bool, code: str) -> None:
    if not value:
        raise KMSSigningRejected(code)


def _pin(document: dict, expected: str) -> None:
    _require(isinstance(expected, str) and SHA256.fullmatch(expected) is not None
             and gate.canonical_digest(document) == expected, "KMS_EXTERNAL_PIN_MISMATCH")


def public_key_jwk(der_bytes: bytes) -> dict[str, str]:
    """Convert public SPKI bytes to the gate's exact P-256 JWK; no file/network I/O."""
    try:
        _require(type(der_bytes) is bytes, "KMS_PUBLIC_KEY_INVALID")
        public = serialization.load_der_public_key(der_bytes)
        _require(isinstance(public, ec.EllipticCurvePublicKey) and isinstance(public.curve, ec.SECP256R1),
                 "KMS_PUBLIC_KEY_INVALID")
        _require(public.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
                 == der_bytes, "KMS_PUBLIC_KEY_INVALID")
        numbers = public.public_numbers()
        return {"kty": "EC", "crv": "P-256", **{
            field: base64.urlsafe_b64encode(getattr(numbers, field).to_bytes(32, "big")).decode("ascii").rstrip("=")
            for field in ("x", "y")}}
    except KMSSigningRejected:
        raise
    except Exception:
        raise KMSSigningRejected("KMS_PUBLIC_KEY_INVALID") from None


def _configuration(client, service: str) -> None:
    from botocore.client import BaseClient
    _require(isinstance(client, BaseClient), "KMS_SDK_CLIENT_REQUIRED")
    meta = client.meta
    expected_endpoint = f"https://{service}.{REGION}.amazonaws.com"
    _require(meta.service_model.service_name == service and meta.region_name == REGION
             and meta.endpoint_url == expected_endpoint and client._endpoint.host == expected_endpoint
             and client._endpoint.http_session._verify is True,
             "KMS_CLIENT_SCOPE_MISMATCH")
    config = meta.config
    _require(config.region_name == REGION and config.signature_version == "v4"
             and config.retries == {"total_max_attempts": 1, "mode": "standard"}
             and config.proxies == {} and config.use_fips_endpoint in (False, None)
             and config.use_dualstack_endpoint in (False, None)
             and config.ignore_configured_endpoint_urls in (True, None), "KMS_CLIENT_CONFIGURATION_REJECTED")
    # Botocore consumes endpoint-resolution flags and normalizes them to None
    # on ClientMeta. The effective HTTPS endpoint is checked independently above.


def _authority(authority: dict, signer: dict, expected_digest: str) -> None:
    _require(type(authority) is dict and set(authority) == AUTHORITY_FIELDS
             and authority["schema_version"] == "release-vsa-kms-authority.v1"
             and authority["account_id"] == ACCOUNT_ID and authority["region"] == REGION,
             "KMS_AUTHORITY_INVALID")
    _pin(authority, expected_digest)
    _require(type(authority["key_arn"]) is str and KEY_ARN.fullmatch(authority["key_arn"]) is not None
             and type(authority["caller_role_arn"]) is str and ROLE_ARN.fullmatch(authority["caller_role_arn"]) is not None
             and type(authority["caller_role_id"]) is str
             and re.fullmatch(r"AROA[A-Z0-9]{17}", authority["caller_role_id"]) is not None,
             "KMS_AUTHORITY_IDENTITY_INVALID")
    _require(type(signer) is dict and set(signer) == SIGNER_FIELDS, "KMS_SIGNER_INVALID")
    _pin(signer, authority["signer_digest"])
    metadata = {"algorithm": "ECDSA_P256_SHA256", **{field: signer[field] for field in ("key_id", "issuer", "identity")}}
    _require(not gate._signing_input_schema_errors(metadata, "signature")
             and all(type(signer[field]) is str and signer[field] for field in ("key_id", "issuer", "identity")),
             "KMS_SIGNER_INVALID")
    jwk = signer["public_key_jwk"]
    _require(type(jwk) is dict and set(jwk) == {"kty", "crv", "x", "y"}
             and jwk["kty"] == "EC" and jwk["crv"] == "P-256"
             and all(type(jwk[field]) is str and re.fullmatch(r"[A-Za-z0-9_-]{43}", jwk[field]) is not None
                     for field in ("x", "y")), "KMS_PUBLIC_KEY_INVALID")
    _pin(jwk, authority["public_jwk_digest"])
    public = ec.EllipticCurvePublicNumbers(
        int.from_bytes(gate._b64url_decode(jwk["x"]), "big"),
        int.from_bytes(gate._b64url_decode(jwk["y"]), "big"), ec.SECP256R1()).public_key()
    _require(public_key_jwk(public.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo))
             == jwk, "KMS_PUBLIC_KEY_INVALID")


class KmsSigningClient:
    """One Sign attempt per instance; failure is never retried automatically.

    The caller owns SDK client integrity and authorization custody. Metadata
    checks do not protect against malicious Python code injected as an SDK hook.
    """

    def __init__(self, *, kms_client, sts_client, authority: dict,
                 expected_authority_digest: str, approved_signer: dict):
        try:
            authority, approved_signer = deepcopy((authority, approved_signer))
            _authority(authority, approved_signer, expected_authority_digest)
            self._authority_bytes = gate.canonical_bytes(authority)
            self._signer_bytes = gate.canonical_bytes(approved_signer)
            self._kms, self._sts = kms_client, sts_client
            self._credential_custody = self._kms._request_signer._credentials
            self._check_clients()
            self._attempted = False
            self._lock = Lock()
        except KMSSigningRejected:
            raise
        except Exception:
            raise KMSSigningRejected("KMS_ADAPTER_CONFIGURATION_REJECTED") from None

    def _check_clients(self) -> None:
        _configuration(self._kms, "kms")
        _configuration(self._sts, "sts")
        # Object identity only: never inspect, serialize or log credential fields.
        _require(self._credential_custody is not None
                 and self._kms._request_signer._credentials is self._credential_custody
                 and self._sts._request_signer._credentials is self._credential_custody,
                 "KMS_CLIENT_CREDENTIAL_CUSTODY_MISMATCH")

    def sign(self, request: SigningRequest) -> dict[str, str]:
        with self._lock:
            try:
                _require(not self._attempted, "KMS_SIGN_ALREADY_ATTEMPTED")
                _require(type(request) is SigningRequest and type(request.statement_bytes) is bytes,
                         "KMS_SIGNING_REQUEST_INVALID")
                authority, signer = json.loads(self._authority_bytes), json.loads(self._signer_bytes)
                payload = request.statement_bytes
                statement = json.loads(payload)
                _require(type(statement) is dict and gate.canonical_bytes(statement) == payload
                         and not gate._signing_input_schema_errors(statement, "statement"),
                         "KMS_STATEMENT_NOT_CANONICAL")
                metadata = {"algorithm": "ECDSA_P256_SHA256", **{
                    field: signer[field] for field in ("key_id", "issuer", "identity")}}
                _require(all(getattr(request, field) == value for field, value in metadata.items()),
                         "KMS_SIGNING_REQUEST_IDENTITY_MISMATCH")
                self._check_clients()
                caller = self._sts.get_caller_identity()
                role = authority["caller_role_arn"].rsplit("/", 1)[1]
                session_prefix = f"arn:aws:sts::{ACCOUNT_ID}:assumed-role/{role}/"
                arn = caller.get("Arn")
                _require(type(arn) is str and arn.startswith(session_prefix), "KMS_CALLER_IDENTITY_MISMATCH")
                session = arn[len(session_prefix):]
                _require(re.fullmatch(r"[A-Za-z0-9_+=,.@-]{2,64}", session) is not None
                         and caller.get("Account") == ACCOUNT_ID
                         and caller.get("UserId") == authority["caller_role_id"] + ":" + session,
                         "KMS_CALLER_IDENTITY_MISMATCH")
                key_arn = authority["key_arn"]
                key = self._kms.describe_key(KeyId=key_arn)["KeyMetadata"]
                _require(key.get("Arn") == key_arn and key.get("KeyId") == key_arn.rsplit("/", 1)[1]
                         and key.get("AWSAccountId") == ACCOUNT_ID and key.get("Enabled") is True
                         and key.get("KeyState") == "Enabled" and key.get("KeyManager") == "CUSTOMER"
                         and key.get("Origin") == "AWS_KMS" and key.get("MultiRegion") is False
                         and key.get("KeySpec") == "ECC_NIST_P256" and key.get("KeyUsage") == "SIGN_VERIFY"
                         and key.get("SigningAlgorithms") == ["ECDSA_SHA_256"], "KMS_KEY_METADATA_MISMATCH")
                public = self._kms.get_public_key(KeyId=key_arn)
                _require(public.get("KeyId") == key_arn and public.get("KeySpec") == "ECC_NIST_P256"
                         and public.get("CustomerMasterKeySpec", "ECC_NIST_P256") == "ECC_NIST_P256"
                         and public.get("KeyUsage") == "SIGN_VERIFY"
                         and public.get("SigningAlgorithms") == ["ECDSA_SHA_256"], "KMS_PUBLIC_KEY_METADATA_MISMATCH")
                public_der = public["PublicKey"]
                jwk = public_key_jwk(public_der)
                _pin(jwk, authority["public_jwk_digest"])
                _require(jwk == signer["public_key_jwk"], "KMS_PUBLIC_KEY_MISMATCH")
                approved_public = serialization.load_der_public_key(public_der)
                # Re-check unchanged transport immediately before the sole write.
                self._check_clients()
                message_digest = hashlib.sha256(payload).digest()
                self._attempted = True
                response = self._kms.sign(KeyId=key_arn, Message=message_digest,
                                          MessageType="DIGEST", SigningAlgorithm="ECDSA_SHA_256")
                _require(response.get("KeyId") == key_arn and response.get("SigningAlgorithm") == "ECDSA_SHA_256"
                         and type(response.get("Signature")) is bytes, "KMS_SIGNATURE_RESPONSE_MISMATCH")
                signature = response["Signature"]
                approved_public.verify(signature, payload, ec.ECDSA(hashes.SHA256()))
                return {**metadata, "value": base64.b64encode(signature).decode("ascii")}
            except KMSSigningRejected:
                raise
            except Exception:
                raise KMSSigningRejected("KMS_SIGNING_FAILED") from None


def create_signing_client(*, profile_name: str, authority: dict, expected_authority_digest: str,
                          approved_signer: dict) -> KmsSigningClient:
    """Explicit SDK factory. Resolves the named SDK profile; performs no Sign.

    SDK credential resolution belongs to the caller's authenticated environment.
    No default profile, endpoint override, grant creation or automatic retry.
    """
    try:
        authority, signer = deepcopy((authority, approved_signer))
        _authority(authority, signer, expected_authority_digest)
        _require(type(profile_name) is str and re.fullmatch(r"[A-Za-z0-9_+=,.@-]{1,128}", profile_name) is not None,
                 "KMS_EXPLICIT_PROFILE_REQUIRED")
        import boto3
        from botocore.config import Config
        session = boto3.Session(profile_name=profile_name, region_name=REGION)
        config = Config(region_name=REGION, signature_version="v4", retries={"total_max_attempts": 1, "mode": "standard"},
                        proxies={}, use_fips_endpoint=False, use_dualstack_endpoint=False,
                        ignore_configured_endpoint_urls=True, connect_timeout=5, read_timeout=15)
        kms = session.client("kms", region_name=REGION, endpoint_url=f"https://kms.{REGION}.amazonaws.com", config=config, verify=True)
        sts = session.client("sts", region_name=REGION, endpoint_url=f"https://sts.{REGION}.amazonaws.com", config=config, verify=True)
        return KmsSigningClient(kms_client=kms, sts_client=sts, authority=authority,
                                expected_authority_digest=expected_authority_digest, approved_signer=signer)
    except KMSSigningRejected:
        raise
    except Exception:
        raise KMSSigningRejected("KMS_SDK_FACTORY_REJECTED") from None
