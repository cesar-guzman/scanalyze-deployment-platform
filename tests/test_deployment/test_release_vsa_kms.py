"""No AWS calls: real SDK models/Stubber, ephemeral keys, real VSA gate."""
from copy import deepcopy
from dataclasses import replace
import hashlib
import importlib
import json
import socket
from concurrent.futures import ThreadPoolExecutor

import boto3
from botocore.config import Config
from botocore.stub import Stubber
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils
import pytest

from tests.test_deployment.test_release_vsa_producer import bundle as producer_bundle
from tooling import release_policy_gate as gate
from tooling import release_vsa_kms as adapter
from tooling import release_vsa_producer as producer

KEY_ARN = "arn:aws:kms:us-east-1:042360977644:key/00000000-0000-0000-0000-000000000009"
ROLE_ARN = "arn:aws:iam::042360977644:role/release/SyntheticVSASigner"
ROLE_ID = "AROA" + "A" * 17


@pytest.fixture
def bundle(monkeypatch):
    def no_network(*args, **kwargs):
        raise AssertionError("test attempted network")
    monkeypatch.setattr(socket, "socket", no_network)
    vsa = producer_bundle.__wrapped__()
    ephemeral = vsa["signing_client"]
    producer.produce_release_vsa(**vsa)
    request = ephemeral.requests[0]
    # Explicit unusable test credentials prevent any profile/cache/IMDS lookup.
    session = boto3.Session(
        **{
            "aws_access_key_id": "synthetic",
            "aws_secret_" + "access_key": "synthetic",
            "region_name": adapter.REGION,
        }
    )
    config = Config(region_name=adapter.REGION, signature_version="v4", retries={"total_max_attempts": 1, "mode": "standard"},
                    proxies={}, use_fips_endpoint=False, use_dualstack_endpoint=False, ignore_configured_endpoint_urls=True)
    clients = {service: session.client(service, region_name=adapter.REGION,
                                      endpoint_url=f"https://{service}.{adapter.REGION}.amazonaws.com", config=config)
               for service in ("kms", "sts")}
    calls = []
    for client in clients.values():
        client.meta.events.register("before-parameter-build.*.*", lambda model, **kwargs: calls.append(model.name))
    authority = {"schema_version": "release-vsa-kms-authority.v1", "account_id": adapter.ACCOUNT_ID,
                 "region": adapter.REGION, "key_arn": KEY_ARN, "caller_role_arn": ROLE_ARN,
                 "caller_role_id": ROLE_ID, "signer_digest": gate.canonical_digest(vsa["signer"]),
                 "public_jwk_digest": gate.canonical_digest(vsa["signer"]["public_key_jwk"])}
    der = ephemeral.key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return {"vsa": vsa, "private": ephemeral.key, "request": request, "session": session,
            "clients": clients, "calls": calls, "authority": authority,
            "expected_authority_digest": gate.canonical_digest(authority),
            "caller": {"Account": adapter.ACCOUNT_ID, "Arn": "arn:aws:sts::042360977644:assumed-role/SyntheticVSASigner/test-session",
                       "UserId": ROLE_ID + ":test-session"},
            "key": {"KeyMetadata": {"Arn": KEY_ARN, "KeyId": KEY_ARN.rsplit("/", 1)[1], "AWSAccountId": adapter.ACCOUNT_ID,
                                      "Enabled": True, "KeyState": "Enabled", "KeyManager": "CUSTOMER", "Origin": "AWS_KMS",
                                      "MultiRegion": False, "KeySpec": "ECC_NIST_P256", "KeyUsage": "SIGN_VERIFY",
                                      "SigningAlgorithms": ["ECDSA_SHA_256"]}},
            "public": {"KeyId": KEY_ARN, "PublicKey": der, "KeySpec": "ECC_NIST_P256", "CustomerMasterKeySpec": "ECC_NIST_P256",
                       "KeyUsage": "SIGN_VERIFY", "SigningAlgorithms": ["ECDSA_SHA_256"]}}


def client_for(bundle):
    return adapter.KmsSigningClient(kms_client=bundle["clients"]["kms"], sts_client=bundle["clients"]["sts"],
                                   authority=bundle["authority"], expected_authority_digest=bundle["expected_authority_digest"],
                                   approved_signer=bundle["vsa"]["signer"])


def signing_response(bundle, *, message=None, key=None):
    digest = hashlib.sha256(bundle["request"].statement_bytes if message is None else message).digest()
    signature = (key or bundle["private"]).sign(digest, ec.ECDSA(utils.Prehashed(hashes.SHA256())))
    return {"KeyId": KEY_ARN, "SigningAlgorithm": "ECDSA_SHA_256", "Signature": signature}


def stubs(bundle, response=None, sign_error=False):
    sts, kms = Stubber(bundle["clients"]["sts"]), Stubber(bundle["clients"]["kms"])
    sts.add_response("get_caller_identity", bundle["caller"], {})
    kms.add_response("describe_key", bundle["key"], {"KeyId": KEY_ARN})
    kms.add_response("get_public_key", bundle["public"], {"KeyId": KEY_ARN})
    params = {"KeyId": KEY_ARN, "Message": hashlib.sha256(bundle["request"].statement_bytes).digest(),
              "MessageType": "DIGEST", "SigningAlgorithm": "ECDSA_SHA_256"}
    if sign_error:
        kms.add_client_error("sign", service_error_code="AccessDeniedException", service_message="synthetic-sensitive-sentinel",
                             http_status_code=403, expected_params=params)
    else:
        kms.add_response("sign", response or signing_response(bundle), params)
    return sts, kms


def test_adapter_real_sdk_digest_signing_and_complete_vsa_gate(bundle):
    before = deepcopy((bundle["authority"], bundle["vsa"]["signer"]))
    client = client_for(bundle)
    assert bundle["calls"] == []
    sts, kms = stubs(bundle)
    with sts, kms:
        result = producer.produce_release_vsa(**{**bundle["vsa"], "signing_client": client})
        sts.assert_no_pending_responses()
        kms.assert_no_pending_responses()
    attestation = json.loads(result.attestation_bytes)
    assert gate.evaluate_release(bundle["vsa"]["manifest"], attestation, bundle["vsa"]["policy"],
                                 expected_policy_digest=bundle["vsa"]["pins"].policy_digest,
                                 evaluated_at=bundle["vsa"]["clock"]()).allowed
    assert bundle["calls"] == ["GetCallerIdentity", "DescribeKey", "GetPublicKey", "Sign"]
    assert (bundle["authority"], bundle["vsa"]["signer"]) == before


@pytest.mark.parametrize("field,value", [
    ("account_id", "111111111111"), ("region", "us-west-2"), ("key_arn", "alias/signing"),
    ("key_arn", KEY_ARN.replace("042360977644", "111111111111")),
    ("caller_role_arn", "arn:aws:iam::042360977644:root"), ("caller_role_id", "synthetic-role"),
    ("public_jwk_digest", "sha256:" + "0" * 64), ("signer_digest", "sha256:" + "0" * 64),
    ("extra", True),
])
def test_authority_invalid_even_when_reanchored_never_calls_aws(bundle, field, value):
    bundle["authority"][field] = value
    bundle["expected_authority_digest"] = gate.canonical_digest(bundle["authority"])
    with pytest.raises(adapter.KMSSigningRejected):
        client_for(bundle)
    assert bundle["calls"] == []


def test_cannot_replace_external_authority_pin_by_rehashing_changed_inputs(bundle):
    bundle["authority"]["key_arn"] = KEY_ARN[:-1] + "8"
    with pytest.raises(adapter.KMSSigningRejected, match="PIN_MISMATCH"):
        client_for(bundle)
    assert bundle["calls"] == []


@pytest.mark.parametrize("mode", ["issuer", "identity", "key_id", "algorithm", "noncanonical", "duplicate_key", "arbitrary_json", "wrong_type"])
def test_invalid_request_rejected_before_read_or_sign(bundle, mode):
    request = bundle["request"]
    if mode in {"issuer", "identity", "key_id", "algorithm"}:
        request = replace(request, **{mode: "foreign"})
    elif mode == "noncanonical": request = replace(request, statement_bytes=request.statement_bytes + b"\n")
    elif mode == "duplicate_key": request = replace(request, statement_bytes=b'{"x":1,"x":1}')
    elif mode == "arbitrary_json": request = replace(request, statement_bytes=b'{}')
    else: request = vars(request)
    with pytest.raises(adapter.KMSSigningRejected):
        client_for(bundle).sign(request)
    assert bundle["calls"] == []


@pytest.mark.parametrize("field,value", [
    ("Account", "111111111111"), ("Arn", "arn:aws:iam::042360977644:root"),
    ("Arn", "arn:aws:sts::042360977644:assumed-role/Administrator/test-session"),
    ("UserId", "AROA" + "B" * 17 + ":test-session"), ("UserId", ROLE_ID + ":different-session"),
])
def test_wrong_sts_account_role_or_role_id_stops_before_kms(bundle, field, value):
    bundle["caller"][field] = value
    sts, kms = stubs(bundle)
    with sts, kms, pytest.raises(adapter.KMSSigningRejected, match="CALLER_IDENTITY_MISMATCH"):
        client_for(bundle).sign(bundle["request"])
    assert bundle["calls"] == ["GetCallerIdentity"]


@pytest.mark.parametrize("field,value", [
    ("Arn", KEY_ARN[:-1] + "8"), ("AWSAccountId", "111111111111"), ("KeyId", "00000000-0000-0000-0000-000000000008"),
    ("Enabled", False), ("KeyState", "Disabled"), ("KeyManager", "AWS"), ("Origin", "EXTERNAL"),
    ("MultiRegion", True), ("KeySpec", "SYMMETRIC_DEFAULT"), ("KeyUsage", "ENCRYPT_DECRYPT"),
    ("SigningAlgorithms", ["ECDSA_SHA_384"]),
])
def test_wrong_key_metadata_stops_before_public_key_and_sign(bundle, field, value):
    bundle["key"]["KeyMetadata"][field] = value
    sts, kms = stubs(bundle)
    with sts, kms, pytest.raises(adapter.KMSSigningRejected, match="KEY_METADATA_MISMATCH"):
        client_for(bundle).sign(bundle["request"])
    assert bundle["calls"] == ["GetCallerIdentity", "DescribeKey"]


@pytest.mark.parametrize("mode", ["other_key", "wrong_curve", "bad_der", "key_id", "algorithm", "usage", "spec"])
def test_public_key_must_match_exact_approved_jwk_before_sign(bundle, mode):
    public = bundle["public"]
    if mode in {"other_key", "wrong_curve"}:
        key = ec.generate_private_key(ec.SECP256R1() if mode == "other_key" else ec.SECP384R1())
        public["PublicKey"] = key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    elif mode == "bad_der": public["PublicKey"] = b"not-der"
    elif mode == "key_id": public["KeyId"] = KEY_ARN[:-1] + "8"
    elif mode == "algorithm": public["SigningAlgorithms"] = ["ECDSA_SHA_384"]
    elif mode == "usage": public["KeyUsage"] = "ENCRYPT_DECRYPT"
    else: public["KeySpec"] = "ECC_NIST_P384"
    sts, kms = stubs(bundle)
    with sts, kms, pytest.raises(adapter.KMSSigningRejected):
        client_for(bundle).sign(bundle["request"])
    assert bundle["calls"] == ["GetCallerIdentity", "DescribeKey", "GetPublicKey"]


@pytest.mark.parametrize("mode", ["wrong_key", "wrong_payload", "double_hash", "invalid_der", "response_key", "response_algorithm", "denied"])
def test_sign_response_is_verified_and_never_retried(bundle, mode, capsys):
    response = signing_response(bundle)
    if mode == "wrong_key": response = signing_response(bundle, key=ec.generate_private_key(ec.SECP256R1()))
    elif mode == "wrong_payload": response = signing_response(bundle, message=b"different")
    elif mode == "double_hash": response = signing_response(bundle, message=hashlib.sha256(bundle["request"].statement_bytes).digest())
    elif mode == "invalid_der": response["Signature"] = b"not-der"
    elif mode == "response_key": response["KeyId"] = KEY_ARN[:-1] + "8"
    elif mode == "response_algorithm": response["SigningAlgorithm"] = "ECDSA_SHA_384"
    client = client_for(bundle)
    sts, kms = stubs(bundle, response=response, sign_error=mode == "denied")
    with sts, kms, pytest.raises(adapter.KMSSigningRejected) as failure:
        client.sign(bundle["request"])
    assert "synthetic-sensitive-sentinel" not in str(failure.value)
    with pytest.raises(adapter.KMSSigningRejected, match="SIGN_ALREADY_ATTEMPTED"):
        client.sign(bundle["request"])
    assert bundle["calls"].count("Sign") == 1
    assert capsys.readouterr() == ("", "")


@pytest.mark.parametrize("field,value", [
    ("region_name", "us-west-2"), ("endpoint_url", "https://unapproved.invalid"),
    ("retries", {"total_max_attempts": 2, "mode": "standard"}),
    ("proxies", {"https": "https://unapproved.invalid"}), ("use_fips_endpoint", True),
    ("ignore_configured_endpoint_urls", False),
])
def test_foreign_or_retrying_sdk_clients_rejected_before_read_or_sign(bundle, field, value):
    kms = bundle["clients"]["kms"]
    if field == "endpoint_url":
        kms._endpoint.host = value
    else:
        setattr(kms.meta.config, field, value)
    with pytest.raises(adapter.KMSSigningRejected): client_for(bundle)
    assert bundle["calls"] == []


def test_different_credential_custody_cannot_borrow_sts_identity(bundle):
    bundle["clients"]["kms"]._request_signer._credentials = object()
    with pytest.raises(adapter.KMSSigningRejected, match="CREDENTIAL_CUSTODY_MISMATCH"):
        client_for(bundle)
    assert bundle["calls"] == []


def test_mutated_transport_configuration_is_rejected_before_sign(bundle):
    client = client_for(bundle)
    bundle["clients"]["kms"].meta.config.retries["total_max_attempts"] = 4
    with pytest.raises(adapter.KMSSigningRejected, match="CONFIGURATION_REJECTED"):
        client.sign(bundle["request"])
    assert bundle["calls"] == []


def test_replacing_both_credential_objects_cannot_change_frozen_custody(bundle):
    client = client_for(bundle)
    replacement = object()
    for sdk_client in bundle["clients"].values():
        sdk_client._request_signer._credentials = replacement
    with pytest.raises(adapter.KMSSigningRejected, match="CREDENTIAL_CUSTODY_MISMATCH"):
        client.sign(bundle["request"])
    assert bundle["calls"] == []


def test_foreign_service_client_cannot_be_used_as_kms(bundle):
    bundle["clients"]["kms"] = bundle["clients"]["sts"]
    with pytest.raises(adapter.KMSSigningRejected, match="CLIENT_SCOPE_MISMATCH"):
        client_for(bundle)
    assert bundle["calls"] == []


def test_disabled_tls_verification_is_rejected_before_identity_or_sign(bundle):
    bundle["clients"]["kms"]._endpoint.http_session._verify = False
    with pytest.raises(adapter.KMSSigningRejected, match="CLIENT_SCOPE_MISMATCH"):
        client_for(bundle)
    assert bundle["calls"] == []


def test_authority_and_signer_are_detached_from_later_caller_mutation(bundle):
    client = client_for(bundle)
    bundle["authority"]["key_arn"] = "unapproved"
    bundle["vsa"]["signer"]["key_id"] = "unapproved"
    sts, kms = stubs(bundle)
    with sts, kms:
        response = client.sign(bundle["request"])
    assert response["key_id"] == bundle["request"].key_id


def test_concurrent_use_of_one_adapter_cannot_duplicate_sign(bundle):
    client = client_for(bundle)
    sts, kms = stubs(bundle)
    def attempt():
        try:
            return client.sign(bundle["request"])
        except adapter.KMSSigningRejected as error:
            return str(error)
    with sts, kms, ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: attempt(), range(2)))
    assert sum(isinstance(value, dict) for value in results) == 1
    assert "KMS_SIGN_ALREADY_ATTEMPTED" in results
    assert bundle["calls"].count("Sign") == 1


def test_factory_uses_only_explicit_profile_fixed_regional_endpoints_and_no_api_calls(bundle, monkeypatch):
    calls = []
    def session_factory(**kwargs):
        calls.append(kwargs)
        return bundle["session"]
    monkeypatch.setattr(boto3, "Session", session_factory)
    client = adapter.create_signing_client(profile_name="synthetic-reviewed-profile", authority=bundle["authority"],
                                          expected_authority_digest=bundle["expected_authority_digest"],
                                          approved_signer=bundle["vsa"]["signer"])
    assert isinstance(client, adapter.KmsSigningClient)
    assert calls == [{"profile_name": "synthetic-reviewed-profile", "region_name": "us-east-1"}]
    assert bundle["calls"] == []
    for sdk_client in (client._kms, client._sts):
        assert sdk_client.meta.config.retries == {"total_max_attempts": 1, "mode": "standard"}
        assert sdk_client.meta.config.connect_timeout == 5 and sdk_client.meta.config.read_timeout == 15


def test_import_creates_no_session_or_cloud_client(monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("import attempted SDK session creation")
    monkeypatch.setattr(boto3, "Session", forbidden)
    importlib.reload(adapter)


def test_unapproved_factory_input_is_rejected_before_resolving_any_profile(bundle, monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("unapproved input reached SDK profile resolution")
    monkeypatch.setattr(boto3, "Session", forbidden)
    bundle["authority"]["key_arn"] = KEY_ARN[:-1] + "8"
    with pytest.raises(adapter.KMSSigningRejected, match="PIN_MISMATCH"):
        adapter.create_signing_client(profile_name="synthetic-reviewed-profile", authority=bundle["authority"],
                                      expected_authority_digest=bundle["expected_authority_digest"],
                                      approved_signer=bundle["vsa"]["signer"])
    assert bundle["calls"] == []
