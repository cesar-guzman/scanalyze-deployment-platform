from __future__ import annotations

from collections.abc import Callable, Mapping
from datetime import UTC, datetime, timedelta
import json
import os
from pathlib import Path
import py_compile
import shutil
import subprocess
import sys
import sysconfig
from types import SimpleNamespace
from typing import Any

import pytest

import tooling.platform_authority_gug376_live_provider as live_provider_module

from tooling.platform_authority_gug365_upstream_inventory import (
    canonical_digest,
    canonical_json,
    canonical_policy_digest,
)
from tooling.platform_authority_gug376_authority_inventory_collector import (
    AuthorityAccessDenied,
)
from tooling.platform_authority_gug376_live_provider import (
    LiveProviderError,
    MAX_PAGES,
    OPERATION_ALLOWLIST,
    _IdentityExactReader,
    _RESPONSE_PROJECTORS,
    _frozen_client_session,
    _load_sdk,
    _validate_direct_sso_profile,
    build_injected_provider_factory,
    build_live_provider_factory,
    is_attested_live_provider,
)
from tooling.platform_authority_gug376_live_readonly_orchestrator import CallLedger
from tooling.platform_authority_gug376_live_request_materializer import (
    render_application_actor_policy,
    render_permission_set_inline_policies,
)


NOW = datetime(2026, 8, 26, 12, 0, tzinfo=UTC)
ACCOUNT = "123456789012"
OTHER_ACCOUNT = "210987654321"
AUTHORITY_PROFILE = "scanalyze-authority-sso"
IDENTITY_PROFILE = "scanalyze-identity-sso"
AUTHORITY_ROLE = "AWSReservedSSO_ScanalyzeAuthority_abc123"
IDENTITY_ROLE = "AWSReservedSSO_ScanalyzeIdentity_def456"
AUTHORITY_PRINCIPAL = f"arn:aws:sts::{ACCOUNT}:assumed-role/{AUTHORITY_ROLE}/operator"
IDENTITY_PRINCIPAL = f"arn:aws:sts::{OTHER_ACCOUNT}:assumed-role/{IDENTITY_ROLE}/operator"
DIGEST = "sha256:" + "a" * 64


def _closed_sdk_runtime(tmp_path: Path) -> Path:
    source_site = Path(sysconfig.get_path("purelib")).resolve(strict=True)
    runtime_root = tmp_path / "closed-sdk-runtime"
    site_root = runtime_root / "site-packages"
    site_root.mkdir(parents=True, mode=0o700)
    for name in sorted(live_provider_module._REVIEWED_SDK_TOP_LEVEL):
        destination = site_root / name
        source = source_site / name
        assert source.exists(), source
        if source.is_dir():
            shutil.copytree(
                source,
                destination,
                ignore=shutil.ignore_patterns(
                    "__pycache__", "*.pyc", "*.pyo", "*.pth"
                ),
            )
        else:
            shutil.copy2(source, destination)
    runtime_root.chmod(0o700)
    site_root.chmod(0o700)
    for candidate in site_root.rglob("*"):
        candidate.chmod(0o700 if candidate.is_dir() else 0o600)
    return runtime_root.resolve(strict=True)


def _run_closed_sdk(runtime_root: Path, body: str) -> subprocess.CompletedProcess[str]:
    code = "\n".join(
        (
            "import sys",
            "sys.dont_write_bytecode = True",
            f"sys.path.insert(0, {str(Path(__file__).parents[2])!r})",
            "from pathlib import Path",
            "from tooling.platform_authority_gug376_live_provider import _load_sdk",
            f"runtime_root = Path({str(runtime_root)!r})",
            body,
        )
    )
    return subprocess.run(
        [sys.executable, "-I", "-S", "-c", code],
        text=True,
        capture_output=True,
        check=False,
    )


def test_operation_allowlist_is_closed_read_only_and_dual_domain() -> None:
    assert set(OPERATION_ALLOWLIST) == {"authority", "identity_center"}
    assert "sso:DescribePermissionSet" in OPERATION_ALLOWLIST["identity_center"]
    assert "kms:Decrypt" not in set().union(*OPERATION_ALLOWLIST.values())
    assert all(
        action == "sts:GetCallerIdentity"
        or action.split(":", 1)[1].startswith(("Describe", "Get", "List"))
        for actions in OPERATION_ALLOWLIST.values()
        for action in actions
    )


def _identity_transition_reader(
    operations: list[str],
) -> tuple[Any, str]:
    session_digest = "sha256:" + "b" * 64
    execution_capability = object()
    owner = SimpleNamespace(
        _execution_capability=execution_capability,
        _provider_attestation=(
            live_provider_module._DISCOVERY_PROVIDER_ATTESTATION
        ),
        _events=[
            {
                "session_digest": session_digest,
                "operation": operation,
                "outcome": "SUCCESS",
            }
            for operation in operations
        ],
    )
    session = SimpleNamespace(
        _owner=owner,
        _stage="discovery",
        _identity_validated=True,
        _session_digest=session_digest,
        _capture_index=1,
        _policy_digest=DIGEST,
    )
    reader = live_provider_module._IdentityDiscoveryReader(session)
    reader._observed = {
        "instances": [{"instance_arn": "instance"}],
        "applications": [],
        "permission_sets": [],
    }
    reader._instance = {"instance_arn": "instance", "encryption": {}}
    return reader, canonical_digest(
        {"discovery": reader._observed, "instance": reader._instance}
    )


def test_identity_transition_attestation_requires_causal_discovery_order(
) -> None:
    ordered = [
        "sts:GetCallerIdentity",
        "sso:ListInstances",
        "sso:DescribeInstance",
        "sso:ListApplications",
        "sso:ListPermissionSets",
        "sso:DescribePermissionSet",
    ]
    reader, digest = _identity_transition_reader(ordered)
    assert type(reader.attest_transition(digest)).__name__ == (
        "_IdentityDiscoveryTransitionAttestation"
    )

    invalid_sequences = (
        [ordered[0], ordered[1], ordered[3], ordered[2], *ordered[4:]],
        [*ordered[:3], ordered[2], *ordered[3:]],
        [*ordered, "sso:ListInstances"],
    )
    for operations in invalid_sequences:
        invalid, invalid_digest = _identity_transition_reader(operations)
        with pytest.raises(
            LiveProviderError,
            match="DISCOVERY_TRANSITION_ATTESTATION_INVALID",
        ):
            invalid.attest_transition(invalid_digest)


def test_every_allowed_operation_has_one_closed_response_projector() -> None:
    assert set(_RESPONSE_PROJECTORS) == set().union(*OPERATION_ALLOWLIST.values())
    assert all(callable(projector) for projector in _RESPONSE_PROJECTORS.values())


@pytest.mark.parametrize("operation", sorted(_RESPONSE_PROJECTORS))
def test_every_response_projector_ignores_unregistered_top_level_fields(
    operation: str,
) -> None:
    base: dict[str, Any] = {}
    if operation == "identitystore:DescribeUser":
        base["UserId"] = "approved-user-id"
    if operation == "sts:GetCallerIdentity":
        base.update(
            {
                "Account": ACCOUNT,
                "Arn": AUTHORITY_PRINCIPAL,
                "UserId": "AROA:operator",
            }
        )
    projector = _RESPONSE_PROJECTORS[operation]

    left = projector(base | {"SensitiveSentinel": "private-left"}, {})
    right = projector(base | {"SensitiveSentinel": "private-right"}, {})

    assert left == right
    assert "SensitiveSentinel" not in canonical_json(left)


@pytest.mark.parametrize(
    ("operation", "left", "right", "forbidden"),
    [
        (
            "lambda:GetFunctionConfiguration",
            {
                "Runtime": "python3.12",
                "Architectures": ["x86_64"],
                "Environment": {"Variables": {"TOKEN": "private-left"}},
                "Role": "arn:aws:iam::123456789012:role/private-left",
            },
            {
                "Runtime": "python3.12",
                "Architectures": ["x86_64"],
                "Environment": {"Variables": {"TOKEN": "private-right"}},
                "Role": "arn:aws:iam::123456789012:role/private-right",
            },
            ("private-left", "private-right", "Environment", "Variables"),
        ),
        (
            "identitystore:DescribeUser",
            {
                "UserId": "approved-user-id",
                "UserName": "private-left",
                "Emails": [{"Value": "left@example.invalid"}],
            },
            {
                "UserId": "approved-user-id",
                "UserName": "private-right",
                "PhoneNumbers": [{"Value": "+1-555-0100"}],
            },
            ("private-left", "private-right", "example.invalid", "+1-555"),
        ),
        (
            "s3:GetBucketAcl",
            {
                "Owner": {"ID": "owner-id", "DisplayName": "private-left"},
                "Grants": [
                    {
                        "Grantee": {
                            "Type": "CanonicalUser",
                            "ID": "grantee-id",
                            "EmailAddress": "private@example.invalid",
                            "DisplayName": "private-left",
                        },
                        "Permission": "FULL_CONTROL",
                    }
                ],
            },
            {
                "Owner": {"ID": "owner-id", "DisplayName": "private-right"},
                "Grants": [
                    {
                        "Grantee": {
                            "Type": "CanonicalUser",
                            "ID": "grantee-id",
                            "EmailAddress": "private@example.invalid",
                            "DisplayName": "private-right",
                            "SensitiveExtra": "private-right",
                        },
                        "Permission": "FULL_CONTROL",
                    }
                ],
            },
            ("private-left", "private-right", "private@example.invalid"),
        ),
        (
            "iam:ListRoles",
            {
                "Roles": [
                    {
                        "Arn": "arn:aws:iam::123456789012:role/approved",
                        "RoleName": "approved",
                        "AssumeRolePolicyDocument": {
                            "Version": "2012-10-17",
                            "Statement": [
                                {
                                    "Effect": "Allow",
                                    "Principal": {
                                        "AWS": "private-policy-sentinel"
                                    },
                                    "Action": "sts:AssumeRole",
                                }
                            ],
                        },
                        "RoleLastUsed": {"Region": "private-left"},
                    }
                ],
                "IsTruncated": False,
            },
            {
                "Roles": [
                    {
                        "Arn": "arn:aws:iam::123456789012:role/approved",
                        "RoleName": "approved",
                        "AssumeRolePolicyDocument": {
                            "Version": "2012-10-17",
                            "Statement": [
                                {
                                    "Effect": "Allow",
                                    "Principal": {
                                        "AWS": "private-policy-sentinel"
                                    },
                                    "Action": "sts:AssumeRole",
                                }
                            ],
                        },
                        "RoleLastUsed": {"Region": "private-right"},
                        "SensitiveExtra": "private-right",
                    }
                ],
                "IsTruncated": False,
            },
            ("private-policy-sentinel", "private-left", "private-right"),
        ),
        (
            "kms:ListGrants",
            {
                "Grants": [
                    {
                        "KeyId": "arn:aws:kms:us-east-1:123456789012:key/approved",
                        "GrantId": "grant-id",
                        "GranteePrincipal": "private-principal",
                        "Operations": ["Verify"],
                        "PrivateNote": "private-left",
                    }
                ],
                "Truncated": False,
            },
            {
                "Grants": [
                    {
                        "KeyId": "arn:aws:kms:us-east-1:123456789012:key/approved",
                        "GrantId": "grant-id",
                        "GranteePrincipal": "private-principal",
                        "Operations": ["Verify"],
                        "PrivateNote": "private-right",
                    }
                ],
                "Truncated": False,
            },
            ("private-principal", "private-left", "private-right"),
        ),
        (
            "signer:DescribeSigningJob",
            {
                "jobId": "job-id",
                "profileName": "approved",
                "status": "Succeeded",
                "source": {"s3": {"bucketName": "private-bucket", "key": "private-key"}},
                "jobOwner": "private-left",
            },
            {
                "jobId": "job-id",
                "profileName": "approved",
                "status": "Succeeded",
                "source": {"s3": {"bucketName": "private-bucket", "key": "private-key"}},
                "jobOwner": "private-right",
            },
            ("private-bucket", "private-key", "private-left", "private-right"),
        ),
        (
            "sso:GetApplicationAuthenticationMethod",
            {
                "AuthenticationMethod": {
                    "Iam": {
                        "ActorPolicy": {
                            "Version": "2012-10-17",
                            "Statement": [
                                {
                                    "Effect": "Allow",
                                    "Principal": {
                                        "AWS": "private-principal"
                                    },
                                    "Action": "sso-oauth:CreateTokenWithIAM",
                                    "Resource": "*",
                                }
                            ],
                        }
                    }
                },
                "PrivateNote": "private-left",
            },
            {
                "AuthenticationMethod": {
                    "Iam": {
                        "ActorPolicy": {
                            "Version": "2012-10-17",
                            "Statement": [
                                {
                                    "Effect": "Allow",
                                    "Principal": {
                                        "AWS": "private-principal"
                                    },
                                    "Action": "sso-oauth:CreateTokenWithIAM",
                                    "Resource": "*",
                                }
                            ],
                        }
                    }
                },
                "PrivateNote": "private-right",
            },
            ("private-principal", "private-left", "private-right"),
        ),
    ],
)
def test_response_projectors_drop_sensitive_plaintext_and_ignore_extras(
    operation: str,
    left: Mapping[str, Any],
    right: Mapping[str, Any],
    forbidden: tuple[str, ...],
) -> None:
    projector = _RESPONSE_PROJECTORS[operation]
    left_projection = projector(left, {})
    right_projection = projector(right, {})

    assert left_projection == right_projection
    rendered = canonical_json(left_projection)
    assert all(value not in rendered for value in forbidden)


def test_source_pinned_policy_digests_survive_raw_boto_response_shapes() -> None:
    repo_root = Path(__file__).resolve().parents[2]
    authority_input = json.loads(
        (
            repo_root
            / "docs/operations/platform-authority-gug392-authority-exact-"
            "plan-input.example.json"
        ).read_text()
    )
    identity_input = json.loads(
        (
            repo_root
            / "docs/operations/platform-authority-gug392-identity-center-exact-"
            "plan-input.example.json"
        ).read_text()
    )
    actor_policy, actor_digest = render_application_actor_policy(
        authority_input["targets"],
        authority_account_id=authority_input["expected_account_id"],
    )
    permission_set_policies = render_permission_set_inline_policies(
        authority_account_id=authority_input["expected_account_id"],
        identity_center_targets=identity_input["expected_state"]["targets"],
    )

    actor_projection = _RESPONSE_PROJECTORS[
        "sso:GetApplicationAuthenticationMethod"
    ](
        {"AuthenticationMethod": {"Iam": {"ActorPolicy": actor_policy}}},
        {},
    )
    assert actor_projection["AuthenticationMethod"]["Iam"]["ActorPolicy"] == {
        "policy_digest": actor_digest
    }
    assert actor_digest == identity_input["private_targets"][
        "application_actor_policy_digest"
    ]

    expected_permission_sets = identity_input["expected_state"]["facts"][
        "permission_sets"
    ]
    for name, (policy_document, source_digest) in permission_set_policies.items():
        sso_projection = _RESPONSE_PROJECTORS[
            "sso:GetInlinePolicyForPermissionSet"
        ]({"InlinePolicy": json.dumps(policy_document, indent=2)}, {})
        iam_projection = _RESPONSE_PROJECTORS["iam:GetRolePolicy"](
            {
                "RoleName": name,
                "PolicyName": name,
                "PolicyDocument": policy_document,
            },
            {},
        )

        assert sso_projection == {
            "InlinePolicy": {"policy_digest": source_digest}
        }
        assert iam_projection["PolicyDocumentDigest"] == source_digest
        assert source_digest == expected_permission_sets[name]["inline_policy"][
            "policy_digest"
        ]


@pytest.mark.parametrize(
    "value",
    (
        (
            '{"Version":"2012-10-17","Version":"2012-10-17",'
            '"Statement":[{"Effect":"Allow","Action":"sts:AssumeRole"}]}'
        ),
        '{"Version":"2012-10-17","Statement":[]}',
        {"Version": "2012-10-17", "Statement": "not-a-statement"},
    ),
)
def test_policy_digest_rejects_duplicate_keys_and_invalid_shapes(
    value: Mapping[str, Any] | str,
) -> None:
    with pytest.raises(ValueError, match="POLICY_DOCUMENT_INVALID"):
        canonical_policy_digest(value)


@pytest.mark.parametrize(
    ("operation", "response"),
    (
        (
            "sso:GetApplicationAuthenticationMethod",
            {
                "AuthenticationMethod": {
                    "Iam": {
                        "ActorPolicy": (
                            '{"Version":"2012-10-17","Version":"2012-10-17",'
                            '"Statement":[{"Effect":"Allow",'
                            '"Action":"sso-oauth:CreateTokenWithIAM"}]}'
                        )
                    }
                }
            },
        ),
        (
            "sso:GetInlinePolicyForPermissionSet",
            {
                "InlinePolicy": (
                    '{"Version":"2012-10-17","Version":"2012-10-17",'
                    '"Statement":[{"Effect":"Allow",'
                    '"Action":"sts:AssumeRole"}]}'
                )
            },
        ),
        (
            "iam:GetRolePolicy",
            {
                "RoleName": "Synthetic",
                "PolicyName": "Synthetic",
                "PolicyDocument": (
                    '{"Version":"2012-10-17","Version":"2012-10-17",'
                    '"Statement":[{"Effect":"Allow",'
                    '"Action":"sts:AssumeRole"}]}'
                ),
            },
        ),
    ),
)
def test_policy_projectors_fail_closed_on_duplicate_json_keys(
    operation: str, response: Mapping[str, Any]
) -> None:
    with pytest.raises(LiveProviderError, match="PROVIDER_RESPONSE_INVALID"):
        _RESPONSE_PROJECTORS[operation](response, {})


def test_identity_exact_reader_preserves_private_instance_encryption() -> None:
    response = {
        "InstanceArn": "arn:aws:sso:::instance/ssoins-abc123",
        "IdentityStoreId": "d-1234567890",
        "OwnerAccountId": OTHER_ACCOUNT,
        "Status": "ACTIVE",
        "EncryptionConfigurationDetails": {
            "KeyType": "CUSTOMER_MANAGED_KEY",
            "KmsKeyArn": (
                f"arn:aws:kms:us-east-1:{OTHER_ACCOUNT}:"
                "key/11111111-1111-1111-1111-111111111111"
            ),
            "EncryptionStatus": "ENABLED",
        },
    }
    session = SimpleNamespace(_invoke=lambda **_kwargs: response)

    assert _IdentityExactReader(session).describe_instance(
        response["InstanceArn"]
    ) == {
        "complete": True,
        "value": {
            "instance_arn": response["InstanceArn"],
            "identity_store_id": "d-1234567890",
            "owner_account_id": OTHER_ACCOUNT,
            "status": "ACTIVE",
            "encryption": {
                "key_type": "CUSTOMER_MANAGED_KEY",
                "kms_key_arn": response["EncryptionConfigurationDetails"][
                    "KmsKeyArn"
                ],
                "status": "ENABLED",
            },
        },
    }


def test_sdk_loader_uses_closed_no_site_source_and_data_runtime(
    tmp_path: Path,
) -> None:
    runtime_root = _closed_sdk_runtime(tmp_path)
    result = _run_closed_sdk(
        runtime_root,
        "\n".join(
            (
                "loaded = _load_sdk(runtime_root)",
                "session_parameters = {",
                "    'aws_access_key_id': 'ASIASYNTHETIC',",
                "    'aws_secret_access_key': 'synthetic-secret',",
                "    'aws_session_token': 'synthetic-token',",
                "    'region_name': 'us-east-1',",
                "}",
                "session = loaded.session_factory(**session_parameters)",
                "model = session._session.get_service_model('sts')",
                "assert model.service_name == 'sts'",
                "assert session._loader.search_paths == [",
                "    '/__scanalyze_gug392_authenticated_botocore_data__'",
                "]",
                "assert 'certifi' not in sys.modules",
                "assert 'awscrt' not in sys.modules",
                "print('GUG392_CLOSED_SDK_OK')",
            )
        ),
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "GUG392_CLOSED_SDK_OK"


def test_sdk_tls_context_never_reopens_mutable_ca_path(tmp_path: Path) -> None:
    runtime_root = _closed_sdk_runtime(tmp_path)
    result = _run_closed_sdk(
        runtime_root,
        "\n".join(
            (
                "loaded = _load_sdk(runtime_root)",
                "import botocore.httpsession",
                "from types import SimpleNamespace",
                "ca_path = runtime_root / 'site-packages/botocore/cacert.pem'",
                "authentic = ca_path.read_bytes()",
                "try:",
                "    http = botocore.httpsession.URLLib3Session(verify=True)",
                "    context = http._manager.connection_pool_kw['ssl_context']",
                "    trusted_der = tuple(context.get_ca_certs(binary_form=True))",
                "    assert trusted_der",
                "    ca_path.write_bytes(b'transient-untrusted-ca')",
                "    replacement = botocore.httpsession.URLLib3Session(verify=True)",
                "    replacement_context = (",
                "        replacement._manager.connection_pool_kw['ssl_context']",
                "    )",
                "    assert tuple(replacement_context.get_ca_certs(binary_form=True)) == trusted_der",
                "    connection = SimpleNamespace(ssl_context=context)",
                "    http._setup_ssl_cert(",
                "        connection, 'https://sts.us-east-1.amazonaws.com', True",
                "    )",
                "    assert connection.cert_reqs == 'CERT_REQUIRED'",
                "    assert connection.ca_certs is None",
                "    assert connection.ca_cert_dir is None",
                "    assert connection.ca_cert_data is None",
                "    proxy_context = http._setup_proxy_ssl_context(",
                "        'https://proxy.example.invalid'",
                "    )",
                "    assert tuple(proxy_context.get_ca_certs(binary_form=True)) == trusted_der",
                "    assert http._setup_proxy_ssl_context(",
                "        'http://proxy.example.invalid'",
                "    ) is None",
                "    forbidden_proxy = botocore.httpsession.URLLib3Session(",
                "        verify=True,",
                "        proxies_config={'proxy_ca_bundle': '/unreviewed/ca.pem'},",
                "    )",
                "    try:",
                "        forbidden_proxy._setup_proxy_ssl_context(",
                "            'https://proxy.example.invalid'",
                "        )",
                "    except Exception as exc:",
                "        assert 'AWS_PROXY_TLS_CONFIGURATION_FORBIDDEN' in str(exc)",
                "    else:",
                "        raise AssertionError('custom proxy CA remained reachable')",
                "    try:",
                "        botocore.httpsession.where()",
                "    except Exception as exc:",
                "        assert 'AWS_SDK_CA_PATH_REOPEN_FORBIDDEN' in str(exc)",
                "    else:",
                "        raise AssertionError('mutable CA path remained reachable')",
                "    try:",
                "        loaded.guard()",
                "    except Exception as exc:",
                "        assert 'AWS_SDK_PROVENANCE_INVALID' in str(exc)",
                "    else:",
                "        raise AssertionError('runtime CA drift was not rejected')",
                "finally:",
                "    ca_path.write_bytes(authentic)",
                "print('GUG392_MEMORY_CA_OK')",
            )
        ),
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "GUG392_MEMORY_CA_OK"


def test_sdk_late_imports_remain_authenticated_and_optional_roots_absent(
    tmp_path: Path,
) -> None:
    runtime_root = _closed_sdk_runtime(tmp_path)
    result = _run_closed_sdk(
        runtime_root,
        "\n".join(
            (
                "loaded = _load_sdk(runtime_root)",
                "import importlib",
                "for name in ('six.moves', 'six.moves._thread', 'botocore.stub'):",
                "    importlib.import_module(name)",
                "    loaded.guard()",
                "for name in ('certifi', 'awscrt'):",
                "    try:",
                "        importlib.import_module(name)",
                "    except ModuleNotFoundError:",
                "        pass",
                "    else:",
                "        raise AssertionError(f'unreviewed optional root loaded: {name}')",
                "print('GUG392_LATE_IMPORTS_OK')",
            )
        ),
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "GUG392_LATE_IMPORTS_OK"


def test_sdk_lock_is_hash_pinned_and_rejects_byte_drift(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    live_provider_module._verify_sdk_lock()
    original = live_provider_module._SDK_LOCK_PATH.read_bytes()
    drifted = tmp_path / "gug392-sdk.lock"
    drifted.write_bytes(original + b"\n")
    monkeypatch.setattr(live_provider_module, "_SDK_LOCK_PATH", drifted)

    with pytest.raises(LiveProviderError, match="AWS_SDK_PROVENANCE_INVALID"):
        live_provider_module._verify_sdk_lock()


def test_sdk_loader_rejects_runtime_content_drift_before_use(
    tmp_path: Path,
) -> None:
    runtime_root = _closed_sdk_runtime(tmp_path)
    target = runtime_root / "site-packages/urllib3/__init__.py"
    target.write_bytes(target.read_bytes() + b"\n# post-install drift\n")
    with pytest.raises(LiveProviderError, match="AWS_SDK_PROVENANCE_INVALID"):
        live_provider_module._capture_verified_sdk_runtime(runtime_root)


@pytest.mark.parametrize(
    "extra",
    (
        "certifi.py",
        "boto3-1.42.57.dist-info",
        "bin",
    ),
)
def test_sdk_loader_rejects_install_metadata_scripts_or_extra_import_root(
    tmp_path: Path, extra: str,
) -> None:
    runtime_root = _closed_sdk_runtime(tmp_path)
    candidate = runtime_root / "site-packages" / extra
    if candidate.suffix == ".py":
        candidate.write_text(
            "def where(): return '/unreviewed/ca.pem'\n", encoding="utf-8"
        )
    else:
        candidate.mkdir(mode=0o700)
        (candidate / "unreviewed").write_text("unreviewed\n", encoding="utf-8")
    with pytest.raises(LiveProviderError, match="AWS_SDK_RUNTIME_CLOSURE_INVALID"):
        live_provider_module._capture_verified_sdk_runtime(runtime_root)


def test_sdk_loader_rejects_timestamp_valid_bytecode_before_execution(
    tmp_path: Path,
) -> None:
    runtime_root = _closed_sdk_runtime(tmp_path)
    source = runtime_root / "site-packages/jmespath/__init__.py"
    marker = tmp_path / "bytecode-executed"
    authentic = source.read_bytes()
    malicious = (
        f"from pathlib import Path\nPath({str(marker)!r}).write_text('PWNED')\n"
    ).encode("utf-8")
    assert len(malicious) < len(authentic)
    malicious += b"#" * (len(authentic) - len(malicious))
    build_source = tmp_path / "malicious-jmespath.py"
    build_source.write_bytes(malicious)
    source_stat = source.stat()
    os.utime(
        build_source,
        ns=(source_stat.st_atime_ns, source_stat.st_mtime_ns),
    )
    cache = source.parent / "__pycache__/__init__.cpython-311.pyc"
    cache.parent.mkdir(mode=0o700)
    py_compile.compile(str(build_source), cfile=str(cache), doraise=True)
    cache.chmod(0o600)

    result = _run_closed_sdk(
        runtime_root,
        "loaded = _load_sdk(runtime_root)",
    )
    assert result.returncode != 0
    assert "AWS_SDK_RUNTIME_CUSTODY_INVALID" in result.stderr
    assert not marker.exists()


def test_sdk_loader_requires_isolated_no_site_process(tmp_path: Path) -> None:
    runtime_root = _closed_sdk_runtime(tmp_path)
    with pytest.raises(LiveProviderError, match="AWS_SDK_ISOLATION_REQUIRED"):
        _load_sdk(runtime_root)


class FakeLedger:
    def __init__(self) -> None:
        self.pending: dict[str, dict[str, Any]] = {}
        self.events: list[dict[str, Any]] = []
        self.sts_complete: set[str] = set()

    def authorize(
        self,
        *,
        domain: str,
        session_digest: str,
        operation: str,
        retries: int,
        request: Any = None,
        page_token: Any = None,
        pagination_key: str | None = None,
        started_at: str | None = None,
    ) -> str:
        assert retries == 0
        assert isinstance(request, str) and request.startswith("sha256:")
        assert page_token is None or str(page_token).startswith("sha256:")
        assert isinstance(started_at, str) and started_at.endswith("Z")
        datetime.fromisoformat(started_at[:-1] + "+00:00")
        if operation != "sts:GetCallerIdentity":
            assert session_digest in self.sts_complete
        ticket = canonical_digest({"ordinal": len(self.events) + len(self.pending) + 1})
        self.pending[ticket] = {
            "domain": domain,
            "session_digest": session_digest,
            "operation": operation,
            "request_digest": request,
            "page_token_digest": page_token,
            "pagination_key": pagination_key,
            "started_at": started_at,
        }
        return ticket

    def complete(
        self,
        ticket: str,
        response: Any = None,
        *,
        complete: bool = True,
        truncated: bool = False,
        next_token: Any = None,
        outcome: str = "SUCCESS",
        completed_at: str | None = None,
    ) -> None:
        call = self.pending.pop(ticket)
        assert isinstance(response, str) and response.startswith("sha256:")
        assert truncated is (next_token is not None)
        assert isinstance(completed_at, str) and completed_at.endswith("Z")
        assert datetime.fromisoformat(completed_at[:-1] + "+00:00") >= datetime.fromisoformat(
            call["started_at"][:-1] + "+00:00"
        )
        if outcome == "SUCCESS" and call["operation"] == "sts:GetCallerIdentity":
            self.sts_complete.add(call["session_digest"])
        self.events.append(
            call
            | {
                "response_digest": response,
                "complete": complete,
                "truncated": truncated,
                "next_token_digest": next_token,
                "outcome": outcome,
                "completed_at": completed_at,
            }
        )

    def finalize(self) -> tuple[int, str]:
        assert not self.pending
        return len(self.events), canonical_digest(self.events)


class FakeClient:
    def __init__(self, service: str, calls: list[tuple[str, str, dict[str, Any]]], handlers: Mapping[tuple[str, str], Callable[..., Mapping[str, Any]]]) -> None:
        self.service = service
        self.calls = calls
        self.handlers = handlers

    def __getattr__(self, method: str) -> Callable[..., Mapping[str, Any]]:
        def invoke(**request: Any) -> Mapping[str, Any]:
            self.calls.append((self.service, method, request))
            handler = self.handlers.get((self.service, method))
            if handler is None:
                raise AssertionError(f"unexpected SDK operation: {self.service}.{method}")
            return handler(**request)

        return invoke


class FakeSdkError(RuntimeError):
    def __init__(self, code: str, private_message: str) -> None:
        self.response = {"Error": {"Code": code, "Message": private_message}}
        super().__init__(private_message)


class FakeEmitter:
    def __init__(self) -> None:
        self.handlers: dict[str, Callable[..., None]] = {}

    def register(
        self,
        event_name: str,
        handler: Callable[..., None],
        *,
        unique_id: str,
    ) -> None:
        assert event_name == "before-call.*.*"
        assert unique_id not in self.handlers
        self.handlers[unique_id] = handler

    def unregister(self, event_name: str, *, unique_id: str) -> None:
        assert event_name == "before-call.*.*"
        self.handlers.pop(unique_id)

    def emit(
        self,
        event_name: str,
        retries: Mapping[str, Any] | None = None,
    ) -> None:
        effective = retries or {"mode": "standard", "total_max_attempts": 1}
        for handler in tuple(self.handlers.values()):
            handler(
                event_name=event_name,
                context={"client_config": SimpleNamespace(retries=effective)},
            )


class FakeBotocoreSession:
    def __init__(self, full_config: Mapping[str, Any], emitter: FakeEmitter) -> None:
        self.full_config = full_config
        self.emitter = emitter
        self.config_variables: dict[str, Any] = {}

    def set_config_variable(self, name: str, value: Any) -> None:
        self.config_variables[name] = value

    def get_config_variable(self, name: str) -> Any:
        return self.config_variables.get(name)

    def get_component(self, name: str) -> FakeEmitter:
        assert name == "event_emitter"
        return self.emitter


class FakeSession:
    def __init__(
        self,
        *,
        profile_name: str,
        region_name: str,
        account_id: str,
        role_name: str,
        calls: list[tuple[str, str, dict[str, Any]]],
        opened: list[str],
        handlers: Mapping[tuple[str, str], Callable[..., Mapping[str, Any]]],
        access_key: str,
        expires_at: datetime,
        profile_extra: Mapping[str, Any] | None = None,
        credential_events: tuple[str, ...] = (),
        credential_retries: Mapping[str, Any] | None = None,
    ) -> None:
        profile = {
            "region": region_name,
            "sso_account_id": account_id,
            "sso_role_name": role_name,
            "sso_session": "corp",
        }
        profile.update(profile_extra or {})
        self._emitter = FakeEmitter()
        self._session = FakeBotocoreSession(
            {
                "profiles": {profile_name: profile},
                "sso_sessions": {
                    "corp": {
                        "sso_start_url": "https://example.invalid/start",
                        "sso_region": "us-east-1",
                    }
                },
            },
            self._emitter,
        )
        self.region_name = region_name
        self._calls = calls
        self._opened = opened
        self._handlers = handlers
        self._access_key = access_key
        self._expires_at = expires_at
        self._credential_events = credential_events
        self._credential_retries = credential_retries

    def get_credentials(self) -> Any:
        def frozen() -> Any:
            for event_name in self._credential_events:
                self._emitter.emit(event_name, self._credential_retries)
            return SimpleNamespace(
                access_key=self._access_key,
                secret_key="synthetic-secret-never-persisted",
                token="synthetic-session-token-never-persisted",
            )

        return SimpleNamespace(
            method="sso",
            _expiry_time=self._expires_at,
            get_frozen_credentials=frozen,
        )

    def client(self, service: str, *, config: Any, verify: bool) -> FakeClient:
        assert verify is True
        self._opened.append(service)
        return FakeClient(service, self._calls, self._handlers)


def policy(*statements: Mapping[str, Any]) -> dict[str, Any]:
    caller = {
        "Sid": "ConfirmOnlyTheCurrentCaller",
        "Effect": "Allow",
        "Action": "sts:GetCallerIdentity",
        "Resource": "*",
        "Condition": {
            "DateGreaterThanEquals": {"aws:CurrentTime": "2026-08-26T11:59:00Z"},
            "DateLessThan": {"aws:CurrentTime": "2026-08-26T12:30:00Z"},
        },
    }
    return {"Version": "2012-10-17", "Statement": [caller, *statements]}


def injected(
    handlers: Mapping[tuple[str, str], Callable[..., Mapping[str, Any]]],
    *,
    session_overrides: Mapping[str, Mapping[str, Any]] | None = None,
    environment: Mapping[str, str] | None = None,
    session_access_keys: list[str] | None = None,
    session_expires_at: datetime | None = None,
    clock: Callable[[], datetime] | None = None,
) -> tuple[Any, list[tuple[str, str, dict[str, Any]]], list[str], list[dict[str, Any]], list[str]]:
    calls: list[tuple[str, str, dict[str, Any]]] = []
    opened: list[str] = []
    sdk_configs: list[dict[str, Any]] = []
    gate_calls: list[str] = []
    session_count = 0

    def session_factory(*, profile_name: str, region_name: str) -> FakeSession:
        nonlocal session_count
        access_key = (
            session_access_keys[session_count]
            if session_access_keys is not None
            and session_count < len(session_access_keys)
            else f"ASIASYNTHETIC{session_count:04d}"
        )
        session_count += 1
        authority = profile_name == AUTHORITY_PROFILE
        return FakeSession(
            profile_name=profile_name,
            region_name=region_name,
            account_id=ACCOUNT if authority else OTHER_ACCOUNT,
            role_name=AUTHORITY_ROLE if authority else IDENTITY_ROLE,
            calls=calls,
            opened=opened,
            handlers=handlers,
            access_key=access_key,
            expires_at=session_expires_at or (NOW + timedelta(minutes=30)),
            profile_extra=(session_overrides or {}).get(profile_name),
        )

    def config_factory(**kwargs: Any) -> dict[str, Any]:
        sdk_configs.append(kwargs)
        return kwargs

    factory = build_injected_provider_factory(
        authority_profile=AUTHORITY_PROFILE,
        identity_center_profile=IDENTITY_PROFILE,
        authority_expected_account_id=ACCOUNT,
        authority_expected_principal_digest=canonical_digest(AUTHORITY_PRINCIPAL),
        authority_expected_sso_role_name_digest=canonical_digest(AUTHORITY_ROLE),
        identity_expected_account_id=OTHER_ACCOUNT,
        identity_expected_principal_digest=canonical_digest(IDENTITY_PRINCIPAL),
        identity_expected_sso_role_name_digest=canonical_digest(IDENTITY_ROLE),
        authority_verification_digest=DIGEST,
        identity_authority_verification_digest=DIGEST,
        validity_gate=lambda: gate_calls.append("checked"),
        session_factory=session_factory,
        config_factory=config_factory,
        clock=clock or (lambda: NOW),
        environment=environment,
    )
    return factory, calls, opened, sdk_configs, gate_calls


def _lambda_projection_capture(
    sensitive_suffix: str,
) -> tuple[Mapping[str, Any], dict[str, str], str]:
    version_arn = (
        f"arn:aws:lambda:us-east-1:{ACCOUNT}:function:runtime-source:7"
    )
    handlers = {
        ("sts", "get_caller_identity"): lambda: {
            "Account": ACCOUNT,
            "Arn": AUTHORITY_PRINCIPAL,
            "UserId": "AROA:operator",
        },
        ("lambda", "get_function_configuration"): lambda **_: {
            "FunctionArn": version_arn,
            "Version": "7",
            "Runtime": "python3.12",
            "Architectures": ["x86_64"],
            "Environment": {
                "Variables": {"PRIVATE_TOKEN": f"private-{sensitive_suffix}"}
            },
            "Role": (
                f"arn:aws:iam::{ACCOUNT}:role/private-{sensitive_suffix}"
            ),
            "VpcConfig": {"VpcId": f"vpc-private-{sensitive_suffix}"},
        },
        ("lambda", "get_runtime_management_config"): lambda **_: {
            "UpdateRuntimeOn": "Manual",
            "RuntimeVersionArn": "arn:aws:lambda:us-east-1::runtime:" + "b" * 64,
        },
        ("lambda", "list_tags"): lambda **_: {"Tags": {"owner": "platform"}},
        ("lambda", "list_versions_by_function"): lambda **_: {
            "Versions": [
                {
                    "FunctionArn": version_arn,
                    "Version": "7",
                    "Runtime": "python3.12",
                    "Architectures": ["x86_64"],
                    "Environment": {
                        "Variables": {
                            "PRIVATE_TOKEN": f"private-{sensitive_suffix}"
                        }
                    },
                    "Role": (
                        f"arn:aws:iam::{ACCOUNT}:role/private-{sensitive_suffix}"
                    ),
                }
            ]
        },
    }
    factory, _, _, _, _ = injected(handlers)
    ledger = FakeLedger()
    rendered = policy(
        {
            "Sid": "ReadExactLambdaRuntimeEvidence",
            "Effect": "Allow",
            "Action": [
                "lambda:GetFunctionConfiguration",
                "lambda:GetRuntimeManagementConfig",
                "lambda:ListTags",
                "lambda:ListVersionsByFunction",
            ],
            "Resource": [version_arn.rsplit(":", 1)[0], version_arn],
        }
    )
    session = factory.build_authority(
        profile=AUTHORITY_PROFILE,
        ledger=ledger,
        capture_index=1,
        retries=0,
    ).open_sts(
        policy=rendered,
        policy_digest=canonical_digest(rendered),
        region="us-east-1",
    )
    session.get_caller_identity()
    page = session.open_reader().lambda_runtime(None)
    response_digests = {
        event["operation"]: event["response_digest"] for event in ledger.events
    }
    _, transcript_digest = ledger.finalize()
    return page, response_digests, transcript_digest


def test_lambda_sensitive_extras_never_reach_snapshot_or_response_digest() -> None:
    left_page, left_responses, left_transcript = _lambda_projection_capture("left")
    right_page, right_responses, right_transcript = _lambda_projection_capture("right")

    assert left_page == right_page
    assert left_responses == right_responses
    assert left_transcript == right_transcript
    rendered = canonical_json(left_page)
    assert all(
        forbidden not in rendered
        for forbidden in (
            "PRIVATE_TOKEN",
            "private-left",
            "private-right",
            "Environment",
            "Variables",
            "VpcConfig",
            '"Role"',
        )
    )


def test_provider_supplies_call_times_to_attested_live_ledger() -> None:
    factory, _, _, _, _ = injected(
        {
            ("sts", "get_caller_identity"): lambda: {
                "Account": ACCOUNT,
                "Arn": AUTHORITY_PRINCIPAL,
                "UserId": "AROA:operator",
            }
        }
    )
    ledger = CallLedger("ATTESTED_LIVE")
    rendered = policy()
    session = factory.build_authority(
        profile=AUTHORITY_PROFILE,
        ledger=ledger,
        capture_index=1,
        retries=0,
    ).open_sts(
        policy=rendered,
        policy_digest=canonical_digest(rendered),
        region="us-east-1",
    )

    session.get_caller_identity()
    events = ledger.evidence_events()

    assert len(events) == 1
    assert events[0]["started_at"] == NOW.isoformat().replace("+00:00", "Z")
    assert events[0]["completed_at"] == NOW.isoformat().replace("+00:00", "Z")


def test_response_crossing_policy_end_is_failed_before_ledger_success() -> None:
    current = [NOW]

    def identity() -> Mapping[str, Any]:
        current[0] = NOW + timedelta(minutes=30)
        return {
            "Account": ACCOUNT,
            "Arn": AUTHORITY_PRINCIPAL,
            "UserId": "AROA:operator",
        }

    factory, calls, _, _, _ = injected(
        {("sts", "get_caller_identity"): identity},
        clock=lambda: current[0],
    )
    ledger = FakeLedger()
    rendered = policy()
    session = factory.build_authority(
        profile=AUTHORITY_PROFILE,
        ledger=ledger,
        capture_index=1,
        retries=0,
    ).open_sts(
        policy=rendered,
        policy_digest=canonical_digest(rendered),
        region="us-east-1",
    )

    with pytest.raises(
        LiveProviderError, match="DIRECT_SSO_SESSION_WINDOW_INACTIVE"
    ):
        session.get_caller_identity()

    assert [item[:2] for item in calls] == [("sts", "get_caller_identity")]
    assert len(ledger.events) == 1
    assert ledger.events[0]["outcome"] == "ERROR"
    assert ledger.events[0]["started_at"] == "2026-08-26T12:00:00Z"
    assert ledger.events[0]["completed_at"] == "2026-08-26T12:30:00Z"


def test_injected_authority_is_sts_first_zero_retry_and_never_live() -> None:
    pages = iter(
        [
            {"Versions": [{"Version": "1"}], "NextMarker": "page-2"},
            {"Versions": [{"Version": "7"}]},
        ]
    )
    handlers = {
        ("sts", "get_caller_identity"): lambda: {
            "Account": ACCOUNT,
            "Arn": AUTHORITY_PRINCIPAL,
            "UserId": "AROA:operator",
        },
        ("lambda", "get_function_configuration"): lambda **_: {
            "Runtime": "python3.12",
            "Architectures": ["x86_64"],
        },
        ("lambda", "get_runtime_management_config"): lambda **_: {
            "UpdateRuntimeOn": "Manual",
            "RuntimeVersionArn": "arn:aws:lambda:us-east-1::runtime:" + "b" * 64,
        },
        ("lambda", "list_tags"): lambda **_: {"Tags": {"owner": "platform"}},
        ("lambda", "list_versions_by_function"): lambda **_: next(pages),
    }
    factory, calls, opened, configs, gate_calls = injected(handlers)
    ledger = FakeLedger()
    rendered = policy(
        {
            "Sid": "ReadExactLambdaRuntimeEvidence",
            "Effect": "Allow",
            "Action": [
                "lambda:GetFunctionConfiguration",
                "lambda:GetRuntimeManagementConfig",
                "lambda:ListTags",
                "lambda:ListVersionsByFunction",
            ],
            "Resource": [
                f"arn:aws:lambda:us-east-1:{ACCOUNT}:function:runtime-source",
                f"arn:aws:lambda:us-east-1:{ACCOUNT}:function:runtime-source:7",
            ],
        }
    )
    session = factory.build_authority(
        profile=AUTHORITY_PROFILE, ledger=ledger, capture_index=1, retries=0
    ).open_sts(policy=rendered, policy_digest=canonical_digest(rendered), region="us-east-1")

    identity = session.get_caller_identity()
    page = session.open_reader().lambda_runtime(None)
    summary = factory.transcript_summary()

    assert identity["principal_arn"] == AUTHORITY_PRINCIPAL
    expected_runtime = {
        "function_arn": f"arn:aws:lambda:us-east-1:{ACCOUNT}:function:runtime-source:7",
        "version": "7",
        "runtime": "python3.12",
        "architectures": ["x86_64"],
        "update_runtime_on": "Manual",
        "runtime_version_arn": "arn:aws:lambda:us-east-1::runtime:" + "b" * 64,
    }
    assert expected_runtime.items() <= page["items"][0].items()
    assert opened == ["sts", "lambda"]
    assert calls[0][:2] == ("sts", "get_caller_identity")
    assert [item[:2] for item in calls].count(("lambda", "list_versions_by_function")) == 2
    assert configs[0]["retries"] == {"mode": "standard", "total_max_attempts": 1}
    assert configs[0]["ignore_configured_endpoint_urls"] is True
    assert len(gate_calls) == (2 * len(calls)) + 1
    assert factory.mode == "INJECTED_NON_LIVE"
    assert factory.concrete_provider is False
    assert is_attested_live_provider(factory) is False
    assert summary == {
        "provider_calls": len(calls),
        "aws_calls": 0,
        "aws_mutations": 0,
        "live_provider_evidence": False,
        "transcript_digest": canonical_digest(ledger.events),
    }
    assert all(event["request_digest"].startswith("sha256:") for event in ledger.events)


def test_evaluation_time_reexecutes_the_validity_gate() -> None:
    factory, calls, opened, configs, gate_calls = injected({})

    assert factory.evaluation_time() == NOW
    assert factory.evaluation_time() == NOW

    assert gate_calls == ["checked", "checked"]
    assert calls == []
    assert opened == []
    assert configs == []


def test_wrong_sts_identity_stops_before_inventory_client() -> None:
    handlers = {
        ("sts", "get_caller_identity"): lambda: {
            "Account": ACCOUNT,
            "Arn": f"arn:aws:sts::{ACCOUNT}:assumed-role/{AUTHORITY_ROLE}/wrong",
            "UserId": "AROA:wrong",
        }
    }
    factory, calls, opened, _, _ = injected(handlers)
    ledger = FakeLedger()
    rendered = policy()
    session = factory.build_authority(
        profile=AUTHORITY_PROFILE, ledger=ledger, capture_index=1, retries=0
    ).open_sts(policy=rendered, policy_digest=canonical_digest(rendered), region="us-east-1")

    with pytest.raises(LiveProviderError, match="CALLER_IDENTITY_MISMATCH"):
        session.get_caller_identity()

    assert opened == ["sts"]
    assert [item[:2] for item in calls] == [("sts", "get_caller_identity")]


def test_repeated_sdk_page_token_fails_without_retrying_the_stream() -> None:
    handlers = {
        ("sts", "get_caller_identity"): lambda: {
            "Account": ACCOUNT,
            "Arn": AUTHORITY_PRINCIPAL,
            "UserId": "AROA:operator",
        },
        ("lambda", "get_function_configuration"): lambda **_: {
            "Runtime": "python3.12",
            "Architectures": ["x86_64"],
        },
        ("lambda", "get_runtime_management_config"): lambda **_: {
            "UpdateRuntimeOn": "Manual",
            "RuntimeVersionArn": "arn:aws:lambda:us-east-1::runtime:" + "b" * 64,
        },
        ("lambda", "list_tags"): lambda **_: {"Tags": {}},
        ("lambda", "list_versions_by_function"): lambda **_: {
            "Versions": [],
            "NextMarker": "repeated",
        },
    }
    factory, calls, _, _, _ = injected(handlers)
    rendered = policy(
        {
            "Sid": "ReadExactLambdaRuntimeEvidence",
            "Effect": "Allow",
            "Action": [
                "lambda:GetFunctionConfiguration",
                "lambda:GetRuntimeManagementConfig",
                "lambda:ListTags",
                "lambda:ListVersionsByFunction",
            ],
            "Resource": [
                f"arn:aws:lambda:us-east-1:{ACCOUNT}:function:runtime-source",
                f"arn:aws:lambda:us-east-1:{ACCOUNT}:function:runtime-source:7",
            ],
        }
    )
    session = factory.build_authority(
        profile=AUTHORITY_PROFILE,
        ledger=FakeLedger(),
        capture_index=1,
        retries=0,
    ).open_sts(
        policy=rendered,
        policy_digest=canonical_digest(rendered),
        region="us-east-1",
    )
    session.get_caller_identity()

    with pytest.raises(LiveProviderError, match="PROVIDER_PAGE_TOKEN_REPEATED"):
        session.open_reader().lambda_runtime(None)

    assert [item[:2] for item in calls].count(
        ("lambda", "list_versions_by_function")
    ) == 2


@pytest.mark.parametrize("resource_kind", ("application", "permission_set"))
@pytest.mark.parametrize(
    ("mode", "error", "expected_calls"),
    (
        ("repeated", "PROVIDER_PAGE_TOKEN_REPEATED", 2),
        ("limit", "PROVIDER_PAGE_LIMIT_EXCEEDED", MAX_PAGES),
    ),
)
def test_identity_tag_pagination_cycle_and_limit_fail_closed(
    resource_kind: str, mode: str, error: str, expected_calls: int
) -> None:
    resource_arn = (
        f"arn:aws:sso::{OTHER_ACCOUNT}:application/ssoins-abc123/apl-abc123"
        if resource_kind == "application"
        else "arn:aws:sso:::permissionSet/ssoins-abc123/ps-approve"
    )
    page_count = 0

    def tags(**_: Any) -> Mapping[str, Any]:
        nonlocal page_count
        page_count += 1
        token = "repeated" if mode == "repeated" else f"page-{page_count}"
        return {
            "Tags": [{"Key": f"key-{page_count}", "Value": "value"}],
            "NextToken": token,
        }

    handlers = {
        ("sts", "get_caller_identity"): lambda: {
            "Account": OTHER_ACCOUNT,
            "Arn": IDENTITY_PRINCIPAL,
            "UserId": "AROA:operator",
        },
        ("sso-admin", "list_tags_for_resource"): tags,
    }
    factory, calls, _, _, _ = injected(handlers)
    rendered = policy(
        {
            "Sid": "ReadEveryExactTag",
            "Effect": "Allow",
            "Action": "sso:ListTagsForResource",
            "Resource": resource_arn,
        }
    )
    session = factory.build_identity(
        profile=IDENTITY_PROFILE,
        ledger=FakeLedger(),
        capture_index=1,
        retries=0,
    ).open_sts(
        stage="exact",
        policy=rendered,
        policy_digest=canonical_digest(rendered),
        region="us-east-1",
    )
    session.get_caller_identity()

    with pytest.raises(LiveProviderError, match=error):
        session._paginate(
            operation="sso:ListTagsForResource",
            service="sso-admin",
            method="list_tags_for_resource",
            request={"ResourceArn": resource_arn},
            item_key="Tags",
            request_token_key="NextToken",
            response_token_key="NextToken",
        )

    assert page_count == expected_calls
    assert [item[:2] for item in calls].count(
        ("sso-admin", "list_tags_for_resource")
    ) == expected_calls


def test_s3_version_pagination_preserves_both_markers() -> None:
    object_arn = "arn:aws:s3:::scanalyze-artifacts/runtime/source.zip"

    def versions(**request: Any) -> Mapping[str, Any]:
        if "KeyMarker" not in request:
            return {
                "IsTruncated": True,
                "NextKeyMarker": "runtime/source.zip",
                "NextVersionIdMarker": "v2",
                "Versions": [{"Key": "runtime/source.zip", "VersionId": "v2"}],
                "DeleteMarkers": [
                    {"Key": "runtime/source.zip", "VersionId": "deleted-v3"}
                ],
            }
        assert request["KeyMarker"] == "runtime/source.zip"
        assert request["VersionIdMarker"] == "v2"
        return {
            "IsTruncated": False,
            "Versions": [{"Key": "runtime/source.zip", "VersionId": "v1"}],
        }

    handlers = {
        ("sts", "get_caller_identity"): lambda: {
            "Account": ACCOUNT,
            "Arn": AUTHORITY_PRINCIPAL,
            "UserId": "AROA:operator",
        },
        ("s3", "list_object_versions"): versions,
        ("s3", "get_object_attributes"): lambda **_: {"ObjectSize": 10},
        ("s3", "get_object_tagging"): lambda **_: {"TagSet": []},
    }
    factory, calls, _, _, _ = injected(handlers)
    rendered = policy(
        {
            "Sid": "ReadExactArtifactObjectVersions",
            "Effect": "Allow",
            "Action": [
                "s3:ListBucketVersions",
                "s3:GetObjectAttributes",
                "s3:GetObjectVersionTagging",
            ],
            "Resource": object_arn,
        }
    )
    session = factory.build_authority(
        profile=AUTHORITY_PROFILE,
        ledger=FakeLedger(),
        capture_index=1,
        retries=0,
    ).open_sts(
        policy=rendered,
        policy_digest=canonical_digest(rendered),
        region="us-east-1",
    )
    session.get_caller_identity()
    page = session.open_reader().artifact_objects(None)

    assert len(page["items"][0]["observations"]) == 3
    assert sum(
        item.get("deleted") is True
        for item in page["items"][0]["observations"]
    ) == 1
    list_calls = [request for service, method, request in calls if (service, method) == ("s3", "list_object_versions")]
    assert len(list_calls) == 2
    assert list_calls[1]["KeyMarker"] == "runtime/source.zip"
    assert list_calls[1]["VersionIdMarker"] == "v2"
    assert [item[:2] for item in calls].count(("s3", "get_object_attributes")) == 2
    attribute_requests = [
        request
        for service, method, request in calls
        if (service, method) == ("s3", "get_object_attributes")
    ]
    assert all(
        request["ObjectAttributes"]
        == ["ETag", "Checksum", "StorageClass", "ObjectSize"]
        for request in attribute_requests
    )


def test_unrequested_truncated_s3_object_parts_fail_closed() -> None:
    object_arn = "arn:aws:s3:::synthetic-authority-artifacts/runtime/source.zip"
    handlers = {
        ("sts", "get_caller_identity"): lambda: {
            "Account": ACCOUNT,
            "Arn": AUTHORITY_PRINCIPAL,
            "UserId": "AROA:operator",
        },
        ("s3", "list_object_versions"): lambda **_: {
            "Versions": [{"Key": "runtime/source.zip", "VersionId": "v1"}],
        },
        ("s3", "get_object_attributes"): lambda **_: {
            "ObjectSize": 10,
            "ObjectParts": {
                "IsTruncated": True,
                "NextPartNumberMarker": 1000,
            },
        },
    }
    factory, _, _, _, _ = injected(handlers)
    rendered = policy(
        {
            "Sid": "ReadExactArtifactObjectVersions",
            "Effect": "Allow",
            "Action": ["s3:ListBucketVersions", "s3:GetObjectAttributes"],
            "Resource": object_arn,
        }
    )
    session = factory.build_authority(
        profile=AUTHORITY_PROFILE,
        ledger=FakeLedger(),
        capture_index=1,
        retries=0,
    ).open_sts(
        policy=rendered,
        policy_digest=canonical_digest(rendered),
        region="us-east-1",
    )
    session.get_caller_identity()

    with pytest.raises(LiveProviderError, match="PROVIDER_PAGE_INCOMPLETE"):
        session.open_reader().artifact_objects(None)


@pytest.mark.parametrize("generated_role_collision", (False, True))
def test_authority_discovery_reports_generated_role_prefix_collisions(
    generated_role_collision: bool,
) -> None:
    bucket = "arn:aws:s3:::synthetic-authority-artifacts"
    version_arn = (
        f"arn:aws:lambda:us-east-1:{ACCOUNT}:function:runtime-source:7"
    )
    statements = (
        {
            "Sid": "ReadExactArtifactBucketAndVersions",
            "Effect": "Allow",
            "Action": "s3:ListAllMyBuckets",
            "Resource": bucket,
        },
        {
            "Sid": "ReadExactKmsKey",
            "Effect": "Allow",
            "Action": "kms:ListKeys",
            "Resource": f"arn:aws:kms:us-east-1:{ACCOUNT}:key/" + "1" * 36,
        },
        {
            "Sid": "ReadExactSigningProfile",
            "Effect": "Allow",
            "Action": "signer:ListSigningProfiles",
            "Resource": (
                f"arn:aws:signer:us-east-1:{ACCOUNT}:"
                "/signing-profiles/synthetic"
            ),
        },
        {
            "Sid": "ReadExactLambdaCodeSigningConfig",
            "Effect": "Allow",
            "Action": "lambda:ListCodeSigningConfigs",
            "Resource": (
                f"arn:aws:lambda:us-east-1:{ACCOUNT}:"
                "code-signing-config:csc-0123456789abcdef0"
            ),
        },
        {
            "Sid": "ReadExactLambdaRuntimeEvidence",
            "Effect": "Allow",
            "Action": [
                "lambda:GetFunctionConfiguration",
                "lambda:GetRuntimeManagementConfig",
                "lambda:ListTags",
                "lambda:ListVersionsByFunction",
            ],
            "Resource": [version_arn.rsplit(":", 1)[0], version_arn],
        },
        {
            "Sid": "ReadExactGeneratedIdentityCenterRoles",
            "Effect": "Allow",
            "Action": "iam:ListRoles",
            "Resource": [
                f"arn:aws:iam::{ACCOUNT}:role/aws-reserved/sso.amazonaws.com/"
                "AWSReservedSSO_ScanalyzeAuthorityRetireApprove_0000000000000000",
                f"arn:aws:iam::{ACCOUNT}:role/aws-reserved/sso.amazonaws.com/"
                "AWSReservedSSO_ScanalyzeAuthorityRetireClass_0000000000000000",
            ],
        },
        {
            "Sid": "ReadExactArtifactObjectVersions",
            "Effect": "Allow",
            "Action": "s3:ListBucketVersions",
            "Resource": [
                bucket + "/broker-signed.zip",
                bucket + "/broker-unsigned.zip",
                bucket + "/factory-signed.zip",
                bucket + "/factory-unsigned.zip",
            ],
        },
    )
    handlers = {
        ("sts", "get_caller_identity"): lambda: {
            "Account": ACCOUNT,
            "Arn": AUTHORITY_PRINCIPAL,
            "UserId": "AROA:operator",
        },
        ("s3", "list_buckets"): lambda **_: {"Buckets": []},
        ("kms", "list_keys"): lambda **_: {"Keys": [], "Truncated": False},
        ("signer", "list_signing_profiles"): lambda **_: {"profiles": []},
        ("lambda", "list_code_signing_configs"): lambda **_: {
            "CodeSigningConfigs": []
        },
        ("lambda", "get_function_configuration"): lambda **_: {
            "Runtime": "python3.12",
            "Architectures": ["x86_64"],
        },
        ("lambda", "get_runtime_management_config"): lambda **_: {
            "UpdateRuntimeOn": "Manual",
            "RuntimeVersionArn": "arn:aws:lambda:us-east-1::runtime:" + "b" * 64,
        },
        ("lambda", "list_tags"): lambda **_: {"Tags": {}},
        ("lambda", "list_versions_by_function"): lambda **_: {
            "Versions": [{"FunctionArn": version_arn, "Version": "7"}]
        },
        ("iam", "list_roles"): lambda **_: {
            "Roles": (
                [
                    {
                        "Path": "/aws-reserved/sso.amazonaws.com/",
                        "RoleName": (
                            "AWSReservedSSO_ScanalyzeAuthorityRetireApprove_"
                            "0123456789abcdef"
                        ),
                        "Arn": (
                            f"arn:aws:iam::{ACCOUNT}:role/aws-reserved/"
                            "sso.amazonaws.com/"
                            "AWSReservedSSO_ScanalyzeAuthorityRetireApprove_"
                            "0123456789abcdef"
                        ),
                        "CreateDate": NOW,
                        "MaxSessionDuration": 3600,
                        "RoleId": "AROASYNTHETIC",
                        "AssumeRolePolicyDocument": {
                            "Version": "2012-10-17",
                            "Statement": [
                                {
                                    "Effect": "Allow",
                                    "Principal": {
                                        "AWS": (
                                            f"arn:aws:iam::{ACCOUNT}:root"
                                        )
                                    },
                                    "Action": "sts:AssumeRole",
                                }
                            ],
                        },
                    }
                ]
                if generated_role_collision
                else []
            ),
            "IsTruncated": False,
        },
        ("s3", "list_object_versions"): lambda **_: {
            "Versions": [],
            "DeleteMarkers": [],
            "IsTruncated": False,
        },
    }
    factory, calls, _, _, _ = injected(handlers)
    rendered = policy(*statements)
    session = factory.build_authority(
        profile=AUTHORITY_PROFILE,
        ledger=FakeLedger(),
        capture_index=1,
        retries=0,
    ).open_sts(
        policy=rendered,
        policy_digest=canonical_digest(rendered),
        region="us-east-1",
    )
    session.get_caller_identity()
    reader = session.open_reader()

    assert reader.s3(None)["items"] == []
    assert reader.kms(None)["items"] == []
    assert reader.signer(None)["items"] == []
    assert reader.lambda_code_signing(None)["items"] == []
    role_items = reader.iam_roles(None)["items"]
    if generated_role_collision:
        assert len(role_items) == 1
        assert role_items[0]["collision"] is True
        assert role_items[0]["role_arn"].endswith("0123456789abcdef")
    else:
        assert role_items == []
    assert reader.artifact_objects(None)["items"] == []
    assert len(reader.lambda_runtime(None)["items"]) == 1
    invoked = [item[:2] for item in calls]
    assert not any(
        method.startswith("get_")
        for service, method in invoked
        if service in {"s3", "kms", "signer", "iam"}
    )
    assert invoked.count(("s3", "list_object_versions")) == 4


def test_direct_sso_profile_chain_is_rejected_before_sts_client() -> None:
    factory, calls, opened, _, _ = injected(
        {},
        session_overrides={
            AUTHORITY_PROFILE: {
                "role_arn": f"arn:aws:iam::{ACCOUNT}:role/chained",
                "source_profile": "source",
            }
        },
    )
    rendered = policy()
    with pytest.raises(LiveProviderError, match="DIRECT_SSO_PROFILE_REQUIRED"):
        factory.build_authority(
            profile=AUTHORITY_PROFILE,
            ledger=FakeLedger(),
            capture_index=1,
            retries=0,
        ).open_sts(
            policy=rendered,
            policy_digest=canonical_digest(rendered),
            region="us-east-1",
        )

    assert calls == []
    assert opened == []


def _credential_session(
    *events: str,
    retries: Mapping[str, Any] | None = None,
) -> FakeSession:
    return FakeSession(
        profile_name=AUTHORITY_PROFILE,
        region_name="us-east-1",
        account_id=ACCOUNT,
        role_name=AUTHORITY_ROLE,
        calls=[],
        opened=[],
        handlers={},
        access_key="ASIAREVIEWEDSESSION",
        expires_at=NOW + timedelta(minutes=30),
        credential_events=tuple(events),
        credential_retries=retries,
    )


def test_direct_sso_bootstrap_allows_only_one_role_credential_vend() -> None:
    cached = _credential_session()
    cached_expiry, cached_digest, _ = _validate_direct_sso_profile(
        cached,
        profile_name=AUTHORITY_PROFILE,
        account_id=ACCOUNT,
        sso_role_name_digest=canonical_digest(AUTHORITY_ROLE),
        region="us-east-1",
        opened_at=NOW,
        required_end=NOW + timedelta(minutes=29),
        observe_credential_bootstrap=True,
    )
    refreshed = _credential_session("before-call.sso.GetRoleCredentials")
    refreshed_expiry, refreshed_digest, _ = _validate_direct_sso_profile(
        refreshed,
        profile_name=AUTHORITY_PROFILE,
        account_id=ACCOUNT,
        sso_role_name_digest=canonical_digest(AUTHORITY_ROLE),
        region="us-east-1",
        opened_at=NOW,
        required_end=NOW + timedelta(minutes=29),
        observe_credential_bootstrap=True,
    )

    assert cached_expiry == refreshed_expiry == NOW + timedelta(minutes=30)
    assert cached_digest != refreshed_digest
    assert cached._session.config_variables == refreshed._session.config_variables == {
        "retry_mode": "standard",
        "max_attempts": 1,
    }
    assert cached._emitter.handlers == refreshed._emitter.handlers == {}


def test_direct_sso_bootstrap_rejects_effective_sdk_retries() -> None:
    session = _credential_session(
        "before-call.sso.GetRoleCredentials",
        retries={"mode": "standard", "total_max_attempts": 2},
    )
    with pytest.raises(
        LiveProviderError, match="DIRECT_SSO_CREDENTIAL_RETRIES_FORBIDDEN"
    ):
        _validate_direct_sso_profile(
            session,
            profile_name=AUTHORITY_PROFILE,
            account_id=ACCOUNT,
            sso_role_name_digest=canonical_digest(AUTHORITY_ROLE),
            region="us-east-1",
            opened_at=NOW,
            required_end=NOW + timedelta(minutes=29),
            observe_credential_bootstrap=True,
        )
    assert session._emitter.handlers == {}


def test_inventory_client_session_uses_static_exact_temporary_credentials() -> None:
    frozen = SimpleNamespace(
        access_key="ASIAREVIEWEDSESSION",
        secret_key="synthetic-secret-never-persisted",
        token="synthetic-session-token-never-persisted",
    )
    supplied: dict[str, str] = {}

    class ExplicitSession:
        region_name = "us-east-1"

        def get_credentials(self) -> Any:
            return SimpleNamespace(
                method="explicit",
                get_frozen_credentials=lambda: frozen,
            )

    def session_factory(**kwargs: str) -> ExplicitSession:
        supplied.update(kwargs)
        assert "profile_name" not in kwargs
        return ExplicitSession()

    session = _frozen_client_session(
        session_factory,
        frozen,
        region="us-east-1",
    )
    assert isinstance(session, ExplicitSession)
    assert supplied == {
        "aws_access_key_id": frozen.access_key,
        "aws_secret_access_key": frozen.secret_key,
        "aws_session_token": frozen.token,
        "region_name": "us-east-1",
    }


def test_frozen_client_session_cannot_reread_a_profile_changed_after_bootstrap() -> None:
    bootstrap = _credential_session()
    _, _, frozen = _validate_direct_sso_profile(
        bootstrap,
        profile_name=AUTHORITY_PROFILE,
        account_id=ACCOUNT,
        sso_role_name_digest=canonical_digest(AUTHORITY_ROLE),
        region="us-east-1",
        opened_at=NOW,
        required_end=NOW + timedelta(minutes=29),
        observe_credential_bootstrap=True,
    )
    bootstrap._session.full_config["profiles"][AUTHORITY_PROFILE].update(
        {
            "sso_account_id": OTHER_ACCOUNT,
            "region": "us-west-2",
            "endpoint_url": "https://changed-after-validation.invalid",
        }
    )
    supplied: dict[str, str] = {}

    class ExplicitSession:
        region_name = "us-east-1"

        def get_credentials(self) -> Any:
            return SimpleNamespace(
                method="explicit",
                get_frozen_credentials=lambda: frozen,
            )

    def session_factory(**kwargs: str) -> ExplicitSession:
        supplied.update(kwargs)
        assert "profile_name" not in kwargs
        return ExplicitSession()

    session = _frozen_client_session(
        session_factory,
        frozen,
        region="us-east-1",
    )

    assert isinstance(session, ExplicitSession)
    assert "profile_name" not in supplied
    assert supplied["region_name"] == "us-east-1"
    assert "changed-after-validation.invalid" not in canonical_json(supplied)


@pytest.mark.parametrize(
    "events",
    (
        ("before-call.sso-oidc.CreateToken",),
        (
            "before-call.sso.GetRoleCredentials",
            "before-call.sso.GetRoleCredentials",
        ),
    ),
)
def test_direct_sso_bootstrap_rejects_refresh_or_multiple_vends(
    events: tuple[str, ...],
) -> None:
    session = _credential_session(*events)
    with pytest.raises(
        LiveProviderError, match="DIRECT_SSO_CREDENTIAL_BOOTSTRAP_FORBIDDEN"
    ):
        _validate_direct_sso_profile(
            session,
            profile_name=AUTHORITY_PROFILE,
            account_id=ACCOUNT,
            sso_role_name_digest=canonical_digest(AUTHORITY_ROLE),
            region="us-east-1",
            opened_at=NOW,
            required_end=NOW + timedelta(minutes=29),
            observe_credential_bootstrap=True,
        )
    assert session._emitter.handlers == {}


def test_direct_sso_expiry_must_cover_the_policy_window() -> None:
    factory, calls, opened, _, _ = injected(
        {}, session_expires_at=NOW + timedelta(minutes=29)
    )
    rendered = policy()
    with pytest.raises(LiveProviderError, match="DIRECT_SSO_SESSION_EXPIRY_INVALID"):
        factory.build_authority(
            profile=AUTHORITY_PROFILE,
            ledger=FakeLedger(),
            capture_index=1,
            retries=0,
        ).open_sts(
            policy=rendered,
            policy_digest=canonical_digest(rendered),
            region="us-east-1",
        )
    assert calls == []
    assert opened == []


def test_same_cached_sso_credentials_bind_two_distinct_capture_sessions() -> None:
    handlers = {
        ("sts", "get_caller_identity"): lambda: {
            "Account": ACCOUNT,
            "Arn": AUTHORITY_PRINCIPAL,
            "UserId": "AROA:operator",
        }
    }
    factory, calls, _, _, _ = injected(
        handlers,
        session_access_keys=["ASIASAMECREDENTIAL", "ASIASAMECREDENTIAL"],
    )
    ledger = CallLedger("SYNTHETIC")
    rendered = policy()
    first = factory.build_authority(
        profile=AUTHORITY_PROFILE,
        ledger=ledger,
        capture_index=1,
        retries=0,
    ).open_sts(
        policy=rendered,
        policy_digest=canonical_digest(rendered),
        region="us-east-1",
    )
    first_identity = first.get_caller_identity()
    second = factory.build_authority(
        profile=AUTHORITY_PROFILE,
        ledger=ledger,
        capture_index=2,
        retries=0,
    ).open_sts(
        policy=rendered,
        policy_digest=canonical_digest(rendered),
        region="us-east-1",
    )

    second_identity = second.get_caller_identity()

    assert first_identity["session_id_digest"] != second_identity["session_id_digest"]
    assert [item[:2] for item in calls] == [
        ("sts", "get_caller_identity"),
        ("sts", "get_caller_identity"),
    ]


def test_access_denied_is_sanitized_mapped_and_never_retried() -> None:
    def denied(**_: Any) -> Mapping[str, Any]:
        raise FakeSdkError("AccessDeniedException", "private provider detail")

    handlers = {
        ("sts", "get_caller_identity"): lambda: {
            "Account": OTHER_ACCOUNT,
            "Arn": IDENTITY_PRINCIPAL,
            "UserId": "AROA:operator",
        },
        ("sso-admin", "list_permission_sets"): lambda **_: {
            "PermissionSets": [
                "arn:aws:sso:::permissionSet/ssoins-abc123/ps-approve"
            ]
        },
        ("sso-admin", "describe_permission_set"): denied,
    }
    factory, calls, _, _, _ = injected(handlers)
    rendered = policy(
        {
            "Sid": "DiscoverExactPermissionSets",
            "Effect": "Allow",
            "Action": ["sso:ListPermissionSets", "sso:DescribePermissionSet"],
            "Resource": "*",
        }
    )
    session = factory.build_identity(
        profile=IDENTITY_PROFILE,
        ledger=FakeLedger(),
        capture_index=1,
        retries=0,
    ).open_sts(
        stage="discovery",
        policy=rendered,
        policy_digest=canonical_digest(rendered),
        region="us-east-1",
    )
    session.get_caller_identity()

    with pytest.raises(AuthorityAccessDenied) as denied_error:
        session.open_discovery().list_permission_sets(
            "arn:aws:sso:::instance/ssoins-abc123",
            ("ScanalyzeAuthorityRetireApprove", "ScanalyzeAuthorityRetireClass"),
            None,
        )

    assert "private provider detail" not in str(denied_error.value)
    assert [item[:2] for item in calls].count(
        ("sso-admin", "describe_permission_set")
    ) == 1


@pytest.mark.parametrize("boundary_present", [False, True])
def test_identity_exact_reader_normalizes_optional_permission_boundary(
    boundary_present: bool,
) -> None:
    instance = "arn:aws:sso:::instance/ssoins-abc123"
    permission_set = "arn:aws:sso:::permissionSet/ssoins-abc123/ps-approve"
    expected_boundary = {
        "ManagedPolicyArn": "arn:aws:iam::aws:policy/ReadOnlyAccess"
    }

    def boundary(**_: Any) -> Mapping[str, Any]:
        if not boundary_present:
            raise FakeSdkError(
                "ResourceNotFoundException", "optional boundary is absent"
            )
        return {"PermissionsBoundary": expected_boundary}

    def tags(**request: Any) -> Mapping[str, Any]:
        if "NextToken" not in request:
            return {
                "Tags": [{"Key": "first", "Value": "one"}],
                "NextToken": "second-page",
            }
        assert request["NextToken"] == "second-page"
        return {"Tags": [{"Key": "second", "Value": "two"}]}

    handlers = {
        ("sts", "get_caller_identity"): lambda: {
            "Account": OTHER_ACCOUNT,
            "Arn": IDENTITY_PRINCIPAL,
            "UserId": "AROA:operator",
        },
        ("sso-admin", "get_permissions_boundary_for_permission_set"): boundary,
        ("sso-admin", "describe_permission_set"): lambda **_: {
            "PermissionSet": {"Name": "ScanalyzeAuthorityRetireApprove"}
        },
        ("sso-admin", "list_managed_policies_in_permission_set"): lambda **_: {
            "AttachedManagedPolicies": []
        },
        (
            "sso-admin",
            "list_customer_managed_policy_references_in_permission_set",
        ): lambda **_: {"CustomerManagedPolicyReferences": []},
        ("sso-admin", "get_inline_policy_for_permission_set"): lambda **_: {},
        ("sso-admin", "list_tags_for_resource"): tags,
    }
    factory, calls, _, _, _ = injected(handlers)
    rendered = policy(
        {
            "Sid": "ReadExactPermissionSet",
            "Effect": "Allow",
            "Action": [
                "sso:DescribePermissionSet",
                "sso:ListManagedPoliciesInPermissionSet",
                "sso:ListCustomerManagedPolicyReferencesInPermissionSet",
                "sso:GetInlinePolicyForPermissionSet",
                "sso:GetPermissionsBoundaryForPermissionSet",
                "sso:ListTagsForResource",
            ],
            "Resource": [instance, permission_set],
        }
    )
    session = factory.build_identity(
        profile=IDENTITY_PROFILE,
        ledger=FakeLedger(),
        capture_index=1,
        retries=0,
    ).open_sts(
        stage="exact",
        policy=rendered,
        policy_digest=canonical_digest(rendered),
        region="us-east-1",
    )
    session.get_caller_identity()

    result = session.open_exact().read_permission_set(instance, permission_set)

    assert result["value"]["boundary"] == (
        expected_boundary if boundary_present else None
    )
    assert result["value"]["tags"] == sorted(
        (
            {
                "key_digest": canonical_digest("first"),
                "value_digest": canonical_digest("one"),
            },
            {
                "key_digest": canonical_digest("second"),
                "value_digest": canonical_digest("two"),
            },
        ),
        key=canonical_json,
    )
    assert [item[:2] for item in calls].count(
        ("sso-admin", "get_permissions_boundary_for_permission_set")
    ) == 1
    assert [item[:2] for item in calls].count(
        ("sso-admin", "list_tags_for_resource")
    ) == 2


def test_identity_exact_reader_preserves_closed_application_configuration_facts() -> None:
    instance = "arn:aws:sso:::instance/ssoins-abc123"
    application = (
        f"arn:aws:sso::{OTHER_ACCOUNT}:application/ssoins-abc123/apl-abc123"
    )
    redirect = "http://127.0.0.1:18443/callback"
    provider_arn = "arn:aws:sso::aws:applicationProvider/custom"
    actor_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{ACCOUNT}:role/source"},
                "Action": "sso-oauth:CreateTokenWithIAM",
                "Resource": "*",
            }
        ],
    }

    def tags(**request: Any) -> Mapping[str, Any]:
        if "NextToken" not in request:
            return {
                "Tags": [{"Key": "first", "Value": "one"}],
                "NextToken": "second-page",
            }
        assert request["NextToken"] == "second-page"
        return {"Tags": [{"Key": "second", "Value": "two"}]}

    handlers = {
        ("sts", "get_caller_identity"): lambda: {
            "Account": OTHER_ACCOUNT,
            "Arn": IDENTITY_PRINCIPAL,
            "UserId": "AROA:operator",
        },
        ("sso-admin", "describe_application"): lambda **_: {
            "ApplicationArn": application,
            "ApplicationProviderArn": provider_arn,
            "Name": "SyntheticAuthority",
            "ApplicationAccount": OTHER_ACCOUNT,
            "InstanceArn": instance,
            "Status": "ENABLED",
            "PortalOptions": {
                "SignInOptions": {
                    "Origin": "APPLICATION",
                    "ApplicationUrl": "http://127.0.0.1:18443",
                },
                "Visibility": "ENABLED",
            },
            "Description": "GUG-376 non-production authority application",
            "CreatedDate": NOW,
            "CreatedFrom": "us-east-1",
        },
        ("sso-admin", "list_application_authentication_methods"): lambda **_: {
            "AuthenticationMethods": [{"AuthenticationMethodType": "IAM"}]
        },
        ("sso-admin", "get_application_authentication_method"): lambda **_: {
            "AuthenticationMethod": {"Iam": {"ActorPolicy": actor_policy}}
        },
        ("sso-admin", "list_application_grants"): lambda **_: {
            "Grants": [{"GrantType": "authorization_code"}]
        },
        ("sso-admin", "get_application_grant"): lambda **_: {
            "Grant": {"AuthorizationCode": {"RedirectUris": [redirect]}}
        },
        ("sso-admin", "list_application_access_scopes"): lambda **_: {
            "Scopes": [{"Scope": "sts:identity_context"}]
        },
        ("sso-admin", "get_application_access_scope"): lambda **_: {
            "Scope": "sts:identity_context",
            "AuthorizedTargets": [instance],
        },
        ("sso-admin", "get_application_assignment_configuration"): lambda **_: {
            "AssignmentRequired": True
        },
        ("sso-admin", "list_application_assignments"): lambda **_: {
            "ApplicationAssignments": [
                {
                    "ApplicationArn": application,
                    "PrincipalId": "approved-user-id",
                    "PrincipalType": "USER",
                }
            ]
        },
        ("sso-admin", "list_tags_for_resource"): tags,
    }
    factory, _, _, _, _ = injected(handlers)
    actions = [
        "sso:DescribeApplication",
        "sso:ListApplicationAuthenticationMethods",
        "sso:GetApplicationAuthenticationMethod",
        "sso:ListApplicationGrants",
        "sso:GetApplicationGrant",
        "sso:ListApplicationAccessScopes",
        "sso:GetApplicationAccessScope",
        "sso:GetApplicationAssignmentConfiguration",
        "sso:ListApplicationAssignments",
        "sso:ListTagsForResource",
    ]
    rendered = policy(
        {
            "Sid": "ReadExactApplication",
            "Effect": "Allow",
            "Action": actions,
            "Resource": application,
        }
    )
    session = factory.build_identity(
        profile=IDENTITY_PROFILE,
        ledger=FakeLedger(),
        capture_index=1,
        retries=0,
    ).open_sts(
        stage="exact",
        policy=rendered,
        policy_digest=canonical_digest(rendered),
        region="us-east-1",
    )
    session.get_caller_identity()

    value = session.open_exact().read_application(application)["value"]

    assert value["description"] == {
        "ApplicationArn": application,
        "ApplicationProviderArn": provider_arn,
        "NameDigest": canonical_digest("SyntheticAuthority"),
        "ApplicationAccount": OTHER_ACCOUNT,
        "InstanceArn": instance,
        "Status": "ENABLED",
        "PortalOptionsDigest": canonical_digest(
            {
                "SignInOptions": {
                    "Origin": "APPLICATION",
                    "ApplicationUrl": "http://127.0.0.1:18443",
                },
                "Visibility": "ENABLED",
            }
        ),
        "DescriptionDigest": canonical_digest(
            "GUG-376 non-production authority application"
        ),
        "CreatedDate": NOW.isoformat().replace("+00:00", "Z"),
        "CreatedFrom": "us-east-1",
    }
    assert value["scopes"] == [
        {
            "authorized_targets_digest": canonical_digest([instance]),
            "scope": "sts:identity_context",
        }
    ]
    assert value["redirect_uris"] == [
        {
            "loopback_pkce": True,
            "uri_digest": canonical_digest(redirect),
        }
    ]
    assert value["tags"] == sorted(
        (
            {
                "key_digest": canonical_digest("first"),
                "value_digest": canonical_digest("one"),
            },
            {
                "key_digest": canonical_digest("second"),
                "value_digest": canonical_digest("two"),
            },
        ),
        key=canonical_json,
    )
    assert value["actor_policy"] == {
        "policy_digest": canonical_policy_digest(actor_policy)
    }


def test_identity_application_discovery_sends_only_the_bound_instance() -> None:
    instance = "arn:aws:sso:::instance/ssoins-abc123"
    application = (
        f"arn:aws:sso::{OTHER_ACCOUNT}:application/ssoins-abc123/apl-exact"
    )
    handlers = {
        ("sts", "get_caller_identity"): lambda: {
            "Account": OTHER_ACCOUNT,
            "Arn": IDENTITY_PRINCIPAL,
            "UserId": "AROA:operator",
        },
        ("sso-admin", "list_applications"): lambda **request: {
            "Applications": [
                {"ApplicationArn": application, "Name": "TargetApplication"}
            ]
        },
    }
    factory, calls, _, _, _ = injected(handlers)
    ledger = FakeLedger()
    rendered = policy(
        {
            "Sid": "DiscoverExactIdentityCenterApplication",
            "Effect": "Allow",
            "Action": "sso:ListApplications",
            "Resource": "*",
        }
    )
    session = factory.build_identity(
        profile=IDENTITY_PROFILE, ledger=ledger, capture_index=1, retries=0
    ).open_sts(
        stage="discovery",
        policy=rendered,
        policy_digest=canonical_digest(rendered),
        region="us-east-1",
    )
    session.get_caller_identity()

    page = session.open_discovery().list_applications(
        instance, "TargetApplication", None
    )

    request = next(
        value
        for service, method, value in calls
        if (service, method) == ("sso-admin", "list_applications")
    )
    assert request == {"InstanceArn": instance}
    assert page["items"] == [
        {"application_arn": application, "name": "TargetApplication"}
    ]


def test_identity_permission_set_discovery_describes_every_arn_and_filters_names() -> None:
    approve = "arn:aws:sso:::permissionSet/ssoins-abc123/ps-approve"
    classify = "arn:aws:sso:::permissionSet/ssoins-abc123/ps-classify"
    unrelated = "arn:aws:sso:::permissionSet/ssoins-abc123/ps-unrelated"
    names_by_arn = {
        approve: "ScanalyzeAuthorityRetireApprove",
        classify: "ScanalyzeAuthorityRetireClass",
        unrelated: "UnrelatedPermissionSet",
    }

    def list_permission_sets(**request: Any) -> Mapping[str, Any]:
        if "NextToken" not in request:
            return {"PermissionSets": [unrelated, approve], "NextToken": "second"}
        assert request["NextToken"] == "second"
        return {"PermissionSets": [classify]}

    def describe_permission_set(**request: Any) -> Mapping[str, Any]:
        arn = request["PermissionSetArn"]
        return {"PermissionSet": {"Name": names_by_arn[arn], "PermissionSetArn": arn}}

    handlers = {
        ("sts", "get_caller_identity"): lambda: {
            "Account": OTHER_ACCOUNT,
            "Arn": IDENTITY_PRINCIPAL,
            "UserId": "AROA:operator",
        },
        ("sso-admin", "list_permission_sets"): list_permission_sets,
        ("sso-admin", "describe_permission_set"): describe_permission_set,
    }
    factory, calls, opened, _, _ = injected(handlers)
    ledger = FakeLedger()
    rendered = policy(
        {
            "Sid": "DiscoverExactPermissionSets",
            "Effect": "Allow",
            "Action": ["sso:ListPermissionSets", "sso:DescribePermissionSet"],
            "Resource": "*",
        }
    )
    session = factory.build_identity(
        profile=IDENTITY_PROFILE, ledger=ledger, capture_index=1, retries=0
    ).open_sts(
        stage="discovery",
        policy=rendered,
        policy_digest=canonical_digest(rendered),
        region="us-east-1",
    )
    session.get_caller_identity()

    page = session.open_discovery().list_permission_sets(
        "arn:aws:sso:::instance/ssoins-abc123",
        ("ScanalyzeAuthorityRetireApprove", "ScanalyzeAuthorityRetireClass"),
        None,
    )

    assert opened == ["sts", "sso-admin"]
    assert [item[:2] for item in calls].count(("sso-admin", "list_permission_sets")) == 2
    assert [item[:2] for item in calls].count(("sso-admin", "describe_permission_set")) == 3
    assert page == {
        "items": [
            {"name": "ScanalyzeAuthorityRetireApprove", "permission_set_arn": approve},
            {"name": "ScanalyzeAuthorityRetireClass", "permission_set_arn": classify},
        ],
        "next_token": None,
        "truncated": False,
        "complete": True,
    }


def test_profile_and_retry_gates_run_before_any_sdk_session() -> None:
    factory, calls, opened, _, _ = injected({})

    with pytest.raises(LiveProviderError, match="PROFILE_BINDING_INVALID"):
        factory.build_authority(
            profile=IDENTITY_PROFILE,
            ledger=FakeLedger(),
            capture_index=1,
            retries=0,
        )
    with pytest.raises(LiveProviderError, match="PROVIDER_RETRIES_FORBIDDEN"):
        factory.build_authority(
            profile=AUTHORITY_PROFILE,
            ledger=FakeLedger(),
            capture_index=1,
            retries=1,
        )

    assert calls == []
    assert opened == []


def test_ambient_aws_override_is_rejected_before_sdk_construction() -> None:
    with pytest.raises(LiveProviderError, match="AMBIENT_AWS_OVERRIDE_FORBIDDEN"):
        injected({}, environment={"AWS_PROFILE": AUTHORITY_PROFILE})


def test_effective_domain_accounts_must_be_distinct() -> None:
    with pytest.raises(LiveProviderError, match="PROFILE_BINDING_INVALID"):
        build_injected_provider_factory(
            authority_profile=AUTHORITY_PROFILE,
            identity_center_profile=IDENTITY_PROFILE,
            authority_expected_account_id=ACCOUNT,
            authority_expected_principal_digest=canonical_digest(
                AUTHORITY_PRINCIPAL
            ),
            authority_expected_sso_role_name_digest=canonical_digest(
                AUTHORITY_ROLE
            ),
            identity_expected_account_id=ACCOUNT,
            identity_expected_principal_digest=canonical_digest(
                AUTHORITY_PRINCIPAL
            ),
            identity_expected_sso_role_name_digest=canonical_digest(
                AUTHORITY_ROLE
            ),
            authority_verification_digest=DIGEST,
            identity_authority_verification_digest=DIGEST,
            validity_gate=lambda: None,
            session_factory=lambda **_: None,
            config_factory=lambda **kwargs: kwargs,
            clock=lambda: NOW,
            environment={},
        )


def test_broad_profile_and_sso_role_names_are_rejected_before_sts() -> None:
    with pytest.raises(LiveProviderError, match="PROFILE_BINDING_INVALID"):
        build_injected_provider_factory(
            authority_profile="042360977644_ScanalyzeAuthorityBootstrapPlan",
            identity_center_profile=IDENTITY_PROFILE,
            authority_expected_account_id=ACCOUNT,
            authority_expected_principal_digest=canonical_digest(AUTHORITY_PRINCIPAL),
            authority_expected_sso_role_name_digest=canonical_digest(AUTHORITY_ROLE),
            identity_expected_account_id=OTHER_ACCOUNT,
            identity_expected_principal_digest=canonical_digest(IDENTITY_PRINCIPAL),
            identity_expected_sso_role_name_digest=canonical_digest(IDENTITY_ROLE),
            authority_verification_digest=DIGEST,
            identity_authority_verification_digest=DIGEST,
            validity_gate=lambda: None,
            session_factory=lambda **_: None,
            config_factory=lambda **kwargs: kwargs,
            clock=lambda: NOW,
            environment={},
        )

    factory, calls, opened, _, _ = injected(
        {},
        session_overrides={
            AUTHORITY_PROFILE: {"sso_role_name": "AWSAdministratorAccess"}
        },
    )
    with pytest.raises(LiveProviderError, match="DIRECT_SSO_PROFILE_REQUIRED"):
        factory.build_authority(
            profile=AUTHORITY_PROFILE,
            ledger=FakeLedger(),
            capture_index=1,
            retries=0,
        ).open_sts(
            policy=policy(),
            policy_digest=canonical_digest(policy()),
            region="us-east-1",
        )
    assert calls == []
    assert opened == []


def test_operation_omitted_from_rendered_stage_policy_is_not_dispatched() -> None:
    permission_set_arn = "arn:aws:sso:::permissionSet/ssoins-abc123/ps-approve"
    handlers = {
        ("sts", "get_caller_identity"): lambda: {
            "Account": OTHER_ACCOUNT,
            "Arn": IDENTITY_PRINCIPAL,
            "UserId": "AROA:operator",
        },
        ("sso-admin", "list_permission_sets"): lambda **_: {
            "PermissionSets": [permission_set_arn]
        },
    }
    factory, calls, _, _, _ = injected(handlers)
    rendered = policy(
        {
            "Sid": "DiscoverExactPermissionSets",
            "Effect": "Allow",
            "Action": "sso:ListPermissionSets",
            "Resource": "*",
        }
    )
    session = factory.build_identity(
        profile=IDENTITY_PROFILE,
        ledger=FakeLedger(),
        capture_index=1,
        retries=0,
    ).open_sts(
        stage="discovery",
        policy=rendered,
        policy_digest=canonical_digest(rendered),
        region="us-east-1",
    )
    session.get_caller_identity()

    with pytest.raises(LiveProviderError, match="PROVIDER_OPERATION_NOT_ALLOWED"):
        session.open_discovery().list_permission_sets(
            "arn:aws:sso:::instance/ssoins-abc123",
            ("ScanalyzeAuthorityRetireApprove", "ScanalyzeAuthorityRetireClass"),
            None,
        )

    assert [item[:2] for item in calls] == [
        ("sts", "get_caller_identity"),
        ("sso-admin", "list_permission_sets"),
    ]


def test_external_call_ledger_is_the_transcript_authority() -> None:
    handlers = {
        ("sts", "get_caller_identity"): lambda: {
            "Account": ACCOUNT,
            "Arn": AUTHORITY_PRINCIPAL,
            "UserId": "AROA:operator",
        }
    }
    factory, _, _, _, _ = injected(handlers)
    ledger = CallLedger("SYNTHETIC")
    rendered = policy()
    session = factory.build_authority(
        profile=AUTHORITY_PROFILE, ledger=ledger, capture_index=1, retries=0
    ).open_sts(policy=rendered, policy_digest=canonical_digest(rendered), region="us-east-1")
    session.get_caller_identity()

    calls, digest = ledger.finalize()
    summary = factory.transcript_summary()

    assert summary["provider_calls"] == calls == 1
    assert summary["transcript_digest"] == digest
    assert summary["aws_calls"] == 0
    assert summary["live_provider_evidence"] is False


def test_concrete_builder_rejects_unminted_execution_capability(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    for key in tuple(os.environ):
        if key.startswith("AWS_") or key in {
            "BOTO_CONFIG",
            "REQUESTS_CA_BUNDLE",
            "SSL_CERT_FILE",
            "SSL_CERT_DIR",
        }:
            monkeypatch.delenv(key)
    with pytest.raises(
        LiveProviderError, match="LIVE_REQUEST_EXECUTION_CAPABILITY_REQUIRED"
    ):
        build_live_provider_factory(
            sdk_runtime_root="/tmp/gug392-unminted-sdk-runtime",
            authority_profile=AUTHORITY_PROFILE,
            identity_center_profile=IDENTITY_PROFILE,
            authority_expected_account_id=ACCOUNT,
            authority_expected_principal_digest=canonical_digest(
                AUTHORITY_PRINCIPAL
            ),
            authority_expected_sso_role_name_digest=canonical_digest(
                AUTHORITY_ROLE
            ),
            identity_expected_account_id=OTHER_ACCOUNT,
            identity_expected_principal_digest=canonical_digest(
                IDENTITY_PRINCIPAL
            ),
            identity_expected_sso_role_name_digest=canonical_digest(
                IDENTITY_ROLE
            ),
            authority_verification_digest=DIGEST,
            identity_authority_verification_digest=DIGEST,
            execution_capability=object(),
        )
