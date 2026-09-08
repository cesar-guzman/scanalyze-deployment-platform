"""Honest Identity Center observations and closed KMS permission selection.

NOT_OBSERVED is an internal observation state, never an AWS KeyType or a claim
that encryption is enabled. It admits only the no-Identity-Center-KMS capability.
Artifact/ledger encryption and the surrounding identity, approval and recovery
contracts are independent and remain mandatory. This module performs no I/O.
"""

from __future__ import annotations

from collections.abc import Mapping
import re
from typing import Any


NOT_OBSERVED = "NOT_OBSERVED"
AWS_OWNED = "AWS_OWNED_KMS_KEY"
CUSTOMER_MANAGED = "CUSTOMER_MANAGED_KEY"
KMS_MODES = frozenset({NOT_OBSERVED, AWS_OWNED, CUSTOMER_MANAGED})
_ACCOUNT = re.compile(r"^[0-9]{12}$")
_KEY = re.compile(
    r"^arn:aws:kms:us-east-1:([0-9]{12}):key/"
    r"(?:[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}|"
    r"mrk-[0-9a-f]{32})$"
)
_PROJECTION_FIELDS = frozenset({"KeyType", "KmsKeyArn", "EncryptionStatus"})


def _invalid() -> None:
    # Error text never includes a private ARN or response payload.
    raise ValueError("IDENTITY_CENTER_ENCRYPTION_INVALID")


def validate_binding(
    mode: Any,
    key_arn: Any,
    *,
    owner_account_id: str | None = None,
) -> tuple[str, str | None]:
    """Validate a sealed observation selector; never infer a key type."""

    if owner_account_id is not None and (
        not isinstance(owner_account_id, str)
        or _ACCOUNT.fullmatch(owner_account_id) is None
    ):
        _invalid()
    if not isinstance(mode, str) or mode not in KMS_MODES:
        _invalid()
    if mode in {NOT_OBSERVED, AWS_OWNED}:
        if key_arn is not None:
            _invalid()
        return mode, None
    if not isinstance(key_arn, str):
        _invalid()
    match = _KEY.fullmatch(key_arn)
    if match is None or (
        owner_account_id is not None and match.group(1) != owner_account_id
    ):
        _invalid()
    return CUSTOMER_MANAGED, key_arn


def observe(
    response: Mapping[str, Any],
    *,
    owner_account_id: str | None = None,
) -> tuple[str, str | None]:
    """Read SDK evidence: an absent block is not an enabled/owned-key claim.

    A present null, partial block, unrecognized mode, or non-enabled status is
    invalid. NOT_OBSERVED cannot be supplied as an AWS-reported KeyType.
    """

    if not isinstance(response, Mapping):
        _invalid()
    if "EncryptionConfigurationDetails" not in response:
        return validate_binding(
            NOT_OBSERVED, None, owner_account_id=owner_account_id
        )
    details = response["EncryptionConfigurationDetails"]
    if not isinstance(details, Mapping):
        _invalid()
    mode = details.get("KeyType")
    if (
        mode not in (AWS_OWNED, CUSTOMER_MANAGED)
        or details.get("EncryptionStatus") != "ENABLED"
    ):
        _invalid()
    return validate_binding(
        mode, details.get("KmsKeyArn"), owner_account_id=owner_account_id
    )


def project(
    response: Mapping[str, Any],
    *,
    owner_account_id: str | None = None,
) -> dict[str, Any] | None:
    """Project the observation; None explicitly preserves a missing block."""

    mode, key_arn = observe(response, owner_account_id=owner_account_id)
    if mode == NOT_OBSERVED:
        return None
    return {
        "KeyType": mode,
        "KmsKeyArn": key_arn,
        "EncryptionStatus": "ENABLED",
    }


def validate_projection(
    projection: Any,
    *,
    owner_account_id: str | None = None,
) -> tuple[str, str | None]:
    """Validate normalized evidence, not an arbitrary raw SDK response.

    Producers must use project() so a raw null is not silently normalized into
    an absent block. Consumers still bind this projection to attested source.
    """

    if projection is None:
        return validate_binding(
            NOT_OBSERVED, None, owner_account_id=owner_account_id
        )
    if not isinstance(projection, Mapping) or set(projection) != _PROJECTION_FIELDS:
        _invalid()
    return observe(
        {"EncryptionConfigurationDetails": projection},
        owner_account_id=owner_account_id,
    )


def permits_kms(
    mode: Any,
    key_arn: Any,
    *,
    owner_account_id: str | None = None,
) -> bool:
    """Only an explicitly observed, validated CMK can select KMS grants."""

    validated_mode, _ = validate_binding(
        mode, key_arn, owner_account_id=owner_account_id
    )
    return validated_mode == CUSTOMER_MANAGED


def collector_binding(
    projection: Any, *, owner_account_id: str | None = None
) -> tuple[str, str | None]:
    """Validate the collector's lowercase projection without adding evidence."""

    if projection is None:
        return validate_projection(None, owner_account_id=owner_account_id)
    if not isinstance(projection, Mapping) or set(projection) != {
        "key_type", "kms_key_arn", "status"
    }:
        _invalid()
    return validate_projection(
        {
            "KeyType": projection["key_type"],
            "KmsKeyArn": projection["kms_key_arn"],
            "EncryptionStatus": projection["status"],
        },
        owner_account_id=owner_account_id,
    )


def expected_collector_projection(
    mode: Any, key_arn: Any, *, owner_account_id: str | None = None
) -> dict[str, Any] | None:
    """Build an expectation for comparison, never an observed instance."""

    validated_mode, validated_key = validate_binding(
        mode, key_arn, owner_account_id=owner_account_id
    )
    if validated_mode == NOT_OBSERVED:
        return None
    return {
        "key_type": validated_mode,
        "kms_key_arn": validated_key,
        "status": "ENABLED",
    }
