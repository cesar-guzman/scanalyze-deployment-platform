"""No-I/O regression contract for missing Identity Center encryption data."""

from copy import deepcopy

import pytest

from tooling import platform_authority_identity_center_encryption as encryption


ACCOUNT = "1" * 12
KEY = f"arn:aws:kms:us-east-1:{ACCOUNT}:key/00000000-0000-0000-0000-000000000001"


def _observed(mode=encryption.AWS_OWNED, key=None):
    return {
        "EncryptionConfigurationDetails": {
            "KeyType": mode,
            "KmsKeyArn": key,
            "EncryptionStatus": "ENABLED",
        }
    }


def test_absence_is_unobserved_and_never_selects_kms():
    binding = encryption.observe({}, owner_account_id=ACCOUNT)
    assert binding == (encryption.NOT_OBSERVED, None)
    assert encryption.project({}) is None
    assert encryption.validate_projection(None) == binding
    assert encryption.permits_kms(*binding) is False


@pytest.mark.parametrize(
    ("mode", "key", "granted"),
    [(encryption.AWS_OWNED, None, False), (encryption.CUSTOMER_MANAGED, KEY, True)],
)
def test_explicit_modes_preserve_existing_semantics(mode, key, granted):
    response = _observed(mode, key)
    assert encryption.observe(response, owner_account_id=ACCOUNT) == (mode, key)
    projection = encryption.project(response, owner_account_id=ACCOUNT)
    assert projection == response["EncryptionConfigurationDetails"]
    assert encryption.validate_projection(projection) == (mode, key)
    assert encryption.permits_kms(mode, key) is granted


@pytest.mark.parametrize(
    "details", [None, {}, [], False, "", {"KeyType": "AWS_OWNED_KMS_KEY"}]
)
def test_present_invalid_block_is_not_absence(details):
    with pytest.raises(ValueError, match="^IDENTITY_CENTER_ENCRYPTION_INVALID$"):
        encryption.project({"EncryptionConfigurationDetails": details})


@pytest.mark.parametrize("status", [None, "UPDATING", "UPDATE_FAILED", "", True])
def test_unsuccessful_or_missing_status_cannot_become_unobserved(status):
    response = _observed()
    response["EncryptionConfigurationDetails"]["EncryptionStatus"] = status
    with pytest.raises(ValueError):
        encryption.observe(response)


@pytest.mark.parametrize("mode", [None, encryption.NOT_OBSERVED, "UNKNOWN", "", [], False])
def test_service_cannot_report_internal_or_invalid_key_mode(mode):
    with pytest.raises(ValueError):
        encryption.observe(_observed(mode))


@pytest.mark.parametrize("key", [KEY, "", False, [], 0])
@pytest.mark.parametrize("mode", [encryption.NOT_OBSERVED, encryption.AWS_OWNED])
def test_no_kms_modes_require_literal_null_arn(mode, key):
    with pytest.raises(ValueError):
        encryption.permits_kms(mode, key)


@pytest.mark.parametrize(
    "key",
    [
        None, "", False, KEY.replace(ACCOUNT, "2" * 12),
        KEY.replace("us-east-1", "us-west-2"), KEY.replace(":key/", ":alias/"),
    ],
)
def test_customer_key_requires_exact_bound_key(key):
    with pytest.raises(ValueError):
        encryption.observe(
            _observed(encryption.CUSTOMER_MANAGED, key), owner_account_id=ACCOUNT
        )


def test_projection_does_not_mutate_or_leak_unrelated_response_fields():
    response = _observed()
    response["unrelated"] = {"not_for_projection": True}
    original = deepcopy(response)
    assert encryption.project(response) == response["EncryptionConfigurationDetails"]
    assert response == original


def test_projection_cannot_invent_unknown_key_type():
    with pytest.raises(ValueError):
        encryption.validate_projection(
            _observed(encryption.NOT_OBSERVED)["EncryptionConfigurationDetails"]
        )


def test_observation_changes_require_a_new_binding():
    absent = encryption.observe({})
    owned = encryption.observe(_observed())
    assert absent != owned
    assert encryption.project({}) != encryption.project(_observed())


@pytest.mark.parametrize(
    ("mode", "key"),
    [(encryption.NOT_OBSERVED, None), (encryption.AWS_OWNED, None),
     (encryption.CUSTOMER_MANAGED, KEY)],
)
def test_collector_projection_round_trip_preserves_exact_state(mode, key):
    expected = encryption.expected_collector_projection(
        mode, key, owner_account_id=ACCOUNT
    )
    assert encryption.collector_binding(expected, owner_account_id=ACCOUNT) == (
        mode, key
    )
    if mode == encryption.NOT_OBSERVED:
        assert expected is None
    else:
        assert expected == {"key_type": mode, "kms_key_arn": key, "status": "ENABLED"}


@pytest.mark.parametrize(
    "projection",
    [{}, [], False,
     {"key_type": "NOT_OBSERVED", "kms_key_arn": None, "status": "ENABLED"},
     {"key_type": "AWS_OWNED_KMS_KEY", "kms_key_arn": None},
     {"key_type": "AWS_OWNED_KMS_KEY", "kms_key_arn": None,
      "status": "ENABLED", "extra": True}],
)
def test_collector_rejects_invalid_or_fabricated_projection(projection):
    with pytest.raises(ValueError, match="^IDENTITY_CENTER_ENCRYPTION_INVALID$"):
        encryption.collector_binding(projection, owner_account_id=ACCOUNT)
