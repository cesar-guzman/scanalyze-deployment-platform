"""Pure renderer tests using public policies and synthetic KMS metadata only."""
from __future__ import annotations

import copy
from datetime import datetime, timedelta, timezone
from fnmatch import fnmatchcase
import hashlib
import json
from pathlib import Path

import pytest

from tooling import platform_authority_workforce_ledger_factory_policy as subject


ROOT = Path(__file__).resolve().parents[2]
ACTIVE_PATH = ROOT / "policies/iam/platform-authority-gug215-workforce-ledger-factory-boundary.json"
INERT_PATH = ROOT / "policies/iam/platform-authority-gug215-workforce-ledger-factory-deny-all.json"
ACCOUNT = "042360977644"
KEY_ID = "11111111-1111-4111-8111-111111111111"
KEY = f"arn:aws:kms:us-east-1:{ACCOUNT}:key/{KEY_ID}"
FUNCTION = f"arn:aws:lambda:us-east-1:{ACCOUNT}:function:scanalyze-platform-authority-gug215-workforce-ledger-factory"
TABLE = f"arn:aws:dynamodb:us-east-1:{ACCOUNT}:table/scanalyze-platform-authority-change-set-retirements"
START = "2026-09-15T06:00:00Z"
END = "2026-09-15T06:15:00Z"
NOW = datetime(2026, 9, 15, 6, 1, tzinfo=timezone.utc)


def encode(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def digest(value):
    return hashlib.sha256(value).hexdigest()


def readback():
    return {
        "schema_version": 1, "account_id": ACCOUNT, "region": "us-east-1",
        "observed_at": "2026-09-15T06:00:00Z",
        "describe_key_request": {"KeyId": "alias/aws/dynamodb"},
        "key_metadata": {
            "AWSAccountId": ACCOUNT, "Arn": KEY, "KeyId": KEY_ID,
            "Enabled": True, "KeyState": "Enabled", "KeyUsage": "ENCRYPT_DECRYPT",
            "KeyManager": "AWS", "Origin": "AWS_KMS", "KeySpec": "SYMMETRIC_DEFAULT",
            "MultiRegion": False, "EncryptionAlgorithms": ["SYMMETRIC_DEFAULT"],
        },
    }


@pytest.fixture
def arguments():
    active, inert, captured = ACTIVE_PATH.read_bytes(), INERT_PATH.read_bytes(), encode(readback())
    return {
        "active_template_bytes": active, "expected_active_template_sha256": digest(active),
        "deny_only_template_bytes": inert, "expected_deny_only_template_sha256": digest(inert),
        "key_readback_bytes": captured, "expected_key_readback_sha256": digest(captured),
        "factory_not_before": START, "factory_not_after": END, "evaluated_at": NOW,
    }


def replace_blob(arguments, name, value, reseal=True):
    arguments[name + "_bytes"] = value
    if reseal:
        arguments["expected_" + name + "_sha256"] = digest(value)


def mutate_readback(arguments, mutate, reseal=True):
    document = json.loads(arguments["key_readback_bytes"])
    mutate(document)
    replace_blob(arguments, "key_readback", encode(document), reseal)


def test_real_renderer_returns_exact_policies_and_honest_preparation(arguments):
    result = subject.render_workforce_factory_policies(**arguments)
    assert result["status"] == "CAPTURED_NOT_AUTHENTICATED"
    assert result["decision"] == "NO-GO" and result["deployment_authorized"] is False
    assert result["source_ci_status"] == "PENDING_CONNECTED_REVALIDATION"
    assert result["runtime_binding_status"] == "PENDING_SIGNED_ARTIFACT_AND_NUMERIC_VERSION_READBACK"
    assert result["revocation_status"] == "REQUIRED_BEFORE_BROKER_ACTIVATION"
    assert result["key_binding"]["alias_binding_status"] == "CAPTURED_NOT_AUTHENTICATED"
    assert result["key_binding"]["describe_key_request"] == {"KeyId": "alias/aws/dynamodb"}
    assert result["key_binding"]["readback_sha256"] == arguments["expected_key_readback_sha256"]
    expected = arguments["active_template_bytes"].decode().replace("${ledger_kms_key_arn}", KEY)
    expected = expected.replace("${factory_not_before}", START).replace("${factory_not_after}", END)
    assert result["policies"]["active"]["document"] == json.loads(expected)
    assert result["policies"]["deny_only"]["document"] == json.loads(arguments["deny_only_template_bytes"])
    for policy in result["policies"].values():
        assert policy["json"].encode() == encode(policy["document"])
        assert policy["sha256"] == digest(encode(policy["document"]))
        assert policy["intended_attached_policy_sha256"] == policy["intended_permissions_boundary_sha256"] == policy["sha256"]
        assert policy["iam_size_chars"] == len(policy["json"]) <= 6144
    assert "RoleId" not in result and "function_version" not in result
    assert "${" not in result["policies"]["active"]["json"]


def test_input_and_output_snapshots_do_not_share_mutable_objects(arguments):
    first = subject.render_workforce_factory_policies(**arguments)
    first["policies"]["active"]["document"]["Statement"].clear()
    first["key_binding"]["describe_key_request"]["KeyId"] = "alias/other"
    second = subject.render_workforce_factory_policies(**arguments)
    assert len(second["policies"]["active"]["document"]["Statement"]) == 20
    assert second["key_binding"]["describe_key_request"] == {"KeyId": "alias/aws/dynamodb"}


@pytest.mark.parametrize("name", ["active_template", "deny_only_template", "key_readback"])
@pytest.mark.parametrize("pin", [None, 1, "", "A" * 64, "0" * 63, "0" * 65, "sha256:" + "0" * 64, "0" * 64])
def test_external_byte_pins_are_exact_and_mandatory(arguments, name, pin):
    arguments["expected_" + name + "_sha256"] = pin
    with pytest.raises(subject.WorkforceFactoryPolicyRejected):
        subject.render_workforce_factory_policies(**arguments)


@pytest.mark.parametrize("name", ["active_template", "deny_only_template", "key_readback"])
def test_changed_bytes_without_new_external_pin_reject(arguments, name):
    replace_blob(arguments, name, arguments[name + "_bytes"] + b" ", reseal=False)
    with pytest.raises(subject.WorkforceFactoryPolicyRejected):
        subject.render_workforce_factory_policies(**arguments)


@pytest.mark.parametrize("name", ["active_template", "deny_only_template", "key_readback"])
@pytest.mark.parametrize("kind", ["text", "mutable", "null"])
def test_only_immutable_byte_inputs_are_accepted(arguments, name, kind):
    data = arguments[name + "_bytes"]
    arguments[name + "_bytes"] = {"text": data.decode(), "mutable": bytearray(data), "null": None}[kind]
    with pytest.raises(subject.WorkforceFactoryPolicyRejected):
        subject.render_workforce_factory_policies(**arguments)


def test_consistent_foreign_key_substitution_still_requires_external_byte_pin(arguments):
    def change(doc):
        doc["key_metadata"]["KeyId"] = KEY_ID.replace("1", "2")
        doc["key_metadata"]["Arn"] = f"arn:aws:kms:us-east-1:{ACCOUNT}:key/" + doc["key_metadata"]["KeyId"]
    mutate_readback(arguments, change, reseal=False)
    with pytest.raises(subject.WorkforceFactoryPolicyRejected):
        subject.render_workforce_factory_policies(**arguments)


def test_whitespace_change_with_explicit_new_byte_pin_preserves_exact_semantics(arguments):
    for name in ("active_template", "deny_only_template"):
        replace_blob(arguments, name, encode(json.loads(arguments[name + "_bytes"])))
    assert subject.render_workforce_factory_policies(**arguments)["decision"] == "NO-GO"


@pytest.mark.parametrize("change", [
    "remove_origin", "remove_fas_deny", "remove_key_deny", "remove_clock", "scope_wide",
    "extra_allow", "wrong_origin", "tag_relaxation", "new_action", "placeholder_embedded",
    "placeholder_unknown", "placeholder_key", "window_operator", "empty",
])
def test_resealed_template_mutations_cannot_replace_reviewed_policy(arguments, change):
    doc = json.loads(arguments["active_template_bytes"])
    rows = {row["Sid"]: row for row in doc["Statement"]}
    remove = {"remove_origin": "DenyUnexpectedFunctionOrigin", "remove_fas_deny": "DenyDirectOrForeignKmsService",
              "remove_key_deny": "DenyOtherKeys", "remove_clock": "DenyMissingClock"}
    if change in remove:
        doc["Statement"].remove(rows[remove[change]])
    elif change == "scope_wide":
        rows["ConfigureAndReadExactLedger"]["Resource"] = "*"
    elif change == "extra_allow":
        doc["Statement"].append({"Effect": "Allow", "Action": "*", "Resource": "*"})
    elif change == "wrong_origin":
        rows["DenyUnexpectedFunctionOrigin"]["Condition"]["ArnNotEqualsIfExists"]["lambda:SourceFunctionArn"] += ":1"
    elif change == "tag_relaxation":
        del rows["CreateExactProductionLedger"]["Condition"]["StringEquals"]["aws:RequestTag/production"]
    elif change == "new_action":
        rows["ConfigureAndReadExactLedger"]["Action"].append("dynamodb:PutItem")
    elif change == "placeholder_embedded":
        rows["DescribePinnedManagedKey"]["Resource"] += "*"
    elif change == "placeholder_unknown":
        rows["DescribePinnedManagedKey"]["Resource"] = "${key}"
    elif change == "placeholder_key":
        rows["DescribePinnedManagedKey"]["${Resource}"] = rows["DescribePinnedManagedKey"].pop("Resource")
    elif change == "window_operator":
        condition = rows["DenyExpiredWindow"]["Condition"]
        condition["DateGreaterThan"] = condition.pop("DateGreaterThanEquals")
    elif change == "empty":
        doc["Statement"] = []
    replace_blob(arguments, "active_template", encode(doc))
    with pytest.raises(subject.WorkforceFactoryPolicyRejected):
        subject.render_workforce_factory_policies(**arguments)


def test_resealed_deny_only_allow_is_rejected(arguments):
    doc = json.loads(arguments["deny_only_template_bytes"])
    doc["Statement"][0]["Effect"] = "Allow"
    replace_blob(arguments, "deny_only_template", encode(doc))
    with pytest.raises(subject.WorkforceFactoryPolicyRejected):
        subject.render_workforce_factory_policies(**arguments)


@pytest.mark.parametrize("name", ["active_template", "deny_only_template", "key_readback"])
@pytest.mark.parametrize("data", [b"", b"x" * 32769, b"\xff", b'[]', b'{"a":1,"a":2}',
                                  b'{"n":NaN}', b'{"n":Infinity}', b'{"n":1e999}',
                                  b'{"a":"\\ud800"}', b'{"n":' + b'[' * 20 + b'0' + b']' * 20 + b'}',
                                  b'{"n":[' + b'0,' * 2100 + b'0]}'])
def test_pinned_but_malformed_or_unbounded_json_rejects(arguments, name, data):
    replace_blob(arguments, name, data)
    with pytest.raises(subject.WorkforceFactoryPolicyRejected) as error:
        subject.render_workforce_factory_policies(**arguments)
    assert str(error.value) == "WORKFORCE_FACTORY_POLICY_REJECTED"


@pytest.mark.parametrize("field,value", [
    ("schema_version", True), ("schema_version", 2), ("account_id", "905418363887"),
    ("region", "us-west-2"), ("describe_key_request", {"KeyId": KEY}),
    ("describe_key_request", {"KeyId": "alias/aws/s3"}),
    ("describe_key_request", {"KeyId": "alias/aws/dynamodb", "GrantTokens": []}),
    ("key_metadata", None), ("observed_at", "2026-09-15T06:00:00+00:00"),
    ("observed_at", "2026-09-15T06:00:00.1Z"), ("observed_at", "2026-02-30T06:00:00Z"),
])
def test_resealed_request_or_capture_scope_swap_is_rejected(arguments, field, value):
    mutate_readback(arguments, lambda doc: doc.__setitem__(field, value))
    with pytest.raises(subject.WorkforceFactoryPolicyRejected):
        subject.render_workforce_factory_policies(**arguments)


@pytest.mark.parametrize("field", list(readback()))
def test_readback_required_fields_cannot_be_omitted(arguments, field):
    mutate_readback(arguments, lambda doc: doc.pop(field))
    with pytest.raises(subject.WorkforceFactoryPolicyRejected):
        subject.render_workforce_factory_policies(**arguments)


@pytest.mark.parametrize("field", ["deployment_authorized", "RoleId", "function_version", "identity", "authority"])
def test_readback_cannot_inject_promotion_or_new_authority(arguments, field):
    mutate_readback(arguments, lambda doc: doc.__setitem__(field, True))
    with pytest.raises(subject.WorkforceFactoryPolicyRejected):
        subject.render_workforce_factory_policies(**arguments)


@pytest.mark.parametrize("field,value", [
    ("AWSAccountId", "905418363887"), ("Arn", KEY.replace("us-east-1", "us-west-2")),
    ("Arn", KEY.replace(ACCOUNT, "905418363887")), ("Arn", KEY + "*"),
    ("Arn", "alias/aws/dynamodb"), ("KeyId", "22222222-2222-4222-8222-222222222222"),
    ("KeyId", True), ("Enabled", 1), ("Enabled", False), ("KeyState", "PendingDeletion"),
    ("KeyUsage", "SIGN_VERIFY"), ("KeyManager", "CUSTOMER"), ("Origin", "EXTERNAL"),
    ("KeySpec", "RSA_2048"), ("MultiRegion", 0), ("MultiRegion", True),
    ("EncryptionAlgorithms", ["SYMMETRIC_DEFAULT", "RSAES_OAEP_SHA_256"]),
    ("CustomerMasterKeySpec", "RSA_2048"), ("Description", 1), ("Description", "x" * 8193),
    ("CurrentKeyMaterialId", "A" * 64), ("CurrentKeyMaterialId", "0" * 63),
    ("CreationDate", True), ("CreationDate", -1), ("CreationDate", "2026-09-14T00:00:00"),
    ("CreationDate", "2026-09-14T01:00:00+01:00"), ("CreationDate", None),
])
def test_resealed_incompatible_key_metadata_is_rejected(arguments, field, value):
    mutate_readback(arguments, lambda doc: doc["key_metadata"].__setitem__(field, value))
    with pytest.raises(subject.WorkforceFactoryPolicyRejected):
        subject.render_workforce_factory_policies(**arguments)


@pytest.mark.parametrize("field", list(readback()["key_metadata"]))
def test_required_key_control_cannot_be_omitted(arguments, field):
    mutate_readback(arguments, lambda doc: doc["key_metadata"].pop(field))
    with pytest.raises(subject.WorkforceFactoryPolicyRejected):
        subject.render_workforce_factory_policies(**arguments)


@pytest.mark.parametrize("field", ["CustomKeyStoreId", "CloudHsmClusterId", "DeletionDate", "ValidTo",
    "ExpirationModel", "MultiRegionConfiguration", "PendingDeletionWindowInDays", "SigningAlgorithms",
    "KeyAgreementAlgorithms", "MacAlgorithms", "XksKeyConfiguration", "Unexpected"])
def test_extra_key_controls_reject_even_when_null(arguments, field):
    mutate_readback(arguments, lambda doc: doc["key_metadata"].__setitem__(field, None))
    with pytest.raises(subject.WorkforceFactoryPolicyRejected):
        subject.render_workforce_factory_policies(**arguments)


@pytest.mark.parametrize("created", [1720000000, 1720000000.123, "2024-07-03T09:46:40.123Z", "2024-07-03T09:46:40.123+00:00"])
def test_documented_optional_key_metadata_does_not_break_capture(arguments, created):
    mutate_readback(arguments, lambda doc: doc["key_metadata"].update({
        "CreationDate": created, "Description": "", "CustomerMasterKeySpec": "SYMMETRIC_DEFAULT",
        "CurrentKeyMaterialId": "a" * 64,
    }))
    assert subject.render_workforce_factory_policies(**arguments)["key_binding"]["key_arn"] == KEY


@pytest.mark.parametrize("observed,offset,accepted", [
    ("2026-09-15T05:56:00Z", timedelta(0), True),
    ("2026-09-15T05:56:00Z", timedelta(microseconds=1), False),
    ("2026-09-15T05:55:59Z", timedelta(0), False),
    ("2026-09-15T06:01:00Z", timedelta(0), True),
    ("2026-09-15T06:01:01Z", timedelta(0), False),
])
def test_captured_freshness_includes_300_seconds_without_rounding(arguments, observed, offset, accepted):
    mutate_readback(arguments, lambda doc: doc.__setitem__("observed_at", observed))
    arguments["evaluated_at"] += offset
    if accepted:
        assert subject.render_workforce_factory_policies(**arguments)["deployment_authorized"] is False
    else:
        with pytest.raises(subject.WorkforceFactoryPolicyRejected):
            subject.render_workforce_factory_policies(**arguments)


@pytest.mark.parametrize("field,value", [
    ("factory_not_before", START.replace("Z", "+00:00")), ("factory_not_before", START.replace("Z", ".001Z")),
    ("factory_not_after", END.replace("Z", ".001Z")), ("factory_not_before", "2026-09-15T06:15:00Z"),
    ("factory_not_after", "2026-09-15T06:15:01Z"), ("factory_not_after", "2026-09-15T06:00:00Z"),
    ("factory_not_after", "2026-09-15T06:01:00Z"), ("factory_not_after", None),
    ("evaluated_at", NOW.replace(tzinfo=None)), ("evaluated_at", START),
    ("evaluated_at", NOW.astimezone(timezone(timedelta(hours=1)))),
])
def test_closed_window_and_aware_utc_evaluation_fail_closed(arguments, field, value):
    arguments[field] = value
    with pytest.raises(subject.WorkforceFactoryPolicyRejected):
        subject.render_workforce_factory_policies(**arguments)


def test_future_window_is_preparable_but_never_activated(arguments):
    arguments.update(factory_not_before="2026-09-15T07:00:00Z", factory_not_after="2026-09-15T07:15:00Z")
    result = subject.render_workforce_factory_policies(**arguments)
    assert result["factory_window"]["not_before"] == "2026-09-15T07:00:00Z"
    assert result["decision"] == "NO-GO"


def strings(value):
    return value if isinstance(value, list) else [value]


def condition(operator, name, values, context):
    present = name in context
    if operator == "Null":
        return (not present) == (values == "true")
    optional = operator.endswith("IfExists")
    base = operator.removesuffix("IfExists")
    if not present:
        return optional
    actual = context[name]
    if base in ("StringEquals", "ArnEquals", "Bool"):
        return str(actual).lower() in [str(value).lower() for value in strings(values)] if base == "Bool" else actual in strings(values)
    if base in ("StringNotEquals", "ArnNotEquals"):
        return actual not in strings(values)
    if base.startswith("Date"):
        left = datetime.fromisoformat(actual.replace("Z", "+00:00"))
        right = datetime.fromisoformat(values.replace("Z", "+00:00"))
        return {"DateLessThan": left < right, "DateGreaterThanEquals": left >= right}[base]
    raise AssertionError("unimplemented condition used by test")


def explicit_denied(document, action, resource, context):
    for row in document["Statement"]:
        if row["Effect"] != "Deny":
            continue
        if "Action" in row and not any(fnmatchcase(action, item) for item in strings(row["Action"])):
            continue
        if "NotAction" in row and any(fnmatchcase(action, item) for item in strings(row["NotAction"])):
            continue
        if "Resource" in row and not any(fnmatchcase(resource, item) for item in strings(row["Resource"])):
            continue
        if "NotResource" in row and any(fnmatchcase(resource, item) for item in strings(row["NotResource"])):
            continue
        if all(condition(operator, name, values, context)
               for operator, fields in row.get("Condition", {}).items() for name, values in fields.items()):
            return True
    return False


FAS = {"aws:CurrentTime": "2026-09-15T06:01:00Z", "kms:ViaService": "dynamodb.us-east-1.amazonaws.com",
       "kms:CallerAccount": ACCOUNT, "kms:GrantIsForAWSResource": "true"}
DIRECT = {"aws:CurrentTime": "2026-09-15T06:01:00Z", "lambda:SourceFunctionArn": FUNCTION}


@pytest.mark.parametrize("sid,action,resource,context", [
    ("DenyUnexpectedFunctionOrigin", "dynamodb:DescribeTable", TABLE, {"aws:CurrentTime": FAS["aws:CurrentTime"]}),
    ("DenyOtherKeys", "kms:Decrypt", KEY.replace("11111111", "22222222", 1), FAS),
    ("DenyOtherTables", "dynamodb:DescribeTable", TABLE + "-other", DIRECT),
    ("DenyDirectOrForeignKmsService", "kms:Decrypt", KEY, {key: value for key, value in FAS.items() if key != "kms:ViaService"}),
    ("DenyForeignKmsCallerAccount", "kms:Decrypt", KEY, {**FAS, "kms:CallerAccount": "905418363887"}),
    ("DenyNonServiceGrant", "kms:CreateGrant", KEY, {**FAS, "kms:GrantIsForAWSResource": "false"}),
    ("DenyForeignFasOriginWhenPresent", "kms:Decrypt", KEY, {**FAS, "lambda:SourceFunctionArn": FUNCTION + ":1"}),
    ("DenyMissingClock", "kms:Decrypt", KEY, {key: value for key, value in FAS.items() if key != "aws:CurrentTime"}),
    ("DenyBeforeWindow", "kms:Decrypt", KEY, {**FAS, "aws:CurrentTime": "2026-09-15T05:59:59.999999Z"}),
    ("DenyExpiredWindow", "kms:Decrypt", KEY, {**FAS, "aws:CurrentTime": END}),
])
def test_rendered_explicit_denies_survive_external_allow_causally(arguments, sid, action, resource, context):
    policy = subject.render_workforce_factory_policies(**arguments)["policies"]["active"]["document"]
    # An external Allow cannot override an applicable explicit Deny. Removing
    # only its named statement makes the same external Allow effective here.
    external = {"Effect": "Allow", "Action": "*", "Resource": "*"}
    policy["Statement"].append(external)
    assert explicit_denied(policy, action, resource, context)
    control = copy.deepcopy(policy)
    control["Statement"] = [row for row in control["Statement"] if row.get("Sid") != sid]
    assert not explicit_denied(control, action, resource, context)


def test_date_start_inclusive_expiry_exclusive_in_rendered_policy(arguments):
    policy = subject.render_workforce_factory_policies(**arguments)["policies"]["active"]["document"]
    assert not explicit_denied(policy, "kms:Decrypt", KEY, {**FAS, "aws:CurrentTime": START})
    assert not explicit_denied(policy, "kms:Decrypt", KEY, {**FAS, "aws:CurrentTime": "2026-09-15T06:14:59.999999Z"})
    assert explicit_denied(policy, "kms:Decrypt", KEY, {**FAS, "aws:CurrentTime": END})


def test_inert_policy_denies_every_capability_even_with_external_allow(arguments):
    policy = subject.render_workforce_factory_policies(**arguments)["policies"]["deny_only"]["document"]
    policy["Statement"].append({"Effect": "Allow", "Action": "*", "Resource": "*"})
    for action, resource, context in [("dynamodb:CreateTable", TABLE, DIRECT), ("kms:CreateGrant", KEY, FAS)]:
        assert explicit_denied(policy, action, resource, context)


def test_prepare_from_repo_wires_deny_all_path_and_stays_no_go(arguments):
    """Repo loader must bind the canonical deny-all file into PREPARED offline output."""
    assert subject.WORKFORCE_FACTORY_DENY_ALL_POLICY_RELPATH.endswith(
        "platform-authority-gug215-workforce-ledger-factory-deny-all.json"
    )
    assert INERT_PATH.as_posix().endswith(subject.WORKFORCE_FACTORY_DENY_ALL_POLICY_RELPATH)
    plan = subject.prepare_workforce_factory_policy_plan(
        repo_root=ROOT,
        key_readback_bytes=arguments["key_readback_bytes"],
        expected_key_readback_sha256=arguments["expected_key_readback_sha256"],
        factory_not_before=START,
        factory_not_after=END,
        evaluated_at=NOW,
    )
    assert plan["deployment_authorized"] is False
    assert plan["decision"] == "NO-GO"
    assert plan["installation_performed"] is False
    assert plan["preparation_status"] == "PREPARED_DENY_ALL_AND_ACTIVE_BOUND_OFFLINE"
    assert plan["deny_all_source"] == subject.WORKFORCE_FACTORY_DENY_ALL_POLICY_RELPATH
    assert plan["policies"]["deny_only"]["document"] == json.loads(INERT_PATH.read_text(encoding="utf-8"))
    assert plan["source_pins"]["deny_only_semantic_sha256"] == subject._INERT_SEMANTIC_SHA256


def test_prepare_rejects_non_directory_repo_root(arguments):
    with pytest.raises(subject.WorkforceFactoryPolicyRejected):
        subject.prepare_workforce_factory_policy_plan(
            repo_root=INERT_PATH,
            key_readback_bytes=arguments["key_readback_bytes"],
            expected_key_readback_sha256=arguments["expected_key_readback_sha256"],
            factory_not_before=START,
            factory_not_after=END,
            evaluated_at=NOW,
        )
