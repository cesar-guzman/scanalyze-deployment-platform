"""Local policy-contract checks, not AWS IAM or installed-role evidence.

Only public JSON policy sources and synthetic authorization-context values are
read. No application/SDK imports, profiles, credentials, network, cloud writes
or legacy test fixtures. The renderer below is a test harness, not an installer.
"""
from __future__ import annotations

import copy
from datetime import datetime, timedelta, timezone
from fnmatch import fnmatchcase
import json
from pathlib import Path
import re

import pytest

ROOT = Path(__file__).resolve().parents[2]
ACTIVE_PATH = ROOT / "policies/iam/platform-authority-gug215-workforce-ledger-factory-boundary.json"
INERT_PATH = ROOT / "policies/iam/platform-authority-gug215-workforce-ledger-factory-deny-all.json"
ACCOUNT = "042360977644"
REGION = "us-east-1"
TABLE = f"arn:aws:dynamodb:{REGION}:{ACCOUNT}:table/scanalyze-platform-authority-change-set-retirements"
FUNCTION = f"arn:aws:lambda:{REGION}:{ACCOUNT}:function:scanalyze-platform-authority-gug215-workforce-ledger-factory"
KEY = f"arn:aws:kms:{REGION}:{ACCOUNT}:key/11111111-1111-4111-8111-111111111111"
LOG_STREAM = f"arn:aws:logs:{REGION}:{ACCOUNT}:log-group:/aws/lambda/scanalyze-platform-authority-gug215-workforce-ledger-factory:log-stream:synthetic"
START = "2026-09-15T06:00:00Z"
END = "2026-09-15T06:15:00Z"
NOW = "2026-09-15T06:01:00Z"
PARAMETERS = {"ledger_kms_key_arn": KEY, "factory_not_before": START, "factory_not_after": END}
TAGS = {
    "managed_by": "reviewed-direct-dynamodb",
    "service": "scanalyze-platform-authority",
    "data_class": "control-metadata",
    "work_package": "GUG-215",
    "environment": "production",
    "production": "true",
    "account_id": ACCOUNT,
    "region": REGION,
}
DDB_ACTIONS = {
    "dynamodb:CreateTable", "dynamodb:TagResource", "dynamodb:PutResourcePolicy",
    "dynamodb:UpdateContinuousBackups", "dynamodb:DescribeContinuousBackups",
    "dynamodb:DescribeTable", "dynamodb:DescribeTimeToLive",
    "dynamodb:GetResourcePolicy", "dynamodb:ListTagsOfResource", "dynamodb:Scan",
}
FAS_ACTIONS = {
    "kms:Encrypt", "kms:Decrypt", "kms:ReEncryptFrom", "kms:ReEncryptTo",
    "kms:GenerateDataKey", "kms:GenerateDataKeyWithoutPlaintext", "kms:CreateGrant",
}
KMS_ACTIONS = FAS_ACTIONS | {"kms:DescribeKey"}
LOG_ACTIONS = {"logs:CreateLogStream", "logs:PutLogEvents"}


def _unique(items):
    result = {}
    for key, value in items:
        if key in result:
            raise ValueError("DUPLICATE_JSON_KEY")
        result[key] = value
    return result


def _load(path):
    return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_unique)


def _timestamp(value):
    if not isinstance(value, str) or re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", value) is None:
        raise ValueError("NONCANONICAL_WINDOW")
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


def render(parameters):
    """Exercise closed placeholder expansion; no provider or authority claim."""
    if type(parameters) is not dict or set(parameters) != set(PARAMETERS):
        raise ValueError("CLOSED_PARAMETERS_REQUIRED")
    key = parameters["ledger_kms_key_arn"]
    if not isinstance(key, str) or re.fullmatch(
        rf"arn:aws:kms:{REGION}:{ACCOUNT}:key/[0-9a-f]{{8}}-[0-9a-f]{{4}}-[0-9a-f]{{4}}-[0-9a-f]{{4}}-[0-9a-f]{{12}}", key
    ) is None:
        raise ValueError("EXACT_MANAGED_KEY_ARN_REQUIRED")
    start = _timestamp(parameters["factory_not_before"])
    end = _timestamp(parameters["factory_not_after"])
    if not timedelta(0) < end - start <= timedelta(minutes=15):
        raise ValueError("SHORT_WINDOW_REQUIRED")

    def expand(value):
        if isinstance(value, dict):
            return {key: expand(item) for key, item in value.items()}
        if isinstance(value, list):
            return [expand(item) for item in value]
        if isinstance(value, str) and "${" in value:
            match = re.fullmatch(r"\$\{([a-z_]+)\}", value)
            if match is None or match[1] not in parameters:
                raise ValueError("UNKNOWN_OR_EMBEDDED_PLACEHOLDER")
            return parameters[match[1]]
        return value

    policy = expand(_load(ACTIVE_PATH))
    if len(json.dumps(policy, ensure_ascii=True, separators=(",", ":"))) > 6144:
        raise ValueError("MANAGED_POLICY_QUOTA")
    return policy


def _strings(value):
    return value if isinstance(value, list) else [value]


def _bool(value):
    if type(value) is bool:
        return value
    if value in ("true", "false"):
        return value == "true"
    return None


def _condition(operator, name, expected, context):
    present = name in context
    actual = context.get(name)
    if operator == "Null":
        return (not present) is _bool(expected)
    if operator == "ForAllValues:StringEquals":
        return not present or all(item in _strings(expected) for item in _strings(actual))
    if operator.endswith("IfExists"):
        if not present:
            return True
        operator = operator.removesuffix("IfExists")
    if not present:
        return False
    if operator in {"StringEquals", "ArnEquals", "StringNotEquals", "ArnNotEquals"}:
        same = any(a == e for a in _strings(actual) for e in _strings(expected))
        return not same if "NotEquals" in operator else same
    if operator == "Bool":
        converted = _bool(actual)
        return converted is not None and converted is _bool(expected)
    if operator == "DateLessThan":
        return _timestamp(actual) < _timestamp(expected)
    if operator == "DateGreaterThanEquals":
        return _timestamp(actual) >= _timestamp(expected)
    raise AssertionError(f"Unsupported test evaluator operator: {operator}")


def _matches(statement, action, resource, context):
    patterns = statement.get("Action", statement.get("NotAction"))
    action_match = any(fnmatchcase(action.lower(), pattern.lower()) for pattern in _strings(patterns))
    if action_match == ("NotAction" in statement):
        return False
    patterns = statement.get("Resource", statement.get("NotResource"))
    resource_match = any(fnmatchcase(resource, pattern) for pattern in _strings(patterns))
    if resource_match == ("NotResource" in statement):
        return False
    return all(
        _condition(operator, name, value, context)
        for operator, terms in statement.get("Condition", {}).items()
        for name, value in terms.items()
    )


def allowed(attached, boundary, action, resource, context):
    """Bounded IAM algebra for these operators, not a provider simulator."""
    groups = [statement for policy in attached for statement in policy["Statement"]]
    ceiling = boundary["Statement"]
    if any(s["Effect"] == "Deny" and _matches(s, action, resource, context) for s in groups + ceiling):
        return False
    return all(any(s["Effect"] == "Allow" and _matches(s, action, resource, context) for s in statements)
               for statements in (groups, ceiling))


def direct(**changes):
    context = {"aws:CurrentTime": NOW, "lambda:SourceFunctionArn": FUNCTION,
               "aws:TagKeys": list(TAGS), "dynamodb:Select": "COUNT"}
    context.update({f"aws:RequestTag/{key}": value for key, value in TAGS.items()})
    context.update(changes)
    return context


def fas(**changes):
    context = {"aws:CurrentTime": NOW, "kms:ViaService": f"dynamodb.{REGION}.amazonaws.com",
               "kms:CallerAccount": ACCOUNT, "kms:GrantIsForAWSResource": "true"}
    context.update(changes)
    return context


@pytest.fixture
def active():
    return render(dict(PARAMETERS))


def test_exact_closed_actions_resources_and_fifteen_minute_render(active):
    actions = {action for row in active["Statement"] if row["Effect"] == "Allow" for action in _strings(row["Action"])}
    assert actions == DDB_ACTIONS | KMS_ACTIONS | LOG_ACTIONS | {"sts:GetCallerIdentity"}
    assert "dynamodb:TransactWriteItems" not in json.dumps(active)
    assert "${" not in json.dumps(active)
    assert len(json.dumps(active, separators=(",", ":"))) <= 6144
    assert len({row["Sid"] for row in active["Statement"]}) == len(active["Statement"])
    for row in active["Statement"]:
        if row["Effect"] != "Allow":
            continue
        if set(_strings(row["Action"])) <= DDB_ACTIONS:
            assert row["Resource"] == TABLE
        elif set(_strings(row["Action"])) <= KMS_ACTIONS:
            assert row["Resource"] == KEY
        elif set(_strings(row["Action"])) <= LOG_ACTIONS:
            assert row["Resource"] == LOG_STREAM.rsplit(":", 1)[0] + ":*"
        else:
            assert row["Action"] == "sts:GetCallerIdentity" and row["Resource"] == "*"


@pytest.mark.parametrize("mutation", [
    {"ledger_kms_key_arn": KEY.replace(ACCOUNT, "905418363887")},
    {"ledger_kms_key_arn": KEY.replace(REGION, "us-west-2")},
    {"ledger_kms_key_arn": "alias/aws/dynamodb"},
    {"ledger_kms_key_arn": KEY + "*"},
    {"ledger_kms_key_arn": KEY + ':17'},
    {"ledger_kms_key_arn": None},
    {"factory_not_before": START.replace("Z", "+00:00")},
    {"factory_not_before": START.replace("Z", ".000Z")},
    {"factory_not_after": START},
    {"factory_not_after": "2026-09-15T05:59:59Z"},
    {"factory_not_after": "2026-09-15T06:15:01Z"},
    {"factory_not_after": None},
    {"factory_role_arn": FUNCTION},
])
def test_render_rejects_foreign_unbounded_or_extra_inputs(mutation):
    with pytest.raises(ValueError):
        render({**PARAMETERS, **mutation})


@pytest.mark.parametrize("missing", sorted(PARAMETERS))
def test_render_rejects_each_missing_protected_input(missing):
    parameters = dict(PARAMETERS)
    del parameters[missing]
    with pytest.raises(ValueError):
        render(parameters)


@pytest.mark.parametrize("action", sorted(DDB_ACTIONS))
def test_valid_direct_dynamodb_contract(active, action):
    assert allowed([active], active, action, TABLE, direct())


@pytest.mark.parametrize("action", sorted(FAS_ACTIONS))
def test_valid_dynamodb_fas_does_not_require_unproven_origin_propagation(active, action):
    assert allowed([active], active, action, KEY, fas())
    assert allowed([active], active, action, KEY, fas(**{"lambda:SourceFunctionArn": FUNCTION}))


def test_direct_describe_key_still_requires_exact_function(active):
    assert allowed([active], active, "kms:DescribeKey", KEY, direct())
    assert not allowed([active], active, "kms:DescribeKey", KEY, fas())


@pytest.mark.parametrize("action", sorted(FAS_ACTIONS))
def test_direct_crypto_or_create_grant_is_denied_even_from_factory(active, action):
    assert not allowed([active], active, action, KEY, direct())


@pytest.mark.parametrize("field,replacement", [
    ("kms:ViaService", None), ("kms:ViaService", "s3.us-east-1.amazonaws.com"),
    ("kms:ViaService", "dynamodb.us-west-2.amazonaws.com"),
    ("kms:CallerAccount", None), ("kms:CallerAccount", "905418363887"),
    ("lambda:SourceFunctionArn", FUNCTION + ":17"),
    ("lambda:SourceFunctionArn", FUNCTION.replace("gug215", "gug365")),
])
@pytest.mark.parametrize("action", ["kms:CreateGrant", "kms:Decrypt"])
def test_missing_foreign_or_historical_fas_context_is_denied(active, field, replacement, action):
    context = fas()
    if replacement is None:
        context.pop(field, None)
    else:
        context[field] = replacement
    assert not allowed([active], active, action, KEY, context)


@pytest.mark.parametrize("value", [False, "false", None, 0, "not-a-boolean"])
def test_create_grant_requires_service_resource_binding(active, value):
    context = fas()
    if value is None:
        del context["kms:GrantIsForAWSResource"]
    else:
        context["kms:GrantIsForAWSResource"] = value
    assert not allowed([active], active, "kms:CreateGrant", KEY, context)


@pytest.mark.parametrize("key", [KEY.replace("11111111", "22222222", 1), KEY.replace(ACCOUNT, "905418363887"), "alias/aws/dynamodb"])
@pytest.mark.parametrize("action", ["kms:DescribeKey", "kms:Decrypt", "kms:CreateGrant"])
def test_no_other_key_access(active, key, action):
    context = direct() if action == "kms:DescribeKey" else fas()
    assert not allowed([active], active, action, key, context)


@pytest.mark.parametrize("value", [None, FUNCTION + ":1", FUNCTION + ":alias", FUNCTION.replace("workforce", "legacy")])
def test_direct_origin_missing_version_alias_or_foreign_rejects(active, value):
    context = direct()
    if value is None:
        del context["lambda:SourceFunctionArn"]
    else:
        context["lambda:SourceFunctionArn"] = value
    assert not allowed([active], active, "dynamodb:CreateTable", TABLE, context)
    assert not allowed([active], active, "kms:DescribeKey", KEY, context)


@pytest.mark.parametrize("key", sorted(TAGS))
@pytest.mark.parametrize("action", ["dynamodb:CreateTable", "dynamodb:TagResource"])
def test_every_exact_production_tag_is_required(active, key, action):
    context = direct()
    del context[f"aws:RequestTag/{key}"]
    assert not allowed([active], active, action, TABLE, context)
    context[f"aws:RequestTag/{key}"] = "different-synthetic-value"
    assert not allowed([active], active, action, TABLE, context)


def test_extra_tag_or_nonproduction_tags_are_denied(active):
    context = direct()
    context["aws:TagKeys"].append("unexpected")
    context["aws:RequestTag/unexpected"] = "value"
    assert not allowed([active], active, "dynamodb:CreateTable", TABLE, context)
    context = direct(**{"aws:RequestTag/environment": "non-production", "aws:RequestTag/production": "false"})
    assert not allowed([active], active, "dynamodb:CreateTable", TABLE, context)


def test_missing_tag_key_set_does_not_pass_vacuous_forall(active):
    context = direct()
    del context["aws:TagKeys"]
    assert not allowed([active], active, "dynamodb:CreateTable", TABLE, context)
    assert not allowed([active], active, "dynamodb:TagResource", TABLE, context)


@pytest.mark.parametrize("select", [None, "ALL_ATTRIBUTES", "ALL_PROJECTED_ATTRIBUTES", "SPECIFIC_ATTRIBUTES"])
def test_scan_cannot_return_document_values(active, select):
    context = direct()
    if select is None:
        del context["dynamodb:Select"]
    else:
        context["dynamodb:Select"] = select
    assert not allowed([active], active, "dynamodb:Scan", TABLE, context)


@pytest.mark.parametrize("action", [
    "dynamodb:PutItem", "dynamodb:UpdateItem", "dynamodb:DeleteItem",
    "dynamodb:BatchWriteItem", "dynamodb:PartiQLInsert", "dynamodb:PartiQLUpdate",
    "dynamodb:PartiQLDelete", "dynamodb:GetItem", "dynamodb:Query",
    "dynamodb:UntagResource", "dynamodb:DeleteTable", "dynamodb:UpdateTable",
    "dynamodb:UpdateTimeToLive", "dynamodb:DeleteResourcePolicy",
])
def test_no_item_writes_reads_or_table_repair_capability(active, action):
    assert not allowed([active], active, action, TABLE, direct())


@pytest.mark.parametrize("action,resource", [
    ("iam:PassRole", "*"), ("iam:PutRolePermissionsBoundary", "*"),
    ("sts:AssumeRole", "*"), ("lambda:InvokeFunction", FUNCTION),
    ("s3:PutObject", "*"), ("cloudformation:DeleteChangeSet", "*"),
    ("logs:CreateLogGroup", LOG_STREAM),
])
def test_no_authority_or_unrelated_service_capabilities(active, action, resource):
    assert not allowed([active], active, action, resource, direct())


@pytest.mark.parametrize("now", [None, "2026-09-15T05:59:59Z", END, "2026-09-15T06:15:01Z"])
@pytest.mark.parametrize("action,resource,context_factory", [
    ("dynamodb:CreateTable", TABLE, direct), ("kms:CreateGrant", KEY, fas), ("kms:Decrypt", KEY, fas)
])
def test_missing_clock_or_outside_window_denies_all_effect_paths(active, now, action, resource, context_factory):
    context = context_factory()
    if now is None:
        del context["aws:CurrentTime"]
    else:
        context["aws:CurrentTime"] = now
    assert not allowed([active], active, action, resource, context)


def test_window_start_is_inclusive_and_expiry_exclusive(active):
    assert allowed([active], active, "dynamodb:CreateTable", TABLE, direct(**{"aws:CurrentTime": START}))
    assert not allowed([active], active, "dynamodb:CreateTable", TABLE, direct(**{"aws:CurrentTime": END}))


def test_create_dependencies_do_not_claim_iam_can_prevent_standalone_retag_or_policy_update(active):
    # These actions are required inside CreateTable. IAM has no documented
    # request-body/hash or enclosing-CreateTable discriminator for them.
    # Signed code, absence checks, one-attempt authority and revocation remain
    # required; this policy is not a substitute for those runtime controls.
    assert allowed([active], active, "dynamodb:TagResource", TABLE, direct())
    assert allowed([active], active, "dynamodb:PutResourcePolicy", TABLE, direct())


@pytest.mark.parametrize("sid,action,resource,context", [
    ("DenyUnexpectedFunctionOrigin", "dynamodb:DescribeTable", TABLE, {"aws:CurrentTime": NOW}),
    ("DenyOtherTables", "dynamodb:DescribeTable", TABLE + "-foreign", direct()),
    ("DenyOtherKeys", "kms:Decrypt", KEY.replace("11111111", "22222222", 1), fas()),
    ("DenyOtherLogStreams", "logs:PutLogEvents", LOG_STREAM.replace("workforce-ledger-factory", "foreign-function"), direct()),
    ("DenyDirectOrForeignKmsService", "kms:Decrypt", KEY, fas(**{"kms:ViaService": "s3.us-east-1.amazonaws.com"})),
    ("DenyForeignKmsCallerAccount", "kms:Decrypt", KEY, fas(**{"kms:CallerAccount": "905418363887"})),
    ("DenyNonServiceGrant", "kms:CreateGrant", KEY, fas(**{"kms:GrantIsForAWSResource": "false"})),
    ("DenyForeignFasOriginWhenPresent", "kms:Decrypt", KEY, fas(**{"lambda:SourceFunctionArn": FUNCTION + ":1"})),
    ("DenyBeforeWindow", "dynamodb:DescribeTable", TABLE, direct(**{"aws:CurrentTime": "2026-09-15T05:59:59Z"})),
    ("DenyExpiredWindow", "dynamodb:DescribeTable", TABLE, direct(**{"aws:CurrentTime": END})),
    ("DenyMissingClock", "dynamodb:DescribeTable", TABLE, {"lambda:SourceFunctionArn": FUNCTION}),
    ("DenyOutsideFactoryActions", "dynamodb:PutItem", TABLE, direct()),
])
def test_named_explicit_deny_blocks_an_accidental_extra_allow(active, sid, action, resource, context):
    broadened = copy.deepcopy(active)
    broadened["Statement"].append({"Sid": "SyntheticExtraAllow", "Effect": "Allow", "Action": "*", "Resource": "*"})
    assert not allowed([broadened], broadened, action, resource, context)
    changed = copy.deepcopy(broadened)
    changed["Statement"] = [row for row in changed["Statement"] if row["Sid"] != sid]
    assert allowed([changed], changed, action, resource, context)


def test_inert_boundary_blocks_each_forward_transition_until_final_swap(active):
    inert = _load(INERT_PATH)
    assert inert == {"Version": "2012-10-17", "Statement": [{
        "Sid": "DenyAllWorkforceFactoryCapabilities", "Effect": "Deny", "Action": "*", "Resource": "*"
    }]}
    for attached, boundary in [([inert], inert), ([inert, active], inert), ([active], inert)]:
        assert not allowed(attached, boundary, "dynamodb:CreateTable", TABLE, direct())
        assert not allowed(attached, boundary, "kms:CreateGrant", KEY, fas())
    assert allowed([active], active, "dynamodb:CreateTable", TABLE, direct())
    # Rollback starts with the dedicated inert boundary, before detach.
    assert not allowed([active], inert, "dynamodb:CreateTable", TABLE, direct())
