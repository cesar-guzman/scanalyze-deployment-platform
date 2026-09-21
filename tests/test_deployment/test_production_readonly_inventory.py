"""No test in this module may invoke AWS; use the fixed-argv fake runner."""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
from types import SimpleNamespace

import pytest

from tooling import production_readonly_inventory as inventory


ACCOUNT = "905418363887"
PROFILE = "905418363887_AWSReadOnlyAccess"
REGION = "us-east-1"
KMS = f"arn:aws:kms:{REGION}:{ACCOUNT}:key/"
SESSION = f"arn:aws:sts::{ACCOUNT}:assumed-role/AWSReadOnlyAccess/private.user@example.com"
RAW_ERROR = f"An error occurred (AccessDenied) when calling ListRoles: {SESSION} token=PRIVATE"


def _payloads():
    return {
        ("sts", "get-caller-identity"): ACCOUNT,
        ("acm", "list-certificates"): [{"arn": f"arn:aws:acm:{REGION}:{ACCOUNT}:certificate/aaaa-bbbb",
            "domain": "api.scanalyze.cloud", "status": "ISSUED", "key_algorithm": "EC_secp384r1"}],
        ("route53", "list-hosted-zones"): [{"id": "/hostedzone/Z123", "name": "scanalyze.cloud.", "private_zone": False}],
        ("s3api", "list-buckets"): ["scanalyze-example", "dep-example", "unrelated-bucket"],
        ("kms", "list-keys"): [KMS + "aaaa", KMS + "bbbb"],
        ("iam", "list-roles"): [{"name": "ScanalyzeCustomer-Promotion", "arn": f"arn:aws:iam::{ACCOUNT}:role/ScanalyzeCustomer-Promotion",
            "AssumeRolePolicyDocument": {"unexpected": "PRIVATE"}, "email": "private.user@example.com"}],
        ("ecr", "describe-repositories"): [{"name": "dep-example/scanalyze-ingest-api",
            "arn": f"arn:aws:ecr:{REGION}:{ACCOUNT}:repository/dep-example/scanalyze-ingest-api", "mutability": "IMMUTABLE"}],
        ("dynamodb", "list-tables"): ["scanalyze-status", "dep-status", "unrelated-table"],
        ("ssm", "describe-parameters"): [{"name": "/scanalyze/runtime/parameter", "type": "SecureString", "version": 2,
            "Value": "PRIVATE", "Description": "private.user@example.com"}],
        ("ecs", "list-clusters"): [f"arn:aws:ecs:{REGION}:{ACCOUNT}:cluster/scanalyze"],
        ("cloudfront", "list-distributions"): [{"id": "E123", "status": "Deployed", "enabled": True,
            "aliases": ["app.scanalyze.cloud", "unrelated.example.com"], "Comment": "PRIVATE"},
            {"id": "E999", "status": "Deployed", "enabled": True, "aliases": ["unrelated.example.com"]}],
        ("logs", "describe-log-groups"): [{"name": "/scanalyze/runtime", "arn": f"arn:aws:logs:{REGION}:{ACCOUNT}:log-group:/scanalyze/runtime:*", "retention_days": 30}],
        ("cloudformation", "list-stacks"): [{"name": "scanalyze-baseline", "status": "CREATE_COMPLETE"},
            {"name": "deleted-stack", "status": "DELETE_COMPLETE"}],
        ("bedrock", "get-foundation-model-availability"): {"model_id": inventory.DEFAULT_MODEL_ID,
            "authorization_status": "AUTHORIZED", "agreement_status": "AVAILABLE",
            "entitlement_status": "AVAILABLE", "region_status": "AVAILABLE", "errorMessage": RAW_ERROR},
    }


class FakeAws:
    def __init__(self):
        self.calls = []
        self.payloads = _payloads()
        self.errors = {}

    def __call__(self, argv, **kwargs):
        assert isinstance(argv, list) and argv[0] == "aws"
        assert argv[argv.index("--profile") + 1] == PROFILE
        assert argv[argv.index("--region") + 1] == REGION
        assert "--query" in argv and "--no-cli-pager" in argv
        assert "--no-paginate" not in argv and "--max-items" not in argv and "--starting-token" not in argv
        assert kwargs == {"capture_output": True, "text": True, "timeout": inventory.CALL_TIMEOUT_SECONDS,
                          "check": False, "shell": False}
        # Global options are fixed by the collector, then the service and operation.
        key = (argv[8], argv[9])
        self.calls.append((key, argv))
        if key in self.errors:
            error = self.errors[key]
            if isinstance(error, Exception):
                raise error
            return SimpleNamespace(returncode=254, stdout=SESSION, stderr=error)
        if key == ("kms", "describe-key"):
            value = {"arn": argv[argv.index("--key-id") + 1], "key_manager": "CUSTOMER", "key_state": "Enabled", "KeyMaterial": "PRIVATE"}
        else:
            value = self.payloads[key]
        return SimpleNamespace(returncode=0, stdout=json.dumps(value), stderr=RAW_ERROR)


@pytest.fixture(autouse=True)
def forbid_real_subprocess(monkeypatch):
    def denied(*args, **kwargs):
        raise AssertionError("real subprocess is forbidden in inventory tests")
    monkeypatch.setattr(inventory.subprocess, "run", denied)


def _collect(fake, **kwargs):
    return inventory.collect_inventory(profile=PROFILE, region=REGION, expected_account_id=ACCOUNT, runner=fake, **kwargs)


def _args(output):
    return ["--profile", PROFILE, "--region", REGION, "--expected-account-id", ACCOUNT, "--output", str(output)]


def test_identity_is_first_and_every_response_is_projected_to_metadata():
    fake = FakeAws()
    report = _collect(fake)
    assert fake.calls[0][0] == ("sts", "get-caller-identity")
    assert fake.calls[0][1][-2:] == ["--query", "Account"]
    assert report["status"] == "METADATA_OBSERVED"
    assert report["production_authorized"] is False
    assert report["readiness"] == "NOT_EVALUATED"
    assert report["scope"]["profile"] == PROFILE
    assert report["checks"]["s3"]["items"] == ["scanalyze-example", "dep-example"]
    assert report["checks"]["dynamodb"]["items"] == ["scanalyze-status", "dep-status"]
    assert report["checks"]["cloudfront"]["items"] == [{"id": "E123", "status": "Deployed", "enabled": True, "aliases": ["app.scanalyze.cloud"]}]
    assert report["checks"]["cloudformation"]["items"] == [{"name": "scanalyze-baseline", "status": "CREATE_COMPLETE"}]
    serialized = json.dumps(report)
    for forbidden in (SESSION, "private.user@example.com", "PRIVATE", "AssumeRolePolicyDocument", "KeyMaterial", "errorMessage"):
        assert forbidden not in serialized
    acm = next(argv for (service, _), argv in fake.calls if service == "acm")
    assert json.loads(acm[acm.index("--includes") + 1])["keyTypes"] == list(inventory.ACM_KEY_TYPES)
    assert report["started_at"].endswith("Z") and report["completed_at"].endswith("Z")


@pytest.mark.parametrize("mode,code", [("denied", "AccessDenied"), ("mismatch", "ACCOUNT_MISMATCH"), ("raw_identity", "IDENTITY_INVALID")])
def test_identity_failure_stops_all_inventory_and_writes_no_report(tmp_path, monkeypatch, capsys, mode, code):
    fake = FakeAws()
    if mode == "denied": fake.errors[("sts", "get-caller-identity")] = RAW_ERROR
    if mode == "mismatch": fake.payloads[("sts", "get-caller-identity")] = "111111111111"
    if mode == "raw_identity": fake.payloads[("sts", "get-caller-identity")] = {"Account": ACCOUNT, "Arn": SESSION}
    monkeypatch.setattr(inventory.subprocess, "run", fake)
    output = tmp_path / "metadata.json"
    assert inventory.main(_args(output)) == 2
    assert len(fake.calls) == 1 and not output.exists()
    captured = capsys.readouterr()
    assert code in captured.err and captured.out == ""
    assert SESSION not in captured.err and "private.user" not in captured.err


@pytest.mark.parametrize("error,code", [
    (RAW_ERROR, "AccessDenied"), ("token=PRIVATE private.user@example.com", "AWS_CLI_FAILED"),
    (f"An error occurred (PRIVATE) when calling ListRoles: {SESSION}", "AWS_CLI_FAILED"),
    (subprocess.TimeoutExpired(["aws", SESSION], 45, stderr=RAW_ERROR), "TIMEOUT"),
    (RuntimeError(RAW_ERROR), "EXECUTION_FAILED"),
])
def test_inventory_errors_are_unknown_not_absence_or_raw_stderr(error, code):
    fake = FakeAws()
    fake.errors[("iam", "list-roles")] = error
    report = _collect(fake)
    assert report["status"] == "INCOMPLETE_METADATA"
    check = report["checks"]["iam"]
    assert check["status"] == "UNKNOWN" and check["error_code"] == code
    assert "items" not in check
    assert report["checks"]["bedrock"]["status"] == "OBSERVED"
    assert "PRIVATE" not in json.dumps(report) and "private.user" not in json.dumps(report)


def test_kms_descriptions_are_bounded_and_truncation_is_explicit():
    fake = FakeAws()
    fake.payloads[("kms", "list-keys")] = [KMS + str(i) for i in range(5)]
    report = _collect(fake, max_kms_keys=2)
    check = report["checks"]["kms"]
    assert check["status"] == "TRUNCATED" and check["truncated"] is True
    assert check["listed_key_count"] == 5 and check["omitted_key_count"] == 3
    assert len([key for key, _ in fake.calls if key == ("kms", "describe-key")]) == 2
    assert report["status"] == "INCOMPLETE_METADATA"


def test_kms_listing_denied_never_triggers_describe_or_claims_no_keys():
    fake = FakeAws()
    fake.errors[("kms", "list-keys")] = RAW_ERROR
    check = _collect(fake)["checks"]["kms"]
    assert check["status"] == "UNKNOWN" and "listed_key_count" not in check
    assert not any(key == ("kms", "describe-key") for key, _ in fake.calls)


def test_kms_description_denied_retains_partial_evidence():
    fake = FakeAws()
    fake.errors[("kms", "describe-key")] = RAW_ERROR
    check = _collect(fake)["checks"]["kms"]
    assert check["status"] == "PARTIAL" and check["truncated"] is False
    assert all(item["status"] == "UNKNOWN" and "items" not in item for item in check["items"])


@pytest.mark.parametrize("key,bad", [(("iam", "list-roles"), [{}]), (("kms", "list-keys"), None),
    (("ssm", "describe-parameters"), None), (("s3api", "list-buckets"), None),
    (("dynamodb", "list-tables"), [{}])])
def test_malformed_success_response_cannot_become_empty_observed_inventory(key, bad):
    fake = FakeAws()
    fake.payloads[key] = bad
    report = _collect(fake)
    service = "s3" if key[0] == "s3api" else key[0]
    assert report["checks"][service]["status"] == "UNKNOWN"


def test_successful_cli_writes_private_report_and_refuses_existing_output(tmp_path, monkeypatch, capsys):
    fake = FakeAws()
    monkeypatch.setattr(inventory.subprocess, "run", fake)
    output = tmp_path / "metadata.json"
    assert inventory.main(_args(output)) == 0
    assert output.stat().st_mode & 0o777 == 0o600
    original = output.read_bytes()
    fake.calls.clear()
    assert inventory.main(_args(output)) == 2
    assert not fake.calls and output.read_bytes() == original
    assert list(tmp_path.iterdir()) == [output]
    captured = capsys.readouterr()
    assert "ALREADY_EXISTS" in captured.err and SESSION not in captured.err


def test_atomic_publish_refuses_racing_writer_without_overwriting(tmp_path, monkeypatch):
    output = tmp_path / "metadata.json"
    real_link = os.link
    def race(source, destination):
        Path(destination).write_text("existing owner file")
        real_link(source, destination)
    monkeypatch.setattr(inventory.os, "link", race)
    with pytest.raises(inventory.InventoryError, match="ALREADY_EXISTS"):
        inventory.write_report({"metadata": "synthetic"}, output)
    assert output.read_text() == "existing owner file"
    assert list(tmp_path.iterdir()) == [output]


def test_output_symlink_is_refused_before_any_aws_operation(tmp_path, monkeypatch):
    fake = FakeAws()
    monkeypatch.setattr(inventory.subprocess, "run", fake)
    output = tmp_path / "metadata.json"
    output.symlink_to(tmp_path / "does-not-exist")
    assert inventory.main(_args(output)) == 2
    assert fake.calls == [] and not (tmp_path / "does-not-exist").exists()


@pytest.mark.parametrize("limit", [0, 201, -1])
def test_invalid_key_limit_fails_before_sts(limit):
    fake = FakeAws()
    with pytest.raises(inventory.InventoryError, match="SCOPE_INVALID"):
        _collect(fake, max_kms_keys=limit)
    assert fake.calls == []


def test_matching_repository_and_table_names_are_filtered_and_filter_is_recorded():
    fake = FakeAws()
    repositories = ["shared/team-scanalyze-api", "dep-unrelated", "shared/other-api"]
    fake.payloads[("ecr", "describe-repositories")] = [{"name": name,
        "arn": f"arn:aws:ecr:{REGION}:{ACCOUNT}:repository/{name}", "mutability": "IMMUTABLE"} for name in repositories]
    fake.payloads[("dynamodb", "list-tables")] = ["team-ScAnAlYzE-status", "dep-table", "other-table"]
    report = _collect(fake)
    assert [row["name"] for row in report["checks"]["ecr"]["items"]] == repositories[:2]
    assert report["checks"]["dynamodb"]["items"] == ["team-ScAnAlYzE-status", "dep-table"]
    assert "case-insensitive" in report["scope"]["filters"]["ecr"]
    assert "case-insensitive" in report["scope"]["filters"]["dynamodb"]
    assert report["scope"]["filters"]["ssm"]["values_read"] is False


def test_cloudfront_only_explicitly_accepts_omitted_items_as_empty():
    fake = FakeAws()
    fake.payloads[("cloudfront", "list-distributions")] = None
    check = _collect(fake)["checks"]["cloudfront"]
    assert check["status"] == "OBSERVED" and check["items"] == []


def test_session_arn_in_role_metadata_is_rejected_without_echo():
    fake = FakeAws()
    fake.payloads[("iam", "list-roles")][0]["arn"] = SESSION
    report = _collect(fake)
    assert report["checks"]["iam"]["status"] == "UNKNOWN"
    assert SESSION not in json.dumps(report)


def test_exact_requested_model_id_is_sent_and_rechecked():
    fake = FakeAws()
    model_id = "amazon.nova-lite-v1:0"
    fake.payloads[("bedrock", "get-foundation-model-availability")]["model_id"] = model_id
    report = _collect(fake, model_id=model_id)
    argv = fake.calls[-1][1]
    assert argv[argv.index("--model-id") + 1] == model_id
    assert report["checks"]["bedrock"]["status"] == "OBSERVED"
    assert report["checks"]["bedrock"]["items"][0]["model_id"] == model_id
    assert report["checks"]["bedrock"]["items"][0]["requested_model_id"] == model_id
    assert report["scope"]["filters"]["bedrock"]["exact_model_id"] == model_id


def test_acm_observed_response_alias_preserves_raw_metadata_and_request_filter():
    fake = FakeAws()
    original = fake.payloads[("acm", "list-certificates")][0]
    fake.payloads[("acm", "list-certificates")] = [
        {**original, "key_algorithm": algorithm}
        for algorithm in ("RSA_2048", "RSA-2048", "EC_secp384r1")
    ]
    report = _collect(fake)
    assert report["status"] == "METADATA_OBSERVED"
    assert [item["key_algorithm"] for item in report["checks"]["acm"]["items"]] == [
        "RSA_2048", "RSA-2048", "EC_secp384r1",
    ]
    argv = next(argv for key, argv in fake.calls if key == ("acm", "list-certificates"))
    key_types = json.loads(argv[argv.index("--includes") + 1])["keyTypes"]
    assert key_types == list(inventory.ACM_KEY_TYPES)
    assert "RSA-2048" not in key_types
    assert report["scope"]["filters"]["acm"]["key_types"] == key_types
    assert report["production_authorized"] is False
    assert report["readiness"] == "NOT_EVALUATED"


@pytest.mark.parametrize("algorithm", ["RSA-1024", "RSA-4096", "rsa-2048", "RSA_8192", None])
def test_acm_unreviewed_response_aliases_remain_unknown(algorithm):
    fake = FakeAws()
    fake.payloads[("acm", "list-certificates")][0]["key_algorithm"] = algorithm
    report = _collect(fake)
    check = report["checks"]["acm"]
    assert check["status"] == "UNKNOWN" and check["error_code"] == "RESPONSE_INVALID"
    assert "items" not in check and report["status"] == "INCOMPLETE_METADATA"


@pytest.mark.parametrize("region,account", [(REGION, "111111111111"), ("us-west-2", ACCOUNT)])
def test_acm_response_alias_preserves_account_and_region_binding(region, account):
    fake = FakeAws()
    fake.payloads[("acm", "list-certificates")][0].update(
        key_algorithm="RSA-2048", arn=f"arn:aws:acm:{region}:{account}:certificate/aaaa-bbbb",
    )
    report = _collect(fake)
    check = report["checks"]["acm"]
    assert check["status"] == "UNKNOWN" and check["error_code"] == "RESPONSE_INVALID"
    assert "items" not in check and report["status"] == "INCOMPLETE_METADATA"


def test_bedrock_observed_response_alias_preserves_requested_and_returned_ids():
    fake = FakeAws()
    fake.payloads[("bedrock", "get-foundation-model-availability")]["model_id"] = "amazon.nova-pro-v1"
    report = _collect(fake)
    assert report["status"] == "METADATA_OBSERVED"
    item = report["checks"]["bedrock"]["items"][0]
    assert item["model_id"] == "amazon.nova-pro-v1"
    assert item["requested_model_id"] == "amazon.nova-pro-v1:0"
    argv = fake.calls[-1][1]
    assert argv[8:10] == ["bedrock", "get-foundation-model-availability"]
    assert argv[argv.index("--model-id") + 1] == "amazon.nova-pro-v1:0"
    assert report["scope"]["model_id"] == "amazon.nova-pro-v1:0"
    assert report["scope"]["filters"]["bedrock"] == {
        "exact_model_id": "amazon.nova-pro-v1:0", "invocation_performed": False,
    }
    assert report["production_authorized"] is False
    assert report["readiness"] == "NOT_EVALUATED"


@pytest.mark.parametrize("requested,returned", [
    ("amazon.nova-pro-v1:0", "amazon.nova-lite-v1"),
    ("amazon.nova-pro-v1:0", "amazon.nova-pro-v2"),
    ("amazon.nova-pro-v1:0", "amazon.nova-pro-v1:1"),
    ("amazon.nova-pro-v1:1", "amazon.nova-pro-v1"),
    ("amazon.nova-lite-v1:0", "amazon.nova-lite-v1"),
    ("amazon.nova-pro-v1", "amazon.nova-pro-v1:0"),
    ("amazon.nova-pro-v1:0", "amazon.nova-pro-v1-extra"),
    ("amazon.nova-pro-v1:0", None),
])
def test_bedrock_unreviewed_response_aliases_remain_unknown(requested, returned):
    fake = FakeAws()
    fake.payloads[("bedrock", "get-foundation-model-availability")]["model_id"] = returned
    report = _collect(fake, model_id=requested)
    check = report["checks"]["bedrock"]
    assert check["status"] == "UNKNOWN" and check["error_code"] == "RESPONSE_INVALID"
    assert "items" not in check and report["status"] == "INCOMPLETE_METADATA"
    argv = fake.calls[-1][1]
    assert argv[argv.index("--model-id") + 1] == requested


@pytest.mark.parametrize("field,value", [
    ("authorization_status", "NOT_AUTHORIZED"),
    ("agreement_status", "NOT_AVAILABLE"),
    ("agreement_status", "PENDING"),
    ("agreement_status", "ERROR"),
    ("entitlement_status", "NOT_AVAILABLE"),
    ("region_status", "NOT_AVAILABLE"),
])
def test_bedrock_response_alias_preserves_unavailable_observations_without_readiness(field, value):
    fake = FakeAws()
    fake.payloads[("bedrock", "get-foundation-model-availability")].update(
        model_id="amazon.nova-pro-v1", **{field: value},
    )
    report = _collect(fake)
    check = report["checks"]["bedrock"]
    assert check["status"] == "OBSERVED" and check["items"][0][field] == value
    assert report["production_authorized"] is False
    assert report["readiness"] == "NOT_EVALUATED"


@pytest.mark.parametrize("field", [
    "authorization_status", "agreement_status", "entitlement_status", "region_status",
])
def test_bedrock_response_alias_preserves_closed_availability_statuses(field):
    fake = FakeAws()
    fake.payloads[("bedrock", "get-foundation-model-availability")].update(
        model_id="amazon.nova-pro-v1", **{field: "UNREVIEWED"},
    )
    report = _collect(fake)
    check = report["checks"]["bedrock"]
    assert check["status"] == "UNKNOWN" and check["error_code"] == "RESPONSE_INVALID"
    assert "items" not in check and report["status"] == "INCOMPLETE_METADATA"


def test_raw_deployment_id_roles_and_tables_match_actual_repository_naming():
    fake = FakeAws()
    deployment_id = "dep_01ARZ3NDEKTSV4RRFFQ69G5FAV"
    role = {"name": deployment_id + "-ocr-worker", "arn": f"arn:aws:iam::{ACCOUNT}:role/{deployment_id}-ocr-worker"}
    table = deployment_id + "-documents"
    fake.payloads[("iam", "list-roles")] = [role]
    fake.payloads[("dynamodb", "list-tables")] = [table]
    report = _collect(fake)
    assert report["checks"]["iam"]["items"] == [role]
    assert report["checks"]["dynamodb"]["items"] == [table]
    iam_query = next(argv[-1] for key, argv in fake.calls if key == ("iam", "list-roles"))
    assert "starts_with(RoleName, 'dep_')" in iam_query
    assert "dep_" in report["scope"]["filters"]["iam"]["role_name_prefixes"]
    assert "dep_" in report["scope"]["filters"]["dynamodb"]
    assert report["scope"]["filters"]["s3"]["name_prefixes"] == ["scanalyze-", "dep-"]
