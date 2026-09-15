"""Synthetic public metadata; no DNS or cloud calls."""
from copy import deepcopy
import json
import shlex

import pytest

from tooling.production_dns_handoff import API, APP, build_plan, main


@pytest.fixture
def metadata():
    aws_zone = {"HostedZone": {"Id": "/hostedzone/ZSYNTHETIC", "Name": APP, "Config": {"PrivateZone": False}}, "DelegationSet": {"NameServers": ["ns-1.awsdns-1.com", "ns-2.awsdns-2.net", "ns-3.awsdns-3.org", "ns-4.awsdns-4.co.uk"]}}
    cert = {"Certificate": {"CertificateArn": "arn:aws:acm:us-east-1:905418363887:certificate/00000000-0000-0000-0000-000000000001", "DomainName": API[:-1], "SubjectAlternativeNames": [API[:-1]], "Type": "AMAZON_ISSUED", "Status": "PENDING_VALIDATION", "DomainValidationOptions": [{"DomainName": API[:-1], "ValidationMethod": "DNS", "ResourceRecord": {"Name": "_abc.api.scanalyze.cloud.", "Type": "CNAME", "Value": "_def.acm-validations.aws."}}]}}
    gcp_zone = {"name": "scanalyze-cloud", "dnsName": "scanalyze.cloud.", "visibility": "public", "nameServers": [f"ns-cloud-a{i}.googledomains.com." for i in range(1, 5)]}
    records = [{"name": "scanalyze.cloud.", "type": "NS", "ttl": 21600, "rrdatas": gcp_zone["nameServers"]}, {"name": "dev.scanalyze.cloud.", "type": "NS", "ttl": 300, "rrdatas": ["ns-99.awsdns-1.org."]}]
    return aws_zone, cert, gcp_zone, records


def test_additions_preserve_apex_and_dev_without_mutating_observations(metadata):
    before = deepcopy(metadata)
    plan = build_plan(*metadata)
    assert metadata == before
    assert plan["status"] == "REVIEW_ONLY_NOT_EXECUTED"
    assert {item["name"] for item in plan["additions"]} == {APP, "_abc.api.scanalyze.cloud."}
    assert plan["deletions"] == []
    assert len(plan["commands"]) == 5
    assert all("--project cs-poc-j1zdh7qfprmlptav4v1vkka" in command for command in plan["commands"])


def test_identical_existing_records_need_no_transaction(metadata):
    additions = build_plan(*metadata)["additions"]
    metadata[3].extend(additions)
    assert build_plan(*metadata)["commands"] == []


def test_acm_routing_label_preserves_observed_validation_destination(metadata):
    value = "_" + "d" * 32 + ".wzccmgtwzk.acm-validations.aws."
    metadata[1]["Certificate"]["DomainValidationOptions"][0]["ResourceRecord"]["Value"] = value
    plan = build_plan(*metadata)
    assert plan["additions"][1]["rrdatas"] == [value]
    assert plan["deletions"] == []


@pytest.mark.parametrize("value", [
    "_def.wzccmgtwzk.acm-validations.aws.attacker.example.",
    "_def.wzccmgtwzk.notacm-validations.aws.",
    "_def.-bad.acm-validations.aws.",
    "_def.bad-.acm-validations.aws.",
    "_def." + "a" * 64 + ".acm-validations.aws.",
    "_def.a.b.acm-validations.aws.",
])
def test_acm_routing_label_rejects_foreign_or_malformed_destination(metadata, value):
    metadata[1]["Certificate"]["DomainValidationOptions"][0]["ResourceRecord"]["Value"] = value
    with pytest.raises(ValueError, match="Unexpected ACM validation destination|Invalid DNS name"):
        build_plan(*metadata)


@pytest.mark.parametrize("case", ["parent_zone", "private_zone", "foreign_cert", "wildcard", "email", "foreign_cname", "duplicate_ns", "wrong_gcp", "conflict", "hidden_app_record", "api_delegation", "dname"])
def test_rejects_wrong_authority_and_namespace_changes(metadata, case):
    zone, cert, gcp, records = metadata
    if case == "parent_zone": zone["HostedZone"]["Name"] = "scanalyze.cloud."
    if case == "private_zone": zone["HostedZone"]["Config"]["PrivateZone"] = True
    if case == "foreign_cert": cert["Certificate"]["CertificateArn"] = cert["Certificate"]["CertificateArn"].replace("905418363887", "111111111111")
    if case == "wildcard": cert["Certificate"]["SubjectAlternativeNames"].append("*.scanalyze.cloud")
    if case == "email": cert["Certificate"]["DomainValidationOptions"][0]["ValidationMethod"] = "EMAIL"
    if case == "foreign_cname": cert["Certificate"]["DomainValidationOptions"][0]["ResourceRecord"]["Value"] = "_abc.attacker.example."
    if case == "duplicate_ns": zone["DelegationSet"]["NameServers"][1] = zone["DelegationSet"]["NameServers"][0]
    if case == "wrong_gcp": gcp["name"] = "other-zone"
    if case == "conflict": records.append({"name": APP, "type": "A", "ttl": 300, "rrdatas": ["192.0.2.1"]})
    if case == "hidden_app_record": records.append({"name": "existing." + APP, "type": "A", "ttl": 300, "rrdatas": ["192.0.2.1"]})
    if case == "api_delegation": records.append({"name": API, "type": "NS", "ttl": 300, "rrdatas": ["ns.example."]})
    if case == "dname": records.append({"name": API, "type": "DNAME", "ttl": 300, "rrdatas": ["example.org."]})
    with pytest.raises(ValueError):
        build_plan(*metadata)


def _cli_args(metadata, tmp_path):
    args = []
    for field, value in zip(("hosted-zone", "certificate", "managed-zone", "records"), metadata):
        path = tmp_path / (field + ".json")
        path.write_text(json.dumps(value))
        args.extend(["--" + field, str(path)])
    return args


def test_cli_accepts_readback_files_and_rejects_without_emitting_plan(metadata, tmp_path, capsys):
    args = _cli_args(metadata, tmp_path)
    assert main(args) == 0
    assert json.loads(capsys.readouterr().out)["deletions"] == []
    (tmp_path / "records.json").write_text("{}")
    with pytest.raises(SystemExit) as error:
        main(args)
    assert error.value.code == 2
    assert capsys.readouterr().out == ""


@pytest.mark.parametrize("name,kind,data,message", [
    (APP, "A", "192.0.2.1", "Existing target record conflicts"),
    ("existing." + APP, "A", "192.0.2.1", "app descendants"),
    (API, "NS", "ns.example.", "API is delegated"),
    (API, "DNAME", "example.org.", "DNAME redirects"),
])
@pytest.mark.parametrize("spelling", ["uppercase", "no_final_dot", "both"])
def test_namespace_protection_uses_dns_name_equivalence(metadata, name, kind, data, message, spelling):
    if spelling in {"uppercase", "both"}:
        name = name.upper()
    if spelling in {"no_final_dot", "both"}:
        name = name.removesuffix(".")
    metadata[3].append({"name": name, "type": kind.lower(), "ttl": 300, "rrdatas": [data]})
    with pytest.raises(ValueError, match=message):
        build_plan(*metadata)


def test_equivalent_existing_dns_records_do_not_create_additions(metadata):
    additions = build_plan(*metadata)["additions"]
    for addition in additions:
        addition["name"] = addition["name"].upper().removesuffix(".")
        addition["type"] = addition["type"].lower()
        addition["rrdatas"] = [value.upper().removesuffix(".") for value in addition["rrdatas"]]
        addition["ttl"] = 3600
    metadata[3].extend(additions)
    before = deepcopy(metadata)
    plan = build_plan(*metadata)
    assert plan["additions"] == plan["commands"] == []
    assert metadata == before


@pytest.mark.parametrize("record", [
    {"type": "A"},
    {"name": "missing-data.scanalyze.cloud.", "type": "A", "ttl": 300},
    {"name": "outside.example.", "type": "A", "ttl": 300, "rrdatas": ["192.0.2.1"]},
    {"name": "bad..scanalyze.cloud.", "type": "A", "ttl": 300, "rrdatas": ["192.0.2.1"]},
    {"name": "app.scanalyze.cloud..", "type": "A", "ttl": 300, "rrdatas": ["192.0.2.1"]},
    {"name": "bad.scanalyze.cloud.", "type": ["A"], "ttl": 300, "rrdatas": ["192.0.2.1"]},
    {"name": "bad.scanalyze.cloud.", "type": "A", "ttl": True, "rrdatas": ["192.0.2.1"]},
    {"name": "bad.scanalyze.cloud.", "type": "A", "ttl": -1, "rrdatas": ["192.0.2.1"]},
    {"name": "bad.scanalyze.cloud.", "type": "A", "ttl": 300, "rrdatas": []},
    {"name": "bad.scanalyze.cloud.", "type": "A", "ttl": 300, "rrdatas": "192.0.2.1"},
    {"name": "bad.scanalyze.cloud.", "type": "A", "ttl": 300, "rrdatas": [None]},
])
def test_malformed_inventory_is_rejected_even_when_unrelated_to_additions(metadata, record):
    metadata[3].append(record)
    with pytest.raises(ValueError):
        build_plan(*metadata)


@pytest.mark.parametrize("identifier", ["-" * 36, "a" * 36, "00000000-0000-0000-0000-00000000000g"])
def test_rejects_malformed_certificate_identifier(metadata, identifier):
    metadata[1]["Certificate"]["CertificateArn"] = "arn:aws:acm:us-east-1:905418363887:certificate/" + identifier
    with pytest.raises(ValueError, match="identifier mismatch"):
        build_plan(*metadata)


def test_duplicate_record_set_cannot_hide_conflicting_apex_inventory(metadata):
    other_apex = deepcopy(metadata[3][0])
    other_apex["name"] = other_apex["name"].upper()
    other_apex["rrdatas"] = ["ns.example."]
    metadata[3].append(other_apex)
    with pytest.raises(ValueError, match="Duplicate DNS record set"):
        build_plan(*metadata)


def test_unrelated_wildcard_and_service_records_are_preserved(metadata):
    metadata[3].extend([
        {"name": "*.dev.scanalyze.cloud.", "type": "A", "ttl": 300, "rrdatas": ["192.0.2.1"]},
        {"name": "_dmarc.scanalyze.cloud.", "type": "TXT", "ttl": 300, "rrdatas": ['"v=DMARC1; p=reject"']},
    ])
    before = deepcopy(metadata)
    assert len(build_plan(*metadata)["additions"]) == 2
    assert metadata == before


@pytest.mark.parametrize("field,payload", [
    ("hosted-zone", '[]'),
    ("certificate", '{"Certificate": null}'),
    ("managed-zone", 'null'),
    ("records", '[{"type":"A"}]'),
    ("records", '[{"name":"scanalyze.cloud.", "name":"app.scanalyze.cloud."}]'),
    ("records", '[NaN]'),
])
def test_cli_malformed_metadata_emits_no_plan(metadata, tmp_path, capsys, field, payload):
    args = _cli_args(metadata, tmp_path)
    (tmp_path / (field + ".json")).write_text(payload)
    with pytest.raises(SystemExit) as error:
        main(args)
    assert error.value.code == 2
    output = capsys.readouterr()
    assert output.out == ""
    assert "DNS_PLAN_REJECTED" in output.err


def test_generated_gcloud_transaction_contains_exact_additions(metadata):
    plan = build_plan(*metadata)
    commands = [shlex.split(command) for command in plan["commands"]]
    assert [command[4] for command in commands] == ["start", "add", "add", "describe", "execute"]
    assert "--skip-soa-update" in commands[0]
    for command, addition in zip(commands[1:3], plan["additions"]):
        assert command[5:command.index("--name")] == addition["rrdatas"]
        assert command[command.index("--name") + 1] == addition["name"]
        assert command[command.index("--type") + 1] == addition["type"]
        assert command[command.index("--ttl") + 1] == str(addition["ttl"])
    for command in commands:
        assert command[command.index("--zone") + 1] == "scanalyze-cloud"
        assert command[command.index("--transaction-file") + 1] == "scanalyze-production-dns-transaction.yaml"


def test_owner_selected_prod_is_exact_and_the_previous_app_zone_is_rejected(metadata):
    assert APP == "prod.scanalyze.cloud."
    metadata[0]["HostedZone"]["Name"] = "app.scanalyze.cloud."
    with pytest.raises(ValueError, match="exact production subdomain"):
        build_plan(*metadata)


def test_explicit_delegation_mode_emits_only_real_ns_without_a_certificate(metadata):
    zone, _, gcp, records = metadata
    before = deepcopy(metadata)
    plan = build_plan(zone, None, gcp, records, mode="delegation")
    assert metadata == before
    assert plan["internal_certificate_arn"] is None
    assert plan["operation"] == "delegation"
    assert plan["deletions"] == []
    assert plan["additions"] == [{"name": APP, "type": "NS", "ttl": 300,
                                   "rrdatas": sorted(name + "." for name in zone["DelegationSet"]["NameServers"])}]
    assert [shlex.split(command)[4] for command in plan["commands"]] == ["start", "add", "describe", "execute"]
    records.extend(plan["additions"])
    assert build_plan(zone, None, gcp, records, mode="delegation")["commands"] == []


@pytest.mark.parametrize("mode,use_certificate", [("complete", False), ("delegation", True), ("unknown", False)])
def test_mode_is_explicit_and_cannot_silently_ignore_certificate_evidence(metadata, mode, use_certificate):
    zone, cert, gcp, records = metadata
    with pytest.raises(ValueError):
        build_plan(zone, cert if use_certificate else None, gcp, records, mode=mode)


@pytest.mark.parametrize("name,kind,data", [
    (APP.upper(), "A", "192.0.2.1"),
    ("existing." + APP, "A", "192.0.2.1"),
    ("scanalyze.cloud.", "DNAME", "example.org."),
])
def test_delegation_preserves_collision_and_parent_namespace_guards(metadata, name, kind, data):
    zone, _, gcp, records = metadata
    records.append({"name": name, "type": kind, "ttl": 300, "rrdatas": [data]})
    with pytest.raises(ValueError):
        build_plan(zone, None, gcp, records, mode="delegation")


def test_delegation_does_not_change_or_admit_api_certificate_operations(metadata):
    zone, _, gcp, records = metadata
    records.append({"name": API, "type": "NS", "ttl": 300, "rrdatas": ["ns.example."]})
    plan = build_plan(zone, None, gcp, records, mode="delegation")
    assert len(plan["additions"]) == 1
    assert plan["additions"][0]["name"] == APP


def test_delegation_cli_requires_explicit_mode_and_never_ignores_a_certificate_file(metadata, tmp_path, capsys):
    args = _cli_args(metadata, tmp_path)
    cert_index = args.index("--certificate")
    no_certificate = args[:cert_index] + args[cert_index + 2:]
    assert main(["--mode", "delegation", *no_certificate]) == 0
    assert json.loads(capsys.readouterr().out)["internal_certificate_arn"] is None
    for invalid in (no_certificate, ["--mode", "delegation", *args]):
        with pytest.raises(SystemExit) as error:
            main(invalid)
        assert error.value.code == 2
        assert capsys.readouterr().out == ""
    (tmp_path / "certificate.json").write_text("null")
    with pytest.raises(SystemExit):
        main(["--mode", "delegation", *args])
    assert capsys.readouterr().out == ""
