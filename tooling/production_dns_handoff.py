"""Compile a review-only DNS transaction from public AWS/GCP metadata.

No cloud client, credentials, publication or execution is part of this module.
The fixed destination is the owner's current Scanalyze production candidate.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import shlex
from pathlib import Path

ACCOUNT = "905418363887"
REGION = "us-east-1"
PROJECT = "cs-poc-j1zdh7qfprmlptav4v1vkka"
GCP_ZONE = "scanalyze-cloud"
PARENT = "scanalyze.cloud."
APP = "prod.scanalyze.cloud."
API = "api.scanalyze.cloud."


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def _object(value: object) -> dict:
    _require(isinstance(value, dict), "Metadata object is required")
    return value


def _fqdn(value: str, *, wildcard: bool = False) -> str:
    _require(isinstance(value, str) and bool(value), "DNS value must be a nonempty string")
    name = value.lower().removesuffix(".")
    labels = name.split(".")
    _require(len(name) <= 253 and all(
        (wildcard and index == 0 and label == "*")
        or re.fullmatch(r"[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?", label)
        for index, label in enumerate(labels)
    ), "Invalid DNS name")
    return name + "."


def _record_inventory(records: list) -> list[dict]:
    _require(isinstance(records, list), "Invalid DNS record inventory")
    normalized = []
    seen = set()
    for raw in records:
        item = _object(raw)
        name = _fqdn(item.get("name"), wildcard=True)
        _require(name == PARENT or name.endswith("." + PARENT), "DNS record is outside the managed zone")
        kind = item.get("type")
        _require(isinstance(kind, str) and re.fullmatch(r"[A-Za-z][A-Za-z0-9]{0,15}", kind), "Invalid DNS record type")
        kind = kind.upper()
        ttl = item.get("ttl")
        _require(type(ttl) is int and 0 <= ttl <= 2147483647, "Invalid DNS record TTL")
        data = item.get("rrdatas")
        _require(isinstance(data, list) and bool(data) and all(
            isinstance(value, str) and bool(value) and not any(char in value for char in "\x00\r\n")
            for value in data
        ), "DNS record requires observed rrdatas; routing-policy records need separate review")
        if kind in {"NS", "CNAME", "DNAME"}:
            data = [_fqdn(value) for value in data]
        _require((name, kind) not in seen, "Duplicate DNS record set in inventory")
        seen.add((name, kind))
        normalized.append({"name": name, "type": kind, "ttl": ttl, "rrdatas": sorted(data)})
    return normalized


def build_plan(hosted_zone: dict, certificate: dict | None, managed_zone: dict, records: list, *, mode: str = "complete") -> dict:
    """Validate metadata and produce additions only; this is not authority."""
    _require(mode in {"complete", "delegation"}, "Unknown DNS operation mode")
    _require((mode == "delegation" and certificate is None) or (mode == "complete" and isinstance(certificate, dict)),
             "Complete mode requires certificate metadata; delegation mode must not include a certificate")
    zone = _object(_object(hosted_zone).get("HostedZone"))
    raw_zone_id = zone.get("Id")
    _require(isinstance(raw_zone_id, str), "Invalid Route53 zone ID")
    zone_id = raw_zone_id.removeprefix("/hostedzone/")
    _require(re.fullmatch(r"Z[A-Z0-9]+", zone_id) is not None, "Invalid Route53 zone ID")
    _require(_fqdn(zone.get("Name")) == APP, "Route53 zone must be the exact production subdomain")
    _require(_object(zone.get("Config")).get("PrivateZone") is False, "Route53 zone must be public")
    nameservers = _object(hosted_zone.get("DelegationSet")).get("NameServers", [])
    _require(isinstance(nameservers, list) and len(nameservers) == 4, "Four observed Route53 nameservers required")
    nameservers = sorted(_fqdn(value) for value in nameservers)
    _require(len(set(nameservers)) == 4 and all(re.fullmatch(r"ns-[0-9]+\.awsdns-[0-9]+\.(?:com|net|org|co\.uk)\.", value) for value in nameservers), "Invalid Route53 delegation")

    proposed = [{"name": APP, "type": "NS", "ttl": 300, "rrdatas": nameservers}]
    arn = None
    if mode == "complete":
        cert = _object(_object(certificate).get("Certificate"))
        arn = cert.get("CertificateArn", "")
        _require(isinstance(arn, str) and re.fullmatch(rf"arn:aws:acm:{REGION}:{ACCOUNT}:certificate/[a-f0-9]{{8}}-(?:[a-f0-9]{{4}}-){{3}}[a-f0-9]{{12}}", arn) is not None, "Certificate account/region or identifier mismatch")
        sans = cert.get("SubjectAlternativeNames")
        _require(isinstance(sans, list) and len(sans) == 1 and _fqdn(sans[0]) == API and _fqdn(cert.get("DomainName")) == API, "Certificate must cover only the exact API hostname")
        _require(cert.get("Type") == "AMAZON_ISSUED" and cert.get("Status") in ("PENDING_VALIDATION", "ISSUED"), "Certificate is not an issuable ACM public certificate")
        validation = cert.get("DomainValidationOptions", [])
        _require(isinstance(validation, list) and len(validation) == 1, "Exactly one ACM validation option required")
        option = _object(validation[0])
        _require(_fqdn(option.get("DomainName")) == API and option.get("ValidationMethod") == "DNS", "Wrong ACM validation target/method")
        rr = _object(option.get("ResourceRecord"))
        name, value = _fqdn(rr.get("Name", "")), _fqdn(rr.get("Value", ""))
        _require(rr.get("Type") == "CNAME" and re.fullmatch(r"_[a-f0-9]+\.api\.scanalyze\.cloud\.", name) is not None, "Unexpected ACM validation record")
        # ACM can include a routing label before its validation domain. Keep the
        # AWS suffix anchored and preserve the exact value from DescribeCertificate.
        _require(re.fullmatch(r"_[a-f0-9]+\.(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)?acm-validations\.aws\.", value) is not None, "Unexpected ACM validation destination")
        proposed.append({"name": name, "type": "CNAME", "ttl": 300, "rrdatas": [value]})

    managed_zone = _object(managed_zone)
    _require(managed_zone.get("name") == GCP_ZONE and _fqdn(managed_zone.get("dnsName")) == PARENT and managed_zone.get("visibility") == "public", "Wrong GCP managed zone")
    parent_ns = managed_zone.get("nameServers", [])
    _require(isinstance(parent_ns, list) and len(parent_ns) == 4, "GCP authoritative nameservers are missing")
    parent_ns = sorted(_fqdn(item) for item in parent_ns)
    _require(len(set(parent_ns)) == 4, "GCP authoritative nameservers must be distinct")
    inventory = _record_inventory(records)
    _require(any(item["name"] == PARENT and item["type"] == "NS" and item["rrdatas"] == parent_ns for item in inventory), "GCP apex NS inventory mismatch")

    additions = []
    for expected in proposed:
        existing = [item for item in inventory if item["name"] == expected["name"]]
        if existing:
            _require(len(existing) == 1 and existing[0].get("type") == expected["type"] and sorted(existing[0].get("rrdatas", [])) == expected["rrdatas"], "Existing target record conflicts; do not replace it")
        else:
            additions.append(expected)
    for item in inventory:
        existing_name = item.get("name", "")
        _require(not (existing_name.endswith("." + APP)), "Existing app descendants would be hidden by delegation")
        _require(not (item.get("type") == "DNAME" and existing_name == PARENT), "A DNAME redirects the delegation namespace")
        if mode == "complete":
            _require(not (item.get("type") == "NS" and existing_name == API), "API is delegated; GCP is not the validation authority")
            _require(not (item.get("type") == "DNAME" and existing_name == API), "A DNAME redirects the validation namespace")

    common = ["--project", PROJECT, "--zone", GCP_ZONE, "--transaction-file", "scanalyze-production-dns-transaction.yaml"]
    commands = []
    if additions:
        commands.append(["gcloud", "dns", "record-sets", "transaction", "start", "--skip-soa-update", *common])
        for addition in additions:
            commands.append(["gcloud", "dns", "record-sets", "transaction", "add", *addition["rrdatas"], "--name", addition["name"], "--type", addition["type"], "--ttl", str(addition["ttl"]), *common])
        commands.append(["gcloud", "dns", "record-sets", "transaction", "describe", *common])
        commands.append(["gcloud", "dns", "record-sets", "transaction", "execute", *common])
    return {
        "status": "REVIEW_ONLY_NOT_EXECUTED",
        "operation": mode,
        "aws_account": ACCOUNT, "aws_region": REGION,
        "gcp_project": PROJECT, "gcp_zone": GCP_ZONE,
        "route53_zone_id": zone_id, "internal_certificate_arn": arn,
        "additions": additions, "deletions": [],
        "observed_records_sha256": hashlib.sha256(json.dumps(records, sort_keys=True, separators=(",", ":")).encode()).hexdigest(),
        "commands": [shlex.join(command) for command in commands],
        "required_before_execution": "Refresh exact metadata, compare this plan and obtain approval of its additions. These input files are observations, not independent deployment authority.",
    }


def _unique_object(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        _require(key not in result, "Duplicate JSON field in metadata")
        result[key] = value
    return result


def _invalid_constant(value: str) -> None:
    raise ValueError("Non-JSON numeric constant in metadata")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("complete", "delegation"), default="complete")
    for field in ("hosted-zone", "certificate", "managed-zone", "records"):
        parser.add_argument("--" + field, required=field != "certificate", type=Path)
    args = parser.parse_args(argv)
    try:
        _require((args.mode == "delegation") == (args.certificate is None),
                 "Use certificate metadata only in complete mode; delegation accepts no certificate file")
        inputs = [json.loads(getattr(args, field).read_text(), object_pairs_hook=_unique_object, parse_constant=_invalid_constant)
                  if getattr(args, field) is not None else None for field in ("hosted_zone", "certificate", "managed_zone", "records")]
        plan = build_plan(*inputs, mode=args.mode)
    except (ValueError, TypeError, AttributeError, KeyError, OSError) as error:
        parser.exit(2, f"DNS_PLAN_REJECTED: {error}\n")
    print(json.dumps(plan, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
