"""Collect bounded AWS metadata after an exact STS account check.

This is preparation evidence, never deployment authority or a readiness gate.
The CLI uses its normal pagination (no --max-items or --no-paginate). It never
requests parameter values, object contents, logs, policies, key material or
Terraform state. No live call is made on import.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
from typing import Any, Callable


ACM_KEY_TYPES = (
    "RSA_1024", "RSA_2048", "RSA_3072", "RSA_4096",
    "EC_prime256v1", "EC_secp384r1", "EC_secp521r1",
)
# Compatibility with one observed CLI response spelling, not an ACM request value.
ACM_RESPONSE_KEY_ALGORITHMS = (*ACM_KEY_TYPES, "RSA-2048")
# ACM's default omits other supported key algorithms:
# https://docs.aws.amazon.com/cli/latest/reference/acm/list-certificates.html
DEFAULT_MODEL_ID = "amazon.nova-pro-v1:0"
# Only this observed availability response alias is accepted; no suffix stripping.
BEDROCK_MODEL_RESPONSE_ALIASES = frozenset({("amazon.nova-pro-v1:0", "amazon.nova-pro-v1")})
CALL_TIMEOUT_SECONDS = 45
DEFAULT_MAX_KMS_KEYS = 50
MAX_KMS_KEYS = 200
ERROR_CODES = frozenset({
    "AccessDenied", "AccessDeniedException", "UnauthorizedOperation",
    "ExpiredToken", "ExpiredTokenException", "InvalidClientTokenId",
    "UnrecognizedClientException", "InvalidSignatureException", "SignatureDoesNotMatch",
    "RequestExpired", "ValidationException", "ValidationError", "InvalidParameterException",
    "ResourceNotFoundException", "NotFoundException", "NoSuchEntity", "NotFound",
    "Throttling", "ThrottlingException", "TooManyRequestsException", "LimitExceededException",
    "ServiceUnavailableException", "ServiceUnavailable", "InternalFailure", "InternalError",
    "InternalServerException", "OptInRequired", "InvalidAction", "UnsupportedOperationException",
})


class InventoryError(Exception):
    """Only fixed operation/code values may reach the CLI error output."""

    def __init__(self, operation: str, code: str):
        self.operation, self.code = operation, code
        super().__init__(code)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _string(value: Any, pattern: str = r"[A-Za-z0-9_./:+*=-]{1,1024}") -> str:
    if not isinstance(value, str) or re.fullmatch(pattern, value) is None:
        raise ValueError("invalid metadata")
    return value


def _bool(value: Any) -> bool:
    if not isinstance(value, bool):
        raise ValueError("invalid metadata")
    return value


def _integer(value: Any) -> int | None:
    if value is None:
        return None
    if type(value) is not int or value < 0:
        raise ValueError("invalid metadata")
    return value


def _version(value: Any) -> int:
    if type(value) is not int or value < 1:
        raise ValueError("invalid metadata")
    return value


def _enum(*values: str) -> Callable:
    def validate(value):
        if value not in values:
            raise ValueError("invalid metadata")
        return value
    return validate


def _list(value: Any) -> list:
    if not isinstance(value, list):
        raise ValueError("invalid metadata")
    return value


def _project(records: Any, fields: dict[str, Callable], select: Callable | None = None) -> list:
    result = []
    for row in _list(records):
        if not isinstance(row, dict):
            raise ValueError("invalid metadata")
        if not set(fields) <= set(row):
            raise ValueError("invalid metadata")
        if select is not None and not select(row):
            continue
        result.append({key: validate(row[key]) for key, validate in fields.items()})
    return result


def _matching_name(value: Any) -> bool:
    return isinstance(value, str) and value.startswith(("Scanalyze", "scanalyze", "dep-", "dep_"))


def _matching_resource_name(value: Any) -> bool:
    return isinstance(value, str) and ("scanalyze" in value.casefold() or value.startswith("dep-"))


def _matching_table_name(value: Any) -> bool:
    return _matching_resource_name(value) or (isinstance(value, str) and value.startswith("dep_"))


def _names(value: Any, select: Callable = _matching_name) -> list[str]:
    names = [_string(name) for name in _list(value)]
    return [name for name in names if select(name)]


def _scope(profile: str, region: str, expected_account_id: str, model_id: str, max_kms_keys: int) -> None:
    _string(profile, r"[A-Za-z0-9][A-Za-z0-9_+=,.@-]{0,127}")
    _string(region, r"[a-z]{2}(?:-gov)?-[a-z]+-[0-9]+")
    _string(expected_account_id, r"[0-9]{12}")
    _string(model_id, r"[a-z0-9][a-z0-9.:-]{0,139}")
    if type(max_kms_keys) is not int or not 1 <= max_kms_keys <= MAX_KMS_KEYS:
        raise ValueError("invalid scope")


class _Collector:
    def __init__(self, profile, region, account, runner=None):
        self.profile, self.region, self.account = profile, region, account
        self.runner = subprocess.run if runner is None else runner
        self.partition = "aws-cn" if region.startswith("cn-") else "aws-us-gov" if region.startswith("us-gov-") else "aws"

    def arn(self, service: str, resource: str, *, global_service=False):
        region = "" if global_service else re.escape(self.region)
        pattern = rf"arn:{self.partition}:{service}:{region}:{self.account}:{resource}"
        return lambda value: _string(value, pattern)

    def call(self, service: str, operation: str, query: str, *arguments: str):
        label = service + ":" + operation
        argv = ["aws", "--profile", self.profile, "--region", self.region,
                "--no-cli-pager", "--output", "json", service, operation,
                *arguments, "--query", query]
        try:
            response = self.runner(argv, capture_output=True, text=True,
                                   timeout=CALL_TIMEOUT_SECONDS, check=False, shell=False)
        except subprocess.TimeoutExpired:
            raise InventoryError(label, "TIMEOUT") from None
        except Exception:
            raise InventoryError(label, "EXECUTION_FAILED") from None
        if response.returncode != 0:
            # Never emit the rest of stderr, exception repr, session ARN or URL.
            match = re.search(r"An error occurred \(([A-Za-z0-9]+)\)", response.stderr or "")
            code = match.group(1) if match and match.group(1) in ERROR_CODES else "AWS_CLI_FAILED"
            raise InventoryError(label, code)
        try:
            return json.loads(response.stdout)
        except (TypeError, ValueError):
            raise InventoryError(label, "RESPONSE_INVALID") from None

    def check(self, service, operation, query, project, *arguments):
        started = _now()
        try:
            value = project(self.call(service, operation, query, *arguments))
            result = {"status": "OBSERVED", "items": value}
        except InventoryError as exc:
            result = {"status": "UNKNOWN", "error_code": exc.code}
        except Exception:
            result = {"status": "UNKNOWN", "error_code": "RESPONSE_INVALID"}
        return {"operation": service + ":" + operation, "started_at": started,
                "completed_at": _now(), **result}

    def kms(self, cap):
        record = self.check("kms", "list-keys", "Keys[].KeyArn",
                            lambda rows: [self.arn("kms", r"key/[A-Za-z0-9-]+")(_string(x)) for x in _list(rows)])
        if record["status"] != "OBSERVED":
            return record
        keys = sorted(set(record.pop("items")))
        record.update(listed_key_count=len(keys), describe_limit=cap,
                      truncated=len(keys) > cap, omitted_key_count=max(len(keys) - cap, 0))
        items = []
        for key in keys[:cap]:
            item = self.check("kms", "describe-key",
                "KeyMetadata.{arn:Arn,key_manager:KeyManager,key_state:KeyState}",
                lambda row: _project([row], {"arn": self.arn("kms", r"key/[A-Za-z0-9-]+"),
                    "key_manager": _enum("AWS", "CUSTOMER"), "key_state": _string}),
                "--key-id", key)
            item["requested_key_arn"] = key
            if item["status"] == "OBSERVED" and item["items"][0]["arn"] != key:
                item.pop("items")
                item.update(status="UNKNOWN", error_code="RESPONSE_INVALID")
            items.append(item)
        record["items"] = items
        record["status"] = "TRUNCATED" if record["truncated"] else "PARTIAL" if any(x["status"] != "OBSERVED" for x in items) else "OBSERVED"
        record["completed_at"] = _now()
        return record


def collect_inventory(*, profile: str, region: str, expected_account_id: str,
                      model_id: str = DEFAULT_MODEL_ID, max_kms_keys: int = DEFAULT_MAX_KMS_KEYS,
                      runner=None) -> dict:
    """Return metadata only after STS matches; identity failures produce no report."""
    try:
        _scope(profile, region, expected_account_id, model_id, max_kms_keys)
    except Exception:
        raise InventoryError("inventory", "SCOPE_INVALID") from None
    collector = _Collector(profile, region, expected_account_id, runner)
    started = _now()
    observed_account = collector.call("sts", "get-caller-identity", "Account")
    if not isinstance(observed_account, str) or re.fullmatch(r"[0-9]{12}", observed_account) is None:
        raise InventoryError("sts:get-caller-identity", "IDENTITY_INVALID")
    if observed_account != expected_account_id:
        raise InventoryError("sts:get-caller-identity", "ACCOUNT_MISMATCH")
    identity = {"operation": "sts:get-caller-identity", "status": "VERIFIED_ACCOUNT",
                "account_id": observed_account, "observed_at": _now()}
    checks = {}
    checks["acm"] = collector.check("acm", "list-certificates",
        "CertificateSummaryList[].{arn:CertificateArn,domain:DomainName,status:Status,key_algorithm:KeyAlgorithm}",
        lambda rows: _project(rows, {"arn": collector.arn("acm", r"certificate/[A-Za-z0-9-]+"),
            "domain": _string, "status": _string, "key_algorithm": _enum(*ACM_RESPONSE_KEY_ALGORITHMS)}),
        "--includes", json.dumps({"keyTypes": list(ACM_KEY_TYPES)}, separators=(",", ":")))
    checks["route53"] = collector.check("route53", "list-hosted-zones",
        "HostedZones[].{id:Id,name:Name,private_zone:Config.PrivateZone}",
        lambda rows: _project(rows, {"id": _string, "name": _string, "private_zone": _bool}))
    checks["s3"] = collector.check("s3api", "list-buckets",
        "Buckets[?starts_with(Name, 'scanalyze-') || starts_with(Name, 'dep-')].Name",
        lambda rows: _names(rows, lambda name: isinstance(name, str) and name.startswith(("scanalyze-", "dep-"))))
    checks["kms"] = collector.kms(max_kms_keys)
    checks["iam"] = collector.check("iam", "list-roles",
        "Roles[?starts_with(RoleName, 'Scanalyze') || starts_with(RoleName, 'scanalyze') || starts_with(RoleName, 'dep-') || starts_with(RoleName, 'dep_')].{name:RoleName,arn:Arn}",
        lambda rows: _project(rows, {"name": _string, "arn": collector.arn("iam", r"role/[A-Za-z0-9_+=,.@/-]+", global_service=True)},
            lambda row: _matching_name(row.get("name"))))
    checks["ecr"] = collector.check("ecr", "describe-repositories",
        "repositories[].{name:repositoryName,arn:repositoryArn,mutability:imageTagMutability}",
        lambda rows: _project(rows, {"name": _string, "arn": collector.arn("ecr", r"repository/[a-z0-9_./-]+"),
            "mutability": _enum("MUTABLE", "IMMUTABLE", "MUTABLE_WITH_EXCLUSION", "IMMUTABLE_WITH_EXCLUSION")},
            lambda row: _matching_resource_name(row.get("name"))))
    checks["dynamodb"] = collector.check("dynamodb", "list-tables", "TableNames[]",
        lambda rows: _names(rows, _matching_table_name))
    checks["ssm"] = collector.check("ssm", "describe-parameters",
        "Parameters[].{name:Name,type:Type,version:Version}",
        lambda rows: _project(rows, {"name": _string, "type": _enum("String", "StringList", "SecureString"), "version": _version},
            lambda row: isinstance(row.get("name"), str) and row["name"].startswith("/scanalyze/")),
        "--parameter-filters", "Key=Name,Option=BeginsWith,Values=/scanalyze/")
    checks["ecs"] = collector.check("ecs", "list-clusters", "clusterArns[]",
        lambda rows: [collector.arn("ecs", r"cluster/[A-Za-z0-9_-]+")(_string(value)) for value in _list(rows)])

    def distributions(rows):
        result = []
        # AWS omits the Items member for an empty distribution list.
        if rows is None:
            return result
        for row in _list(rows):
            if not isinstance(row, dict) or not {"id", "status", "enabled", "aliases"} <= set(row):
                raise ValueError("invalid metadata")
            aliases = [_string(alias) for alias in _list(row["aliases"] or [])
                       if isinstance(alias, str) and "scanalyze" in alias.lower()]
            if aliases:
                item = _project([row], {"id": _string, "status": _string, "enabled": _bool})[0]
                result.append({**item, "aliases": aliases})
        return result

    checks["cloudfront"] = collector.check("cloudfront", "list-distributions",
        "DistributionList.Items[].{id:Id,status:Status,enabled:Enabled,aliases:Aliases.Items}", distributions)
    checks["logs"] = collector.check("logs", "describe-log-groups",
        "logGroups[].{name:logGroupName,arn:arn,retention_days:retentionInDays}",
        lambda rows: _project(rows, {"name": _string, "arn": collector.arn("logs", r"log-group:/scanalyze/[A-Za-z0-9_./:#*-]+"), "retention_days": _integer},
            lambda row: isinstance(row.get("name"), str) and row["name"].startswith("/scanalyze/")),
        "--log-group-name-prefix", "/scanalyze/")
    checks["cloudformation"] = collector.check("cloudformation", "list-stacks",
        "StackSummaries[?StackStatus!='DELETE_COMPLETE'].{name:StackName,status:StackStatus}",
        lambda rows: _project(rows, {"name": _string, "status": _string}, lambda row: row.get("status") != "DELETE_COMPLETE"))

    def availability(row):
        result = _project([row], {"model_id": _string,
            "authorization_status": _enum("AUTHORIZED", "NOT_AUTHORIZED"),
            "agreement_status": _enum("AVAILABLE", "NOT_AVAILABLE", "PENDING", "ERROR"),
            "entitlement_status": _enum("AVAILABLE", "NOT_AVAILABLE"),
            "region_status": _enum("AVAILABLE", "NOT_AVAILABLE")})[0]
        if result["model_id"] != model_id and (model_id, result["model_id"]) not in BEDROCK_MODEL_RESPONSE_ALIASES:
            raise ValueError("invalid metadata")
        return [{**result, "requested_model_id": model_id}]

    checks["bedrock"] = collector.check("bedrock", "get-foundation-model-availability",
        "{model_id:modelId,authorization_status:authorizationStatus,agreement_status:agreementAvailability.status,entitlement_status:entitlementAvailability,region_status:regionAvailability}",
        availability, "--model-id", model_id)
    return {"schema_version": "1", "record_type": "production_readonly_metadata_inventory",
        "production_authorized": False, "readiness": "NOT_EVALUATED",
        "status": "METADATA_OBSERVED" if all(x["status"] == "OBSERVED" for x in checks.values()) else "INCOMPLETE_METADATA",
        "started_at": started, "completed_at": _now(),
        "scope": {"profile": profile, "region": region, "expected_account_id": expected_account_id,
                  "model_id": model_id, "max_kms_keys": max_kms_keys, "pagination": "AWS_CLI_AUTOMATIC_ALL_PAGES",
                  "filters": {
                      "acm": {"key_types": list(ACM_KEY_TYPES), "certificate_statuses": "all"},
                      "route53": "all hosted-zone metadata",
                      "s3": {"name_prefixes": ["scanalyze-", "dep-"]},
                      "kms": "all listed key ARNs; sorted unique ARNs described up to max_kms_keys",
                      "iam": {"role_name_prefixes": ["Scanalyze", "scanalyze", "dep-", "dep_"]},
                      "ecr": "name contains scanalyze (case-insensitive) OR starts with dep-",
                      "dynamodb": "name contains scanalyze (case-insensitive) OR starts with dep- or dep_",
                      "ssm": {"name_prefix": "/scanalyze/", "values_read": False},
                      "ecs": "all cluster ARNs",
                      "cloudfront": "only distributions and aliases containing scanalyze (case-insensitive)",
                      "logs": {"name_prefix": "/scanalyze/", "log_contents_read": False},
                      "cloudformation": "all stack names/statuses except DELETE_COMPLETE",
                      "bedrock": {"exact_model_id": model_id, "invocation_performed": False},
                  }},
        "identity": identity, "checks": checks,
        "limitations": ["Metadata only; no resource contents, policies, key material, logs, secrets or state.",
            "Filtered names and aliases are discovery hints, not ownership, authority or deployment proof.",
            "UNKNOWN, PARTIAL and TRUNCATED are incomplete evidence, never proof of absence.",
            "Model availability does not test model invocation or authorize its use.",
            "Observations are not an atomic snapshot and may change between calls."]}


def _output_path(path: Path) -> Path:
    path = path.expanduser().absolute()
    if path.exists() or path.is_symlink():
        raise InventoryError("output", "ALREADY_EXISTS")
    parent = path.parent.resolve(strict=True)
    if not parent.is_dir():
        raise InventoryError("output", "DIRECTORY_INVALID")
    return parent / path.name


def write_report(report: dict, output: Path) -> None:
    """Publish a complete private file atomically, without replacing any name."""
    destination = _output_path(output)
    temporary = None
    try:
        fd, temporary = tempfile.mkstemp(prefix=".readonly-metadata-", dir=destination.parent)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            os.fchmod(handle.fileno(), 0o600)
            json.dump(report, handle, indent=2, sort_keys=True, allow_nan=False)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        # link() is atomic and fails if the final name appeared during collection.
        os.link(temporary, destination)
    except FileExistsError:
        raise InventoryError("output", "ALREADY_EXISTS") from None
    except Exception:
        raise InventoryError("output", "WRITE_FAILED") from None
    finally:
        if temporary is not None:
            os.unlink(temporary)


class _Parser(argparse.ArgumentParser):
    def error(self, message):
        self.exit(2, "inventory:ARGUMENTS_INVALID\n")


def main(argv: list[str] | None = None) -> int:
    parser = _Parser(description=__doc__)
    parser.add_argument("--profile", required=True)
    parser.add_argument("--region", required=True)
    parser.add_argument("--expected-account-id", required=True)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--model-id", default=DEFAULT_MODEL_ID)
    parser.add_argument("--max-kms-keys", default=DEFAULT_MAX_KMS_KEYS, type=int)
    args = parser.parse_args(argv)
    try:
        output = _output_path(args.output)
        report = collect_inventory(profile=args.profile, region=args.region,
            expected_account_id=args.expected_account_id, model_id=args.model_id, max_kms_keys=args.max_kms_keys)
        write_report(report, output)
    except InventoryError as exc:
        print(f"{exc.operation}:{exc.code}", file=sys.stderr)
        return 2
    except Exception:
        print("inventory:FAILED", file=sys.stderr)
        return 2
    print(report["status"])
    return 0 if report["status"] == "METADATA_OBSERVED" else 1


if __name__ == "__main__":
    raise SystemExit(main())
