"""Fail-closed verification for externally produced ACCOUNT_READY v2.

The verifier treats the contract and its expected-value anchor as independent
inputs. It never substitutes account, customer, deployment, region,
environment, role, bucket, key, or backend coordinates from caller input. The
three bucket names are exact baseline-template invariants; matching them does
not prove live existence or ownership.
"""

from __future__ import annotations

import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any

try:
    import jsonschema
except ImportError:
    print("BLOCKED_TOOLING: jsonschema not installed", file=sys.stderr)
    sys.exit(2)


EXPECTED_SCHEMA_ID = "https://scanalyze.dev/schemas/account-ready.v2.schema.json"
EXPECTED_SCHEMA_VERSION = "2"
EXPECTED_SCHEMA_SHA256 = (
    "8fb75663bf42c9b78c0227e45b5110bfea04792cf6df094500b5e2f311ff8464"
)
ROLE_NAMES = {
    "plan": "ScanalyzeCustomer-Plan",
    "apply": "ScanalyzeCustomer-Apply",
    "identity_plan": "ScanalyzeCustomer-Identity-Plan",
    "identity_apply": "ScanalyzeCustomer-Identity-Apply",
    "promotion": "ScanalyzeCustomer-Promotion",
    "validation": "ScanalyzeCustomer-Validation",
    "diagnostic": "ScanalyzeCustomer-Diagnostic",
    "state_recovery": "ScanalyzeCustomer-StateRecovery",
}
REQUIRED_ROLES = frozenset(ROLE_NAMES)
REQUIRED_INFRA = frozenset(
    {
        "state_bucket",
        "evidence_bucket",
        "contracts_bucket",
        "state_kms_key",
        "evidence_kms_key",
        "contracts_kms_key",
    }
)
EXPECTED_ANCHOR_FIELDS = frozenset(
    {
        "customer_id",
        "deployment_id",
        "account_id",
        "region",
        "environment",
        "baseline_version",
        "expected_contract_digest",
    }
)
EXPECTED_CONTROLS = {
    "state_versioning_enabled": True,
    "state_default_encryption": "aws:kms",
    "state_bucket_key_enabled": True,
    "state_public_access_blocked": True,
    "state_object_lock_enabled": False,
    "native_lockfile_enabled": True,
}
ROLE_ARN_PATTERN = re.compile(
    r"^arn:(?P<partition>aws(?:-[a-z]+)*):iam::"
    r"(?P<account>[0-9]{12}):role/(?P<name>[A-Za-z0-9+=,.@_-]+)$"
)
KMS_ARN_PATTERN = re.compile(
    r"^arn:(?P<partition>aws(?:-[a-z]+)*):kms:"
    r"(?P<region>[a-z0-9-]+):(?P<account>[0-9]{12}):"
    r"key/[A-Za-z0-9-]+$"
)
S3_ARN_PATTERN = re.compile(
    r"^arn:(?P<partition>aws(?:-[a-z]+)*):s3:::"
    r"(?P<bucket>[a-z0-9][a-z0-9.-]{1,61}[a-z0-9])$"
)


class VerificationResult:
    """Accumulate sanitized pass/fail checks."""

    def __init__(self) -> None:
        self.checks: list[dict[str, Any]] = []

    def add(self, name: str, passed: bool, reason: str = "") -> None:
        self.checks.append({"name": name, "passed": passed, "reason": reason})

    @property
    def passed(self) -> bool:
        return bool(self.checks) and all(check["passed"] for check in self.checks)

    def summary(self) -> str:
        lines = []
        for check in self.checks:
            status = "PASS" if check["passed"] else "FAIL"
            line = f"  {status}: {check['name']}"
            if check["reason"]:
                line += f" — {check['reason']}"
            lines.append(line)
        overall = "PASS" if self.passed else "FAIL"
        lines.insert(0, f"=== ACCOUNT_READY Verification: {overall} ===")
        return "\n".join(lines)


def canonical_digest(contract: dict[str, Any]) -> str:
    """Return a SHA-256 digest of canonical JSON without contract_digest."""
    body = {key: value for key, value in contract.items() if key != "contract_digest"}
    canonical = json.dumps(
        body,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )
    return "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _approved_schema(schema: Any) -> bool:
    if not isinstance(schema, dict):
        return False
    properties = schema.get("properties")
    try:
        canonical = json.dumps(
            schema,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")
    except (TypeError, ValueError):
        return False
    return (
        hashlib.sha256(canonical).hexdigest() == EXPECTED_SCHEMA_SHA256
        and schema.get("$id") == EXPECTED_SCHEMA_ID
        and isinstance(properties, dict)
        and properties.get("schema_version", {}).get("const")
        == EXPECTED_SCHEMA_VERSION
    )


def _schema_valid(contract: Any, schema: dict[str, Any]) -> bool:
    try:
        jsonschema.Draft202012Validator.check_schema(schema)
        validator = jsonschema.Draft202012Validator(
            schema,
            format_checker=jsonschema.FormatChecker(),
        )
        return not any(validator.iter_errors(contract))
    except (jsonschema.SchemaError, TypeError, ValueError):
        return False


def _role_bindings_valid(contract: dict[str, Any]) -> tuple[bool, set[str]]:
    roles = contract["roles"]
    expected_tags = {
        "customer_id_tag": contract["customer_id"],
        "deployment_id_tag": contract["deployment_id"],
        "account_id_tag": contract["account_id"],
        "region_tag": contract["region"],
        "environment_tag": contract["environment"],
    }
    partitions: set[str] = set()
    arns: set[str] = set()
    for role_key, role in roles.items():
        match = ROLE_ARN_PATTERN.fullmatch(role["arn"])
        if (
            match is None
            or match.group("account") != contract["account_id"]
            or match.group("name") != ROLE_NAMES[role_key]
        ):
            return False, set()
        if any(role.get(field) != expected for field, expected in expected_tags.items()):
            return False, set()
        partitions.add(match.group("partition"))
        arns.add(role["arn"])
    return len(arns) == len(REQUIRED_ROLES) and len(partitions) == 1, partitions


def _state_bindings_valid(
    contract: dict[str, Any],
    role_partitions: set[str],
) -> bool:
    infrastructure = contract["state_infrastructure"]
    expected_buckets = {
        "state_bucket": f"scanalyze-{contract['account_id']}-tf-state",
        "evidence_bucket": f"scanalyze-{contract['account_id']}-tf-evidence",
        "contracts_bucket": f"scanalyze-{contract['account_id']}-contracts",
    }
    bucket_arns = [infrastructure[field] for field in expected_buckets]
    kms_arns = [
        infrastructure["state_kms_key"],
        infrastructure["evidence_kms_key"],
        infrastructure["contracts_kms_key"],
    ]
    if len(set(bucket_arns)) != len(bucket_arns) or len(set(kms_arns)) != len(kms_arns):
        return False

    partitions = set(role_partitions)
    for field, expected_bucket in expected_buckets.items():
        arn = infrastructure[field]
        match = S3_ARN_PATTERN.fullmatch(arn)
        if match is None or match.group("bucket") != expected_bucket:
            return False
        partitions.add(match.group("partition"))

    for arn in kms_arns:
        match = KMS_ARN_PATTERN.fullmatch(arn)
        if match is None:
            return False
        if (
            match.group("account") != contract["account_id"]
            or match.group("region") != contract["region"]
        ):
            return False
        partitions.add(match.group("partition"))

    return len(partitions) == 1


def verify_account_ready(
    contract: dict[str, Any],
    anchor: dict[str, Any],
    schema: dict[str, Any] | None = None,
) -> VerificationResult:
    """Verify one ACCOUNT_READY v2 contract against an independent anchor."""
    result = VerificationResult()

    if schema is None:
        result.add("schema_validation", False, "approved v2 schema is required")
        return result
    if not _approved_schema(schema):
        result.add("schema_validation", False, "schema is not approved ACCOUNT_READY v2")
        return result
    if not _schema_valid(contract, schema):
        result.add("schema_validation", False, "contract does not satisfy ACCOUNT_READY v2")
        return result
    result.add("schema_validation", True)

    if not isinstance(anchor, dict) or set(anchor) != EXPECTED_ANCHOR_FIELDS:
        result.add("anchor_validation", False, "anchor fields are incomplete or unexpected")
        return result
    if any(not isinstance(value, str) or not value for value in anchor.values()):
        result.add("anchor_validation", False, "anchor values are malformed")
        return result
    result.add("anchor_validation", True)

    for field in (
        "customer_id",
        "deployment_id",
        "account_id",
        "region",
        "environment",
        "baseline_version",
    ):
        matches = contract[field] == anchor[field]
        result.add(
            f"{field}_match",
            matches,
            "anchor does not match contract" if not matches else "",
        )

    claimed_digest = contract["contract_digest"]
    computed_digest = canonical_digest(contract)
    digest_matches = claimed_digest == computed_digest
    result.add(
        "digest_match",
        digest_matches,
        "canonical contract digest mismatch" if not digest_matches else "",
    )
    external_digest_matches = claimed_digest == anchor["expected_contract_digest"]
    result.add(
        "external_digest_match",
        external_digest_matches,
        "external anchor digest mismatch" if not external_digest_matches else "",
    )

    roles = contract["roles"]
    roles_exact = set(roles) == REQUIRED_ROLES
    result.add(
        "required_roles",
        roles_exact,
        "role set is not the approved eight-role baseline" if not roles_exact else "",
    )
    if roles_exact:
        role_bindings_valid, role_partitions = _role_bindings_valid(contract)
    else:
        role_bindings_valid, role_partitions = False, set()
    result.add(
        "role_bindings",
        role_bindings_valid,
        "role ARN or resource-tag binding mismatch"
        if not role_bindings_valid
        else "",
    )

    infrastructure = contract["state_infrastructure"]
    infrastructure_exact = set(infrastructure) == REQUIRED_INFRA
    result.add(
        "state_infrastructure",
        infrastructure_exact,
        "state infrastructure field set is incomplete or unexpected"
        if not infrastructure_exact
        else "",
    )
    state_bindings_valid = infrastructure_exact and _state_bindings_valid(
        contract,
        role_partitions,
    )
    result.add(
        "state_bindings",
        state_bindings_valid,
        "state infrastructure ARN binding mismatch"
        if not state_bindings_valid
        else "",
    )

    controls_valid = contract["controls"] == EXPECTED_CONTROLS
    result.add(
        "state_controls",
        controls_valid,
        "state controls do not match the approved baseline"
        if not controls_valid
        else "",
    )
    return result


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    document: dict[str, Any] = {}
    for key, value in pairs:
        if key in document:
            raise ValueError("duplicate JSON key")
        document[key] = value
    return document


def _load_json_strict(path: Path) -> dict[str, Any]:
    document = json.loads(
        path.read_text(encoding="utf-8"),
        object_pairs_hook=_reject_duplicate_keys,
    )
    if not isinstance(document, dict):
        raise ValueError("JSON document must be an object")
    return document


def main() -> int:
    """CLI entry point: verify_account_ready.py contract anchor schema."""
    if len(sys.argv) != 4:
        print(
            "Usage: verify_account_ready.py <contract.json> <anchor.json> <schema.json>",
            file=sys.stderr,
        )
        return 1

    try:
        contract = _load_json_strict(Path(sys.argv[1]))
        anchor = _load_json_strict(Path(sys.argv[2]))
        schema = _load_json_strict(Path(sys.argv[3]))
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError):
        print("ERROR: unable to load verification inputs", file=sys.stderr)
        return 1

    result = verify_account_ready(contract, anchor, schema)
    print(result.summary())
    return 0 if result.passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
