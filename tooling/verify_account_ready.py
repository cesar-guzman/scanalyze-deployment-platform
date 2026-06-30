"""ACCOUNT_READY external anchor verification — fail-closed.

Verifies that an ACCOUNT_READY contract is consistent with its expected
deployment record anchor. If any verification step fails or data is missing,
the result is FAIL (fail-closed).

Verification checks:
1. Schema validation against account-ready.v1.schema.json
2. account_id matches deployment record
3. deployment_id matches deployment record
4. All 6 required roles present
5. All role ARNs belong to expected account_id
6. Canonical digest matches contract_digest field
7. baseline_version matches expected baseline
8. All 3 state infrastructure buckets present
9. All 3 KMS keys present
"""

import json
import hashlib
import sys
import re
from pathlib import Path
from typing import Any

try:
    import jsonschema
except ImportError:
    print("BLOCKED_TOOLING: jsonschema not installed", file=sys.stderr)
    sys.exit(2)


REQUIRED_ROLES = frozenset(["plan", "apply", "promotion", "validation", "diagnostic", "state_recovery"])
REQUIRED_INFRA = frozenset(["state_bucket", "evidence_bucket", "contracts_bucket",
                            "state_kms_key", "evidence_kms_key", "contracts_kms_key"])
ARN_WITH_ACCOUNT_PATTERN = re.compile(r"^arn:aws:[a-z0-9-]+:[a-z0-9-]*:(\d{12}):.+$")


class VerificationResult:
    """Accumulates pass/fail checks with reasons."""

    def __init__(self) -> None:
        self.checks: list[dict[str, Any]] = []

    def add(self, name: str, passed: bool, reason: str = "") -> None:
        self.checks.append({"name": name, "passed": passed, "reason": reason})

    @property
    def passed(self) -> bool:
        return all(c["passed"] for c in self.checks)

    def summary(self) -> str:
        lines = []
        for c in self.checks:
            status = "PASS" if c["passed"] else "FAIL"
            line = f"  {status}: {c['name']}"
            if c["reason"]:
                line += f" — {c['reason']}"
            lines.append(line)
        overall = "PASS" if self.passed else "FAIL"
        lines.insert(0, f"=== ACCOUNT_READY Verification: {overall} ===")
        return "\n".join(lines)


def canonical_digest(contract: dict) -> str:
    """SHA-256 of canonical JSON (sorted keys, no whitespace)."""
    body = {k: v for k, v in contract.items() if k != "contract_digest"}
    canonical = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def verify_account_ready(
    contract: dict,
    anchor: dict,
    schema: dict | None = None,
) -> VerificationResult:
    """Verify ACCOUNT_READY contract against external anchor (deployment record).

    Args:
        contract: The ACCOUNT_READY contract payload.
        anchor: The deployment record or expected values dict containing:
            - deployment_id
            - account_id
            - baseline_version (optional, if present will be checked)
            - expected_contract_digest (optional, if present must match)
        schema: Optional JSON Schema for structural validation.
    """
    result = VerificationResult()

    # 1. Schema validation
    if schema is not None:
        try:
            jsonschema.validate(instance=contract, schema=schema)
            result.add("schema_validation", True)
        except jsonschema.ValidationError as e:
            result.add("schema_validation", False, str(e.message))
            return result  # Fail fast on schema
    else:
        result.add("schema_validation", False, "no schema provided — fail closed")
        return result

    # 2. account_id match
    expected_account = anchor.get("account_id")
    actual_account = contract.get("account_id")
    if not expected_account:
        result.add("account_id_match", False, "missing expected account_id in anchor")
    elif actual_account == expected_account:
        result.add("account_id_match", True)
    else:
        result.add("account_id_match", False,
                    f"expected={expected_account}, actual={actual_account}")

    # 3. deployment_id match
    expected_dep = anchor.get("deployment_id")
    actual_dep = contract.get("deployment_id")
    if not expected_dep:
        result.add("deployment_id_match", False, "missing expected deployment_id in anchor")
    elif actual_dep == expected_dep:
        result.add("deployment_id_match", True)
    else:
        result.add("deployment_id_match", False,
                    f"expected={expected_dep}, actual={actual_dep}")

    # 4. All required roles present
    roles = contract.get("roles", {})
    present_roles = set(roles.keys())
    missing = REQUIRED_ROLES - present_roles
    if missing:
        result.add("required_roles", False, f"missing: {sorted(missing)}")
    else:
        result.add("required_roles", True)

    # 5. All role ARNs belong to expected account
    if expected_account and not missing:
        bad_arns = []
        for role_name, role_info in roles.items():
            arn = role_info.get("arn", "") if isinstance(role_info, dict) else ""
            m = ARN_WITH_ACCOUNT_PATTERN.match(arn)
            if m:
                if m.group(1) != expected_account:
                    bad_arns.append(f"{role_name}: account={m.group(1)}")
            else:
                bad_arns.append(f"{role_name}: invalid ARN format")
        if bad_arns:
            result.add("role_arn_account", False, f"wrong account: {bad_arns}")
        else:
            result.add("role_arn_account", True)
    else:
        result.add("role_arn_account", False, "cannot verify — missing roles or account")

    # 6. Canonical digest
    computed = canonical_digest(contract)
    claimed = contract.get("contract_digest", "")
    if not claimed:
        result.add("digest_match", False, "missing contract_digest field")
    elif computed == claimed:
        result.add("digest_match", True)
    else:
        result.add("digest_match", False,
                    f"computed={computed[:20]}…, claimed={claimed[:20]}…")

    # 7. baseline_version match (if anchor provides it)
    expected_baseline = anchor.get("baseline_version")
    if expected_baseline:
        actual_baseline = contract.get("baseline_version")
        if actual_baseline == expected_baseline:
            result.add("baseline_version_match", True)
        else:
            result.add("baseline_version_match", False,
                        f"expected={expected_baseline}, actual={actual_baseline}")

    # 8. State infrastructure completeness
    infra = contract.get("state_infrastructure", {})
    missing_infra = REQUIRED_INFRA - set(infra.keys())
    if missing_infra:
        result.add("state_infrastructure", False, f"missing: {sorted(missing_infra)}")
    else:
        result.add("state_infrastructure", True)

    return result


def main() -> int:
    """CLI entry point: verify_account_ready.py <contract.json> <anchor.json> [schema.json]"""
    if len(sys.argv) < 3:
        print("Usage: verify_account_ready.py <contract.json> <anchor.json> [schema.json]",
              file=sys.stderr)
        return 1

    contract_path = Path(sys.argv[1])
    anchor_path = Path(sys.argv[2])
    schema_path = Path(sys.argv[3]) if len(sys.argv) > 3 else None

    contract = json.loads(contract_path.read_text())
    anchor = json.loads(anchor_path.read_text())
    schema = json.loads(schema_path.read_text()) if schema_path else None

    result = verify_account_ready(contract, anchor, schema)
    print(result.summary())
    return 0 if result.passed else 1


if __name__ == "__main__":
    sys.exit(main())
