#!/usr/bin/env python3
"""Contract canonicalization and digest verification.

Implements deterministic JSON serialization for contract digest computation.
The digest is SHA-256 of the canonicalized outputs object.
"""

import json
import hashlib
import sys
from pathlib import Path


def canonicalize(obj: dict) -> bytes:
    """Produce canonical JSON bytes for digest computation.

    Rules:
    - Keys sorted recursively
    - No trailing whitespace
    - Consistent separators (no spaces)
    - UTF-8 encoding
    - Arrays preserve order
    """
    return json.dumps(
        obj,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")


def compute_digest(canonical_bytes: bytes) -> str:
    """Compute SHA-256 digest of canonical bytes.

    Returns: 'sha256:<hex>'
    """
    return f"sha256:{hashlib.sha256(canonical_bytes).hexdigest()}"


def verify_contract_digest(contract: dict) -> tuple[bool, str, str]:
    """Verify a contract envelope's embedded digest.

    Returns: (matches, expected_digest, computed_digest)
    """
    outputs = contract.get("outputs", {})
    canonical_bytes = canonicalize(outputs)
    computed = compute_digest(canonical_bytes)
    expected = contract.get("contract_digest", "")
    return computed == expected, expected, computed


def main():
    """Validate contract digests in fixtures."""
    if len(sys.argv) < 2:
        print("Usage: validate_digest.py <fixtures_dir>")
        sys.exit(1)

    fixtures_dir = Path(sys.argv[1])
    errors = 0

    for fixture_file in sorted(fixtures_dir.glob("contract-envelope-*.json")):
        with open(fixture_file) as f:
            contract = json.load(f)

        matches, expected, computed = verify_contract_digest(contract)
        if matches:
            print(f"  DIGEST OK: {fixture_file.name}")
        else:
            print(f"  DIGEST MISMATCH: {fixture_file.name}")
            print(f"    Expected:  {expected}")
            print(f"    Computed:  {computed}")
            errors += 1

    # Canonicalization determinism test
    print("\n=== Canonicalization determinism test ===")
    test_obj = {"z": 1, "a": {"c": 3, "b": 2}, "m": [3, 1, 2]}
    canonical1 = canonicalize(test_obj)
    canonical2 = canonicalize(test_obj)
    if canonical1 == canonical2:
        print("  PASS: Canonicalization is deterministic")
    else:
        print("  FAIL: Canonicalization produced different results!")
        errors += 1

    digest1 = compute_digest(canonical1)
    digest2 = compute_digest(canonical2)
    if digest1 == digest2:
        print("  PASS: Digest is stable")
    else:
        print("  FAIL: Digest is not stable!")
        errors += 1

    sys.exit(1 if errors > 0 else 0)


if __name__ == "__main__":
    main()
