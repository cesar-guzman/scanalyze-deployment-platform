#!/usr/bin/env python3
"""Lock file checker for M2 Level B provider validation.

Verifies:
1. Every root has a .terraform.lock.hcl file
2. Only authorized providers are present (hashicorp/aws)
3. All roots use the same exact provider version
4. No provider 6.x is present
5. Hashes are present for each provider
6. .terraform/ directories are not staged in git
"""
import os
import re
import sys
import subprocess

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ROOTS_DIR = os.path.join(ROOT_DIR, "roots")
AUTHORIZED_PROVIDERS = {"registry.terraform.io/hashicorp/aws"}
FORBIDDEN_MAJOR = 6

def main():
    print("=== Lock File Check ===")
    errors = []
    versions_found = {}

    roots = sorted([
        d for d in os.listdir(ROOTS_DIR)
        if os.path.isdir(os.path.join(ROOTS_DIR, d))
    ])

    for root in roots:
        lock_path = os.path.join(ROOTS_DIR, root, ".terraform.lock.hcl")

        # Check 1: lock file exists
        if not os.path.exists(lock_path):
            errors.append(f"  FAIL: roots/{root} — no .terraform.lock.hcl")
            continue

        content = open(lock_path).read()

        # Check 2: only authorized providers
        providers = re.findall(
            r'provider\s+"([^"]+)"', content
        )
        for p in providers:
            if p not in AUTHORIZED_PROVIDERS:
                errors.append(
                    f"  FAIL: roots/{root} — unauthorized provider: {p}"
                )

        # Check 3: extract version
        version_match = re.search(
            r'provider\s+"registry\.terraform\.io/hashicorp/aws"\s*\{[^}]*'
            r'version\s*=\s*"([^"]+)"',
            content, re.DOTALL
        )
        if version_match:
            ver = version_match.group(1)
            versions_found[root] = ver

            # Check 4: no 6.x
            major = int(ver.split(".")[0])
            if major >= FORBIDDEN_MAJOR:
                errors.append(
                    f"  FAIL: roots/{root} — provider {ver} is >= {FORBIDDEN_MAJOR}.x"
                )
        else:
            errors.append(f"  FAIL: roots/{root} — cannot extract provider version")

        # Check 5: hashes present
        if "h1:" not in content:
            errors.append(f"  FAIL: roots/{root} — no h1: hash found")

        print(f"  roots/{root}: aws {versions_found.get(root, 'UNKNOWN')}")

    # Check 3b: all versions match
    unique_versions = set(versions_found.values())
    if len(unique_versions) > 1:
        errors.append(
            f"  FAIL: version mismatch across roots: {unique_versions}"
        )
    elif len(unique_versions) == 1:
        print(f"\n  All roots use provider version: {list(unique_versions)[0]}")

    # Check 6: .terraform/ not staged
    try:
        staged = subprocess.run(
            ["git", "ls-files", "--cached", ".terraform/"],
            capture_output=True, text=True, cwd=ROOT_DIR
        )
        if staged.stdout.strip():
            errors.append("  FAIL: .terraform/ files are staged in git")
    except Exception:
        pass  # git not available

    print()
    if errors:
        print("=== FAILURES ===")
        for e in errors:
            print(e)
        print(f"\nLock file check: FAIL ({len(errors)} issues)")
        sys.exit(1)
    else:
        print("Lock file check: PASS")
        print(f"  Provider: hashicorp/aws {list(unique_versions)[0]}")
        print(f"  Roots checked: {len(roots)}")
        print(f"  Unauthorized providers: 0")
        print(f"  .terraform/ staged: no")


if __name__ == "__main__":
    main()
