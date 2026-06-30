#!/usr/bin/env python3
"""Check that all M0 required artifacts exist.

Reads required-artifacts.yaml and verifies every listed file is present.
Exits 1 if any required file is missing.
"""

import sys
from pathlib import Path

# Inline YAML parser (no external dependency)
# Parses the simple flat-list structure of required-artifacts.yaml

def parse_required_files(yaml_path: Path) -> list[str]:
    """Extract all file paths from required-artifacts.yaml."""
    files = []
    with open(yaml_path) as f:
        for line in f:
            stripped = line.strip()
            if stripped.startswith("- ") and not stripped.startswith("- path:"):
                path = stripped[2:].strip()
                # Skip non-path entries
                if "/" in path or path.endswith(".json") or path.endswith(".md") or path.endswith(".py") or path.endswith(".yaml"):
                    files.append(path)
    return files


def main():
    yaml_path = Path("required-artifacts.yaml")
    if not yaml_path.exists():
        print("ERROR: required-artifacts.yaml not found")
        sys.exit(1)

    required_files = parse_required_files(yaml_path)

    missing = []
    present = []

    for filepath in sorted(set(required_files)):
        if Path(filepath).exists():
            present.append(filepath)
        else:
            missing.append(filepath)

    print(f"=== Required Artifacts Check ===")
    print(f"Total required: {len(required_files)}")
    print(f"Present:        {len(present)}")
    print(f"Missing:        {len(missing)}")

    if missing:
        print(f"\n❌ MISSING ARTIFACTS ({len(missing)}):")
        for f in missing:
            print(f"  - {f}")
        print(f"\nFAIL: {len(missing)} required artifacts missing")
        sys.exit(1)
    else:
        print("\n✅ All required artifacts present")
        sys.exit(0)


if __name__ == "__main__":
    main()
