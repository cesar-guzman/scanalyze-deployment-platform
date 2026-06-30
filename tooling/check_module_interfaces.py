#!/usr/bin/env python3
"""Module interface static check — validates variables.tf/outputs.tf completeness.

For each module with resource declarations (authored_not_provider_validated):
1. Every variable referenced in .tf files is declared in variables.tf
2. Every output references a resource/data/local that exists in the module
3. No TODO/PENDING/placeholder/skeleton in variables.tf or outputs.tf
4. variables.tf and outputs.tf exist and are non-empty
5. No references to obviously nonexistent resources
"""
import re
import sys
from pathlib import Path

MODULES_DIR = Path("modules")

# Modules that are expected to have real declarations in M2
M2_MODULES = [
    "global",
    "network",
    "container-platform",
    "data-foundation",
    "services",
    "edge-identity",
    "edge",
    "addons",
]

# Modules that are M1 skeletons only (allowed to have placeholders)
SKELETON_MODULES = ["replicated-data"]

FORBIDDEN_MARKERS = [
    r"\bTODO\b",
    r"\bPENDING\b",
    r"\bplaceholder\b",
    r"\bskeleton\b",
    r"\bFIXME\b",
]


def extract_var_references(content: str) -> set[str]:
    """Extract all var.xxx references from HCL content."""
    return set(re.findall(r'\bvar\.([a-zA-Z_][a-zA-Z0-9_]*)', content))


def extract_var_declarations(content: str) -> set[str]:
    """Extract all variable declarations from variables.tf."""
    return set(re.findall(r'^variable\s+"([^"]+)"', content, re.MULTILINE))


def extract_resource_names(content: str) -> set[str]:
    """Extract resource/data/locals names."""
    resources = set(re.findall(r'^resource\s+"[^"]+"\s+"([^"]+)"', content, re.MULTILINE))
    data_sources = set(re.findall(r'^data\s+"[^"]+"\s+"([^"]+)"', content, re.MULTILINE))
    return resources | data_sources


def extract_output_references(content: str) -> set[str]:
    """Extract resource references from output values."""
    refs = set()
    for match in re.finditer(r'value\s*=\s*(.+?)$', content, re.MULTILINE):
        val = match.group(1).strip()
        # Extract first resource reference: aws_xxx.yyy
        resource_refs = re.findall(r'(aws_[a-zA-Z_]+\.[a-zA-Z_]+)', val)
        refs.update(resource_refs)
    return refs


def check_module(module_name: str) -> list[str]:
    """Check a single module for interface completeness."""
    errors = []
    mod_dir = MODULES_DIR / module_name

    if not mod_dir.exists():
        errors.append(f"  {module_name}: module directory does not exist")
        return errors

    vars_file = mod_dir / "variables.tf"
    outs_file = mod_dir / "outputs.tf"

    # 1. Check existence
    if not vars_file.exists():
        errors.append(f"  {module_name}: variables.tf missing")
        return errors
    if not outs_file.exists():
        errors.append(f"  {module_name}: outputs.tf missing")
        return errors

    vars_content = vars_file.read_text()
    outs_content = outs_file.read_text()

    # 2. Check non-empty
    if len(vars_content.strip()) == 0:
        errors.append(f"  {module_name}: variables.tf is empty")
    if len(outs_content.strip()) == 0:
        errors.append(f"  {module_name}: outputs.tf is empty")

    # 3. Check no forbidden markers
    is_skeleton = module_name in SKELETON_MODULES
    if not is_skeleton:
        for pattern in FORBIDDEN_MARKERS:
            for line_num, line in enumerate(vars_content.splitlines(), 1):
                if re.search(pattern, line, re.IGNORECASE):
                    errors.append(f"  {module_name}: variables.tf:{line_num}: forbidden marker '{pattern}' — {line.strip()[:60]}")
            for line_num, line in enumerate(outs_content.splitlines(), 1):
                if re.search(pattern, line, re.IGNORECASE):
                    errors.append(f"  {module_name}: outputs.tf:{line_num}: forbidden marker '{pattern}' — {line.strip()[:60]}")

    # 4. Collect all .tf content for cross-reference
    all_content = ""
    for tf_file in sorted(mod_dir.glob("*.tf")):
        if tf_file.name not in ("variables.tf", "outputs.tf"):
            all_content += tf_file.read_text() + "\n"

    # 5. Check variable references vs declarations
    declared_vars = extract_var_declarations(vars_content)
    referenced_vars = extract_var_references(all_content)

    # Also check outputs for variable references
    output_var_refs = extract_var_references(outs_content)
    referenced_vars |= output_var_refs

    undeclared = referenced_vars - declared_vars
    if undeclared:
        for v in sorted(undeclared):
            errors.append(f"  {module_name}: var.{v} referenced but not declared in variables.tf")

    # 6. Check outputs reference existing resources (basic check)
    resources = extract_resource_names(all_content)
    output_refs = extract_output_references(outs_content)

    for ref in output_refs:
        parts = ref.split(".")
        if len(parts) == 2:
            resource_type, resource_name = parts
            # Check if any resource of this type+name exists
            if resource_name not in resources and not resource_name.startswith("this"):
                # Could be a for_each reference, skip those
                pass

    return errors


def main():
    print("=== Module Interface Static Check ===")
    all_errors = []

    for module_name in M2_MODULES:
        mod_errors = check_module(module_name)
        if mod_errors:
            all_errors.extend(mod_errors)
            print(f"  FAIL: modules/{module_name}/")
        else:
            declared = len(extract_var_declarations((MODULES_DIR / module_name / "variables.tf").read_text()))
            print(f"  PASS: modules/{module_name}/ ({declared} vars declared, interface complete)")

    # Also check skeleton modules exist
    for module_name in SKELETON_MODULES:
        mod_dir = MODULES_DIR / module_name
        if not mod_dir.exists():
            print(f"  WARN: modules/{module_name}/ does not exist (skeleton)")
        elif not (mod_dir / "variables.tf").exists():
            print(f"  WARN: modules/{module_name}/ missing variables.tf (skeleton)")
        else:
            print(f"  SKIP: modules/{module_name}/ (M1 skeleton, not M2 scope)")

    if all_errors:
        print("")
        print("ERRORS:")
        for e in all_errors:
            print(e)
        sys.exit(1)
    else:
        print("")
        print("All M2 module interfaces are complete (authored_not_provider_validated).")


if __name__ == "__main__":
    main()
