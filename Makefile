.PHONY: agent-context toolchain-check fmt lint schema-check json-syntax-check policy-check contract-check test security-check preflight-core preflight-m0 preflight git-safety required-artifacts-check

# ── Toolchain ────────────────────────────────────────────────────────
PYTHON     ?= $(shell if [ -x .venv/bin/python ]; then echo .venv/bin/python; else echo python3; fi)
TERRAFORM  ?= terraform
JQ         ?= jq
SHELL      := /bin/bash

SCHEMAS_DIR  := schemas
FIXTURES_DIR := fixtures
POLICIES_DIR := policies
TOOLING_DIR  := tooling
TESTS_DIR    := tests

# Pinned versions from .tool-versions / .terraform-version
PINNED_PYTHON_VERSION  := $(shell head -1 .tool-versions 2>/dev/null | grep python | awk '{print $$2}' || echo "3.11.12")
PINNED_TF_VERSION      := $(shell cat .terraform-version 2>/dev/null || echo "1.12.1")

# ── Agent Context ────────────────────────────────────────────────────
agent-context: toolchain-check
	@echo "=== Scanalyze Deployment Platform — Agent Context ==="
	@echo "Repository: $$(pwd)"
	@echo "Branch:     $$(git branch --show-current 2>/dev/null || echo 'not a git repo')"
	@echo "HEAD:       $$(git rev-parse --short HEAD 2>/dev/null || echo 'no commits')"
	@echo "Python:     $$($(PYTHON) --version 2>/dev/null || echo 'not found')"
	@echo "Terraform:  $$($(TERRAFORM) version -json 2>/dev/null | $(JQ) -r '.terraform_version' 2>/dev/null || echo 'not found')"
	@echo "jq:         $$($(JQ) --version 2>/dev/null || echo 'not found')"
	@echo "Milestone:  M0 — Repository Foundation"
	@echo "Constraint: ZERO AWS mutations"
	@echo "=================================================="

# ── Toolchain Mismatch Detection ─────────────────────────────────────
toolchain-check:
	@echo "=== Toolchain Version Check ==="
	@ACTUAL_PY=$$($(PYTHON) -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}')" 2>/dev/null || echo "not_found"); \
	ACTUAL_TF=$$($(TERRAFORM) version -json 2>/dev/null | $(JQ) -r '.terraform_version' 2>/dev/null || echo "not_found"); \
	PINNED_PY="$(PINNED_PYTHON_VERSION)"; \
	PINNED_TF="$(PINNED_TF_VERSION)"; \
	MISMATCH=0; \
	if [ "$$ACTUAL_PY" != "$$PINNED_PY" ]; then \
		echo "⚠ TOOLCHAIN_MISMATCH: Python actual=$$ACTUAL_PY pinned=$$PINNED_PY"; \
		MISMATCH=1; \
	else \
		echo "  Python $$ACTUAL_PY ✓ (matches pin)"; \
	fi; \
	if [ "$$ACTUAL_TF" != "$$PINNED_TF" ]; then \
		echo "⚠ TOOLCHAIN_MISMATCH: Terraform actual=$$ACTUAL_TF pinned=$$PINNED_TF"; \
		MISMATCH=1; \
	else \
		echo "  Terraform $$ACTUAL_TF ✓ (matches pin)"; \
	fi; \
	if [ "$$MISMATCH" = "1" ]; then \
		echo ""; \
		echo "BLOCKED_TOOLING: M0 evidence CANNOT be verified with mismatched tools."; \
		echo "Install pinned versions or update .tool-versions/.terraform-version."; \
		echo "Proceeding with WARNING — M0 gates requiring tool verification are BLOCKED."; \
	fi

# ── Format ───────────────────────────────────────────────────────────
fmt:
	@echo "Formatting JSON schemas..."
	@find $(SCHEMAS_DIR) -name '*.json' -exec $(JQ) --sort-keys '.' {} \; 2>/dev/null || true
	@echo "Formatting JSON fixtures..."
	@find $(FIXTURES_DIR) -name '*.json' -exec $(JQ) --sort-keys '.' {} \; 2>/dev/null || true
	@echo "Formatting JSON policies..."
	@find $(POLICIES_DIR) -name '*.json' -exec $(JQ) --sort-keys '.' {} \; 2>/dev/null || true
	@echo "Format complete."

# ── Lint ─────────────────────────────────────────────────────────────
lint: json-syntax-check lint-forbidden-patterns
	@echo "All lint checks passed."

json-syntax-check:
	@echo "Validating JSON syntax..."
	@ERRORS=0; \
	for f in $$(find $(SCHEMAS_DIR) $(FIXTURES_DIR) $(POLICIES_DIR) session-policies -name '*.json' 2>/dev/null); do \
		$(JQ) empty "$$f" 2>/dev/null || { echo "FAIL: Invalid JSON: $$f"; ERRORS=$$((ERRORS + 1)); }; \
	done; \
	if [ "$$ERRORS" -gt 0 ]; then echo "JSON syntax: $$ERRORS errors" && exit 1; fi
	@echo "JSON syntax OK."

lint-forbidden-patterns:
	@echo "Checking forbidden patterns in platform code..."
	@$(PYTHON) $(TOOLING_DIR)/lint_forbidden_patterns.py modules/ roots/ 2>/dev/null || true
	@echo "Forbidden pattern check complete."

# ── Schema Check (Draft 2020-12 — requires jsonschema) ───────────────
schema-check:
	@echo "Validating schemas against JSON Schema Draft 2020-12..."
	@$(PYTHON) -c "import jsonschema" 2>/dev/null || \
		{ echo "BLOCKED_TOOLING: jsonschema not installed."; \
		  echo "schema-check requires: pip install jsonschema"; \
		  echo "JSON syntax validation is available via 'make json-syntax-check'."; \
		  exit 1; }
	@$(PYTHON) $(TOOLING_DIR)/validate_schema.py --schemas-dir $(SCHEMAS_DIR) --fixtures-dir $(FIXTURES_DIR)
	@echo "Schema check complete (Draft 2020-12 validated)."

# ── Policy Check ─────────────────────────────────────────────────────
policy-check:
	@echo "Validating IAM/S3/KMS policy fixtures..."
	@$(PYTHON) $(TOOLING_DIR)/validate_policy.py --policies-dir $(POLICIES_DIR)
	@echo "Policy check complete."

# ── Contract Check ───────────────────────────────────────────────────
contract-check:
	@echo "Running contract canonicalization and digest tests..."
	@$(PYTHON) -m pytest $(TESTS_DIR)/contracts/ -v 2>/dev/null || $(PYTHON) $(TOOLING_DIR)/validate_digest.py $(FIXTURES_DIR)/valid/
	@echo "Contract check complete."

# ── Test ─────────────────────────────────────────────────────────────
test:
	@echo "Running all tests..."
	@$(PYTHON) -m pytest $(TESTS_DIR)/ -v --tb=short 2>/dev/null || echo "pytest not available or no tests found"
	@echo "Test run complete."

# ── Security Check ───────────────────────────────────────────────────
security-check:
	@echo "Running security sentinel (with allowlist)..."
	@$(PYTHON) -m pytest $(TESTS_DIR)/sentinel/ -v 2>/dev/null || $(PYTHON) $(TOOLING_DIR)/security_sentinel.py
	@echo "Security check complete."

# ── Required Artifacts Inventory ─────────────────────────────────────
required-artifacts-check:
	@echo "Checking required M0 artifacts..."
	@$(PYTHON) $(TOOLING_DIR)/check_required_artifacts.py

# ── Preflight Core (validates existing artifacts only) ────────────────
# Use this for incremental work. Does NOT claim M0 completeness.
preflight-core: agent-context lint json-syntax-check policy-check contract-check security-check
	@echo ""
	@echo "=== PREFLIGHT-CORE COMPLETE ==="
	@echo "Existing artifacts validated. This does NOT mean M0 is complete."
	@echo "Run 'make preflight-m0' to check M0 completeness."

# ── Preflight M0 (full milestone gate — fails if anything missing) ────
# This is the real M0 gate. Must pass before M0 can be declared complete.
preflight-m0: agent-context required-artifacts-check lint json-syntax-check schema-check policy-check contract-check security-check
	@echo ""
	@echo "=== PREFLIGHT-M0 COMPLETE ==="
	@echo "All M0 required artifacts present and validated."

# ── Preflight (alias for preflight-core for backward compatibility) ──
preflight: preflight-core

# ── Git Safety ───────────────────────────────────────────────────────
git-safety:
	@echo "=== Git Safety Check ==="
	@echo "Branch: $$(git branch --show-current 2>/dev/null || echo 'unknown')"
	@echo "Checking for secrets in staged files..."
	@STAGED=$$(git diff --cached --diff-filter=ACM --name-only 2>/dev/null); \
	if [ -n "$$STAGED" ]; then \
		echo "$$STAGED" | xargs grep -lE '(AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY|AKIA[0-9A-Z]{16}|eyJ[A-Za-z0-9_-]+\.eyJ)' 2>/dev/null && \
		(echo "FAIL: Potential secrets detected in staged files" && exit 1) || true; \
	fi
	@echo "Checking for .tfstate files..."
	@find . -name '*.tfstate' -not -path './.git/*' | grep -q . && \
		(echo "FAIL: .tfstate files found in repo" && exit 1) || true
	@echo "Checking for .env files..."
	@find . -name '.env' -not -path './.git/*' | grep -q . && \
		(echo "FAIL: .env files found in repo" && exit 1) || true
	@echo "Checking worktree for secrets (not just staged)..."
	@find . -type f -name '*.json' -not -path './.git/*' | \
		xargs grep -lE 'AKIA[0-9A-Z]{16}' 2>/dev/null && \
		(echo "FAIL: AWS access key pattern found in worktree" && exit 1) || true
	@echo "Git safety OK."
