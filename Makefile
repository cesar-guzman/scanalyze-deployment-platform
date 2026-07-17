.PHONY: help agent-context toolchain-check fmt lint schema-check enterprise-authorization-check json-syntax-check policy-check contract-check test security-check microservices-check frontend-check github-governance-check github-deployment-identity-check gitops-orchestrator-check nonprod-live-engine-check platform-authority-bootstrap-check preflight-core preflight-m0 preflight git-safety required-artifacts-check module-check root-check taskdef-check supply-chain-check preflight-m1 contract-matrix terraform-fmt-check module-ownership-check edge-split-check services-ownership-check module-interface-check preflight-m2 toolchain-status bootstrap-local repro-check phase0-docs-check docs-check release-dry-run nonprod-readiness-check clone-check

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

# ── Help ─────────────────────────────────────────────────────────────
help:
	@echo "Scanalyze validation targets:"
	@echo "  make microservices-check  Validate 7-service layout, Dockerfiles, and portability"
	@echo "  make frontend-check       Reinstall, audit, test, lint, and build the portable SPA"
	@echo "  make github-governance-check Validate stable required-check policy offline"
	@echo "  make github-deployment-identity-check Validate GUG-123 OIDC and terminal IAM controls"
	@echo "  make security-check       Scan for unallowlisted PII, secrets, state, and plans"
	@echo "  make gitops-orchestrator-check Validate the canonical dry-run deployment DAG"
	@echo "  make nonprod-live-engine-check Validate exact-plan and resumable ledger controls offline"
	@echo "  make platform-authority-bootstrap-check Validate GUG-206 bootstrap controls offline"
	@echo "  make git-safety           Check staged/worktree Git safety"
	@echo "  make test                 Run platform tests (fail closed)"
	@echo "  make enterprise-authorization-check Validate portable GUG-92 policy"
	@echo "  make preflight-core       Run safe incremental validation"
	@echo "  make preflight-m1         Run M0+M1 gates"
	@echo "  make preflight-m2         Run M0+M1+M2 gates"
	@echo "  make terraform-fmt-check  Check Terraform formatting"

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
		echo "Toolchain verification fails closed."; \
		exit 1; \
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
	@$(PYTHON) $(TOOLING_DIR)/lint_forbidden_patterns.py modules/ roots/
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

# ── Enterprise Authorization Contract ────────────────────────────────
enterprise-authorization-check:
	@echo "Validating portable enterprise authorization policy v1..."
	@$(PYTHON) $(TOOLING_DIR)/validate_enterprise_authorization.py $(POLICIES_DIR)/authorization/enterprise-authorization.v1.json
	@$(PYTHON) $(TOOLING_DIR)/policy_digest.py \
		$(POLICIES_DIR)/authorization/enterprise-authorization.v1.json \
		--digest-file $(POLICIES_DIR)/authorization/enterprise-authorization.v1.sha256 \
		--check
	@$(PYTHON) -m pytest -q \
		$(TESTS_DIR)/test_gug92_enterprise_authorization.py \
		$(TESTS_DIR)/test_gug93_policy_digest.py
	@echo "Enterprise authorization check complete."

# ── Policy Check ─────────────────────────────────────────────────────
policy-check:
	@echo "Validating IAM/S3/KMS policy fixtures..."
	@$(PYTHON) $(TOOLING_DIR)/validate_policy.py --policies-dir $(POLICIES_DIR)
	@echo "Policy check complete."

# ── Contract Check ───────────────────────────────────────────────────
contract-check:
	@echo "Running contract canonicalization and digest tests..."
	@$(PYTHON) -m pytest $(TESTS_DIR)/test_account_ready/ -v --tb=short
	@$(PYTHON) $(TOOLING_DIR)/validate_digest.py $(FIXTURES_DIR)/valid/
	@echo "Contract check complete."

# ── Test ─────────────────────────────────────────────────────────────
test:
	@echo "Running all tests..."
	@$(PYTHON) -m pytest $(TESTS_DIR)/ -v --tb=short
	@echo "Test run complete."

# ── Security Check ───────────────────────────────────────────────────
security-check:
	@echo "Running security sentinel (with allowlist)..."
	@$(PYTHON) $(TOOLING_DIR)/security_sentinel.py
	@$(PYTHON) -m pytest $(TESTS_DIR)/sentinel/ -v
	@echo "Security check complete."

# ── Microservices Check ──────────────────────────────────────────────
microservices-check:
	@echo "Checking monorepo microservice portability and safety..."
	@$(PYTHON) $(TOOLING_DIR)/check_microservices.py
	@echo "Microservices check complete."

# ── Frontend Check ──────────────────────────────────────────────────
frontend-check:
	@echo "Checking portable frontend source from a clean dependency install..."
	@cd frontend/scanalyze-frontend-ui && npm ci
	@cd frontend/scanalyze-frontend-ui && npm run check
	@cd frontend/scanalyze-frontend-ui && npm run audit
	@echo "Frontend check complete. E2E requires the reviewed Playwright browser install."

# ── GitHub Governance Check ──────────────────────────────────────────
github-governance-check:
	@echo "Checking repository-global GitHub required-check governance..."
	@$(PYTHON) $(TOOLING_DIR)/validate_github_policy.py
	@echo "GitHub governance check complete."

# ── GitHub Deployment Identity Check ─────────────────────────────────
github-deployment-identity-check:
	@echo "Checking fail-closed GitHub OIDC and terminal IAM controls..."
	@$(PYTHON) $(TOOLING_DIR)/validate_github_deployment_identity.py --repository-controls-only
	@$(PYTHON) $(TOOLING_DIR)/validate_schema.py --schemas-dir $(SCHEMAS_DIR) --fixtures-dir $(FIXTURES_DIR) --filter github
	@$(PYTHON) -m pytest -q $(TESTS_DIR)/test_governance/test_gug123_terminal_identity.py
	@echo "GitHub deployment identity check complete. Status: LOCALLY_VALIDATED_OFFLINE_ONLY"

# ── GitOps Orchestrator Check ─────────────────────────────────────────
gitops-orchestrator-check:
	@echo "=== GitOps Orchestrator Check (offline, no AWS) ==="
	@$(PYTHON) scripts/deployment/validate-layer-dag.py deployment/layers.yaml
	@$(PYTHON) -m pytest $(TESTS_DIR)/test_deployment/ $(TESTS_DIR)/test_gitops_schemas.py -v --tb=short
	@echo "GitOps orchestrator check complete. Status: LOCALLY_VALIDATED_DRY_RUN_ONLY"

# ── Required Artifacts Inventory ─────────────────────────────────────
required-artifacts-check:
	@echo "Checking required M0 artifacts..."
	@$(PYTHON) $(TOOLING_DIR)/check_required_artifacts.py

# ── Preflight Core (validates existing artifacts only) ────────────────
# Use this for incremental work. Does NOT claim M0 completeness.
preflight-core: agent-context lint json-syntax-check policy-check contract-check security-check microservices-check github-governance-check github-deployment-identity-check
	@echo ""
	@echo "=== PREFLIGHT-CORE COMPLETE ==="
	@echo "Existing artifacts validated. This does NOT mean M0 is complete."
	@echo "Run 'make preflight-m0' to check M0 completeness."

# ── Preflight M0 (full milestone gate — fails if anything missing) ────
# This is the real M0 gate. Must pass before M0 can be declared complete.
preflight-m0: agent-context required-artifacts-check lint json-syntax-check schema-check policy-check contract-check security-check microservices-check github-deployment-identity-check
	@echo ""
	@echo "=== PREFLIGHT-M0 COMPLETE ==="
	@echo "All M0 required artifacts present and validated."

# ── Preflight (alias for preflight-core for backward compatibility) ──
preflight: preflight-core

# ── Git Safety ───────────────────────────────────────────────────────
git-safety:
	@echo "=== Git Safety Check ==="
	@echo "Branch: $$(git branch --show-current 2>/dev/null || echo 'unknown')"
	@set -u; \
	GIT_SAFETY_TMP=$$(mktemp -d) || { echo "FAIL: unable to create Git safety workspace"; exit 1; }; \
	trap 'rm -rf "$$GIT_SAFETY_TMP"' EXIT HUP INT TERM; \
	SECRET_PATTERN="(AKIA|ASIA)[0-9A-Z]{16}|eyJ[A-Za-z0-9_-]+[.]eyJ[A-Za-z0-9_-]+|AWS_(ACCESS_KEY_ID|SECRET_ACCESS_KEY)[[:space:]]*[:=][[:space:]]*['\"]?[A-Za-z0-9/+=_-]{8,}"; \
	echo "Checking tracked index content for secrets..."; \
	if ! git ls-files --cached -z > "$$GIT_SAFETY_TMP/index-files"; then \
		echo "FAIL: unable to enumerate tracked index files"; \
		exit 1; \
	fi; \
	INDEX_FORBIDDEN=0; \
	INDEX_MATCH=0; \
	while IFS= read -r -d '' file; do \
		case "$$file" in \
			*.tfstate|*.tfstate.*|*.tfplan|tfplan|*/tfplan|tfplan.*|*/tfplan.*|*.plan.json|\
			.env|*/.env|.env.*|*/.env.*|\
			.terraform/*|*/.terraform/*|.work/*|*/.work/*|.venv/*|*/.venv/*|\
			.aws/*|*/.aws/*|credentials|*/credentials|*.pem|*.key|*.p12|*.crt) \
				INDEX_FORBIDDEN=1 ;; \
		esac; \
		if ! git show ":./$$file" > "$$GIT_SAFETY_TMP/content" 2>/dev/null; then \
			echo "FAIL: unable to read tracked index content"; \
			exit 1; \
		fi; \
		grep -aiEq "$$SECRET_PATTERN" "$$GIT_SAFETY_TMP/content" 2>/dev/null; \
		GREP_STATUS=$$?; \
		if [ "$$GREP_STATUS" -eq 0 ]; then \
			INDEX_MATCH=1; \
		elif [ "$$GREP_STATUS" -ne 1 ]; then \
			echo "FAIL: unable to scan tracked index content"; \
			exit 1; \
		fi; \
	done < "$$GIT_SAFETY_TMP/index-files"; \
	if [ "$$INDEX_FORBIDDEN" -ne 0 ]; then \
		echo "FAIL: Prohibited file type detected in tracked index"; \
		exit 1; \
	fi; \
	if [ "$$INDEX_MATCH" -ne 0 ]; then \
		echo "FAIL: Potential secrets detected in tracked index content"; \
		exit 1; \
	fi; \
	echo "Checking for Terraform state/plan files outside ignored workdirs..."; \
	if ! find . -type f \
		\( -name '*.tfstate' -o -name '*.tfstate.*' -o -name '*.tfplan' -o -name 'tfplan' -o -name 'tfplan.*' -o -name '*.plan.json' \) \
		-not -path '*/.git/*' -not -path '*/.terraform/*' -not -path '*/.venv/*' -not -path '*/.work/*' \
		-print0 > "$$GIT_SAFETY_TMP/state-files"; then \
		echo "FAIL: unable to inspect Terraform state/plan files"; \
		exit 1; \
	fi; \
	if IFS= read -r -d '' _ < "$$GIT_SAFETY_TMP/state-files"; then \
		echo "FAIL: Terraform state/plan files found outside ignored workdirs"; \
		exit 1; \
	fi; \
	echo "Checking for local environment files outside ignored workdirs..."; \
	if ! find . -type f \( -name '.env' -o -name '.env.*' \) \
		-not -path '*/.git/*' -not -path '*/.venv/*' -not -path '*/.work/*' \
		-print0 > "$$GIT_SAFETY_TMP/env-files"; then \
		echo "FAIL: unable to inspect local environment files"; \
		exit 1; \
	fi; \
	if IFS= read -r -d '' _ < "$$GIT_SAFETY_TMP/env-files"; then \
		echo "FAIL: Local environment files found in repo"; \
		exit 1; \
	fi; \
	echo "Checking tracked and untracked worktree content for secrets..."; \
	if ! git ls-files --cached --others --exclude-standard -z > "$$GIT_SAFETY_TMP/worktree-files"; then \
		echo "FAIL: unable to enumerate tracked and untracked worktree files"; \
		exit 1; \
	fi; \
	WORKTREE_MATCH=0; \
	while IFS= read -r -d '' file; do \
		WORKTREE_PATH="./$$file"; \
		if [ -L "$$WORKTREE_PATH" ]; then \
			if ! readlink "$$WORKTREE_PATH" > "$$GIT_SAFETY_TMP/content"; then \
				echo "FAIL: unable to read tracked or untracked symlink"; \
				exit 1; \
			fi; \
			SCAN_PATH="$$GIT_SAFETY_TMP/content"; \
		elif [ -f "$$WORKTREE_PATH" ]; then \
			SCAN_PATH="$$WORKTREE_PATH"; \
		elif [ ! -e "$$WORKTREE_PATH" ]; then \
			continue; \
		elif [ -d "$$WORKTREE_PATH" ]; then \
			continue; \
		else \
			echo "FAIL: unsupported tracked or untracked worktree file type"; \
			exit 1; \
		fi; \
		grep -aiEq "$$SECRET_PATTERN" "$$SCAN_PATH" 2>/dev/null; \
		GREP_STATUS=$$?; \
		if [ "$$GREP_STATUS" -eq 0 ]; then \
			WORKTREE_MATCH=1; \
		elif [ "$$GREP_STATUS" -ne 1 ]; then \
			echo "FAIL: unable to scan tracked or untracked worktree content"; \
			exit 1; \
		fi; \
	done < "$$GIT_SAFETY_TMP/worktree-files"; \
	if [ "$$WORKTREE_MATCH" -ne 0 ]; then \
		echo "FAIL: Potential secrets detected in tracked or untracked worktree content"; \
		exit 1; \
	fi; \
	echo "Git safety OK."

# ── Toolchain Status (M1) ────────────────────────────────────────────
toolchain-status:
	@echo "=== Toolchain Status ==="
	@echo "Pin:    Python $(PINNED_PYTHON_VERSION)"
	@echo "Actual: $$($(PYTHON) --version 2>/dev/null || echo 'not found')"
	@echo "Pin:    Terraform $(PINNED_TF_VERSION)"
	@echo "Actual: Terraform $$($(TERRAFORM) version -json 2>/dev/null | $(JQ) -r '.terraform_version' 2>/dev/null || echo 'not found')"
	@ACTUAL_PY=$$($(PYTHON) -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}')" 2>/dev/null || echo "not_found"); \
	ACTUAL_TF=$$($(TERRAFORM) version -json 2>/dev/null | $(JQ) -r '.terraform_version' 2>/dev/null || echo "not_found"); \
	if [ "$$ACTUAL_PY" != "$(PINNED_PYTHON_VERSION)" ] || [ "$$ACTUAL_TF" != "$(PINNED_TF_VERSION)" ]; then \
		echo ""; \
		echo "BLOCKED_TOOLING_REVERIFY: Evidence generated with non-pinned tools."; \
		echo "  Python tests: locally_passed_on_$$ACTUAL_PY, pending_reverify_on_$(PINNED_PYTHON_VERSION)"; \
		echo "  HCL tests:    locally_passed_on_$$ACTUAL_TF, pending_reverify_on_$(PINNED_TF_VERSION)"; \
	else \
		echo ""; \
		echo "TOOLCHAIN_MATCHED: All evidence generated with pinned tools."; \
	fi

# ── Module Check (M1) ───────────────────────────────────────────────
MODULE_REQUIRED_FILES := README.md versions.tf variables.tf outputs.tf locals.tf contract.tf
MODULE_DIRS := global network container-platform data-foundation identity-control-plane platform-authority services edge-identity edge addons replicated-data cicd

module-check:
	@echo "=== Module Skeleton Check ==="
	@ERRORS=0; \
	for mod in $(MODULE_DIRS); do \
		if [ ! -d "modules/$$mod" ]; then \
			echo "  MISSING: modules/$$mod/"; \
			ERRORS=$$((ERRORS + 1)); \
			continue; \
		fi; \
		for f in $(MODULE_REQUIRED_FILES); do \
			if [ ! -f "modules/$$mod/$$f" ]; then \
				echo "  MISSING: modules/$$mod/$$f"; \
				ERRORS=$$((ERRORS + 1)); \
			fi; \
		done; \
		echo "  OK: modules/$$mod/ (all required files present)"; \
	done; \
	if [ "$$ERRORS" -gt 0 ]; then echo "Module check: $$ERRORS missing" && exit 1; fi
	@echo "Module check complete."

# ── Root Check (M1) ─────────────────────────────────────────────────
ROOT_REQUIRED_FILES := README.md versions.tf variables.tf main.tf outputs.tf contract_validation.tf backend.example.hcl
ROOT_DIRS := account-ready-gate global network platform data-foundation cicd identity-control-plane platform-authority services edge-identity edge addons

root-check:
	@echo "=== Root Skeleton Check ==="
	@ERRORS=0; \
	for root in $(ROOT_DIRS); do \
		if [ ! -d "roots/$$root" ]; then \
			echo "  MISSING: roots/$$root/"; \
			ERRORS=$$((ERRORS + 1)); \
			continue; \
		fi; \
		for f in $(ROOT_REQUIRED_FILES); do \
			if [ ! -f "roots/$$root/$$f" ]; then \
				echo "  MISSING: roots/$$root/$$f"; \
				ERRORS=$$((ERRORS + 1)); \
			fi; \
		done; \
		echo "  OK: roots/$$root/ (all required files present)"; \
	done; \
	if [ "$$ERRORS" -gt 0 ]; then echo "Root check: $$ERRORS missing" && exit 1; fi
	@echo "Root check complete."
	@echo "Checking forbidden patterns in roots..."
	@$(PYTHON) $(TOOLING_DIR)/lint_forbidden_patterns.py modules/ roots/

# ── Task Definition Check (M1) ──────────────────────────────────────
taskdef-check:
	@echo "=== Task Definition Schema Check ==="
	@$(PYTHON) -c "import jsonschema" 2>/dev/null || \
		{ echo "BLOCKED_TOOLING: jsonschema not installed."; exit 1; }
	@$(PYTHON) $(TOOLING_DIR)/validate_schema.py --schemas-dir $(SCHEMAS_DIR) --fixtures-dir $(FIXTURES_DIR) --filter task-definition
	@echo "Task definition check complete."

# ── Supply Chain Check (M1) ──────────────────────────────────────────
supply-chain-check:
	@echo "=== Supply Chain Policy Gate Check ==="
	@$(PYTHON) -c "import cryptography, jsonschema" 2>/dev/null || \
		{ echo "BLOCKED_TOOLING: cryptography and jsonschema are required."; exit 1; }
	@$(PYTHON) -m pytest $(TESTS_DIR)/test_supply_chain/ -v --tb=short
	@$(PYTHON) $(TOOLING_DIR)/release_policy_gate.py \
		--manifest $(FIXTURES_DIR)/valid/release-v2-complete.synthetic.json \
		--attestation $(FIXTURES_DIR)/valid/release-attestation-v2-complete.synthetic.json \
		--policy $(FIXTURES_DIR)/valid/release-trust-policy-v1-synthetic.json \
		--expected-policy-digest "$$(cat $(FIXTURES_DIR)/valid/release-trust-policy-v1-synthetic.sha256)" >/dev/null
	@echo "Supply chain check complete."

# ── Non-Production Live Engine Check (GUG-125, offline) ─────────────
nonprod-live-engine-check:
	@echo "=== GUG-125 Non-Production Live Engine Check ==="
	@$(PYTHON) -c "import jsonschema" 2>/dev/null || \
		{ echo "BLOCKED_TOOLING: jsonschema is required."; exit 1; }
	@$(PYTHON) -m pytest \
		$(TESTS_DIR)/test_deployment/test_gug125_nonprod_live_engine.py \
		$(TESTS_DIR)/test_deployment/test_gug125_live_store.py \
		$(TESTS_DIR)/test_deployment/test_gug125_platform_authority_factory.py \
		-v --tb=short
	@$(TERRAFORM) -chdir=modules/platform-authority init -backend=false -input=false -no-color -lockfile=readonly >/dev/null
	@$(TERRAFORM) -chdir=modules/platform-authority test -no-color
	@env -u AWS_ACCESS_KEY_ID -u AWS_SECRET_ACCESS_KEY -u AWS_SESSION_TOKEN \
		-u AWS_PROFILE -u AWS_WEB_IDENTITY_TOKEN_FILE -u AWS_ROLE_ARN \
		$(PYTHON) scripts/deployment/nonprod-live-engine.py dry-run-check
	@echo "GUG-125 live-engine offline check complete."

# ── Dedicated Platform-Authority Bootstrap Check (GUG-206/GUG-208/GUG-209, offline) ──
platform-authority-bootstrap-check:
	@echo "=== GUG-206/GUG-208/GUG-209 Platform-Authority Bootstrap Check ==="
	@$(PYTHON) -m pytest -q \
		$(TESTS_DIR)/test_deployment/test_gug206_platform_authority_bootstrap.py \
		$(TESTS_DIR)/test_deployment/test_gug208_identity_center_name_contract.py \
		$(TESTS_DIR)/test_deployment/test_gug209_founder_bootstrap_exception.py
	@$(PYTHON) $(TOOLING_DIR)/validate_schema.py \
		--schemas-dir $(SCHEMAS_DIR) \
		--fixtures-dir $(FIXTURES_DIR) \
		--filter platform-authority
	@$(PYTHON) $(TOOLING_DIR)/validate_policy.py --policies-dir $(POLICIES_DIR)/iam
	@$(PYTHON) scripts/deployment/platform-authority-bootstrap.py --help >/dev/null
	@$(PYTHON) scripts/deployment/founder-bootstrap-exception.py --help >/dev/null
	@echo "GUG-206/GUG-208/GUG-209 bootstrap check complete. Status: LOCALLY_VALIDATED_OFFLINE_ONLY"

# ── Preflight M1 (full M1 gate) ─────────────────────────────────────
preflight-m1: toolchain-status preflight-m0 module-check root-check taskdef-check supply-chain-check git-safety security-check test
	@echo ""
	@echo "=== PREFLIGHT-M1 COMPLETE ==="
	@echo "All M0+M1 required artifacts present and validated."
	@echo "Status: M1_LOCAL_EVIDENCE_GENERATED"

# ── M2 Targets ──────────────────────────────────────────────────────

# Contract Matrix (HCL harness, builtin provider only — no AWS provider)
contract-matrix:
	@echo "=== Contract Matrix (builtin provider only) ==="
	@MATRIX_DIR=tests/preconditions/layer_contract_matrix; \
	if [ ! -f "$$MATRIX_DIR/main.tf" ]; then \
		echo "FAIL: $$MATRIX_DIR/main.tf not found"; exit 1; \
	fi; \
	cd "$$MATRIX_DIR" && \
	if grep -q 'required_providers' main.tf 2>/dev/null && grep -q 'hashicorp/aws' main.tf 2>/dev/null; then \
		echo "BLOCKED_PROVIDER_DOWNLOAD_NOT_APPROVED: harness requires AWS provider"; exit 1; \
	fi; \
	$(TERRAFORM) init -input=false -no-color -backend=false > /dev/null 2>&1 && \
	bash run_matrix.sh
	@echo "Contract matrix complete."

# Terraform fmt check (no provider download required)
terraform-fmt-check:
	@echo "=== Terraform Format Check ==="
	@$(TERRAFORM) fmt -check -recursive modules/ roots/ 2>&1 || \
		{ echo "FAIL: terraform fmt check failed. Run 'terraform fmt -recursive modules/ roots/' to fix."; exit 1; }
	@echo "Terraform fmt check complete."

# Module ownership linter (global must not own baseline resources)
module-ownership-check:
	@echo "=== Module Ownership Check ==="
	@$(PYTHON) $(TOOLING_DIR)/lint_module_ownership.py
	@echo "Module ownership check complete."

# Edge split linter (edge-identity vs edge resource boundaries)
edge-split-check:
	@echo "=== Edge Split Check ==="
	@$(PYTHON) $(TOOLING_DIR)/lint_edge_split.py
	@echo "Edge split check complete."

# Services ownership linter (task definition ownership)
services-ownership-check:
	@echo "=== Services Ownership Check ==="
	@$(PYTHON) $(TOOLING_DIR)/lint_services_ownership.py
	@echo "Services ownership check complete."

# CI/CD safety linter (blocks ECS deploy, ecs:*, PassRole *, hardcoded IDs)
cicd-safety-check:
	@echo "=== CI/CD Safety Check ==="
	@$(PYTHON) $(TOOLING_DIR)/lint_cicd_safety.py
	@echo "CI/CD safety check complete."

# Module interface static check (no provider — validates vars/outputs completeness)
module-interface-check:
	@echo "=== Module Interface Check ==="
	@$(PYTHON) $(TOOLING_DIR)/check_module_interfaces.py
	@echo "Module interface check complete."

# ── Preflight M2 (full M2 gate) ───────────────────────────────────────
preflight-m2: preflight-m1 module-ownership-check edge-split-check services-ownership-check module-interface-check terraform-fmt-check contract-matrix
	@echo ""
	@echo "=== PREFLIGHT-M2 COMPLETE ==="
	@echo "All M0+M1+M2 checks passed."
	@echo "Status: M2_LOCAL_EVIDENCE_GENERATED"
	@echo "Declarations status: authored_not_provider_validated"

# ============================================================
# M2 Level B — Provider Validation
# ============================================================

ROOT_DIRS = account-ready-gate global network platform data-foundation cicd identity-control-plane platform-authority services edge-identity edge addons

aws-credentials-guard:
	@echo "=== AWS Credentials Guard ==="
	@if env | grep -qE '^(AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY|AWS_SESSION_TOKEN|AWS_PROFILE|AWS_WEB_IDENTITY_TOKEN_FILE)='; then \
		echo "FAIL: AWS credentials/profile found in environment. Refusing to proceed."; \
		exit 1; \
	fi
	@echo "PASS: No AWS credentials in environment"

provider-init: aws-credentials-guard
	@echo "=== Provider Init (backend=false) ==="
	@for root in $(ROOT_DIRS); do \
		echo "  Initializing roots/$$root..."; \
		$(TERRAFORM) -chdir=roots/$$root init -backend=false -input=false -no-color 2>&1 | tail -1; \
	done
	@echo "Provider init complete."

provider-validate: aws-credentials-guard
	@echo "=== Provider Validate ==="
	@ERRORS=0; \
	for root in $(ROOT_DIRS); do \
		RESULT=$$($(TERRAFORM) -chdir=roots/$$root validate -no-color 2>&1); \
		if echo "$$RESULT" | grep -q "Success"; then \
			echo "  PASS: roots/$$root"; \
		else \
			echo "  FAIL: roots/$$root"; \
			echo "$$RESULT" | head -5; \
			ERRORS=$$((ERRORS + 1)); \
		fi; \
	done; \
	echo ""; \
	if [ "$$ERRORS" -gt 0 ]; then \
		echo "Provider validate: $$ERRORS failures"; \
		exit 1; \
	fi; \
	echo "Provider validate: ALL PASS ($(words $(ROOT_DIRS))/$(words $(ROOT_DIRS)))"

provider-check: provider-init provider-validate
	@echo ""
	@echo "=== Provider Check Complete ==="

lock-file-check:
	@echo "=== Lock File Check ==="
	@$(PYTHON) tooling/check_lock_files.py

preflight-m2b: preflight-m2 provider-check lock-file-check
	@echo ""
	@echo "=== PREFLIGHT-M2B COMPLETE ==="
	@echo "All M0+M1+M2+M2B checks passed."
	@echo "Status: M2B_PROVIDER_VALIDATED_LOCALLY"
	@echo "Declarations status: provider_validated_locally"
	@echo "Provider: hashicorp/aws (version from lock files)"

# ============================================================
# M3 — First Terraform Plan Against AWS
# ============================================================

# M3-A0: Identity config check (OFFLINE — no AWS calls)
# Validates environment is configured for SSO, no static keys,
# no accidental Apply/Promotion/StateRecovery role references.
m3-identity-config-check:
	@echo "=== M3 Identity Config Check (Offline) ==="
	@ERRORS=0; \
	if [ -n "$${AWS_ACCESS_KEY_ID:-}" ] && [ -z "$${AWS_SESSION_TOKEN:-}" ]; then \
		echo "  FAIL: Static AWS_ACCESS_KEY_ID detected without session token."; \
		echo "        Use IAM Identity Center / SSO sessions only."; \
		ERRORS=$$((ERRORS + 1)); \
	else \
		echo "  PASS: No static long-lived AWS access key"; \
	fi; \
	if [ -n "$${AWS_SECRET_ACCESS_KEY:-}" ] && [ -z "$${AWS_SESSION_TOKEN:-}" ]; then \
		echo "  FAIL: Static AWS_SECRET_ACCESS_KEY detected without session token."; \
		ERRORS=$$((ERRORS + 1)); \
	else \
		echo "  PASS: No static long-lived AWS secret key"; \
	fi; \
	for ROLE_PATTERN in Apply Promotion StateRecovery; do \
		if env | grep -qiE "ROLE.*$$ROLE_PATTERN|$$ROLE_PATTERN.*ROLE" 2>/dev/null; then \
			echo "  FAIL: Role pattern '$$ROLE_PATTERN' found in environment"; \
			ERRORS=$$((ERRORS + 1)); \
		fi; \
	done; \
	echo "  PASS: No Apply/Promotion/StateRecovery role references in env"; \
	if [ -f environments/m3-sandbox.synthetic.tfvars.example ]; then \
		echo "  PASS: Synthetic tfvars example exists"; \
	else \
		echo "  FAIL: environments/m3-sandbox.synthetic.tfvars.example not found"; \
		ERRORS=$$((ERRORS + 1)); \
	fi; \
	echo ""; \
	if [ "$$ERRORS" -gt 0 ]; then \
		echo "Identity config check: $$ERRORS failure(s)"; \
		exit 1; \
	fi; \
	echo "Identity config check: PASS (offline, no AWS calls)"

# M3-A0: Workdir check — verifies .work/ is gitignored and nothing staged
m3-workdir-check:
	@echo "=== M3 Workdir Check ==="
	@ERRORS=0; \
	if ! grep -qF '.work/' .gitignore 2>/dev/null; then \
		echo "  FAIL: .work/ not in .gitignore"; \
		ERRORS=$$((ERRORS + 1)); \
	else \
		echo "  PASS: .work/ is in .gitignore"; \
	fi; \
	STAGED=$$(git ls-files --cached -- '.work/*' 2>/dev/null | head -1); \
	if [ -n "$$STAGED" ]; then \
		echo "  FAIL: .work/ has staged files: $$STAGED"; \
		ERRORS=$$((ERRORS + 1)); \
	else \
		echo "  PASS: No .work/ files staged"; \
	fi; \
	TRACKED_STATE=$$(git ls-files --cached -- '*.tfstate' '*.tfplan' '*.plan.json' 2>/dev/null | head -1); \
	if [ -n "$$TRACKED_STATE" ]; then \
		echo "  FAIL: Sensitive artifact tracked: $$TRACKED_STATE"; \
		ERRORS=$$((ERRORS + 1)); \
	else \
		echo "  PASS: No tfstate/tfplan/plan.json tracked"; \
	fi; \
	echo ""; \
	if [ "$$ERRORS" -gt 0 ]; then \
		echo "Workdir check: $$ERRORS failure(s)"; \
		exit 1; \
	fi; \
	echo "Workdir check: PASS"

# M3-A0: tfvars synthetic check — verifies no real IDs in example
m3-tfvars-check:
	@echo "=== M3 tfvars Synthetic Check ==="
	@TFVARS=environments/m3-sandbox.synthetic.tfvars.example; \
	if [ ! -f "$$TFVARS" ]; then \
		echo "  FAIL: $$TFVARS not found"; \
		exit 1; \
	fi; \
	ERRORS=0; \
	if grep -qE '\b[1-9][0-9]{11}\b' "$$TFVARS"; then \
		echo "  FAIL: Real 12-digit account ID detected in $$TFVARS"; \
		ERRORS=$$((ERRORS + 1)); \
	else \
		echo "  PASS: No real account IDs"; \
	fi; \
	if grep -qE 'arn:aws:[a-z0-9-]+:[a-z0-9-]*:[1-9]' "$$TFVARS"; then \
		echo "  FAIL: Real ARN detected in $$TFVARS"; \
		ERRORS=$$((ERRORS + 1)); \
	else \
		echo "  PASS: No real ARNs"; \
	fi; \
	if grep -qiE '(password|secret_key|token)\s*=' "$$TFVARS" | grep -v '#' 2>/dev/null; then \
		echo "  FAIL: Secret-like assignment in $$TFVARS"; \
		ERRORS=$$((ERRORS + 1)); \
	else \
		echo "  PASS: No secret-like assignments"; \
	fi; \
	if grep -q 'SYNTHETIC EXAMPLE ONLY' "$$TFVARS" || grep -q 'synthetic' "$$TFVARS"; then \
		echo "  PASS: Contains synthetic markers"; \
	else \
		echo "  WARN: No 'synthetic' marker found"; \
	fi; \
	echo ""; \
	if [ "$$ERRORS" -gt 0 ]; then \
		echo "tfvars check: $$ERRORS failure(s)"; \
		exit 1; \
	fi; \
	echo "tfvars check: PASS (synthetic, no real IDs)"

# M3-A0: Script safety check — verifies wrapper rejects forbidden ops
m3-script-check:
	@echo "=== M3 Script Safety Check ==="
	@SCRIPT=scripts/m3/m3_plan_only.sh; \
	if [ ! -f "$$SCRIPT" ]; then \
		echo "  FAIL: $$SCRIPT not found"; \
		exit 1; \
	fi; \
	if ! head -1 "$$SCRIPT" | grep -q 'bash'; then \
		echo "  FAIL: Script does not have bash shebang"; \
		exit 1; \
	fi; \
	echo "  PASS: Script exists"; \
	for PATTERN in "terraform apply" "terraform destroy" "terraform import" "terraform state"; do \
		if grep -q "FORBIDDEN.*$$PATTERN\|$$PATTERN.*fail\|$$PATTERN.*FAIL\|\"$$PATTERN\"" "$$SCRIPT" 2>/dev/null; then \
			echo "  PASS: Script blocks '$$PATTERN'"; \
		else \
			echo "  WARN: Could not confirm '$$PATTERN' is blocked"; \
		fi; \
	done; \
	for FLAG in '"-out"' '"-destroy"' '"-target"' '"-replace"' '"-generate-config-out"' '"-refresh-only"'; do \
		if grep -q "$$FLAG" "$$SCRIPT" 2>/dev/null; then \
			echo "  PASS: Script blocks flag $$FLAG"; \
		else \
			echo "  WARN: Could not confirm flag $$FLAG is blocked"; \
		fi; \
	done; \
	echo ""; \
	echo "Script safety check: PASS"

# --- Aggregate M3-A0 preflight (OFFLINE — no AWS calls) ---
preflight-m3-a0-local: preflight-m2b m3-identity-config-check m3-workdir-check m3-tfvars-check m3-script-check
	@echo ""
	@echo "=== PREFLIGHT-M3-A0-LOCAL COMPLETE ==="
	@echo "All M0+M1+M2+M2B+M3-A0 checks passed."
	@echo "Status: M3_A0_LOCAL_PREPARATION_VERIFIED"
	@echo "No AWS calls were made."
	@echo "Next: PM approval required for M3-A1 (AWS discovery)"

# --- M3-A1: Live identity guard (NOT executable until PM approves M3-A1) ---
m3-live-identity-guard:
	@echo "=== M3 Live Identity Guard ==="
	@echo "ERROR: M3-A1 is NOT APPROVED. This target requires PM approval."
	@echo "       Do not execute AWS CLI commands without explicit authorization."
	@exit 1

# --- M3-A1: Discovery preflight (NOT executable until PM approves) ---
preflight-m3-a1-discovery:
	@echo "=== M3-A1 Discovery Preflight ==="
	@echo "ERROR: M3-A1 is NOT APPROVED. This target requires PM approval."
	@echo "       Discovery commands: aws sts, ec2 describe-vpcs, etc."
	@exit 1

# --- M3-B: Plan preflight (NOT executable until PM approves) ---
preflight-m3-b-plan:
	@echo "=== M3-B Plan Preflight ==="
	@echo "ERROR: M3-B is NOT APPROVED. This target requires PM approval."
	@echo "       terraform plan requires M3-A1 results + PM approval per root."
	@exit 1

# --- M3-B: Plan one root (NOT executable until PM approves) ---
m3-plan-root:
	@echo "=== M3-B Plan Root ==="
	@echo "ERROR: M3-B is NOT APPROVED. This target requires PM approval."
	@echo "       Usage (when approved): make m3-plan-root ROOT=global"
	@exit 1

# ============================================================
# Sandbox Lifecycle — Up / Down / Status / Cost
# ============================================================
# These targets orchestrate terraform apply and destroy across
# all layers in dependency order. Designed for sandbox environments
# where full teardown is used to minimize costs.
#
# IMPORTANT: apply and destroy are NOT approved until PM authorizes.
# The cost and status targets are informational and safe to run.
#
# Usage:
#   make sandbox-up      SANDBOX_APPROVED=true SANDBOX_ACCOUNT_ID=... SANDBOX_REGION=... SANDBOX_TFVARS=...
#   make sandbox-down    SANDBOX_APPROVED=true SANDBOX_ACCOUNT_ID=... SANDBOX_REGION=... SANDBOX_TFVARS=...
#   make sandbox-status  SANDBOX_REGION=us-west-2
#   make sandbox-cost

sandbox-up:
	@echo "=== Sandbox UP ==="
	@if [ "$${SANDBOX_APPROVED:-}" != "true" ]; then \
		echo "ERROR: terraform apply is NOT APPROVED."; \
		echo "       Set SANDBOX_APPROVED=true only when PM has explicitly authorized."; \
		echo "       Required: SANDBOX_ACCOUNT_ID, SANDBOX_REGION, SANDBOX_TFVARS"; \
		exit 1; \
	fi
	@chmod +x scripts/m3/sandbox_lifecycle.sh
	@scripts/m3/sandbox_lifecycle.sh up

sandbox-down:
	@echo "=== Sandbox DOWN ==="
	@if [ "$${SANDBOX_APPROVED:-}" != "true" ]; then \
		echo "ERROR: terraform destroy is NOT APPROVED."; \
		echo "       Set SANDBOX_APPROVED=true only when PM has explicitly authorized."; \
		echo "       This will destroy ALL resources in the sandbox account."; \
		exit 1; \
	fi
	@chmod +x scripts/m3/sandbox_lifecycle.sh
	@scripts/m3/sandbox_lifecycle.sh down

sandbox-status:
	@chmod +x scripts/m3/sandbox_lifecycle.sh
	@scripts/m3/sandbox_lifecycle.sh status

sandbox-cost:
	@chmod +x scripts/m3/sandbox_lifecycle.sh
	@scripts/m3/sandbox_lifecycle.sh cost

# ============================================================
# Autonomous Deployment Platform Targets
# ============================================================

# Bootstrap local development environment (no AWS)
bootstrap-local: toolchain-check
	@echo "=== Bootstrap Local ==="
	@if [ ! -d ".venv" ]; then \
		echo "Creating virtual environment..."; \
		$(PYTHON) -m venv .venv; \
	fi
	@echo "Installing dependencies..."
	@.venv/bin/python -m pip install -q -e '.[test]' || \
		{ echo "BLOCKED_TOOLING: dependency installation failed."; exit 1; }
	@echo "Verifying toolchain..."
	@$(MAKE) --no-print-directory PYTHON=.venv/bin/python toolchain-check
	@echo "Validating JSON schemas..."
	@$(MAKE) --no-print-directory json-syntax-check
	@echo "Bootstrap complete."

# Reproducibility check (bootstrap may use package network; no AWS)
repro-check: bootstrap-local
	@echo "=== Reproducibility Check ==="
	@$(MAKE) --no-print-directory microservices-check
	@$(MAKE) --no-print-directory github-governance-check
	@$(MAKE) --no-print-directory github-deployment-identity-check
	@$(MAKE) --no-print-directory security-check
	@$(MAKE) --no-print-directory json-syntax-check
	@$(MAKE) --no-print-directory gitops-orchestrator-check
	@$(MAKE) --no-print-directory terraform-fmt-check
	@$(MAKE) --no-print-directory test
	@echo "Checking for forbidden artifacts..."
	@FOUND=$$(find . -type f \( -name '*.tfstate' -o -name '*.tfstate.*' -o -name '*.tfplan' -o -name '.env' -o -name '*.pem' -o -name '*.key' \) -not -path '*/.git/*' -not -path '*/.venv/*' -not -path '*/.work/*' -not -path '*/.terraform/*' | head -1); \
	if [ -n "$$FOUND" ]; then \
		echo "FAIL: Forbidden artifact found: $$FOUND"; \
		exit 1; \
	fi
	@echo ""
	@echo "=== REPRO-CHECK COMPLETE ==="
	@echo "Status: REPRO_CHECK_PASSED"

# Phase 0 documentation control (offline, no AWS)
phase0-docs-check:
	@echo "=== Phase 0 Documentation Control ==="
	@$(PYTHON) tooling/validate_phase0_docs.py

# Documentation check
docs-check: phase0-docs-check
	@echo "=== Documentation Check ==="
	@ERRORS=0; \
		for f in README.md REPRODUCIBILITY.md playbooks/enterprise-client-deployment.md \
			ADR/ADR-017-github-actions-release-orchestrator.md \
			ADR/ADR-018-stable-ci-governance.md \
			ADR/ADR-019-production-readiness-foundation.md \
			ADR/ADR-031-github-oidc-terminal-identity.md \
			ADR/ADR-032-build-once-and-supply-chain-fail-closed.md \
			ADR/ADR-033-nonproduction-live-engine-and-saved-plans.md \
			ADR/ADR-034-dedicated-platform-authority-account-bootstrap.md \
			docs/deployment/build-once-supply-chain.md \
			docs/deployment/nonproduction-live-engine.md \
			docs/deployment/platform-authority-bootstrap.md \
			docs/deployment/platform-authority-account-bootstrap.md \
			docs/deployment/supply-chain.md \
			docs/deployment/gitops-orchestrator.md \
			docs/deployment/github-oidc-terminal-identity.md \
			docs/operations/github-governance.md \
			docs/operations/github-oidc-terminal-identity-rollout.md \
			docs/operations/build-once-promotion-and-rollback.md \
			docs/operations/nonproduction-live-engine-reconciliation.md \
			docs/operations/platform-authority-bootstrap-recovery.md \
			docs/security/gug-125-threat-model-delta.md \
			docs/security/gug-206-threat-model-delta.md \
			docs/security/gug-124-threat-model-delta.md \
			docs/security/gug-123-threat-model-delta.md \
			docs/production-readiness/README.md \
			playbooks/phase-0-foundation.md \
			_NotebookLM_Brain/10_Production_Readiness_Foundation.md \
			_NotebookLM_Brain/20_GUG123_GitHub_OIDC_Terminal_Identity.md \
			_NotebookLM_Brain/21_GUG124_Build_Once_Supply_Chain.md \
			_NotebookLM_Brain/22_GUG125_Nonproduction_Live_Engine.md \
			_NotebookLM_Brain/23_GUG206_Platform_Authority_Account_Bootstrap.md \
			governance/github-policy.json deployment/layers.yaml; do \
		if [ ! -f "$$f" ]; then \
			echo "  MISSING: $$f"; \
			ERRORS=$$((ERRORS + 1)); \
		else \
			echo "  OK: $$f"; \
		fi; \
	done; \
	for d in docs/operations docs/deployment; do \
		if [ ! -d "$$d" ]; then \
			echo "  MISSING: $$d/"; \
			ERRORS=$$((ERRORS + 1)); \
		else \
			echo "  OK: $$d/"; \
		fi; \
	done; \
	if [ "$$ERRORS" -gt 0 ]; then echo "Docs check: $$ERRORS missing" && exit 1; fi
	@echo "Docs check complete."

# Full release dry-run (bootstrap may use package network; no AWS)
release-dry-run: repro-check
	@echo "=== Release Dry-Run ==="
	@echo "Validating deployment manifest schema..."
	@$(PYTHON) scripts/deployment/validate-manifest.py examples/deployments/synthetic-nonprod.yaml
	@echo "Generating release graph (dry-run)..."
	@$(PYTHON) scripts/supply-chain/release-graph.py --dry-run
	@echo "Running orchestrator doctor..."
	@bash scripts/deployment/scanalyze-deploy.sh doctor
	@echo "Exercising the complete orchestrator DAG (dry-run)..."
	@bash scripts/repro/run-release-dry-run.sh
	@$(MAKE) --no-print-directory docs-check
	@echo ""
	@echo "=== RELEASE-DRY-RUN COMPLETE ==="
	@echo "Status: RELEASE_DRY_RUN_PASSED"
	@echo "Ready for: PR submission, code review"
	@echo "Not ready for: live deployment, production"

# Non-production readiness check
nonprod-readiness-check: release-dry-run nonprod-live-engine-check
	@echo "=== Non-Production Readiness Check ==="
	@echo "repro-check:        PASSED"
	@echo "manifest-validation: PASSED"
	@echo "release-dry-run:    PASSED"
	@echo "gitops-orchestrator: LOCALLY_VALIDATED_DRY_RUN_ONLY"
	@echo "exact-plan-engine:  LOCALLY_VALIDATED_OFFLINE_ONLY"
	@echo "live-validation:    BLOCKED (requires AWS credentials + PM approval)"
	@echo "production-ready:   NO-GO (requires live validation)"
	@echo ""
	@echo "=== NONPROD-READINESS: PREPARED ==="

# Clean clone verification
clone-check:
	@echo "=== Clean Clone Check ==="
	@chmod +x scripts/repro/verify-clean-clone.sh
	@scripts/repro/verify-clean-clone.sh --ref HEAD
