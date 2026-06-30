# Account-Ready Gate — validation-only root.
#
# This root does NOT create resources, does NOT produce contracts,
# and does NOT own state backend infrastructure.
#
# ADR-006 maintains that account-baseline real belongs to the
# AccountVendingProvider. This root is ONLY a consumption gate
# that validates ACCOUNT_READY contract preconditions.

# All validation logic is in contract_validation.tf
