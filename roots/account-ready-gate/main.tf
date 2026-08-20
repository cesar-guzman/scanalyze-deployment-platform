# Account-Ready Gate — validation-only root.
#
# This root does NOT create resources, does NOT produce contracts,
# and does NOT own state backend infrastructure.
#
# ADR-003 and ADR-030 maintain that the real account baseline belongs to the
# external AccountVendingProvider. This root is only a consumption gate that
# binds verified ACCOUNT_READY v2 evidence to the deployment registry.

# All validation logic is in contract_validation.tf
