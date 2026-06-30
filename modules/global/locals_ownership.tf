# OWNERSHIP GUARD — modules/global
#
# This module owns ONLY application workload IAM resources.
#
# The following are owned by AccountVendingProvider / account baseline
# and consumed via the ACCOUNT_READY contract. They MUST NOT be declared here:
#
#   - ScanalyzeCustomer-Plan IAM role
#   - ScanalyzeCustomer-Apply IAM role
#   - ScanalyzeCustomer-Promotion IAM role
#   - ScanalyzeCustomer-Validation IAM role
#   - ScanalyzeCustomer-Diagnostic IAM role
#   - ScanalyzeCustomer-StateRecovery IAM role
#   - State S3 bucket and its KMS key
#   - Evidence S3 bucket and its KMS key
#   - Contracts S3 bucket
#   - Plan-execution KMS key
#   - Account baseline trust policies and boundaries
#   - AccountVendingProvider automation roles
#
# If you need to reference any of the above, consume them from the
# ACCOUNT_READY contract via data sources or input variables.

locals {
  # M2: authored_not_provider_validated
  ownership_boundary = "workload_application_only"
}
