terraform {
  required_version = ">= 1.5.0"

  # M1: No backend configuration — interface skeleton only.
  # Backend is rendered by orchestrator from deployment record.
  # See backend.example.hcl for the expected format.

  # M1: No provider blocks — no AWS resources created.
  # When providers are added (M2+), they must NOT include
  # default_tags that override ownership-critical tags.
}
