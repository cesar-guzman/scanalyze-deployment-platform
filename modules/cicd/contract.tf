# CI/CD Contract Outputs
#
# Contract: cicd/v1
# Schema: schemas/cicd-contract.v1.schema.json
# State scope: regional
# State key: {deployment_id}/{region}/cicd/terraform.tfstate
#
# Consumers:
# - services layer (ECR URIs, image digests)
# - deployment orchestrator (pipeline status, release metadata)
#
# This module's contract outputs are defined in outputs.tf.
# This file documents the contract structure for the skeleton check.
