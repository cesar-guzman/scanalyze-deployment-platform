module "platform_authority" {
  source = "../../modules/platform-authority"

  authority_account_id = var.authority_account_id
  authority_region     = var.authority_region
  aws_partition        = var.aws_partition
  release_bucket_name  = var.release_bucket_name
  deployments          = var.deployments
  tags                 = var.tags

  depends_on = [terraform_data.root_contract]
}
