# Optional control-plane coordination; no deployment or data-write authority.
# The three externally reviewed roles are deliberately not inferred or created.
module "release_orchestration" {
  source = "../release_orchestration"
  count  = var.release_orchestration == null ? 0 : 1

  environment        = var.env_name
  artifact_directory = abspath("${path.root}/release-orchestration-artifacts")
  validator_role_arn = var.release_orchestration.validator_role_arn
  release_role_arn   = var.release_orchestration.release_role_arn
  health_role_arn    = var.release_orchestration.health_role_arn
  probe_version_arn  = var.release_orchestration.probe_version_arn
  private_subnet_ids = module.network.private_subnet_ids
  security_group_ids = module.network.lambda_security_group_ids

  depends_on = [terraform_data.reject_offline_provider_validation_in_plans]
}
