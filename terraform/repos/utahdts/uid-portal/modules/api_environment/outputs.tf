output "api_gateway_url" {
  description = "Custom-domain URL for the single host-gated HTTP API."
  value       = module.portal_api.invoke_url
}

output "api_gateway_name" {
  value = module.portal_api.api_name
}

output "api_gateway_custom_domain_target" {
  description = "Regional API Gateway origin hostname for the separately owned edge distribution."
  value       = module.portal_api.custom_domain_target
}

output "api_gateway_id" {
  value = module.portal_api.api_id
}

output "api_gateway_routes" {
  description = "All route keys on the one physical HTTP API."
  value       = module.portal_api.routes
}

# Compatibility aliases for existing operators. These all describe the same
# single gateway; no licensee-specific API outputs remain.
output "portal_api_url" {
  value = module.portal_api.custom_domain_url
}

output "portal_api_id" {
  value = module.portal_api.api_id
}

output "portal_routes" {
  description = "Compatibility alias for api_gateway_routes."
  value       = module.portal_api.routes
}

output "function_names" {
  value = { for id, f in module.function : id => f.function_name }
}

output "lambda_vpc_config" {
  description = "Non-sensitive canonical VPC contract expected on every live Lambda alias."
  value = {
    vpc_id             = module.network.vpc_id
    vpc_ipv4_cidr      = module.network.vpc_ipv4_cidr
    subnet_ids         = sort(module.network.private_subnet_ids)
    security_group_ids = sort(module.network.lambda_security_group_ids)
  }
}

output "reserved_concurrency_total" {
  description = "Concurrency reserved by this stack; compare with the account quota and other workloads before apply."
  value = sum([
    for id, f in local.all_functions :
    try(f.vpc, local.defaults.vpc) && local.function_enabled[id]
    ? (contains(keys(local.scheduled_functions), id) ? 1 : var.per_function_reserved_concurrency)
    : 0
  ])
}

output "log_groups" {
  value = { for id, f in module.function : id => f.log_group }
}

output "alert_topic_arn" {
  value = module.alerting.alert_topic_arn
}

output "dashboard_url" {
  value = "https://${var.region}.console.aws.amazon.com/cloudwatch/home?region=${var.region}#dashboards:name=${module.observability.dashboard_name}"
}

output "buckets" {
  value = {
    uploads   = module.storage.upload_bucket
    downloads = module.storage.download_bucket
    artifacts = module.storage.artifact_bucket
  }
}

output "runtime_permissions_boundary_review" {
  description = "Per-profile policy caps for independent bootstrap review; never provisioned by application Terraform."
  value = var.env_name == "at" ? merge(
    module.iam.permissions_boundary_review,
    { scheduler = module.scheduling.permissions_boundary_review },
  ) : {}
}
