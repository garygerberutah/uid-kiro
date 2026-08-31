output "api_gateway_url" {
  value = module.stack.api_gateway_url
}

output "api_gateway_name" {
  value = module.stack.api_gateway_name
}

output "api_gateway_custom_domain_target" {
  value = module.stack.api_gateway_custom_domain_target
}

output "api_gateway_id" {
  value = module.stack.api_gateway_id
}

output "api_gateway_routes" {
  value = module.stack.api_gateway_routes
}

output "portal_api_url" {
  value = module.stack.portal_api_url
}

output "portal_routes" {
  value = module.stack.portal_routes
}
output "function_names" {
  value = module.stack.function_names
}

output "lambda_vpc_config" {
  value = module.stack.lambda_vpc_config
}

output "reserved_concurrency_total" {
  value = module.stack.reserved_concurrency_total
}

output "dashboard_url" {
  value = module.stack.dashboard_url
}

output "buckets" {
  value = module.stack.buckets
}
