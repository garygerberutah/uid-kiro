output "db_proxy_host" {
  description = "Paste into envs/dev/terraform.tfvars as db_proxy_host."
  value       = module.proxy.endpoint
}

output "proxy_security_group_ids" {
  description = "Existing, network-owner-provided groups attached to the proxy."
  value       = module.proxy.security_group_ids
}
