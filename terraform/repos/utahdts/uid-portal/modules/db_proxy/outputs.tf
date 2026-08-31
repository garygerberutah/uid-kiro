output "endpoint" {
  description = "Host for the API stack's db_proxy_host."
  value       = aws_db_proxy.this.endpoint
}

output "arn" {
  description = "RDS Proxy ARN for inventory and external monitoring."
  value       = aws_db_proxy.this.arn
}

output "security_group_ids" {
  description = "The existing network-owner-provided security groups attached to the proxy."
  value       = var.proxy_security_group_ids
}
