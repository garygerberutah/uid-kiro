output "lambda_security_group_ids" {
  description = "Existing security groups attached to every VPC-enabled Lambda function."
  value       = sort(tolist(var.lambda_security_group_ids))
}

output "private_subnet_ids" {
  value = sort(data.aws_subnets.lambda.ids)
}

output "vpc_id" {
  value = data.aws_vpc.this.id
}

output "vpc_ipv4_cidr" {
  description = "Observed primary IPv4 CIDR of the existing State-owned VPC."
  value       = data.aws_vpc.this.cidr_block
}

output "vpc_config" {
  description = "Read-only existing-network configuration for the lambda_function module."
  value = {
    subnet_ids         = sort(data.aws_subnets.lambda.ids)
    security_group_ids = sort(tolist(var.lambda_security_group_ids))
  }
}
