variable "vpc_id" {
  description = "Existing State-owned VPC used by the Lambda functions."
  type        = string

  validation {
    condition     = can(regex("^vpc-[0-9a-f]{8,}$", var.vpc_id))
    error_message = "vpc_id must be an existing VPC id supplied by the State network owner."
  }
}

variable "vpc_ipv4_cidr" {
  description = "Owner-supplied canonical IPv4 CIDR that must be the existing VPC's sole associated IPv4 CIDR and every selected route table's AWS local destination."
  type        = string

  validation {
    condition = (
      can(cidrnetmask(var.vpc_ipv4_cidr)) &&
      try(
        format("%s/%s", cidrhost(var.vpc_ipv4_cidr, 0), split("/", var.vpc_ipv4_cidr)[1]) == var.vpc_ipv4_cidr,
        false,
      )
    )
    error_message = "vpc_ipv4_cidr must be a canonical owner-supplied IPv4 CIDR such as 10.192.6.0/23; placeholders deliberately block planning."
  }
}

variable "private_subnet_ids" {
  description = "Existing State-owned private subnets used by the Lambda functions."
  type        = list(string)

  validation {
    condition = (
      length(var.private_subnet_ids) >= 2 &&
      length(toset(var.private_subnet_ids)) == length(var.private_subnet_ids) &&
      alltrue([
        for id in var.private_subnet_ids : can(regex("^subnet-[0-9a-f]{8,}$", id))
      ])
    )
    error_message = "private_subnet_ids must contain at least two distinct existing subnet ids supplied by the State network owner."
  }
}

variable "lambda_security_group_ids" {
  description = "Existing State-owned security groups attached to every VPC-enabled Lambda function."
  type        = set(string)

  validation {
    condition = (
      length(var.lambda_security_group_ids) > 0 &&
      alltrue([
        for id in var.lambda_security_group_ids : can(regex("^sg-[0-9a-f]{8,}$", id))
      ])
    )
    error_message = "lambda_security_group_ids must contain at least one existing security group id supplied by the State network owner."
  }
}

variable "database_security_group_id" {
  description = "Existing RDS Proxy security group. Its owner must already allow the Lambda security groups; empty when no AWS group is applicable."
  type        = string
  default     = ""

  validation {
    condition     = var.database_security_group_id == "" || can(regex("^sg-[0-9a-f]{8,}$", var.database_security_group_id))
    error_message = "database_security_group_id must be empty or an existing security group id."
  }
}

variable "snap_database_security_group_id" {
  description = "Existing snapproxy security group. Its owner must already allow the Lambda security groups; empty when no AWS group is applicable."
  type        = string
  default     = ""

  validation {
    condition     = var.snap_database_security_group_id == "" || can(regex("^sg-[0-9a-f]{8,}$", var.snap_database_security_group_id))
    error_message = "snap_database_security_group_id must be empty or an existing security group id."
  }
}

variable "oracle_database_security_group_id" {
  description = "Existing Oracle security group. Its owner must already allow the Lambda security groups; empty when no AWS group is applicable."
  type        = string
  default     = ""

  validation {
    condition     = var.oracle_database_security_group_id == "" || can(regex("^sg-[0-9a-f]{8,}$", var.oracle_database_security_group_id))
    error_message = "oracle_database_security_group_id must be empty or an existing security group id."
  }
}

variable "existing_interface_endpoint_security_group_ids" {
  description = "Existing State-owned interface-endpoint security groups. Their owner must already allow HTTPS from every Lambda security group."
  type        = set(string)
  default     = []

  validation {
    condition = alltrue([
      for id in var.existing_interface_endpoint_security_group_ids : can(regex("^sg-[0-9a-f]{8,}$", id))
    ])
    error_message = "existing_interface_endpoint_security_group_ids must contain only existing security group ids."
  }
}
