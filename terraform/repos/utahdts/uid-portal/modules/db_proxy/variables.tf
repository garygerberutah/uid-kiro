variable "name" {
  description = "Proxy name. Also prefixes its IAM role."
  type        = string
}

variable "subnet_ids" {
  description = "Owner-provided subnets for the proxy's ENIs. At least two, in different AZs."
  type        = list(string)

  validation {
    condition = (
      length(var.subnet_ids) >= 2 &&
      length(distinct(var.subnet_ids)) == length(var.subnet_ids) &&
      alltrue([for id in var.subnet_ids : can(regex("^subnet-[0-9a-f]{8}([0-9a-f]{9})?$", id))])
    )
    error_message = "subnet_ids must contain at least two distinct, existing AWS subnet IDs in different availability zones."
  }
}

variable "proxy_security_group_ids" {
  description = "Existing, network-owner-provided security groups to attach to the proxy. This module never manages their rules."
  type        = list(string)

  validation {
    condition = (
      length(var.proxy_security_group_ids) >= 1 &&
      length(distinct(var.proxy_security_group_ids)) == length(var.proxy_security_group_ids) &&
      alltrue([
        for id in var.proxy_security_group_ids :
        can(regex("^sg-[0-9a-f]{8}([0-9a-f]{9})?$", id))
      ])
    )
    error_message = "proxy_security_group_ids must contain distinct, existing AWS security-group IDs supplied by the State network owner."
  }
}

variable "db_cluster_identifier" {
  description = "Aurora cluster the proxy fronts."
  type        = string
}

variable "secret_arn" {
  description = "Secrets Manager secret holding username and password for the proxy's database user."
  type        = string
}

variable "secret_kms_key_arn" {
  description = "Customer-managed key encrypting the secret. Empty when the secret uses the AWS managed key."
  type        = string
  default     = ""
}

variable "client_password_auth_type" {
  description = "POSTGRES_SCRAM_SHA_256 for PostgreSQL 14+, POSTGRES_MD5 if the stored password predates it."
  type        = string
  default     = "POSTGRES_SCRAM_SHA_256"

  validation {
    condition     = contains(["POSTGRES_SCRAM_SHA_256", "POSTGRES_MD5"], var.client_password_auth_type)
    error_message = "client_password_auth_type must be POSTGRES_SCRAM_SHA_256 or POSTGRES_MD5."
  }
}

variable "idle_client_timeout" {
  description = "Seconds an idle client connection is held before the proxy closes it."
  type        = number
  default     = 1800
}

variable "max_connections_percent" {
  description = "Share of the cluster's max_connections the proxy may use."
  type        = number
  default     = 90
}

variable "max_idle_connections_percent" {
  description = "Share of max_connections the proxy keeps idle for reuse."
  type        = number
  default     = 50
}

variable "connection_borrow_timeout" {
  description = "Seconds a client waits for a pooled connection before erroring."
  type        = number
  default     = 120
}

variable "tags" {
  description = "Tags applied to every resource."
  type        = map(string)
  default     = {}
}
