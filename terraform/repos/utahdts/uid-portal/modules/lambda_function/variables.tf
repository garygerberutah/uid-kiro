variable "name" {
  description = "Fully qualified function name, e.g. uid-portal-dev-sife_report."
  type        = string
}

variable "handler" {
  description = "Python entry point in AWS form, e.g. handlers.sife_report.submit."
  type        = string
}

variable "package_zip_path" {
  description = "Committed placeholder archive used only for initial function provisioning."
  type        = string
}

variable "layer_arns" {
  description = "Layers providing third-party dependencies."
  type        = list(string)
  default     = []
}

variable "runtime" {
  type    = string
  default = "python3.13"
}

variable "architecture" {
  description = "arm64 is ~20% cheaper per GB-second than x86_64 and every dependency here has an aarch64 wheel."
  type        = string
  default     = "arm64"
}

variable "timeout" {
  type    = number
  default = 29

  validation {
    condition     = var.timeout >= 1 && var.timeout <= 900
    error_message = "timeout must be between 1 and 900 seconds."
  }
}

variable "memory_size" {
  type    = number
  default = 512

  validation {
    condition     = var.memory_size >= 128 && var.memory_size <= 10240
    error_message = "memory_size must be between 128 and 10240 MB."
  }
}

variable "ephemeral_storage_size" {
  description = "Writable /tmp space in MB. Large archive workers need enough room for their spooled ZIP."
  type        = number
  default     = 512

  validation {
    condition     = var.ephemeral_storage_size >= 512 && var.ephemeral_storage_size <= 10240
    error_message = "ephemeral_storage_size must be between 512 and 10240 MB."
  }
}

variable "environment" {
  description = "Environment variables. Never put secret values here; pass a Secrets Manager name instead."
  type        = map(string)
  default     = {}
}

variable "vpc_config" {
  description = "Set for functions that reach Aurora or RDS Proxy; null for functions that do not."
  type = object({
    subnet_ids         = list(string)
    security_group_ids = list(string)
  })
  default = null
}

variable "vpc_enabled" {
  description = "Plan-time switch controlling whether the Lambda VPC block exists."
  type        = bool
  default     = false
}

variable "role_arn" {
  description = "Execution role. Shared across functions with the same access profile."
  type        = string
}

variable "log_retention_days" {
  type    = number
  default = 30
}

variable "reserved_concurrency" {
  description = "-1 leaves the function on the unreserved pool. Set a real number on functions that talk to the database, so a traffic spike cannot exhaust the connection pool."
  type        = number
  default     = -1

  validation {
    condition     = var.reserved_concurrency == -1 || var.reserved_concurrency >= 0
    error_message = "reserved_concurrency must be -1 (unreserved) or a non-negative number."
  }
}

variable "provisioned_concurrency" {
  description = "Pre-warmed environments. Worth it only for the authorizer, which is on the critical path of every request."
  type        = number
  default     = 0

  validation {
    condition     = var.provisioned_concurrency >= 0
    error_message = "provisioned_concurrency cannot be negative."
  }
}

variable "kms_key_arn" {
  description = "Customer-managed key for environment variable encryption at rest."
  type        = string
  default     = null
}

variable "dead_letter_arn" {
  description = "SNS or SQS target for asynchronous invocations that exhaust their retries."
  type        = string
  default     = null
}

variable "dead_letter_enabled" {
  description = "Plan-time switch controlling whether the Lambda dead-letter block exists."
  type        = bool
  default     = false
}

variable "tracing_mode" {
  type    = string
  default = "Active"
}

variable "alarm_topic_arn" {
  description = "SNS topic receiving this function's alarms. Empty keeps alarm history without publishing."
  type        = string
  default     = ""
}

variable "tags" {
  type    = map(string)
  default = {}
}
