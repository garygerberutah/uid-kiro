variable "environment" {
  type = string
  validation {
    condition     = contains(["at", "prod"], var.environment)
    error_message = "Use at or prod."
  }
}
variable "artifact_directory" {
  description = "Absolute path to the reviewed output of build_release_orchestration.py."
  type        = string
}
variable "validator_role_arn" {
  description = "Reviewed Lambda role: log writes and approved VPC ENI permissions only."
  type        = string
}
variable "release_role_arn" {
  description = "Reviewed states.amazonaws.com role: invoke this validator version only."
  type        = string
}
variable "health_role_arn" {
  description = "Reviewed states.amazonaws.com role: invoke this probe version only."
  type        = string
}
variable "probe_version_arn" {
  description = "Published infrastructure_probe version including release_health output."
  type        = string
}
variable "private_subnet_ids" {
  type = list(string)
  validation {
    condition     = length(toset(var.private_subnet_ids)) == 2 && alltrue([for id in var.private_subnet_ids : can(regex("^subnet-[0-9a-f]+$", id))])
    error_message = "Supply the two reviewed existing private subnets."
  }
}
variable "security_group_ids" {
  type = list(string)
  validation {
    condition     = length(var.security_group_ids) > 0 && alltrue([for id in var.security_group_ids : can(regex("^sg-[0-9a-f]+$", id))])
    error_message = "Supply reviewed existing security groups."
  }
}
