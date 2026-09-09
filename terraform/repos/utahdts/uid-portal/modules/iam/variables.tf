variable "name_prefix" {
  type = string
}

variable "region" {
  type = string
}

variable "account_id" {
  type = string
}

variable "permissions_boundary_arns" {
  description = "Independently provisioned runtime boundaries, keyed by manifest IAM profile."
  type        = map(string)
  default     = {}

  validation {
    condition = alltrue([
      for profile, arn in var.permissions_boundary_arns :
      arn == "arn:aws:iam::${var.account_id}:policy/uid-insureu-at-runtime-${profile}"
    ])
    error_message = "Runtime boundaries must use the exact bootstrap-owned AT policy names in this account."
  }
}

variable "role_profiles" {
  description = "Least-privilege capabilities keyed by the iam_profile values in routes.yaml."
  type = map(object({
    secret_arns         = list(string)
    secret_kms_key_arns = list(string)
    data_kms_actions    = list(string)
    data_kms_key_arns   = list(string)
    s3_statements = list(object({
      actions   = list(string)
      resources = list(string)
    }))
    invokable_function_arns = list(string)
    write_dead_letter       = bool
    vpc_access              = bool
  }))

  validation {
    condition = alltrue([
      for profile, capabilities in var.role_profiles :
      alltrue([
        for statement in capabilities.s3_statements :
        length(statement.actions) > 0 &&
        length(statement.resources) > 0 &&
        alltrue([for action in statement.actions : startswith(action, "s3:")]) &&
        alltrue([for resource in statement.resources : startswith(resource, "arn:aws:s3:::")])
      ])
    ])
    error_message = "Every S3 statement must have non-empty s3:* actions and S3 ARN resources."
  }
}

variable "dead_letter_queue_arn" {
  description = "SQS queue receiving failed asynchronous worker invocations."
  type        = string

  validation {
    condition     = trimspace(var.dead_letter_queue_arn) != ""
    error_message = "dead_letter_queue_arn is required because write_dead_letter capability profiles are present."
  }
}

variable "tags" {
  type    = map(string)
  default = {}
}
