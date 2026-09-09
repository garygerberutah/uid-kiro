variable "name_prefix" {
  type = string
}

variable "account_id" {
  type = string
}

variable "permissions_boundary_arn" {
  description = "Independently provisioned AT scheduler runtime boundary."
  type        = string
  default     = null

  validation {
    condition     = var.permissions_boundary_arn == null || var.permissions_boundary_arn == "arn:aws:iam::${var.account_id}:policy/uid-insureu-at-runtime-scheduler"
    error_message = "The scheduler boundary must use the exact bootstrap-owned AT policy name in this account."
  }
}

variable "schedules" {
  description = "Job id -> schedule definition."
  type = map(object({
    schedule                  = string
    timezone                  = string
    target_arn                = string
    function_name             = string
    enabled                   = bool
    alarm_on_missing          = bool
    expected_interval_seconds = number
  }))
}

variable "dead_letter_arn" {
  description = "SQS queue for invocations that exhaust their retries."
  type        = string
  default     = null
}

variable "dead_letter_enabled" {
  description = "Plan-time switch controlling whether Scheduler configures and may write to a dead-letter queue."
  type        = bool
  default     = false
}

variable "alarm_topic_arn" {
  description = "SNS topic receiving did-it-run alarms. Empty keeps alarm history without publishing."
  type        = string
  default     = ""
}

variable "tags" {
  type    = map(string)
  default = {}
}
