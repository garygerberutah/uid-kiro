variable "name_prefix" {
  type = string
}

variable "account_id" {
  type = string
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
