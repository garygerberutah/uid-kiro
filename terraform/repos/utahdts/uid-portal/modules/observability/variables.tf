variable "name_prefix" {
  type = string
}

variable "region" {
  type = string
}

variable "alert_topic_arn" {
  description = "SNS topic receiving every alarm action. Empty records alarm history without publishing."
  type        = string
  default     = ""
}

variable "alert_topic_name" {
  description = "Human-readable alert topic name shown on the dashboard."
  type        = string
  default     = "not-configured"
}

variable "dead_letter_queue_name" {
  description = "Queue name used as the CloudWatch metric dimension."
  type        = string
}

variable "api_ids" {
  type    = list(string)
  default = []
}

variable "authorizer_function_names" {
  type    = list(string)
  default = []
}

variable "authorizer_log_groups" {
  description = "Manifest-stable id to authorizer log-group name. Keys must be known during planning."
  type        = map(string)
  default     = {}
}

variable "handler_log_groups" {
  description = "Manifest-stable id to routed/worker log-group name. Keys must be known during planning."
  type        = map(string)
  default     = {}
}

variable "report_worker_log_groups" {
  description = "Report-worker groups whose caught job failures are invisible to Lambda Errors."
  type        = map(string)
  default     = {}
}

variable "notification_log_groups" {
  description = "Notification groups whose per-recipient failures can leave the invocation successful."
  type        = map(string)
  default     = {}
}

variable "licensee_sync_log_groups" {
  description = "Fast-sync groups whose caught watchdog failures are invisible to Lambda Errors."
  type        = map(string)
  default     = {}
}

variable "metric_namespace" {
  type    = string
  default = "UidPortalApi"
}

variable "tags" {
  type    = map(string)
  default = {}
}
