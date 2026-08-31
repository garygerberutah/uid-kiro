variable "name_prefix" {
  type = string
}

variable "alert_emails" {
  description = "Addresses subscribed to the alarm topic. Each must confirm the SNS subscription by email once."
  type        = list(string)
  default     = []
}

variable "tags" {
  type    = map(string)
  default = {}
}
