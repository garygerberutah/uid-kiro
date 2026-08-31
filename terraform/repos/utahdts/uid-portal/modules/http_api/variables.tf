variable "name" {
  description = "Stable resource prefix for log groups, permissions and alarms, e.g. uid-portal-dev-portal."
  type        = string
}

variable "api_name" {
  description = "AWS display name for the HTTP API. Empty uses the stable resource prefix."
  type        = string
  default     = ""
}

variable "api_key" {
  description = "The sole key under `apis:` in routes.yaml."
  type        = string
}

variable "manifest" {
  description = "The decoded routes.yaml document."
  type        = any
}

variable "env_name" {
  description = "dev | at | prod. Selects the CORS origin list from the manifest."
  type        = string
}

variable "region" {
  description = "AWS region that must own any regional ACM certificate."
  type        = string
}

variable "account_id" {
  description = "AWS account that must own any regional ACM certificate."
  type        = string
}

variable "description" {
  type    = string
  default = ""
}

variable "integrations" {
  description = "route id -> Lambda alias invoke ARN, for every python route in this API."
  type        = map(string)
}

variable "integration_function_names" {
  description = "route id -> Lambda function name, used for the invoke permission."
  type        = map(string)
}

variable "authorizer" {
  description = "This API's Lambda authorizer."
  type = object({
    invoke_arn    = string
    function_name = string
  })
}

variable "domain_name" {
  description = "Required custom API-origin domain, e.g. portal-api.uid.utah.gov. The default execute-api endpoint is disabled."
  type        = string
  default     = ""
}

variable "domain_ownership" {
  description = "Whether this module manages the API Gateway custom-domain object or only reads an externally owned one."
  type        = string
  default     = "managed"

  validation {
    condition     = contains(["external", "managed"], var.domain_ownership)
    error_message = "domain_ownership must be exactly external or managed."
  }
}

variable "certificate_arn" {
  description = "Reviewed regional ACM certificate to create on, or verify against, the custom domain."
  type        = string
  default     = ""
}

variable "hosted_zone_id" {
  description = "Route53 zone for the alias record. Empty leaves DNS to be managed elsewhere."
  type        = string
  default     = ""

  validation {
    condition     = var.hosted_zone_id == "" || can(regex("^Z[A-Z0-9]+$", var.hosted_zone_id))
    error_message = "hosted_zone_id must be empty or a Route53 hosted-zone id beginning with Z."
  }
}

variable "throttle_burst" {
  description = "Stage-wide burst limit."
  type        = number
  default     = 200
}

variable "throttle_rate" {
  description = "Stage-wide steady-state requests per second."
  type        = number
  default     = 100
}

variable "route_throttles" {
  description = "route id -> {burst, rate}, overriding the stage default on expensive routes."
  type = map(object({
    burst = number
    rate  = number
  }))
  default = {}
}

variable "log_retention_days" {
  type    = number
  default = 90
}

variable "kms_key_arn" {
  type    = string
  default = null
}

variable "alarm_topic_arn" {
  description = "SNS topic receiving API alarms. Empty keeps alarm history without publishing."
  type        = string
  default     = ""
}

variable "tags" {
  type    = map(string)
  default = {}
}
