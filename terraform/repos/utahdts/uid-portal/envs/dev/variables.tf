# Variables for the dev environment. Generated from modules/api_environment/variables.tf;
# keep them in step -- a variable added there must be forwarded in main.tf here.

variable "region" {
  type    = string
  default = "us-west-2"
}

variable "aws_account_id" {
  description = "Twelve-digit account that this environment is allowed to modify."
  type        = string

  validation {
    condition     = can(regex("^[0-9]{12}$", var.aws_account_id))
    error_message = "aws_account_id must be the twelve-digit target AWS account id."
  }
}

variable "offline_provider_validation" {
  description = "Disable AWS identity and metadata checks only for credential-free terraform init/validate. Never enable for plan or apply."
  type        = bool
  default     = false
}

variable "release_version" {
  description = "Git sha or tag, surfaced by /health. Set by CI."
  type        = string
}

variable "build_time" {
  description = "RFC3339 commit/build timestamp surfaced by health and version banners. Set by CI."
  type        = string
}

variable "log_level" {
  type    = string
  default = "INFO"
}

# --- network (no defaults: these describe the existing account) ------------

variable "vpc_id" {
  description = "The VPC containing the Aurora cluster."
  type        = string
}

variable "vpc_ipv4_cidr" {
  description = "Reviewed primary IPv4 CIDR of the existing shared dev/AT VPC."
  type        = string

  validation {
    condition     = var.vpc_ipv4_cidr == "10.192.6.0/23"
    error_message = "Dev and AT local routing is pinned to the existing VPC CIDR 10.192.6.0/23."
  }
}

variable "private_subnet_ids" {
  description = "The two approved existing private-app subnets in the shared dev/AT VPC."
  type        = list(string)

  validation {
    condition = (
      length(var.private_subnet_ids) == 2 &&
      toset(var.private_subnet_ids) == toset([
        "subnet-0c6272b1eea00003c",
        "subnet-0a1e2c8e6751b6833",
      ])
    )
    error_message = "Dev and AT Lambda placement is pinned to the two approved existing private-app subnets; request any inventory change from the State network owner."
  }
}

variable "private_route_table_ids" {
  description = "Exact existing route tables used by the Lambda subnets. Required for read-only validation of local and default routing."
  type        = list(string)
  default     = []
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
  description = "RDS Proxy client security group to open to the functions. Do not pass the cluster group unless allow_cluster_db_host deliberately bypasses the proxy."
  type        = string
  default     = ""
}

variable "snap_database_security_group_id" {
  description = "Security group on the separate snapproxy database; empty when managed out of band."
  type        = string
  default     = ""
}

variable "oracle_database_security_group_id" {
  description = "Security group on the Oracle watchdog database; empty when managed out of band."
  type        = string
  default     = ""
}

variable "oracle_database_port" {
  description = "Oracle listener port encoded in the Oracle admin secret; update both together when it is not 1521."
  type        = number
  default     = 1521
}

variable "existing_interface_endpoint_security_group_ids" {
  description = "Existing State-owned interface-endpoint security groups. Their owner must already allow HTTPS from every Lambda security group."
  type        = set(string)
  default     = []
}

# --- database ---------------------------------------------------------------

variable "db_proxy_host" {
  description = "RDS Proxy endpoint. Must NOT be the cluster endpoint: pointing Lambdas at the cluster defeats connection pooling."
  type        = string
}

variable "allow_cluster_db_host" {
  description = "Explicitly permit a cluster endpoint when this environment has no RDS Proxy."
  type        = bool
  default     = false
}

variable "db_port" {
  type    = number
  default = 5432
}

variable "db_name" {
  type    = string
  default = "insureu"
}

variable "db_schema" {
  type    = string
  default = "uid_portal"
}

variable "per_function_reserved_concurrency" {
  description = "Concurrency cap per database-backed function. Sum across functions must stay under the proxy's connection budget."
  type        = number
  default     = 5
}

variable "authorizer_provisioned_concurrency" {
  description = "Pre-warmed authorizer environments. 0 in dev; production should hold a few so no user pays the cold start."
  type        = number
  default     = 0
}

# --- identity ---------------------------------------------------------------

variable "oidc_issuer" {
  type    = string
  default = "https://sso.mylogin.utah.gov:443/am/oauth2"
}

variable "oidc_jwks_url" {
  description = "Empty derives it as <issuer>/connect/jwk_uri, matching application.properties."
  type        = string
  default     = ""
}

variable "oidc_audience" {
  description = "Cloud IAM-approved shared AT/production Ping access-token aud value. Empty keeps an incomplete environment fail-closed; never infer it from a browser client id."
  type        = string
  default     = ""

  validation {
    condition     = var.oidc_audience == trimspace(var.oidc_audience)
    error_message = "oidc_audience must not contain leading or trailing whitespace."
  }
}

variable "oidc_scope_claim" {
  description = "Cloud IAM-approved Ping claim containing required scopes. Empty keeps an incomplete environment fail-closed."
  type        = string
  default     = ""
}

variable "oidc_required_scopes" {
  description = "Cloud IAM-approved scopes every Ping access token must contain. Empty keeps an incomplete environment fail-closed."
  type        = list(string)
  default     = []

  validation {
    condition = (
      length(var.oidc_required_scopes) == length(distinct(var.oidc_required_scopes)) &&
      alltrue([
        for scope in var.oidc_required_scopes :
        scope != "" && scope == trimspace(scope) && length(regexall("\\s", scope)) == 0
      ])
    )
    error_message = "oidc_required_scopes must contain unique, nonempty OAuth scope tokens without whitespace."
  }
}

variable "oidc_authorized_party_claim" {
  description = "Cloud IAM-approved Ping authorized-party/client claim name. Empty keeps an incomplete environment fail-closed."
  type        = string
  default     = ""
}

variable "oidc_authorized_party_value" {
  description = "Cloud IAM-approved Ping authorized-party/client value accepted by this API. Empty keeps an incomplete environment fail-closed."
  type        = string
  default     = ""
}

variable "oidc_token_type_source" {
  description = "Cloud IAM-approved location of Ping's signed access-token discriminator: claim or header. Empty keeps an incomplete environment fail-closed."
  type        = string
  default     = ""

  validation {
    condition     = contains(["", "claim", "header"], var.oidc_token_type_source)
    error_message = "oidc_token_type_source must be empty, claim, or header."
  }
}

variable "oidc_token_type_name" {
  description = "Cloud IAM-approved signed Ping payload-claim or protected-header field carrying the token type. Empty keeps an incomplete environment fail-closed."
  type        = string
  default     = ""
}

variable "oidc_token_type_value" {
  description = "Cloud IAM-approved Ping field value that distinguishes API access tokens from ID tokens. Empty keeps an incomplete environment fail-closed."
  type        = string
  default     = ""
}

variable "oidc_utah_id_claim" {
  type    = string
  default = "legacy_sub"
}

variable "api_allowed_hosts" {
  description = "The one exact lowercase API hostname accepted from API Gateway requestContext.domainName. This is an authentication boundary, not CORS."
  type        = list(string)

  validation {
    condition = (
      length(var.api_allowed_hosts) == 1 &&
      length(var.api_allowed_hosts) == length(distinct(var.api_allowed_hosts)) &&
      alltrue([
        for host in var.api_allowed_hosts :
        host == lower(trimspace(host)) && length(host) <= 253 && alltrue([
          for label in split(".", host) :
          length(label) <= 63 && can(regex("^[a-z0-9]([a-z0-9-]*[a-z0-9])?$", label))
        ])
      ])
    )
    error_message = "api_allowed_hosts must contain exactly one lowercase DNS hostname (no scheme, port, path, wildcard, or trailing dot)."
  }
}

variable "api_gateway_survivor_id" {
  description = "Reviewed id of the sole existing UID Portal HTTP API. Empty is allowed only for a genuinely fresh deployment."
  type        = string
  default     = ""

  validation {
    condition     = var.api_gateway_survivor_id == "" || can(regex("^[a-z0-9]{10}$", var.api_gateway_survivor_id))
    error_message = "api_gateway_survivor_id must be empty or a ten-character API Gateway v2 API id."
  }
}

# --- secrets ----------------------------------------------------------------

variable "portal_secret_name" {
  description = "Secrets Manager name holding the portal database credentials, e.g. prod/postgres/portal."
  type        = string
}

variable "portal_secret_kms_key_arn" {
  type    = string
  default = null
}

variable "sendgrid_secret_arn" {
  description = "ARN of the existing State-owned Secrets Manager secret containing the SendGrid API key."
  type        = string

  validation {
    condition = can(regex(
      "^arn:aws:secretsmanager:${var.region}:${var.aws_account_id}:secret:[A-Za-z0-9/_+=.@-]+-[A-Za-z0-9]{6}$",
      var.sendgrid_secret_arn,
    ))
    error_message = "sendgrid_secret_arn must be a complete Secrets Manager secret ARN, including its six-character suffix, in this environment's account and region."
  }
}

# --- packaging --------------------------------------------------------------

variable "layer_zip_path" {
  description = "Committed placeholder layer archive used only for initial provisioning."
  type        = string
  default     = "../../assets/layer-placeholder.zip"
}

variable "function_zip_path" {
  description = "Committed placeholder function archive used only for initial provisioning."
  type        = string
  default     = "../../assets/lambda-placeholder.zip"
}

# --- domains and edge -------------------------------------------------------

variable "api_gateway_name" {
  description = "Optional AWS name for the single HTTP API. Empty preserves the historical portal API name."
  type        = string
  default     = ""
}

variable "portal_domain_name" {
  type    = string
  default = ""
}

variable "portal_domain_ownership" {
  description = "Whether application Terraform manages the custom-domain object or only reads the externally owned object."
  type        = string
  default     = "managed"

  validation {
    condition     = contains(["external", "managed"], var.portal_domain_ownership)
    error_message = "portal_domain_ownership must be exactly external or managed."
  }
}

variable "certificate_arn" {
  description = "Reviewed regional ACM certificate to create on, or verify against, the API custom domain."
  type        = string
  default     = ""
}

variable "hosted_zone_id" {
  type    = string
  default = ""
}

variable "browser_origins" {
  description = "Origins allowed to upload directly to the S3 uploads bucket."
  type        = list(string)
}

# --- throttling -------------------------------------------------------------

variable "portal_throttle_burst" {
  type    = number
  default = 200
}

variable "portal_throttle_rate" {
  type    = number
  default = 100
}

variable "portal_route_throttles" {
  type = map(object({
    burst = number
    rate  = number
  }))
  default = {}
}

variable "licensee_throttle_burst" {
  type    = number
  default = 40
}

variable "licensee_throttle_rate" {
  description = "Default per-route requests/second for former licensee paths on the shared API stage; distinct from the per-Utah-ID database limiter."
  type        = number
  default     = 10
}

variable "licensee_route_throttles" {
  type = map(object({
    burst = number
    rate  = number
  }))
  default = {}
}

# --- scheduling -------------------------------------------------------------

variable "scheduled_jobs_enabled" {
  description = "job id -> enabled. Used to stage cutover: leave the SIFE notifier off until Elastic Beanstalk stops sending it."
  type        = map(bool)
  default     = {}
}

variable "scheduled_job_intervals" {
  description = "job id -> seconds, for the did-it-run alarm."
  type        = map(number)
  default     = {}
}

# --- misc -------------------------------------------------------------------

variable "email_from" {
  type    = string
  default = "noreply@utah.gov"
}

variable "portal_client_url" {
  type    = string
  default = ""
}

variable "sife_exclude_group_ids" {
  description = "Groups whose notifications go to a shared mailbox. Was a hard-coded `= 31` in NotificationService."
  type        = list(number)
  default     = [31]
}

variable "sife_captive_mailbox" {
  description = "Mailbox receiving notifications for groups in sife_exclude_group_ids."
  type        = string
  default     = "captive@utah.gov"
}

variable "alert_emails" {
  type    = list(string)
  default = []
}

variable "kms_key_arn" {
  description = "Optional CMK for Lambda environment variables and CloudWatch logs."
  type        = string
  default     = null
}

variable "storage_kms_key_arn" {
  description = "Optional CMK used for buckets this stack creates; null relies on SSE-S3 or an adopted bucket's default."
  type        = string
  default     = null
}

variable "adopted_bucket_kms_key_arns" {
  description = "Existing SSE-KMS keys keyed by adopted bucket purpose, used for runtime IAM grants."
  type        = map(string)
  default     = {}
}

variable "adopted_buckets_without_customer_kms" {
  description = "Adopted bucket purposes verified to use SSE-S3 or an AWS-managed key."
  type        = set(string)
  default     = []
}

variable "log_retention_days" {
  type    = number
  default = 90
}

variable "generated_object_days" {
  type    = number
  default = 7
}

variable "tags" {
  type    = map(string)
  default = {}
}

variable "existing_bucket_names" {
  description = "Buckets that already exist and must be used rather than created, keyed uploads/downloads/artifacts. Empty creates them."
  type        = map(string)
}

variable "snap_secret_name" {
  type    = string
  default = ""
}

variable "snap_secret_kms_key_arn" {
  type    = string
  default = null
}

variable "oracle_admin_secret" {
  type = string
}

variable "oracle_admin_secret_kms_key_arn" {
  type    = string
  default = null
}

variable "licensee_sync_stale_seconds" {
  type    = number
  default = 7200
}

variable "licensee_sync_kill_settle_seconds" {
  type    = number
  default = 10
}

variable "snap_db_host" {
  type    = string
  default = ""
}

variable "snap_db_port" {
  type    = number
  default = 5432
}

variable "snap_db_name" {
  type    = string
  default = "postgres"
}

variable "snap_db_schema" {
  type    = string
  default = "snapproxy"
}
