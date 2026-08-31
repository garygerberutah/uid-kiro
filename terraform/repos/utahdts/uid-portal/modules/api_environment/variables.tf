# ---------------------------------------------------------------------------
# Inputs for one environment. Values live in the per-environment terraform.tfvars.
#
# Anything whose correct value is a fact about the existing AWS account -- VPC
# id, subnet ids, the RDS Proxy endpoint, certificate ARNs -- has NO default.
# Guessing one of those produces a plan that looks fine and deploys into the
# wrong network. They must be supplied.
# ---------------------------------------------------------------------------

variable "env_name" {
  description = "dev | at | prod."
  type        = string

  validation {
    condition     = contains(["dev", "at", "prod"], var.env_name)
    error_message = "env_name must be one of dev, at, prod."
  }
}

variable "region" {
  type    = string
  default = "us-west-2"
}

variable "aws_account_id" {
  description = "Twelve-digit account that this environment is allowed to modify. The provider refuses any other active credentials."
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

  validation {
    condition     = length(trimspace(var.release_version)) > 0 && lower(trimspace(var.release_version)) != "unset"
    error_message = "release_version must be the reviewed commit SHA or release tag; the placeholder 'unset' is not deployable."
  }
}

variable "build_time" {
  description = "RFC3339 commit/build timestamp surfaced by health and version banners. Set by CI from the reviewed commit."
  type        = string

  validation {
    condition     = length(trimspace(var.build_time)) > 0 && lower(trimspace(var.build_time)) != "unknown"
    error_message = "build_time must identify the reviewed build; the runtime placeholder 'unknown' is not deployable."
  }
}

variable "log_level" {
  type    = string
  default = "INFO"
}

# --- network (no defaults: these describe the existing account) ------------

variable "vpc_id" {
  description = "The VPC containing the Aurora cluster."
  type        = string

  validation {
    # A placeholder that reaches AWS is rejected there too, but this says so in
    # this repository's words and before anything else in the plan runs. The
    # dangerous case is not a placeholder -- it is a real id from the wrong
    # environment, which nothing here can detect. See D-007.
    condition     = can(regex("^vpc-[0-9a-f]{8,}$", var.vpc_id))
    error_message = "vpc_id must be a real VPC id such as vpc-05d3e6ccb65d2d11c. The at and prod values are still placeholders: only the dev VPC has been exported to this repository (D-007)."
  }
}

variable "vpc_ipv4_cidr" {
  description = "Owner-supplied canonical IPv4 CIDR that must be the existing VPC's sole associated IPv4 CIDR and every selected route table's AWS local destination."
  type        = string

  validation {
    condition = (
      can(cidrnetmask(var.vpc_ipv4_cidr)) &&
      try(
        format("%s/%s", cidrhost(var.vpc_ipv4_cidr, 0), split("/", var.vpc_ipv4_cidr)[1]) == var.vpc_ipv4_cidr,
        false,
      )
    )
    error_message = "vpc_ipv4_cidr must be a canonical owner-supplied IPv4 CIDR such as 10.192.6.0/23; placeholders deliberately block planning."
  }
}

variable "private_subnet_ids" {
  description = "Private subnets with a route to the database, at least two AZs."
  type        = list(string)

  validation {
    condition     = length(var.private_subnet_ids) >= 2
    error_message = "Provide at least two private subnets so the functions survive an AZ failure."
  }

  validation {
    condition     = alltrue([for s in var.private_subnet_ids : can(regex("^subnet-[0-9a-f]{8,}$", s))])
    error_message = "private_subnet_ids must be real subnet ids such as subnet-0c6272b1eea00003c. The production values are still placeholders (D-007)."
  }
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

variable "private_route_table_ids" {
  description = "Exact existing route tables used by the Lambda subnets. Required for read-only validation of local and default routing."
  type        = list(string)
  default     = []
}

variable "database_security_group_id" {
  description = "Existing RDS Proxy security group. Its owner must already allow the Lambda security groups; do not pass the cluster group unless allow_cluster_db_host deliberately bypasses the proxy."
  type        = string
  default     = ""

  validation {
    condition     = var.database_security_group_id == "" || can(regex("^sg-[0-9a-f]{8,}$", var.database_security_group_id))
    error_message = "database_security_group_id must be empty or an existing security group id."
  }
}

variable "snap_database_security_group_id" {
  description = "Existing security group on the separate snapproxy database; its owner must already allow the Lambda security groups."
  type        = string
  default     = ""

  validation {
    condition     = var.snap_database_security_group_id == "" || can(regex("^sg-[0-9a-f]{8,}$", var.snap_database_security_group_id))
    error_message = "snap_database_security_group_id must be empty or an existing security group id."
  }
}

variable "oracle_database_security_group_id" {
  description = "Existing security group on the Oracle watchdog database; its owner must already allow the Lambda security groups."
  type        = string
  default     = ""

  validation {
    condition     = var.oracle_database_security_group_id == "" || can(regex("^sg-[0-9a-f]{8,}$", var.oracle_database_security_group_id))
    error_message = "oracle_database_security_group_id must be empty or an existing security group id."
  }
}

variable "oracle_database_port" {
  description = "Oracle listener port encoded in the Oracle admin secret; update both together when it is not 1521."
  type        = number
  default     = 1521

  validation {
    condition     = var.oracle_database_port >= 1 && var.oracle_database_port <= 65535
    error_message = "oracle_database_port must be between 1 and 65535."
  }
}

variable "existing_interface_endpoint_security_group_ids" {
  description = "Existing State-owned interface-endpoint security groups. Their owner must already allow HTTPS from every Lambda security group."
  type        = set(string)
  default     = []

  validation {
    condition = alltrue([
      for id in var.existing_interface_endpoint_security_group_ids : can(regex("^sg-[0-9a-f]{8,}$", id))
    ])
    error_message = "existing_interface_endpoint_security_group_ids must contain only existing security group ids."
  }
}

# --- database ---------------------------------------------------------------

variable "db_proxy_host" {
  description = "RDS Proxy endpoint. Must NOT be the cluster endpoint: pointing Lambdas at the cluster defeats connection pooling."
  type        = string

  validation {
    # F-10: DB_PROXY_HOST defaulted to the Aurora *cluster* endpoint. Survivable
    # for a few JVM connection pools, fatal for hundreds of Lambda execution
    # environments, and it fails as exhaustion under load rather than at deploy.
    # A cluster endpoint is spelled `<name>.cluster-<hash>.<region>.rds.amazonaws.com`;
    # a proxy endpoint is `<name>.proxy-<hash>...`.
    condition     = var.allow_cluster_db_host || !can(regex("\\.cluster-", var.db_proxy_host))
    error_message = "db_proxy_host looks like an Aurora cluster endpoint (it contains '.cluster-'), not an RDS Proxy endpoint. Pointing Lambdas at the cluster defeats pooling and exhausts connections under load -- see F-10. If this environment genuinely has no proxy, set allow_cluster_db_host = true to say so deliberately; that is decision D-003."
  }

  validation {
    condition     = !can(regex("REPLACE_ME", var.db_proxy_host))
    error_message = "db_proxy_host is still a placeholder. Fill it from the account before planning."
  }
}

variable "allow_cluster_db_host" {
  description = <<-EOT
    Accept a cluster endpoint for db_proxy_host.

    D-003 asks whether an RDS Proxy exists per environment. That question is
    open, so this is an escape hatch rather than a hard refusal: if an
    environment has no proxy, setting this records that as a decision instead of
    leaving the guard looking wrong.
  EOT
  type        = bool
  default     = false
}

variable "db_port" {
  type    = number
  default = 5432
}

variable "db_name" {
  type    = string
  default = "postgres"
}

variable "db_schema" {
  type    = string
  default = "uid_portal"
}

variable "per_function_reserved_concurrency" {
  description = "Concurrency cap per database-backed function. Sum across functions must stay under the proxy's connection budget."
  type        = number
  default     = 5

  validation {
    condition     = var.per_function_reserved_concurrency >= 1
    error_message = "per_function_reserved_concurrency must be at least 1 for enabled database functions."
  }
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
  description = "Reviewed id of the sole existing UID Portal HTTP API to import into the stable module address. Leave empty only when live inventory proves this is a genuinely fresh deployment."
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
  description = "Customer-managed KMS key encrypting the portal secret, or null when the secret uses the AWS-managed key."
  type        = string
  default     = null
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

# --- snapproxy (the Vertafore replica) --------------------------------------
# The Python licensee handlers read these directly.

variable "snap_secret_name" {
  description = "Secrets Manager entry holding the snapproxy username/password."
  type        = string
  default     = ""
}

variable "snap_secret_kms_key_arn" {
  description = "Customer-managed KMS key encrypting the snapproxy secret, or null for the AWS-managed key."
  type        = string
  default     = null
}

variable "oracle_admin_secret" {
  description = "Secrets Manager name holding the Oracle watchdog administrator credentials."
  type        = string
}

variable "oracle_admin_secret_kms_key_arn" {
  description = "Customer-managed KMS key encrypting the Oracle admin secret, or null for the AWS-managed key."
  type        = string
  default     = null
}

variable "licensee_sync_stale_seconds" {
  description = "Age after which the weekday Oracle refresh watchdog treats the materialized view as stale."
  type        = number
  default     = 7200

  validation {
    condition     = var.licensee_sync_stale_seconds >= 900
    error_message = "licensee_sync_stale_seconds must be at least 900 seconds."
  }
}

variable "licensee_sync_kill_settle_seconds" {
  description = "Seconds to wait after killing stale Oracle refresh sessions before the watchdog completes."
  type        = number
  default     = 10

  validation {
    condition     = var.licensee_sync_kill_settle_seconds >= 0 && var.licensee_sync_kill_settle_seconds <= 60
    error_message = "licensee_sync_kill_settle_seconds must be between 0 and 60."
  }
}

variable "snap_db_host" {
  description = "snapproxy host. Empty means this environment has no replica and /licensee/* returns 502."
  type        = string
  default     = ""
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
  description = "Default per-route requests/second for former licensee paths on the shared API stage. Per-Utah-ID 60/minute enforcement remains in the handler/database."
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

  validation {
    condition     = can(regex("^[^@\\s]+@[^@\\s]+\\.[^@\\s]+$", var.sife_captive_mailbox))
    error_message = "sife_captive_mailbox must be one valid email address."
  }
}

variable "alert_emails" {
  type    = list(string)
  default = []
}

variable "kms_key_arn" {
  description = "Optional CMK for Lambda environment variables and CloudWatch logs. Storage keys are configured separately."
  type        = string
  default     = null
}

variable "storage_kms_key_arn" {
  description = "Optional CMK used as the default and explicit SSE key for buckets this stack creates. Leave null for adopted buckets that keep their own default encryption."
  type        = string
  default     = null

  validation {
    condition = var.storage_kms_key_arn == null || can(regex(
      "^arn:aws:kms:${var.region}:${var.aws_account_id}:key/[A-Za-z0-9-]+$",
      var.storage_kms_key_arn,
    ))
    error_message = "storage_kms_key_arn must be null or a KMS key ARN in this environment's account and region."
  }
}

variable "adopted_bucket_kms_key_arns" {
  description = "Existing SSE-KMS keys keyed by adopted bucket purpose (uploads, downloads, artifacts), used only for runtime IAM grants; this stack does not change adopted-bucket encryption."
  type        = map(string)
  default     = {}

  validation {
    condition = alltrue([
      for bucket, arn in var.adopted_bucket_kms_key_arns :
      contains(["uploads", "downloads", "artifacts"], bucket) && can(regex(
        "^arn:aws:kms:${var.region}:${var.aws_account_id}:key/[A-Za-z0-9-]+$",
        arn,
      ))
    ])
    error_message = "adopted_bucket_kms_key_arns keys must be uploads/downloads/artifacts and values must be KMS key ARNs in this environment's account and region."
  }
}

variable "adopted_buckets_without_customer_kms" {
  description = "Adopted bucket purposes verified to use SSE-S3 or an AWS-managed key. Together with adopted_bucket_kms_key_arns this must classify every adopted bucket exactly once."
  type        = set(string)
  default     = []

  validation {
    condition = (
      length(setintersection(
        var.adopted_buckets_without_customer_kms,
        toset(keys(var.adopted_bucket_kms_key_arns)),
      )) == 0 &&
      length(setsubtract(
        toset([for bucket, name in var.existing_bucket_names : bucket if name != ""]),
        setunion(var.adopted_buckets_without_customer_kms, toset(keys(var.adopted_bucket_kms_key_arns))),
      )) == 0 &&
      length(setsubtract(
        setunion(var.adopted_buckets_without_customer_kms, toset(keys(var.adopted_bucket_kms_key_arns))),
        toset([for bucket, name in var.existing_bucket_names : bucket if name != ""]),
      )) == 0
    )
    error_message = "Classify every non-empty existing_bucket_names entry exactly once: put its CMK in adopted_bucket_kms_key_arns, or list its purpose in adopted_buckets_without_customer_kms after verifying SSE-S3/AWS-managed encryption."
  }
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
