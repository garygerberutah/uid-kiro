# ---------------------------------------------------------------------------
# NETWORK VALUES FOR THIS ENVIRONMENT ARE NOT KNOWN.
#
# The only account Terraform this repository has seen is
# The inventory/state-owned-network/aws-vpc-base snapshot, and everything in it, is tagged
# env = dev: one VPC, UID-Dev-VPC (vpc-05d3e6ccb65d2d11c, 10.192.6.0/23).
# There is no prod VPC in it.
#
# The dev ids are deliberately NOT copied here and no id has been guessed from
# the dev naming pattern. A vpc- or subnet- id that looks right and is not is
# the one failure this file can produce that a plan will not catch: it applies
# cleanly into the wrong network. Fill these from the prod account.
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# prod environment values.
#
# Lines marked REQUIRED describe the existing AWS account and have no safe
# default. They are left as placeholders on purpose: a guessed VPC id or RDS
# Proxy endpoint yields a plan that applies cleanly into the wrong place.
# Fill them from the account before the first plan.
# ---------------------------------------------------------------------------

region         = "us-west-2"
log_level      = "WARN"
aws_account_id = "281669077180"

# --- REQUIRED: existing network ---------------------------------------------
vpc_id                    = "vpc-REPLACE_ME"
vpc_ipv4_cidr             = "REPLACE_ME"
private_subnet_ids        = ["subnet-REPLACE_ME_A", "subnet-REPLACE_ME_B"]
lambda_security_group_ids = ["sg-REPLACE_ME"]
# Route-table inventory is required by the read-only network guard. An empty
# inventory is rejected rather than allowing an unchecked Lambda default route
# into a reviewed plan.
private_route_table_ids    = []
database_security_group_id = "sg-REPLACE_ME"

# The State network owner supplies shared endpoints, their security-group rules
# and egress. Application Terraform only reads the supplied identifiers.
existing_interface_endpoint_security_group_ids = []

# REQUIRED: adopt the existing SIFE buckets. Creating replacements strands all
# files in flight without producing an API error (D-006).
existing_bucket_names = {
  uploads   = "REPLACE_ME"
  downloads = "REPLACE_ME"
}

# Record any customer-managed default key used by each adopted bucket. Empty is
# correct only after confirming the bucket uses SSE-S3/the AWS-managed key.
storage_kms_key_arn                  = null
adopted_bucket_kms_key_arns          = {}
adopted_buckets_without_customer_kms = []

# --- REQUIRED: existing database --------------------------------------------
# The RDS Proxy endpoint. The Elastic Beanstalk app read this from DB_PROXY_HOST;
# application-dev.properties currently defaults it to the CLUSTER endpoint
# (uid-dev-postgresqlv2.cluster-....rds.amazonaws.com), which bypasses the proxy.
# Put the proxy endpoint here, not the cluster endpoint.
db_proxy_host = "REPLACE_ME.proxy-REPLACE.us-west-2.rds.amazonaws.com"
db_name       = "postgres"
db_schema     = "uid_portal"

# --- database secret --------------------------------------------------------
portal_secret_name  = "prod/postgres/portal"
sendgrid_secret_arn = "REPLACE_ME_SENDGRID_SECRET_ARN"

# --- identity ---------------------------------------------------------------
oidc_issuer        = "https://sso.mylogin.utah.gov:443/am/oauth2"
oidc_utah_id_claim = "legacy_sub"
api_allowed_hosts  = ["insureu.uid.utah.gov"]
# Cloud IAM confirmed this exact shared AT/production Ping access-token
# contract for the public SPA client. These are non-secret verification facts,
# not credentials. Keep every value exact; changing one requires a fresh token
# sample and IAM review under D-026.
oidc_audience               = "7ZokREaGUFCgJprj3JX48Aa2tsrbsRbFwgeE"
oidc_scope_claim            = "scope"
oidc_required_scopes        = ["openid", "profile", "email", "directory"]
oidc_authorized_party_claim = "azp"
oidc_authorized_party_value = "7ZokREaGUFCgJprj3JX48Aa2tsrbsRbFwgeE"
oidc_token_type_source      = "header"
oidc_token_type_name        = "typ"
oidc_token_type_value       = "at+jwt"

# --- REQUIRED: edge ---------------------------------------------------------
# D-028 must resolve whether CloudFront presents the insureu viewer host or a
# distinct API origin host. The domain and allowlist intentionally disagree so
# the plan-time contract stops instead of guessing; update them together from
# the approved CloudFront/API mapping without moving insureu DNS off CloudFront.
# Empty is permitted only after live inventory proves this account/Region has
# no current or historical UID Portal HTTP API. Otherwise set the exact sole id
# so imports.tf makes the reviewed plan import it instead of creating another.
api_gateway_survivor_id = ""
api_gateway_name        = "uid-prod-api-gateway"
portal_domain_name      = "portal-api.uid.utah.gov"
portal_domain_ownership = "managed"
certificate_arn         = "arn:aws:acm:us-west-2:REPLACE_ME:certificate/REPLACE_ME"
hosted_zone_id          = "REPLACE_ME"

browser_origins   = ["https://insureu.uid.utah.gov"]
portal_client_url = "https://insureu.uid.utah.gov"

# snapproxy: the Vertafore replica the licensee handlers read. Leave the host
# empty and /licensee/* answers 502 saying so, which is the right failure for an
# environment that has no replica -- better than looking like an outage.
snap_secret_name                = "prod/postgres/snapproxy"
snap_db_host                    = "REPLACE_ME"
snap_database_security_group_id = ""
snap_db_name                    = "postgres"
snap_db_schema                  = "snapproxy"

# Oracle refresh watchdog. Confirm whether its listener is protected by an AWS
# security group; leave the group empty only when the existing network owns it.
oracle_admin_secret               = "prod/oracle/admin"
oracle_database_security_group_id = ""
oracle_database_port              = 1521
licensee_sync_stale_seconds       = 7200
licensee_sync_kill_settle_seconds = 10

# --- packaging --------------------------------------------------------------
layer_zip_path    = "../../assets/layer-placeholder.zip"
function_zip_path = "../../assets/lambda-placeholder.zip"

# --- capacity ---------------------------------------------------------------
per_function_reserved_concurrency  = 5
authorizer_provisioned_concurrency = 3

portal_throttle_burst = 200
portal_throttle_rate  = 100

# The report and the download bundle are the expensive routes: each one is a
# database scan plus an S3 write, so they get their own, much lower, budget.
portal_route_throttles = {
  sife_report          = { burst = 5, rate = 2 }
  sife_create_download = { burst = 10, rate = 5 }
}

# Per-route capacity protection for the licensee paths on the shared stage. The
# handler/database separately preserves the 60 requests/minute Utah-ID limit.
licensee_throttle_burst = 40
licensee_throttle_rate  = 10

licensee_route_throttles = {
  licensee_all_title_agents = { burst = 2, rate = 1 }
  licensee_all_uhe_agents   = { burst = 2, rate = 1 }
}

# --- scheduling -------------------------------------------------------------
# Every job starts DISABLED. Elastic Beanstalk is still running the Spring
# @Scheduled versions during cutover, and having both send SIFE notification
# emails is exactly the duplicate-email problem this migration fixes.
# Flip these to true in the same change that stops the Beanstalk environment.
scheduled_jobs_enabled = {
  sife_notification    = false
  sife_retention_sweep = false
  search_log_reaper    = false
  licensee_fast_sync   = false
}

scheduled_job_intervals = {
  sife_notification    = 1800
  sife_retention_sweep = 90000
  search_log_reaper    = 7200
  licensee_fast_sync   = 1800
}

# --- misc -------------------------------------------------------------------
email_from             = "noreply@utah.gov"
sife_exclude_group_ids = [31]
sife_captive_mailbox   = "captive@utah.gov"
alert_emails           = []

log_retention_days    = 365
generated_object_days = 7

tags = {
  Owner      = "uid-portal"
  CostCenter = "uid"
}
