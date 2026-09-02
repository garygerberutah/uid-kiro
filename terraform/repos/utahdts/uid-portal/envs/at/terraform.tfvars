# ---------------------------------------------------------------------------
# at environment values.
#
# Live inventory on 2026-08-17 confirmed that AT deliberately shares the dev
# account, VPC, databases and SIFE buckets. The concrete identifiers below are
# observed account facts rather than names inferred from the dev convention.
# ---------------------------------------------------------------------------

region         = "us-west-2"
log_level      = "INFO"
aws_account_id = "705157108110"

# --- REQUIRED: existing network ---------------------------------------------
vpc_id                     = "vpc-05d3e6ccb65d2d11c"
vpc_ipv4_cidr              = "10.192.6.0/23"
private_subnet_ids         = ["subnet-0c6272b1eea00003c", "subnet-0a1e2c8e6751b6833"]
lambda_security_group_ids  = ["sg-01e9d097e3d7585ea"]
private_route_table_ids    = ["rtb-00f83bc1b800e256e"]
database_security_group_id = "sg-0f8629e93d313e6d5"

# Live inventory on 2026-08-18 found no Secrets Manager, Logs, Lambda, KMS,
# X-Ray or S3 endpoint. The remaining interface endpoints serve GuardDuty Data,
# RDS Data and a custom PrivateLink service; none is an application dependency
# to adopt here. External AWS-service calls require the separately repaired and
# verified egress path. See F-15 for the exact read-only endpoint inventory.
existing_interface_endpoint_security_group_ids = []

# REQUIRED: adopt the existing SIFE buckets. Creating replacements strands all
# files in flight without producing an API error (D-006).
existing_bucket_names = {
  uploads   = "uid-dev-sife-files"
  downloads = "uid-dev-sife-download-files"
}

# Record any customer-managed default key used by each adopted bucket. Empty is
# correct only after confirming the bucket uses SSE-S3/the AWS-managed key.
storage_kms_key_arn                  = null
adopted_bucket_kms_key_arns          = {}
adopted_buckets_without_customer_kms = ["uploads", "downloads"]

# --- REQUIRED: existing database --------------------------------------------
# The RDS Proxy endpoint. The Elastic Beanstalk app read this from DB_PROXY_HOST;
# application-dev.properties currently defaults it to the CLUSTER endpoint
# (uid-dev-postgresqlv2.cluster-....rds.amazonaws.com), which bypasses the proxy.
# Put the proxy endpoint here, not the cluster endpoint.
db_proxy_host = "uid-dev-portal-proxy.proxy-cxk41gv3busd.us-west-2.rds.amazonaws.com"
db_name       = "insureu"
db_schema     = "uid_portal"

# --- database secret --------------------------------------------------------
portal_secret_name  = "dev/postgres/portal/rotate"
sendgrid_secret_arn = "arn:aws:secretsmanager:us-west-2:705157108110:secret:prod/sendgrid/new-ri9tTm"

# --- identity ---------------------------------------------------------------
oidc_issuer        = "https://sso.mylogin.utah.gov:443/am/oauth2"
oidc_utah_id_claim = "legacy_sub"
api_allowed_hosts  = ["api.uid-dev.utah.gov"]
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

# --- edge -------------------------------------------------------------------
# The attended 2026-08-19 apply created this reviewed survivor before failing
# on the external domain routing mode and dashboard body. Bind every recovery
# plan to that exact API instead of allowing another fresh create.
api_gateway_survivor_id = "ler9ythto0"
api_gateway_name        = "uid-dev-api-gateway"

# The browser stays on the existing CloudFront distribution at insureu.*.
# CloudFront's API behaviors use this custom origin and do not forward
# the viewer Host, so API Gateway and every Lambda see this exact allowlisted
# origin hostname. The issued wildcard certificate is shared with the
# historical dev inventory in this same account.
portal_domain_name      = "api.uid-dev.utah.gov"
portal_domain_ownership = "external"
certificate_arn         = "arn:aws:acm:us-west-2:705157108110:certificate/5b17baae-453a-4418-81e8-788e8336c3de"

# The State-owned custom-domain object is REGIONAL/TLS_1_2 with the reviewed
# certificate, but its routing mode must be mapping-only before the HTTP API can
# use it. Application Terraform reads the domain and may create only the root
# API mapping. It never creates, imports, tags, updates, replaces, or deletes
# the domain or DNS.
hosted_zone_id = ""

browser_origins   = ["https://insureu.uid-dev.utah.gov"]
portal_client_url = "https://insureu.uid-dev.utah.gov"

# snapproxy: live inventory confirmed that AT reuses the dev Aurora cluster,
# secret and database security group for the Vertafore replica path.
snap_secret_name                = "dev/postgres/snapproxy/rotate"
snap_db_host                    = "uid-dev-postgresqlv2.cluster-cxk41gv3busd.us-west-2.rds.amazonaws.com"
snap_database_security_group_id = "sg-0637efea445216701"
snap_db_name                    = "postgres"
snap_db_schema                  = "snapproxy"

# Live inventory confirmed that AT reuses the dev Oracle secret and database
# security group. Keep licensee_fast_sync disabled until SendGrid and egress
# probes pass and the legacy scheduler has been stopped.
oracle_admin_secret               = "dev/oracle/admin"
oracle_database_security_group_id = "sg-088e3b3e7215f4bb9"
oracle_database_port              = 1521
licensee_sync_stale_seconds       = 7200
licensee_sync_kill_settle_seconds = 10

# --- packaging --------------------------------------------------------------
layer_zip_path    = "../../assets/layer-placeholder.zip"
function_zip_path = "../../assets/lambda-placeholder.zip"

# --- capacity ---------------------------------------------------------------
per_function_reserved_concurrency  = 5
authorizer_provisioned_concurrency = 1

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

log_retention_days    = 90
generated_object_days = 7

tags = {
  Owner      = "uid-portal"
  CostCenter = "uid"
  app        = "uid-dev-portal-api"
  contact    = "gary gerber"
  dept       = "uid"
  division   = "dts"
  elcid      = "id6901alaa"
  env        = "dev"
  # Modules expand this reviewed prefix to uid-dev-<resource_id>. Provider
  # defaults retain it as a fail-safe on taggable resources without a more
  # specific Name override.
  Name     = "uid-dev"
  security = "0"
}
