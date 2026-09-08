# ---------------------------------------------------------------------------
# dev validation/reference values.
#
# Dev and AT share one AWS account. This root is deliberately non-deployable so
# it cannot maintain a second HTTP API; envs/at is the non-production owner.
# Values remain useful for credential-free validation and state reconciliation.
# ---------------------------------------------------------------------------

region         = "us-west-2"
log_level      = "DEBUG"
aws_account_id = "705157108110"

# --- existing network --------------------------------------------------------
# Taken from the devops account's own Terraform state:
# aws/terraform/repos/utahdts/uid-portal/inventory/state-owned-network/aws-vpc-base
# records the source state as historical inventory (serial 4, us-west-2).
# These are read, never created -- see modules/network, which has no aws_vpc.
#
# UID-Dev-VPC, 10.192.6.0/23. The account has seven subnets in three tiers;
# the two below are the `subnet-type = private-app` pair, which is where
# application workloads belong. The private-db tier is the Aurora cluster's and
# the public tier holds the NAT gateways.
vpc_id        = "vpc-05d3e6ccb65d2d11c"
vpc_ipv4_cidr = "10.192.6.0/23"

# UID-Dev-SUBNET-PRIVATE-1-A (us-west-2a) and -1-B (us-west-2b), /26 each.
# Two AZs, which is the module's minimum. There is no private-app subnet in
# us-west-2c -- only a third private-db one -- so two is also the maximum.
private_subnet_ids = [
  "subnet-0c6272b1eea00003c",
  "subnet-0a1e2c8e6751b6833",
]
lambda_security_group_ids = ["sg-0ab06d83d516f0163"]

# Live inventory on 2026-08-17 resolved both selected subnets to this exact
# route table. Keep it explicit: the external-egress guard must inspect every
# Lambda subnet route table instead of passing vacuously through discovery.
private_route_table_ids = ["rtb-00f83bc1b800e256e"]

# Live inventory on 2026-08-18 found no Secrets Manager, Logs, Lambda, KMS,
# X-Ray or S3 endpoint. The remaining interface endpoints serve GuardDuty Data,
# RDS Data and a custom PrivateLink service; none is an application dependency
# to adopt here. External AWS-service calls require the separately repaired and
# verified egress path. See F-15 for the exact read-only endpoint inventory.
existing_interface_endpoint_security_group_ids = []

# Empty deliberately. The separate db-proxy stack admits both Lambda subnet
# CIDRs to the proxy and adds the proxy security group to the cluster. Passing
# the cluster group here would also grant Lambdas a direct path around the
# proxy, defeating the connection pool this stack depends on.
database_security_group_id = ""

# --- REQUIRED: existing SIFE buckets -----------------------------------------
# SIFE has been running on Elastic Beanstalk for years, so its uploads and
# downloads buckets exist and hold files right now. Leaving this empty creates
# `uid-portal-dev-sife-uploads` and `-downloads` instead, and at cutover the new
# API would read an empty bucket and truthfully report that nobody has any files
# waiting -- no error, no warning, just an exchange that has apparently lost
# everything.
#
# The names are not in this repository. The Spring app reads them from
# AWS_S3_FILE_UPLOAD_BUCKET and AWS_S3_FILE_DOWNLOAD_BUCKET, which are set on
# the Beanstalk environment. Recorded as D-006; fill both before the first plan.
#
#   aws elasticbeanstalk describe-configuration-settings \
#     --application-name <app> --environment-name <env> \
#     --query "ConfigurationSettings[].OptionSettings[?contains(OptionName,'BUCKET')]"
#
# Read from the account, not from Beanstalk -- this account has no Beanstalk
# environment. uid-dev-sife-files held 127 objects / 741MB when this was filled;
# uid-dev-sife-download-files is generated content and was empty.
existing_bucket_names = {
  uploads   = "uid-dev-sife-files"
  downloads = "uid-dev-sife-download-files"
}

# This stack does not change encryption on adopted buckets. Before plan, inspect
# each bucket's default encryption. If either uses a customer-managed key, add
# its exact key ARN here so the narrowly scoped worker roles can use it.
storage_kms_key_arn = null
adopted_bucket_kms_key_arns = {
  # uploads   = "arn:aws:kms:us-west-2:705157108110:key/<key-id>"
  # downloads = "arn:aws:kms:us-west-2:705157108110:key/<key-id>"
}
# REQUIRED: after inspection, list any adopted purpose that does not use a
# customer-managed key. A plan is refused until every adopted bucket appears in
# exactly one of these two encryption inventories.
adopted_buckets_without_customer_kms = []

# The State resource owner must maintain browser CORS on adopted uploads. This
# stack reads bucket/object data but never changes any adopted configuration.

# --- REQUIRED: existing database --------------------------------------------
# The RDS Proxy, created by the namespaced stacks/db-proxy/dev root, which holds its own
# state so the pool is not in the blast radius of an API apply. This is the
# PROXY endpoint; application-dev.properties defaults DB_PROXY_HOST to the
# CLUSTER endpoint, which bypasses pooling and exhausts max_connections once
# hundreds of Lambdas connect.
db_proxy_host = "uid-dev-portal-proxy.proxy-cxk41gv3busd.us-west-2.rds.amazonaws.com"
db_name       = "insureu"
db_schema     = "uid_portal"

# --- database secret --------------------------------------------------------
# portal is the managed-rotation secret; the bare "dev/postgres/portal" the Java
# referenced does not exist in this account.
portal_secret_name  = "dev/postgres/portal/rotate"
sendgrid_secret_arn = "arn:aws:secretsmanager:us-west-2:705157108110:secret:prod/sendgrid/new-ri9tTm"

# --- identity ---------------------------------------------------------------
oidc_issuer        = "https://sso.mylogin.utah.gov:443/am/oauth2"
oidc_utah_id_claim = "legacy_sub"
api_allowed_hosts  = ["api.uid-dev.utah.gov"]
# Cloud IAM supplied the shared AT/production Ping contract, but this historical
# dev root is non-deploying and exists only for validation/state reconciliation.
# Keep its values empty so it cannot be mistaken for another deploy owner.
oidc_audience               = ""
oidc_scope_claim            = ""
oidc_required_scopes        = []
oidc_authorized_party_claim = ""
oidc_authorized_party_value = ""
oidc_token_type_source      = ""
oidc_token_type_name        = ""
oidc_token_type_value       = ""

# --- REQUIRED: edge ---------------------------------------------------------
# Empty is permitted only when the target account/Region contains no current
# or historical UID Portal HTTP API. If one exists, set its reviewed API id;
# imports.tf makes the reviewed plan import it instead of creating another API.
api_gateway_survivor_id = ""
portal_domain_name      = "api.uid-dev.utah.gov"
portal_domain_ownership = "external"

# The only ISSUED *.uid-dev.utah.gov certificate in the account; the other four
# are EXPIRED.
certificate_arn = "arn:aws:acm:us-west-2:705157108110:certificate/5b17baae-453a-4418-81e8-788e8336c3de"

# Deliberately empty, and not a placeholder. uid-dev.utah.gov is not a delegated
# zone -- it sits inside utah.gov, served by state nameservers (ns3/ns4/ns6.
# state.ut.us and *.utad.state.ut.us), and this account has no Route53 hosted
# zone at all. The existing API Gateway custom-domain object and its DNS are
# State-owned. This historical root only reads and validates the domain; it does
# not create, adopt, import, or mutate either object. After the domain owner
# completes the reviewed REGIONAL/TLS_1_2 migration and DNS cutover, the AT root
# may create only the API's root mapping.
hosted_zone_id = ""

browser_origins   = ["http://localhost:9181"]
portal_client_url = "http://localhost:9181"

# snapproxy: the Vertafore replica the licensee handlers read. Leave the host
# empty and /licensee/* answers 502 saying so, which is the right failure for an
# environment that has no replica -- better than looking like an outage.
snap_secret_name                = "dev/postgres/snapproxy/rotate"
snap_db_host                    = ""
snap_database_security_group_id = ""
snap_db_name                    = "postgres"
snap_db_schema                  = "snapproxy"

# Oracle refresh watchdog. The host and credentials remain inside this named
# secret; the listener port is repeated only so Terraform can scope an optional
# security-group ingress rule to the same port.
oracle_admin_secret               = "dev/oracle/admin"
oracle_database_security_group_id = ""
oracle_database_port              = 1521
licensee_sync_stale_seconds       = 7200
licensee_sync_kill_settle_seconds = 10

# --- packaging --------------------------------------------------------------
layer_zip_path    = "../../assets/layer-placeholder.zip"
function_zip_path = "../../assets/lambda-placeholder.zip"

# --- capacity ---------------------------------------------------------------
per_function_reserved_concurrency  = 5
authorizer_provisioned_concurrency = 0

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

log_retention_days    = 30
generated_object_days = 7

# This account tags everything with a fixed set -- every subnet, route table and
# gateway in the devops state carries all eight. Values copied from UID-Dev-VPC
# rather than invented, so new resources are attributable the same way the
# existing ones are. `app` is the exception: the VPC's value describes the VPC
# ("UID-DEV AWS acct vpc"), so this names the workload instead.
#
# `security = "0"` is copied verbatim. It is a classification this repository
# has no definition for; matching the surrounding infrastructure is the
# conservative choice, but confirm it is right for an internet-facing API.
tags = {
  Owner       = "uid-portal"
  CostCenter  = "uid"
  app         = "uid-portal-api"
  contact     = "Gary Gerber"
  dept        = "uid"
  elcid       = "ID6903ALAA"
  env         = "dev"
  managedby   = "Terraform - State in S3 Bucket"
  security    = "0"
  supportcode = "hstsahsy"
}
