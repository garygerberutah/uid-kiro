# ---------------------------------------------------------------------------
# at environment.
#
# The stack itself lives in modules/api_environment and is identical across environments.
# This file only forwards variables, so a change to the architecture is made
# once rather than three times and cannot drift between environments.
# ---------------------------------------------------------------------------

module "stack" {
  source = "../../modules/api_environment"

  env_name                    = "at"
  region                      = var.region
  aws_account_id              = var.aws_account_id
  offline_provider_validation = var.offline_provider_validation
  release_version             = var.release_version
  build_time                  = var.build_time
  log_level                   = var.log_level

  vpc_id                            = var.vpc_id
  vpc_ipv4_cidr                     = var.vpc_ipv4_cidr
  private_subnet_ids                = var.private_subnet_ids
  lambda_security_group_ids         = var.lambda_security_group_ids
  private_route_table_ids           = var.private_route_table_ids
  database_security_group_id        = var.database_security_group_id
  snap_database_security_group_id   = var.snap_database_security_group_id
  oracle_database_security_group_id = var.oracle_database_security_group_id
  oracle_database_port              = var.oracle_database_port
  existing_interface_endpoint_security_group_ids = (
    var.existing_interface_endpoint_security_group_ids
  )

  db_proxy_host                      = var.db_proxy_host
  allow_cluster_db_host              = var.allow_cluster_db_host
  db_port                            = var.db_port
  db_name                            = var.db_name
  db_schema                          = var.db_schema
  per_function_reserved_concurrency  = var.per_function_reserved_concurrency
  authorizer_provisioned_concurrency = var.authorizer_provisioned_concurrency

  oidc_issuer                 = var.oidc_issuer
  oidc_jwks_url               = var.oidc_jwks_url
  oidc_audience               = var.oidc_audience
  oidc_scope_claim            = var.oidc_scope_claim
  oidc_required_scopes        = var.oidc_required_scopes
  oidc_authorized_party_claim = var.oidc_authorized_party_claim
  oidc_authorized_party_value = var.oidc_authorized_party_value
  oidc_token_type_source      = var.oidc_token_type_source
  oidc_token_type_name        = var.oidc_token_type_name
  oidc_token_type_value       = var.oidc_token_type_value
  oidc_utah_id_claim          = var.oidc_utah_id_claim
  api_allowed_hosts           = var.api_allowed_hosts
  api_gateway_survivor_id     = var.api_gateway_survivor_id

  portal_secret_name        = var.portal_secret_name
  portal_secret_kms_key_arn = var.portal_secret_kms_key_arn
  sendgrid_secret_arn       = var.sendgrid_secret_arn
  snap_secret_name          = var.snap_secret_name
  snap_secret_kms_key_arn   = var.snap_secret_kms_key_arn
  snap_db_host              = var.snap_db_host
  snap_db_port              = var.snap_db_port
  snap_db_name              = var.snap_db_name
  snap_db_schema            = var.snap_db_schema

  oracle_admin_secret               = var.oracle_admin_secret
  oracle_admin_secret_kms_key_arn   = var.oracle_admin_secret_kms_key_arn
  licensee_sync_stale_seconds       = var.licensee_sync_stale_seconds
  licensee_sync_kill_settle_seconds = var.licensee_sync_kill_settle_seconds

  layer_zip_path    = var.layer_zip_path
  function_zip_path = var.function_zip_path

  api_gateway_name        = var.api_gateway_name
  portal_domain_name      = var.portal_domain_name
  portal_domain_ownership = var.portal_domain_ownership
  certificate_arn         = var.certificate_arn
  hosted_zone_id          = var.hosted_zone_id
  existing_bucket_names   = var.existing_bucket_names

  browser_origins = var.browser_origins

  portal_throttle_burst    = var.portal_throttle_burst
  portal_throttle_rate     = var.portal_throttle_rate
  portal_route_throttles   = var.portal_route_throttles
  licensee_throttle_burst  = var.licensee_throttle_burst
  licensee_throttle_rate   = var.licensee_throttle_rate
  licensee_route_throttles = var.licensee_route_throttles

  scheduled_jobs_enabled  = var.scheduled_jobs_enabled
  scheduled_job_intervals = var.scheduled_job_intervals

  email_from             = var.email_from
  portal_client_url      = var.portal_client_url
  sife_exclude_group_ids = var.sife_exclude_group_ids
  sife_captive_mailbox   = var.sife_captive_mailbox
  alert_emails           = var.alert_emails

  kms_key_arn                          = var.kms_key_arn
  storage_kms_key_arn                  = var.storage_kms_key_arn
  adopted_bucket_kms_key_arns          = var.adopted_bucket_kms_key_arns
  adopted_buckets_without_customer_kms = var.adopted_buckets_without_customer_kms
  log_retention_days                   = var.log_retention_days
  generated_object_days                = var.generated_object_days
  tags                                 = var.tags
}
