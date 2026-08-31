# ---------------------------------------------------------------------------
# The whole environment, assembled from services/api/routes/routes.yaml.
#
# Every environment root validates this shared shape with different tfvars. AT
# is the one non-production deploy owner (dev shares its account and is blocked
# at plan time); production owns the one gateway in its separate account. The
# route list is read once, below, and all resources fan out from it.
#
# Read this file top to bottom and you can see exactly what the manifest turns
# into. Add a route to the YAML and it appears here on the next plan; nothing
# in this file names an individual endpoint.
# ---------------------------------------------------------------------------

terraform {
  required_version = ">= 1.10, < 2.0"
  required_providers {
    aws = { source = "hashicorp/aws", version = ">= 5.40, < 7.0" }
  }
}

provider "aws" {
  region = var.region

  # `terraform validate` needs the provider schema but should not need an AWS
  # identity. This escape hatch is deliberately opt-in and CI scopes it to the
  # no-plan validation step. Real plan/apply runs keep the account guard and
  # all normal credential checks because the variable defaults to false.
  allowed_account_ids         = var.offline_provider_validation ? null : [var.aws_account_id]
  skip_credentials_validation = var.offline_provider_validation
  skip_requesting_account_id  = var.offline_provider_validation
  skip_metadata_api_check     = var.offline_provider_validation

  default_tags {
    tags = local.tags
  }
}

# Provider configuration must be credential-free for `terraform validate`, but
# that mode is never a deploy mode. Unlike variable validation, this lifecycle
# condition is checked while constructing a plan, so even a committed tfvars
# change cannot silently plan/apply without the account guard.
resource "terraform_data" "reject_offline_provider_validation_in_plans" {
  lifecycle {
    precondition {
      condition     = !var.offline_provider_validation
      error_message = "offline_provider_validation is only for credential-free terraform init/validate; disable it before plan or apply."
    }

    # AT has a confirmed live operator subscription supplied by an ignored
    # local override. A clean CI plan must stop rather than interpret the
    # tracked empty list as authorization to delete that subscription.
    precondition {
      condition     = lower(var.env_name) != "at" || length(var.alert_emails) > 0
      error_message = "AT alert_emails is empty. Supply the approved ignored deployment override before planning so Terraform cannot delete the confirmed live alert subscription."
    }

    precondition {
      condition = lower(var.env_name) != "at" || alltrue([
        lookup(var.tags, "app", "") == "uid-dev-portal-api",
        lookup(var.tags, "contact", "") == "gary gerber",
        lookup(var.tags, "dept", "") == "uid",
        lookup(var.tags, "division", "") == "dts",
        lookup(var.tags, "elcid", "") == "id6901alaa",
        lookup(var.tags, "env", "") == "dev",
        lookup(var.tags, "Name", "") == "uid-dev",
        lookup(var.tags, "security", "") == "0",
      ])
      error_message = "AT application resources must retain the reviewed UID-Dev organizational tag contract, including the uid-dev Name prefix."
    }
  }
}

locals {
  name_prefix = "uid-portal-${var.env_name}"

  # This State-owned non-production domain is a read-only prerequisite, not an
  # application resource. Pin the reviewed contract independently of tfvars so
  # a CLI override cannot bless a different domain or certificate merely
  # because the live object happens to match the override.
  approved_nonprod_api_domain = "api.uid-dev.utah.gov"
  approved_nonprod_api_certificate_arn = (
    "arn:aws:acm:us-west-2:705157108110:certificate/5b17baae-453a-4418-81e8-788e8336c3de"
  )

  # Keep the existing portal module/resource addresses while allowing the
  # account-facing API name to follow the platform naming convention. An empty
  # override preserves the historical name in environments that have not yet
  # scheduled their rename.
  api_gateway_name = var.api_gateway_name != "" ? var.api_gateway_name : "${local.name_prefix}-portal"
  expected_api_gateway_name = (
    var.env_name == "prod" ? "uid-prod-api-gateway" : "uid-dev-api-gateway"
  )

  # Cloud IAM-approved Ping access-token contract shared by AT and production.
  # Pin it independently of tfvars so a CLI override cannot substitute a
  # different but merely nonempty audience, scope, client, or token type.
  approved_ping_audience               = "7ZokREaGUFCgJprj3JX48Aa2tsrbsRbFwgeE"
  approved_ping_scope_claim            = "scope"
  approved_ping_required_scopes        = toset(["openid", "profile", "email", "directory"])
  approved_ping_authorized_party_claim = "azp"
  approved_ping_authorized_party_value = "7ZokREaGUFCgJprj3JX48Aa2tsrbsRbFwgeE"
  approved_ping_token_type_source      = "header"
  approved_ping_token_type_name        = "typ"
  approved_ping_token_type_value       = "at+jwt"

  # API Gateway permits duplicate display names, so inventory both the tag
  # contract and every name this repository has used. The set union counts a
  # physical API only once when it matches more than one lookup.
  uid_portal_api_names = toset([
    "uid-dev-api-gateway",
    "uid-prod-api-gateway",
    "uid-portal-dev-portal",
    "uid-portal-dev-licensee",
    "uid-portal-at-portal",
    "uid-portal-at-licensee",
    "uid-portal-prod-portal",
    "uid-portal-prod-licensee",
  ])

  manifest = yamldecode(file("${path.root}/../../../../../../../services/api/routes/routes.yaml"))
  defaults = local.manifest.defaults

  # IAM rejects tag keys differing only by case, and this account's convention
  # supplies `managedby`. Only add ours when the caller has not, or every
  # aws_iam_role in the stack fails with "Duplicate tag keys found".
  managed_by = anytrue([for k in keys(var.tags) : lower(k) == "managedby"]) ? {} : { ManagedBy = "terraform" }

  tags = merge(var.tags, local.managed_by, {
    Application = "uid-portal-api"
    Environment = var.env_name
    Source      = "aws/terraform/repos/utahdts/uid-portal/envs/${var.env_name}"
  })

  # --- every function the manifest asks for -------------------------------
  # Route entries with method NONE are the async workers: no gateway route,
  # but they still need a function. Every routed endpoint is a Python Lambda;
  # there is no hidden proxy/container target outside this expansion.
  route_functions = merge([
    for api_name, api in local.manifest.apis : {
      for r in api.routes : r.id => merge(r, {
        api     = api_name
        profile = r.iam_profile
      })
      if try(r.target, local.defaults.target) == "python"
    }
  ]...)

  scheduled_functions = {
    for s in local.manifest.scheduled : s.id => merge(s, {
      api     = "scheduled"
      profile = s.iam_profile
      roles   = []
    })
  }

  authorizer_functions = {
    for api_name, api in local.manifest.apis : api.authorizer.id => merge(api.authorizer, {
      api     = api_name
      profile = api.authorizer.iam_profile
      roles   = []
    })
  }

  # The custom authorizer is the first role gate. Keep its route contract
  # derived from the same manifest that supplies REQUIRED_ROLES to each handler,
  # so neither side can be widened independently. Public and worker entries do
  # not belong in an authorization decision keyed by an HTTP route.
  api_route_roles = {
    for r in local.manifest.apis.portal.routes : "${upper(r.method)} ${r.path}" => try(r.roles, local.defaults.roles)
    if try(r.method, "NONE") != "NONE" && try(r.auth, "none") != "none"
  }

  all_functions = merge(local.route_functions, local.scheduled_functions, local.authorizer_functions)

  # Keep the unmerged ids as well. `merge` necessarily overwrites a duplicate,
  # so validating only all_functions would make the very defect we need to
  # detect disappear before the assertion sees it.
  manifest_function_ids = concat(
    flatten([
      for api_name, api in local.manifest.apis : concat(
        [for route in api.routes : route.id],
        [api.authorizer.id],
      )
    ]),
    [for schedule in local.manifest.scheduled : schedule.id],
  )

  # Disabled scheduled jobs reserve zero as a second safety belt; enabling the
  # schedule and its function happens in the same reviewed plan.
  function_enabled = merge(
    { for id, f in local.route_functions : id => true },
    {
      for id, f in local.scheduled_functions : id => try(var.scheduled_jobs_enabled[id], false)
    },
    { for id, f in local.authorizer_functions : id => true },
  )

  # "handlers.meta:root" in the manifest is "handlers.meta.root" to Lambda.
  # Keeping the colon in the manifest makes the module/function split explicit
  # for the local gateway's importer, which has to split it anyway.
  handler_for = { for id, f in local.all_functions : id => replace(f.handler, ":", ".") }

  # --- environment variables ----------------------------------------------
  base_environment = {
    UID_RUNTIME    = "aws"
    UID_ENV        = var.env_name
    UID_SERVICE    = "uid-portal-api"
    UID_VERSION    = var.release_version
    UID_BUILD_TIME = var.build_time
    LOG_LEVEL      = var.log_level

    OIDC_ISSUER        = var.oidc_issuer
    OIDC_JWKS_URL      = var.oidc_jwks_url
    OIDC_AUDIENCE      = var.oidc_audience
    OIDC_UTAH_ID_CLAIM = var.oidc_utah_id_claim
    API_ALLOWED_HOSTS  = join(",", var.api_allowed_hosts)

    PORTAL_SECRET_NAME = var.portal_secret_name
    # The RDS Proxy endpoint, not the cluster endpoint. Pointing at the cluster
    # bypasses the proxy and every Lambda opens its own database connection.
    PORTAL_DB_HOST   = var.db_proxy_host
    PORTAL_DB_PORT   = tostring(var.db_port)
    PORTAL_DB_NAME   = var.db_name
    PORTAL_DB_SCHEMA = var.db_schema
    DB_SSLMODE       = "require"

    UPLOAD_BUCKET   = module.storage.upload_bucket
    DOWNLOAD_BUCKET = module.storage.download_bucket
    ARTIFACT_BUCKET = module.storage.artifact_bucket
    # Runtime writes choose a key by the actual destination bucket. A single
    # global value is unsafe in a mixed environment: it can force the managed
    # bucket key onto an adopted bucket whose policy requires a different CMK.
    UPLOAD_KMS_KEY_ID = (
      local.effective_storage_kms_key_arns["uploads"] == null ?
      "" : local.effective_storage_kms_key_arns["uploads"]
    )
    DOWNLOAD_KMS_KEY_ID = (
      local.effective_storage_kms_key_arns["downloads"] == null ?
      "" : local.effective_storage_kms_key_arns["downloads"]
    )
    ARTIFACT_KMS_KEY_ID = (
      local.effective_storage_kms_key_arns["artifacts"] == null ?
      "" : local.effective_storage_kms_key_arns["artifacts"]
    )

    ZIP_LAMBDA_NAME = "${local.name_prefix}-sife_zip_worker:live"
    # Invoke the stable alias, not $LATEST. Every gateway and scheduled target
    # already uses an alias; asynchronous report work must have the same
    # rollback boundary.
    REPORT_WORKER_LAMBDA_NAME = "${local.name_prefix}-sife_report_worker:live"

    # snapproxy: the Vertafore replica the ported licensee handlers read. A
    # second database entirely -- different host, different credentials -- and
    # unset in an environment that has not been given one, where the handlers
    # say so rather than failing like an outage.
    SNAP_SECRET_NAME = var.snap_secret_name
    SNAP_DB_HOST     = var.snap_db_host
    SNAP_DB_PORT     = tostring(var.snap_db_port)
    SNAP_DB_NAME     = var.snap_db_name
    SNAP_DB_SCHEMA   = var.snap_db_schema

    ORACLE_ADMIN_SECRET               = var.oracle_admin_secret
    LICENSEE_SYNC_STALE_SECONDS       = tostring(var.licensee_sync_stale_seconds)
    LICENSEE_SYNC_KILL_SETTLE_SECONDS = tostring(var.licensee_sync_kill_settle_seconds)

    SENDGRID_SECRET_ARN    = var.sendgrid_secret_arn
    ALERT_EMAILS           = join(",", var.alert_emails)
    EMAIL_FROM             = var.email_from
    PORTAL_CLIENT_URL      = var.portal_client_url
    SIFE_EXCLUDE_GROUP_IDS = join(",", [for g in var.sife_exclude_group_ids : tostring(g)])
    SIFE_CAPTIVE_MAILBOX   = var.sife_captive_mailbox
  }

  # Lambda limits the complete environment to 4 KB. The route functions need
  # the full runtime map, but the authorizer needs only identity, host and portal
  # role-database configuration plus its route contract. Selecting those keys
  # here prevents unrelated S3, snapproxy, Oracle and notification settings from
  # crowding API_ROUTE_ROLES out of the authorizer environment.
  portal_authorizer_environment_keys = toset([
    "UID_RUNTIME",
    "UID_ENV",
    "UID_SERVICE",
    "UID_VERSION",
    "UID_BUILD_TIME",
    "LOG_LEVEL",
    "OIDC_ISSUER",
    "OIDC_JWKS_URL",
    "OIDC_AUDIENCE",
    "OIDC_UTAH_ID_CLAIM",
    "API_ALLOWED_HOSTS",
    "PORTAL_SECRET_NAME",
    "PORTAL_DB_HOST",
    "PORTAL_DB_PORT",
    "PORTAL_DB_NAME",
    "PORTAL_DB_SCHEMA",
    "DB_SSLMODE",
  ])
  portal_authorizer_environment = merge(
    {
      for key, value in local.base_environment : key => value
      if contains(local.portal_authorizer_environment_keys, key)
    },
    {
      API_ROUTE_ROLES             = jsonencode(local.api_route_roles)
      OIDC_SCOPE_CLAIM            = var.oidc_scope_claim
      OIDC_REQUIRED_SCOPES        = join(" ", var.oidc_required_scopes)
      OIDC_AUTHORIZED_PARTY_CLAIM = var.oidc_authorized_party_claim
      OIDC_AUTHORIZED_PARTY_VALUE = var.oidc_authorized_party_value
      OIDC_TOKEN_TYPE_SOURCE      = var.oidc_token_type_source
      OIDC_TOKEN_TYPE_NAME        = var.oidc_token_type_name
      OIDC_TOKEN_TYPE_VALUE       = var.oidc_token_type_value
    },
  )

  portal_secret_arns = var.portal_secret_name == "" ? [] : [
    "arn:aws:secretsmanager:${var.region}:${var.aws_account_id}:secret:${var.portal_secret_name}-??????",
  ]
  snap_secret_arns = var.snap_secret_name == "" ? [] : [
    "arn:aws:secretsmanager:${var.region}:${var.aws_account_id}:secret:${var.snap_secret_name}-??????",
  ]
  oracle_admin_secret_arns = var.oracle_admin_secret == "" ? [] : [
    "arn:aws:secretsmanager:${var.region}:${var.aws_account_id}:secret:${var.oracle_admin_secret}-??????",
  ]
  sendgrid_secret_arns = [var.sendgrid_secret_arn]
  portal_secret_kms_key_arns = var.portal_secret_kms_key_arn == null ? [] : [
    var.portal_secret_kms_key_arn,
  ]
  snap_secret_kms_key_arns = var.snap_secret_kms_key_arn == null ? [] : [
    var.snap_secret_kms_key_arn,
  ]
  oracle_admin_secret_kms_key_arns = var.oracle_admin_secret_kms_key_arn == null ? [] : [
    var.oracle_admin_secret_kms_key_arn,
  ]

  # `storage_kms_key_arn` belongs only to buckets this stack creates. An adopted
  # bucket instead uses only its separately inventoried key, or null after it
  # has been explicitly classified as SSE-S3/AWS-managed. Never combine both:
  # doing so grants and sends a key that the destination bucket does not use.
  effective_storage_kms_key_arns = {
    for purpose in ["uploads", "downloads", "artifacts"] : purpose => (
      try(var.existing_bucket_names[purpose], "") != "" ?
      lookup(var.adopted_bucket_kms_key_arns, purpose, null) :
      var.storage_kms_key_arn
    )
  }

  # Profiles below receive only the effective key for the buckets they touch.
  storage_data_kms_key_arns = {
    for purpose, key_arn in local.effective_storage_kms_key_arns :
    purpose => key_arn == null ? [] : [key_arn]
  }

  # Callers use the stable alias names in their environment variables. Grant
  # exactly those aliases too: permission on the unqualified function ARN (or
  # every qualifier) would let a compromised orchestrator invoke $LATEST or a
  # version that has not passed the live-alias deployment gate.
  report_worker_arn = "arn:aws:lambda:${var.region}:${var.aws_account_id}:function:${local.name_prefix}-sife_report_worker:live"
  zip_worker_arn    = "arn:aws:lambda:${var.region}:${var.aws_account_id}:function:${local.name_prefix}-sife_zip_worker:live"

  empty_iam_profile = {
    secret_arns             = []
    secret_kms_key_arns     = []
    data_kms_actions        = []
    data_kms_key_arns       = []
    s3_statements           = []
    invokable_function_arns = []
    write_dead_letter       = false
    vpc_access              = false
  }

  # Capability sets named by `iam_profile` in routes.yaml. These are execution
  # permissions, not application roles: REQUIRED_ROLES still controls who may
  # call a route. Keeping both beside each route makes it possible to audit the
  # caller boundary and the AWS-resource boundary independently.
  iam_role_profiles = {
    public = merge(local.empty_iam_profile, {
      # Public means unauthenticated/resource-empty, not outside the network
      # boundary. All Lambdas are VPC-attached and therefore need ENI access.
      vpc_access = true
    })
    portal_authorizer = merge(local.empty_iam_profile, {
      secret_arns         = local.portal_secret_arns
      secret_kms_key_arns = local.portal_secret_kms_key_arns
      vpc_access          = true
    })
    portal_database = merge(local.empty_iam_profile, {
      secret_arns         = local.portal_secret_arns
      secret_kms_key_arns = local.portal_secret_kms_key_arns
      vpc_access          = true
    })
    licensee_database = merge(local.empty_iam_profile, {
      secret_arns = concat(local.portal_secret_arns, local.snap_secret_arns)
      secret_kms_key_arns = concat(
        local.portal_secret_kms_key_arns,
        local.snap_secret_kms_key_arns,
      )
      vpc_access = true
    })
    licensee_snap = merge(local.empty_iam_profile, {
      secret_arns         = local.snap_secret_arns
      secret_kms_key_arns = local.snap_secret_kms_key_arns
      vpc_access          = true
    })
    portal_upload = merge(local.empty_iam_profile, {
      secret_arns         = local.portal_secret_arns
      secret_kms_key_arns = local.portal_secret_kms_key_arns
      s3_statements = [
        {
          actions   = ["s3:GetBucketLocation"]
          resources = [module.storage.bucket_arns["uploads"]]
        },
        {
          # HeadObject is authorized by s3:GetObject. The same function signs
          # the browser's exact-size conditional PUT, so PutObject is intentional here.
          actions   = ["s3:GetObject", "s3:PutObject"]
          resources = ["${module.storage.bucket_arns["uploads"]}/*"]
        },
      ]
      # HeadObject does not decrypt content; the only data-key permission this
      # function needs is for the browser's presigned PutObject.
      data_kms_actions  = ["kms:GenerateDataKey"]
      data_kms_key_arns = local.storage_data_kms_key_arns["uploads"]
      vpc_access        = true
    })
    portal_job_reader = merge(local.empty_iam_profile, {
      secret_arns         = local.portal_secret_arns
      secret_kms_key_arns = local.portal_secret_kms_key_arns
      s3_statements = [
        {
          actions = ["s3:GetObject"]
          resources = [
            "${module.storage.bucket_arns["downloads"]}/*",
            "${module.storage.bucket_arns["artifacts"]}/*",
          ]
        },
      ]
      data_kms_actions = ["kms:Decrypt"]
      data_kms_key_arns = distinct(concat(
        local.storage_data_kms_key_arns["downloads"],
        local.storage_data_kms_key_arns["artifacts"],
      ))
      vpc_access = true
    })
    download_orchestrator = merge(local.empty_iam_profile, {
      secret_arns             = local.portal_secret_arns
      secret_kms_key_arns     = local.portal_secret_kms_key_arns
      invokable_function_arns = [local.zip_worker_arn, local.report_worker_arn]
      vpc_access              = true
    })
    report_orchestrator = merge(local.empty_iam_profile, {
      secret_arns             = local.portal_secret_arns
      secret_kms_key_arns     = local.portal_secret_kms_key_arns
      invokable_function_arns = [local.report_worker_arn]
      vpc_access              = true
    })
    report_worker = merge(local.empty_iam_profile, {
      secret_arns         = local.portal_secret_arns
      secret_kms_key_arns = local.portal_secret_kms_key_arns
      s3_statements = [{
        actions   = ["s3:PutObject"]
        resources = ["${module.storage.bucket_arns["artifacts"]}/*"]
      }]
      data_kms_actions        = ["kms:GenerateDataKey"]
      data_kms_key_arns       = local.storage_data_kms_key_arns["artifacts"]
      invokable_function_arns = [local.zip_worker_arn]
      write_dead_letter       = true
      vpc_access              = true
    })
    retention_worker = merge(local.empty_iam_profile, {
      secret_arns         = local.portal_secret_arns
      secret_kms_key_arns = local.portal_secret_kms_key_arns
      s3_statements = [
        {
          actions = ["s3:DeleteObject"]
          resources = [
            "${module.storage.bucket_arns["uploads"]}/*",
            "${module.storage.bucket_arns["downloads"]}/*",
            "${module.storage.bucket_arns["artifacts"]}/*",
          ]
        },
      ]
      write_dead_letter = true
      vpc_access        = true
    })
    zip_worker = merge(local.empty_iam_profile, {
      s3_statements = [
        {
          actions = ["s3:GetBucketLocation"]
          resources = [
            module.storage.bucket_arns["uploads"],
            module.storage.bucket_arns["downloads"],
          ]
        },
        {
          # Source objects are read-only. Keeping this separate from the
          # destination statement prevents the ZIP worker from overwriting an
          # uploaded source file.
          actions   = ["s3:GetObject"]
          resources = ["${module.storage.bucket_arns["uploads"]}/*"]
        },
        {
          actions   = ["s3:GetObject", "s3:PutObject", "s3:AbortMultipartUpload"]
          resources = ["${module.storage.bucket_arns["downloads"]}/*"]
        },
      ]
      # Multipart SSE-KMS writes require GenerateDataKey and source reads
      # require Decrypt. kms:Encrypt is not part of the S3 request contract.
      data_kms_actions = ["kms:Decrypt", "kms:GenerateDataKey"]
      data_kms_key_arns = distinct(concat(
        local.storage_data_kms_key_arns["uploads"],
        local.storage_data_kms_key_arns["downloads"],
      ))
      vpc_access = true
    })
    notification_worker = merge(local.empty_iam_profile, {
      secret_arns         = concat(local.portal_secret_arns, local.sendgrid_secret_arns)
      secret_kms_key_arns = local.portal_secret_kms_key_arns
      write_dead_letter   = true
      vpc_access          = true
    })
    licensee_worker = merge(local.empty_iam_profile, {
      # search_log_reaper closes replica search logs, then independently reaps
      # temp IDs and principal rate windows from the portal database. It must
      # be able to finish the portal cleanup even when the replica half fails.
      secret_arns = concat(
        local.portal_secret_arns,
        local.snap_secret_arns,
      )
      secret_kms_key_arns = concat(
        local.portal_secret_kms_key_arns,
        local.snap_secret_kms_key_arns,
      )
      write_dead_letter = true
      vpc_access        = true
    })
    licensee_sync = merge(local.empty_iam_profile, {
      secret_arns = concat(
        local.snap_secret_arns,
        local.oracle_admin_secret_arns,
        local.sendgrid_secret_arns,
      )
      secret_kms_key_arns = concat(
        local.snap_secret_kms_key_arns,
        local.oracle_admin_secret_kms_key_arns,
      )
      write_dead_letter = true
      vpc_access        = true
    })
  }
}

# Inventory the account/Region before the gateway graph is allowed to run.
# The tag query catches the current contract even after a future rename; the
# exact-name queries also catch pre-consolidation APIs that lack that tag.
data "aws_apigatewayv2_apis" "uid_portal_tagged" {
  protocol_type = "HTTP"
  tags = {
    Application = "uid-portal-api"
  }
}

data "aws_apigatewayv2_apis" "uid_portal_named" {
  for_each = local.uid_portal_api_names

  name          = each.value
  protocol_type = "HTTP"
}

locals {
  existing_uid_portal_api_ids = setunion(
    data.aws_apigatewayv2_apis.uid_portal_tagged.ids,
    [for inventory in data.aws_apigatewayv2_apis.uid_portal_named : inventory.ids]...
  )
  sole_existing_uid_portal_api_id = (
    length(local.existing_uid_portal_api_ids) == 1
    ? one(local.existing_uid_portal_api_ids)
    : ""
  )
}

# These are hard lifecycle preconditions, not warning-only `check` assertions.
# Zero APIs is valid only for a first deployment with no survivor declaration.
# One is valid only when its exact, independently reviewed id is declared; each
# environment root then plans an import into the stable module address instead
# of a create. This prevents an empty or wrong state from planning a second API.
resource "terraform_data" "single_uid_portal_api" {
  input = {
    discovered_ids = sort(tolist(local.existing_uid_portal_api_ids))
    survivor_id    = var.api_gateway_survivor_id
  }

  lifecycle {
    precondition {
      condition     = length(local.existing_uid_portal_api_ids) <= 1
      error_message = "More than one UID Portal HTTP API exists in this account/Region. Reconcile the dev/AT states and retire or import historical APIs before planning any gateway change."
    }

    precondition {
      condition = (
        length(local.existing_uid_portal_api_ids) == 0
        ? var.api_gateway_survivor_id == ""
        : var.api_gateway_survivor_id == local.sole_existing_uid_portal_api_id
      )
      error_message = "The reviewed api_gateway_survivor_id must be empty when no UID Portal HTTP API exists, or exactly match the sole live API id. Inventory the target account/Region and import/adopt that survivor; never plan a replacement API beside it."
    }
  }
}

# Networking for VPC-attached Lambdas is State-owned infrastructure, not
# something this application state may create or repair. Read every explicitly
# selected private route table to prove that the chosen Lambda subnets use the
# reviewed VPC-local route and have one existing IPv4 default route. The State
# network owner, not this stack, chooses and maintains the non-local targets.
data "aws_route_table" "lambda_private" {
  for_each = toset(var.private_route_table_ids)

  route_table_id = each.value
}

# aws_route_table.routes omits AWS-created local routes in AWS provider 6.58.
# An exact route lookup still returns that route, so use it to verify the local
# target instead of treating an incomplete aggregate route list as inventory.
data "aws_route" "lambda_local" {
  for_each = toset(var.private_route_table_ids)

  route_table_id         = each.value
  destination_cidr_block = var.vpc_ipv4_cidr
}

# Do not trust a caller-supplied list that happens to name a safe route table
# while the actual Lambda subnets use another one. Every selected subnet must
# have one explicit association, and the discovered set must exactly equal the
# route tables inspected below. A subnet using the VPC main table fails closed
# until that table is explicitly inventoried/associated.
data "aws_route_tables" "lambda_subnet" {
  for_each = toset(var.private_subnet_ids)

  filter {
    name   = "association.subnet-id"
    values = [each.value]
  }
}

locals {
  dev_at_vpc_ipv4_cidr = "10.192.6.0/23"
  dev_at_private_subnet_ids = toset([
    "subnet-0c6272b1eea00003c",
    "subnet-0a1e2c8e6751b6833",
  ])
  vpc_ipv4_prefix_length = tonumber(split("/", var.vpc_ipv4_cidr)[1])
  vpc_ipv4_first_address_number = sum([
    for index, octet in split(".", cidrhost(var.vpc_ipv4_cidr, 0)) :
    tonumber(octet) * pow(256, 3 - index)
  ])
  vpc_ipv4_last_address_number = sum([
    for index, octet in split(".", cidrhost(var.vpc_ipv4_cidr, -1)) :
    tonumber(octet) * pow(256, 3 - index)
  ])
  lambda_subnet_route_table_ids = toset(flatten([
    for result in data.aws_route_tables.lambda_subnet : result.ids
  ]))
  lambda_ipv4_default_routes = {
    for route_table_id, route_table in data.aws_route_table.lambda_private :
    route_table_id => [
      for route in route_table.routes : route
      if try(route.cidr_block, "") == "0.0.0.0/0"
    ]
  }
  lambda_ipv4_routes = flatten([
    for route_table_id, route_table in data.aws_route_table.lambda_private : [
      for route in route_table.routes : {
        route_table_id = route_table_id
        destination_cidr_block = coalesce(
          try(route.cidr_block, null),
          "__not_an_ipv4_cidr__",
        )
        gateway_id = coalesce(try(route.gateway_id, null), "__not_a_gateway__")
      }
      if try(route.cidr_block, null) != null
    ]
  ])
  lambda_ipv4_routes_with_ranges = [
    for route in local.lambda_ipv4_routes : merge(route, {
      destination_ipv4_prefix_length = try(
        tonumber(split("/", route.destination_cidr_block)[1]),
        null,
      )
      destination_ipv4_first_address_number = try(
        sum([
          for index, octet in split(".", cidrhost(route.destination_cidr_block, 0)) :
          tonumber(octet) * pow(256, 3 - index)
        ]),
        null,
      )
    })
  ]
}

resource "terraform_data" "lambda_external_egress" {
  input = {
    vpc_id                 = module.network.vpc_id
    vpc_ipv4_cidr          = module.network.vpc_ipv4_cidr
    existing_subnet_ids    = sort(module.network.private_subnet_ids)
    subnet_route_table_ids = sort(tolist(local.lambda_subnet_route_table_ids))
    route_table_ids        = sort(var.private_route_table_ids)
    ipv4_default_route_counts = {
      for route_table_id, routes in local.lambda_ipv4_default_routes :
      route_table_id => length(routes)
    }
  }

  lifecycle {
    precondition {
      condition = alltrue([
        for id, function in local.all_functions : try(function.vpc, local.defaults.vpc) == true
      ])
      error_message = "Every UID Portal Lambda, including public handlers, workers, schedules and the authorizer, must be VPC-attached. A manifest vpc=false override is forbidden."
    }

    precondition {
      condition     = toset(module.network.private_subnet_ids) == toset(var.private_subnet_ids)
      error_message = "Every Lambda must remain in the exact existing private_subnet_ids selected from the reviewed VPC; application Terraform cannot create, substitute or repair a subnet."
    }

    precondition {
      condition = !contains(["dev", "at"], var.env_name) || (
        var.vpc_ipv4_cidr == local.dev_at_vpc_ipv4_cidr &&
        toset(var.private_subnet_ids) == local.dev_at_private_subnet_ids
      )
      error_message = "Dev/AT is pinned to VPC CIDR 10.192.6.0/23 and the approved existing subnet pair; an application plan cannot substitute either."
    }

    precondition {
      condition     = length(var.private_route_table_ids) > 0
      error_message = "private_route_table_ids must explicitly name every Lambda subnet route table so the read-only network guard cannot pass without inspecting a route."
    }

    precondition {
      condition = (
        alltrue([
          for result in data.aws_route_tables.lambda_subnet : length(result.ids) == 1
        ]) &&
        local.lambda_subnet_route_table_ids == toset(var.private_route_table_ids)
      )
      error_message = "private_route_table_ids must exactly match the one explicitly associated route table for every Lambda subnet. A missing association or unrelated route table cannot satisfy the read-only network guard."
    }

    precondition {
      condition = alltrue([
        for route_table_id, local_route in data.aws_route.lambda_local : try(
          local_route.destination_cidr_block == var.vpc_ipv4_cidr &&
          local_route.gateway_id == "local",
          false,
        )
      ])
      error_message = "Every Lambda subnet route table must resolve the reviewed vpc_ipv4_cidr to its exact AWS local route. Secondary IPv4 CIDRs and IPv6 associations are forbidden by the existing-VPC guard."
    }

    precondition {
      condition = alltrue([
        for route in local.lambda_ipv4_routes_with_ranges :
        (
          route.gateway_id == "local" &&
          route.destination_cidr_block == var.vpc_ipv4_cidr
          ) || try(
          route.destination_ipv4_prefix_length <= local.vpc_ipv4_prefix_length ||
          route.destination_ipv4_first_address_number < local.vpc_ipv4_first_address_number ||
          route.destination_ipv4_first_address_number > local.vpc_ipv4_last_address_number,
          false,
        )
      ])
      error_message = "A more-specific IPv4 route must not divert traffic inside the reviewed vpc_ipv4_cidr away from its exact AWS local route. Non-local route targets remain State-owned and are validated operationally rather than managed by this stack."
    }

    precondition {
      condition = alltrue([
        for route_table_id, default_routes in local.lambda_ipv4_default_routes :
        length(default_routes) == 1
      ])
      error_message = "Every Lambda private route table must contain exactly one existing 0.0.0.0/0 route. Its State-owned target and live reachability must be verified outside this application stack."
    }
  }
}

check "manifest_is_python_only" {
  assert {
    condition = alltrue(flatten([
      for api_name, api in local.manifest.apis : [
        for route in api.routes : try(route.target, local.defaults.target) == "python"
      ]
    ]))
    error_message = "Every API route must target its own Python Lambda; container/java/proxy targets are not supported."
  }
}

check "manifest_iam_profiles_exist" {
  assert {
    condition = alltrue([
      for id, function in local.all_functions : contains(keys(local.iam_role_profiles), function.profile)
    ])
    error_message = "Every route, scheduled job and authorizer iam_profile must name a profile in local.iam_role_profiles."
  }
}

check "vpc_functions_have_vpc_iam" {
  assert {
    condition = alltrue([
      for id, function in local.all_functions :
      !try(function.vpc, local.defaults.vpc) || try(local.iam_role_profiles[function.profile].vpc_access, false)
    ])
    error_message = "Every function with vpc=true must use an IAM profile that grants Lambda ENI operations."
  }
}

check "adopted_bucket_keys_name_adopted_buckets" {
  assert {
    condition = alltrue([
      for bucket in keys(var.adopted_bucket_kms_key_arns) :
      try(var.existing_bucket_names[bucket], "") != ""
    ])
    error_message = "adopted_bucket_kms_key_arns may name only a non-empty bucket in existing_bucket_names; managed buckets use storage_kms_key_arn."
  }
}

# ---------------------------------------------------------------------------
# foundations
# ---------------------------------------------------------------------------

# The API states historically created these shared-network objects. Forget
# every legacy address without destroying the live object. The network owner
# can inventory/adopt them independently; this application state must never
# regain lifecycle control. The saved-plan boundary permits Terraform's
# `forget` action but rejects any network create, update, replacement or delete.
removed {
  from = module.network.aws_security_group.lambda

  lifecycle {
    destroy = false
  }
}

removed {
  from = module.network.aws_vpc_security_group_ingress_rule.database_from_lambda

  lifecycle {
    destroy = false
  }
}

removed {
  from = module.network.aws_vpc_security_group_ingress_rule.snap_database_from_lambda

  lifecycle {
    destroy = false
  }
}

removed {
  from = module.network.aws_vpc_security_group_ingress_rule.oracle_database_from_lambda

  lifecycle {
    destroy = false
  }
}

removed {
  from = module.network.aws_security_group.endpoints

  lifecycle {
    destroy = false
  }
}

removed {
  from = module.network.aws_vpc_endpoint.interface

  lifecycle {
    destroy = false
  }
}

removed {
  from = module.network.aws_vpc_security_group_ingress_rule.existing_endpoint_from_lambda

  lifecycle {
    destroy = false
  }
}

removed {
  from = module.network.aws_vpc_endpoint.s3

  lifecycle {
    destroy = false
  }
}

module "network" {
  source = "../network"

  vpc_id                            = var.vpc_id
  vpc_ipv4_cidr                     = var.vpc_ipv4_cidr
  private_subnet_ids                = var.private_subnet_ids
  lambda_security_group_ids         = var.lambda_security_group_ids
  database_security_group_id        = var.database_security_group_id
  snap_database_security_group_id   = var.snap_database_security_group_id
  oracle_database_security_group_id = var.oracle_database_security_group_id
  existing_interface_endpoint_security_group_ids = (
    var.existing_interface_endpoint_security_group_ids
  )
}

module "storage" {
  source = "../storage"

  upload_bucket_name    = "${local.name_prefix}-sife-uploads"
  download_bucket_name  = "${local.name_prefix}-sife-downloads"
  artifact_bucket_name  = "${local.name_prefix}-artifacts"
  browser_origins       = var.browser_origins
  kms_key_arn           = var.storage_kms_key_arn
  generated_object_days = var.generated_object_days
  tags                  = local.tags

  # SIFE's buckets predate this migration. Naming them here uses them in place
  # instead of creating empty replacements alongside the files in flight.
  existing_bucket_names = var.existing_bucket_names
}

module "alerting" {
  source = "../alerting"

  name_prefix  = local.name_prefix
  alert_emails = var.alert_emails
  tags         = local.tags
}

module "iam" {
  source = "../iam"

  name_prefix           = local.name_prefix
  region                = var.region
  account_id            = var.aws_account_id
  role_profiles         = local.iam_role_profiles
  dead_letter_queue_arn = module.alerting.dlq_arn
  tags                  = local.tags
}

module "observability" {
  source = "../observability"

  name_prefix            = local.name_prefix
  region                 = var.region
  alert_topic_arn        = module.alerting.alert_topic_arn
  alert_topic_name       = module.alerting.alert_topic_name
  dead_letter_queue_name = module.alerting.dlq_name
  api_ids                = [module.portal_api.api_id]
  authorizer_function_names = [
    for id, f in local.authorizer_functions : module.function[id].function_name
  ]
  # Map keys come from the manifest and are known during planning. Log-group
  # names are module outputs and may remain unknown until apply; using them as
  # set keys would make a first plan impossible.
  authorizer_log_groups = {
    for id, f in local.authorizer_functions : id => module.function[id].log_group
  }
  handler_log_groups = {
    for id, f in local.route_functions : id => module.function[id].log_group
  }
  report_worker_log_groups = {
    sife_report_worker = module.function["sife_report_worker"].log_group
  }
  notification_log_groups = {
    sife_notification = module.function["sife_notification"].log_group
  }
  licensee_sync_log_groups = {
    licensee_fast_sync = module.function["licensee_fast_sync"].log_group
  }
  tags = local.tags
}

# ---------------------------------------------------------------------------
# dependency layer
# ---------------------------------------------------------------------------

# Terraform creates the layer with a committed placeholder. Application CI
# publishes dependency layers and updates function configuration afterwards.
resource "aws_lambda_layer_version" "deps" {
  layer_name               = "${local.name_prefix}-deps"
  filename                 = var.layer_zip_path
  source_code_hash         = filebase64sha256(var.layer_zip_path)
  compatible_runtimes      = ["python3.13"]
  compatible_architectures = ["arm64"]
  description              = "psycopg3, PyJWT, cryptography, PyYAML, openpyxl and python-oracledb for the UID portal API."

  # Unlike top-level `check` blocks (which intentionally warn), these are hard
  # preconditions. An invalid manifest/environment contract must stop the plan
  # before any AWS resource change can be approved.
  lifecycle {
    ignore_changes = [filename, source_code_hash]

    precondition {
      condition     = var.env_name != "dev"
      error_message = "The dev and AT roots share one AWS account. AT is the sole non-production API Gateway owner; reconcile the historical dev state instead of planning this root."
    }

    precondition {
      condition     = local.api_gateway_name == local.expected_api_gateway_name
      error_message = "The sole gateway name must be uid-dev-api-gateway for AT or uid-prod-api-gateway for production."
    }

    precondition {
      condition     = !contains(["at", "prod"], var.env_name) || var.oidc_audience == local.approved_ping_audience
      error_message = "AT and production oidc_audience must exactly match the Cloud IAM-approved shared Ping access-token audience recorded by D-026. A different nonempty value is not an acceptable override."
    }

    precondition {
      condition = !contains(["at", "prod"], var.env_name) || (
        var.oidc_scope_claim == local.approved_ping_scope_claim &&
        length(var.oidc_required_scopes) == length(local.approved_ping_required_scopes) &&
        toset(var.oidc_required_scopes) == local.approved_ping_required_scopes &&
        var.oidc_authorized_party_claim == local.approved_ping_authorized_party_claim &&
        var.oidc_authorized_party_value == local.approved_ping_authorized_party_value &&
        var.oidc_token_type_source == local.approved_ping_token_type_source &&
        var.oidc_token_type_name == local.approved_ping_token_type_name &&
        var.oidc_token_type_value == local.approved_ping_token_type_value
      )
      error_message = "AT and production must use the exact Cloud IAM-approved Ping scope, authorized-party, and signed token-type contract recorded by D-026. A different merely nonempty contract is forbidden."
    }

    precondition {
      condition = !contains(["at", "prod"], var.env_name) || (
        var.oidc_issuer == "https://sso.mylogin.utah.gov:443/am/oauth2" &&
        contains([
          "",
          "https://sso.mylogin.utah.gov:443/am/oauth2/connect/jwk_uri",
        ], var.oidc_jwks_url) &&
        var.oidc_utah_id_claim == "legacy_sub"
      )
      error_message = "AT and production are Ping-only until D-026 is resolved. Keep the exact mylogin issuer/JWKS and legacy_sub identity claim; do not switch providers or identity keys in Terraform."
    }

    precondition {
      condition     = length(keys(local.manifest.apis)) == 1 && contains(keys(local.manifest.apis), "portal")
      error_message = "routes.yaml must declare exactly one API named portal; every HTTP route is maintained by the single module.portal_api instance."
    }

    precondition {
      condition = (
        length(local.manifest.apis.portal.authorizer.identity_sources) == 2 &&
        length(setsubtract(
          toset(["$request.header.Authorization", "$context.domainName"]),
          toset(local.manifest.apis.portal.authorizer.identity_sources),
        )) == 0
      )
      error_message = "The portal authorizer identity sources must be exactly Authorization and API Gateway context domainName."
    }

    precondition {
      condition     = var.portal_domain_name == "" || contains(var.api_allowed_hosts, lower(var.portal_domain_name))
      error_message = "portal_domain_name must be present in api_allowed_hosts whenever this stack publishes an API mapping."
    }

    precondition {
      condition = (
        contains(["at", "dev"], var.env_name)
        ? var.portal_domain_ownership == "external"
        : var.env_name != "prod" || var.portal_domain_ownership == "managed"
      )
      error_message = "AT/dev must read the external API Gateway custom domain; production must retain managed custom-domain ownership."
    }

    precondition {
      condition = !contains(["at", "dev"], var.env_name) || (
        var.aws_account_id == "705157108110" &&
        var.region == "us-west-2" &&
        var.portal_domain_name == local.approved_nonprod_api_domain &&
        var.certificate_arn == local.approved_nonprod_api_certificate_arn
      )
      error_message = "AT/dev must use the reviewed read-only api.uid-dev.utah.gov domain and exact us-west-2 ACM certificate; CLI overrides cannot substitute another external domain contract."
    }

    precondition {
      condition = alltrue(flatten([
        for api_name, api in local.manifest.apis : [
          for route in api.routes : try(route.target, local.defaults.target) == "python"
        ]
      ]))
      error_message = "Every API route must target a Python Lambda."
    }

    precondition {
      condition     = length(local.manifest_function_ids) == length(distinct(local.manifest_function_ids))
      error_message = "Route, worker, schedule and authorizer ids must be globally unique; duplicate ids are overwritten by Terraform maps."
    }

    precondition {
      condition = alltrue([
        for id, function in local.all_functions : contains(keys(local.iam_role_profiles), function.profile)
      ])
      error_message = "Every manifest function must name a defined IAM profile."
    }

    precondition {
      condition = alltrue([
        for id, function in local.all_functions :
        !try(function.vpc, local.defaults.vpc) || try(local.iam_role_profiles[function.profile].vpc_access, false)
      ])
      error_message = "Every VPC-attached function must use a VPC-capable IAM profile."
    }

    precondition {
      condition = alltrue([
        for api_name, api in local.manifest.apis :
        length([for route in api.routes : "${try(route.method, "NONE")} ${try(route.path, "")}" if try(route.method, "NONE") != "NONE"]) ==
        length(distinct([for route in api.routes : "${try(route.method, "NONE")} ${try(route.path, "")}" if try(route.method, "NONE") != "NONE"]))
      ])
      error_message = "HTTP method/path route keys must be unique within each API."
    }

    precondition {
      condition = (
        length(setsubtract(toset(keys(local.scheduled_functions)), toset(keys(var.scheduled_jobs_enabled)))) == 0 &&
        length(setsubtract(toset(keys(var.scheduled_jobs_enabled)), toset(keys(local.scheduled_functions)))) == 0 &&
        length(setsubtract(toset(keys(local.scheduled_functions)), toset(keys(var.scheduled_job_intervals)))) == 0 &&
        length(setsubtract(toset(keys(var.scheduled_job_intervals)), toset(keys(local.scheduled_functions)))) == 0
      )
      error_message = "scheduled_jobs_enabled and scheduled_job_intervals must each name every manifest schedule exactly once."
    }

    precondition {
      condition = length(setsubtract(
        toset(try(local.manifest.apis.portal.cors.allow_origins_by_env[var.env_name], [])),
        toset(var.browser_origins),
      )) == 0
      error_message = "browser_origins must include every portal API CORS origin so direct presigned S3 uploads work from the same UI origins."
    }

  }
}

# ---------------------------------------------------------------------------
# functions — one per manifest entry
# ---------------------------------------------------------------------------

module "function" {
  source   = "../lambda_function"
  for_each = local.all_functions

  name                   = "${local.name_prefix}-${each.key}"
  handler                = local.handler_for[each.key]
  package_zip_path       = var.function_zip_path
  layer_arns             = [aws_lambda_layer_version.deps.arn]
  timeout                = try(each.value.timeout, local.defaults.timeout)
  memory_size            = try(each.value.memory, local.defaults.memory)
  ephemeral_storage_size = try(each.value.ephemeral_storage, 512)
  role_arn               = module.iam.role_arns[each.value.profile]

  vpc_enabled = try(each.value.vpc, local.defaults.vpc)
  vpc_config  = try(each.value.vpc, local.defaults.vpc) ? module.network.vpc_config : null

  environment = each.key == "portal_jwt" ? local.portal_authorizer_environment : merge(
    local.base_environment, {
      # This stays on every route Lambda as a second authorization check after
      # the authorizer's manifest-derived route decision.
      REQUIRED_ROLES         = join(",", try(each.value.roles, local.defaults.roles))
      REQUIRE_AUTHENTICATION = tostring(try(each.value.auth, "none") != "none")
    },
  )

  log_retention_days = var.log_retention_days
  kms_key_arn        = var.kms_key_arn

  # Bound the number of database connections the whole fleet can demand. The
  # RDS Proxy has a finite pool; without a cap, one traffic spike on one route
  # starves every other route of connections.
  reserved_concurrency = try(each.value.vpc, local.defaults.vpc) ? (
    !local.function_enabled[each.key] ? 0 : (
      contains(keys(local.scheduled_functions), each.key) ? 1 : var.per_function_reserved_concurrency
    )
  ) : -1

  # Only the authorizer gets pre-warmed: it is on the critical path of every
  # protected request, so its cold start is everyone's cold start.
  provisioned_concurrency = endswith(each.value.profile, "_authorizer") ? var.authorizer_provisioned_concurrency : 0

  # Only functions invoked asynchronously can use a Lambda DLQ. Attaching one
  # to synchronous API handlers and authorizers is decorative and forces queue
  # permissions onto roles that never send a message.
  dead_letter_enabled = local.iam_role_profiles[each.value.profile].write_dead_letter
  dead_letter_arn     = local.iam_role_profiles[each.value.profile].write_dead_letter ? module.alerting.dlq_arn : null
  alarm_topic_arn     = module.alerting.alert_topic_arn
  tags                = merge(local.tags, { Route = each.key, Api = each.value.api })

  # A role ARN alone does not depend on its policies. VPC-attached Lambda
  # creation can otherwise race AWSLambdaVPCAccessExecutionRole propagation.
  depends_on = [terraform_data.lambda_external_egress, module.iam, aws_lambda_layer_version.deps]
}

# ---------------------------------------------------------------------------
# the APIs
# ---------------------------------------------------------------------------

module "portal_api" {
  source = "../http_api"

  depends_on = [terraform_data.single_uid_portal_api, terraform_data.lambda_external_egress]

  # Keep this module block name stable: it owns the surviving physical API and
  # changing the module address would turn a consolidation into a replacement.
  # `name` stays stable because it is also the access-log/alarm/permission
  # prefix; `api_name` changes only the HTTP API's display name in place.
  name       = "${local.name_prefix}-portal"
  api_name   = local.api_gateway_name
  api_key    = "portal"
  manifest   = local.manifest
  env_name   = var.env_name
  region     = var.region
  account_id = var.aws_account_id

  integrations = {
    for r in local.manifest.apis.portal.routes :
    r.id => module.function[r.id].invoke_arn
    if try(r.method, "NONE") != "NONE"
  }
  integration_function_names = {
    for r in local.manifest.apis.portal.routes :
    r.id => module.function[r.id].function_name
    if try(r.method, "NONE") != "NONE"
  }

  authorizer = {
    invoke_arn    = module.function["portal_jwt"].invoke_arn
    function_name = module.function["portal_jwt"].function_name
  }

  domain_name      = var.portal_domain_name
  domain_ownership = var.portal_domain_ownership
  certificate_arn  = var.certificate_arn
  hosted_zone_id   = var.hosted_zone_id

  throttle_burst = var.portal_throttle_burst
  throttle_rate  = var.portal_throttle_rate
  route_throttles = merge(
    {
      for r in local.manifest.apis.portal.routes : r.id => {
        burst = var.licensee_throttle_burst
        rate  = var.licensee_throttle_rate
      }
      if startswith(r.id, "licensee_") && try(r.method, "NONE") != "NONE"
    },
    var.portal_route_throttles,
    var.licensee_route_throttles,
  )
  log_retention_days = var.log_retention_days
  kms_key_arn        = var.kms_key_arn
  alarm_topic_arn    = module.alerting.alert_topic_arn
  tags               = local.tags
}

# ---------------------------------------------------------------------------
# scheduled work
# ---------------------------------------------------------------------------

module "scheduling" {
  source = "../scheduling"

  name_prefix = local.name_prefix
  account_id  = var.aws_account_id

  schedules = {
    for s in local.manifest.scheduled : s.id => {
      schedule      = s.schedule
      timezone      = try(s.timezone, "America/Denver")
      target_arn    = module.function[s.id].alias_arn
      function_name = module.function[s.id].function_name
      # Disabled unless an environment explicitly opts in. A newly added
      # manifest job must never become live in every account merely because an
      # environment map has not caught up yet.
      enabled                   = try(var.scheduled_jobs_enabled[s.id], false)
      alarm_on_missing          = true
      expected_interval_seconds = try(var.scheduled_job_intervals[s.id], 86400 + 3600)
    }
  }

  dead_letter_enabled = true
  dead_letter_arn     = module.alerting.dlq_arn
  alarm_topic_arn     = module.alerting.alert_topic_arn
  tags                = local.tags
}
