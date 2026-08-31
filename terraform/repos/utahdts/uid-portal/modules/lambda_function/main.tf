# ---------------------------------------------------------------------------
# One Python Lambda function, its log group, its alias and its alarms.
#
# Every route in routes.yaml gets its own instance of this module rather than
# sharing one fat function behind a proxy route. That costs a little more
# packaging time and buys three things worth having:
#
#   * per-route IAM. The report worker can write to the artifact bucket; the
#     roles endpoint cannot. A single function would need the union of every
#     permission any route requires.
#   * per-route memory, timeout and concurrency, so a slow report cannot
#     consume the concurrency the login path needs.
#   * per-route metrics and alarms, with no log filtering to work out which
#     endpoint is failing.
# ---------------------------------------------------------------------------

terraform {
  required_version = ">= 1.6"
  required_providers {
    aws = { source = "hashicorp/aws", version = ">= 5.40, < 7.0" }
  }
}

# Terraform provisions with a committed placeholder package. The application
# deployment workflow owns every subsequent code version.

locals {
  name_tag_prefix = lookup(var.tags, "Name", "")
  resource_id = trimprefix(
    trimprefix(
      trimprefix(var.name, "uid-portal-at-"),
      "uid-portal-dev-",
    ),
    "uid-portal-prod-",
  )
}

# Created explicitly rather than letting Lambda create it on first invocation:
# an implicitly created log group has no retention policy and keeps logs
# forever, and Terraform will not adopt it later without an import.
resource "aws_cloudwatch_log_group" "this" {
  name              = "/aws/lambda/${var.name}"
  retention_in_days = var.log_retention_days
  kms_key_id        = var.kms_key_arn
  tags = merge(
    var.tags,
    local.name_tag_prefix == "" ? {} : { Name = "${local.name_tag_prefix}-${local.resource_id}-logs" },
  )
}

resource "aws_lambda_function" "this" {
  function_name = var.name
  role          = var.role_arn
  handler       = var.handler
  runtime       = var.runtime
  architectures = [var.architecture]

  filename         = var.package_zip_path
  source_code_hash = filebase64sha256(var.package_zip_path)

  timeout     = var.timeout
  memory_size = var.memory_size
  layers      = var.layer_arns
  kms_key_arn = var.kms_key_arn
  publish     = true

  ephemeral_storage {
    size = var.ephemeral_storage_size
  }

  reserved_concurrent_executions = var.reserved_concurrency

  environment {
    variables = var.environment
  }

  dynamic "vpc_config" {
    # Whether the block exists is manifest-derived and known at plan time. The
    # security-group id inside vpc_config is created in this same plan and may
    # remain unknown until apply without changing the graph shape.
    for_each = var.vpc_enabled ? [1] : []
    content {
      subnet_ids                  = var.vpc_config.subnet_ids
      security_group_ids          = var.vpc_config.security_group_ids
      ipv6_allowed_for_dual_stack = false
    }
  }

  dynamic "dead_letter_config" {
    # The capability flag is static; the queue ARN is intentionally allowed to
    # be unknown during the first plan.
    for_each = var.dead_letter_enabled ? [1] : []
    content {
      target_arn = var.dead_letter_arn
    }
  }

  tracing_config {
    mode = var.tracing_mode
  }

  lifecycle {
    # CI publishes the application package and dependency layer, then advances
    # the live alias. Terraform retains ownership of runtime configuration but
    # must not roll any of those software release fields back.
    ignore_changes = [source_code_hash, filename, image_uri, layers]

    precondition {
      condition     = !var.vpc_enabled || var.vpc_config != null
      error_message = "vpc_config is required when vpc_enabled is true."
    }

    precondition {
      condition     = !var.dead_letter_enabled || var.dead_letter_arn != null
      error_message = "dead_letter_arn is required when dead_letter_enabled is true."
    }

    precondition {
      # base64 length reflects UTF-8 bytes, unlike Terraform string length.
      # 5,460 encoded characters represent at most 4,095 input bytes, leaving
      # one conservative byte below Lambda's 4 KiB aggregate limit.
      condition     = length(base64encode(jsonencode(var.environment))) <= 5460
      error_message = "Lambda environment variables exceed the 4 KB service limit. Keep API_ROUTE_ROLES only on the authorizer and move unrelated settings out of that function's environment."
    }
  }

  # Without this the first invocation can race the log group into existence and
  # create an unmanaged one with infinite retention.
  depends_on = [aws_cloudwatch_log_group.this]

  tags = merge(
    var.tags,
    local.name_tag_prefix == "" ? {} : { Name = "${local.name_tag_prefix}-${local.resource_id}" },
  )
}

# API Gateway and EventBridge point at this alias, never at $LATEST. That makes
# a rollback a single alias update instead of a redeploy.
resource "aws_lambda_alias" "live" {
  name             = "live"
  function_name    = aws_lambda_function.this.function_name
  function_version = aws_lambda_function.this.version

  lifecycle {
    # Application deployment publishes code and advances this alias. Terraform
    # owns the alias resource, not its deployed software version.
    ignore_changes = [function_version]
  }
}

resource "aws_lambda_provisioned_concurrency_config" "this" {
  count = var.provisioned_concurrency > 0 ? 1 : 0

  function_name                     = aws_lambda_function.this.function_name
  qualifier                         = aws_lambda_alias.live.name
  provisioned_concurrent_executions = var.provisioned_concurrency

  lifecycle {
    precondition {
      condition     = var.reserved_concurrency == -1 || var.provisioned_concurrency <= var.reserved_concurrency
      error_message = "provisioned_concurrency cannot exceed reserved_concurrency for ${var.name}."
    }
  }
}

# --- alarms ----------------------------------------------------------------

resource "aws_cloudwatch_metric_alarm" "errors" {
  alarm_name          = "${var.name}-errors"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  threshold           = 0
  period              = 300
  statistic           = "Sum"
  namespace           = "AWS/Lambda"
  metric_name         = "Errors"
  treat_missing_data  = "notBreaching"
  dimensions          = { FunctionName = aws_lambda_function.this.function_name }
  alarm_description   = "Unhandled errors in ${var.name}. Handled 4xx responses do not appear here; this means the function itself failed."
  alarm_actions       = var.alarm_topic_arn == "" ? [] : [var.alarm_topic_arn]
  tags = merge(
    var.tags,
    local.name_tag_prefix == "" ? {} : { Name = "${local.name_tag_prefix}-${local.resource_id}-errors" },
  )
}

resource "aws_cloudwatch_metric_alarm" "throttles" {
  alarm_name          = "${var.name}-throttles"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  threshold           = 0
  period              = 300
  statistic           = "Sum"
  namespace           = "AWS/Lambda"
  metric_name         = "Throttles"
  treat_missing_data  = "notBreaching"
  dimensions          = { FunctionName = aws_lambda_function.this.function_name }
  alarm_description   = "${var.name} is being throttled: either reserved concurrency is too low or the account limit is exhausted."
  alarm_actions       = var.alarm_topic_arn == "" ? [] : [var.alarm_topic_arn]
  tags = merge(
    var.tags,
    local.name_tag_prefix == "" ? {} : { Name = "${local.name_tag_prefix}-${local.resource_id}-throttles" },
  )
}

# Fires while requests still succeed, which is the point: a function sitting at
# 90% of its timeout is one slow query away from 504s.
resource "aws_cloudwatch_metric_alarm" "duration" {
  alarm_name          = "${var.name}-duration-near-timeout"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 3
  threshold           = var.timeout * 1000 * 0.9
  period              = 300
  extended_statistic  = "p95"
  namespace           = "AWS/Lambda"
  metric_name         = "Duration"
  treat_missing_data  = "notBreaching"
  dimensions          = { FunctionName = aws_lambda_function.this.function_name }
  alarm_description   = "p95 duration of ${var.name} is within 10% of its ${var.timeout}s timeout."
  alarm_actions       = var.alarm_topic_arn == "" ? [] : [var.alarm_topic_arn]
  tags = merge(
    var.tags,
    local.name_tag_prefix == "" ? {} : { Name = "${local.name_tag_prefix}-${local.resource_id}-duration" },
  )
}
