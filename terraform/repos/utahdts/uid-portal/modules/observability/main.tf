# ---------------------------------------------------------------------------
# Alarm routing, log-derived metrics and a dashboard.
#
# The Elastic Beanstalk application wrote to /var/log/portal-api.log on each
# instance, which meant diagnosing an incident began with working out which
# instance served the request. Structured JSON in CloudWatch plus the metric
# filters below replace that: the questions operators actually ask -- "is the
# authorizer failing?", "are we rejecting everyone?" -- are answered by a
# metric with an alarm on it rather than by grep over an instance.
# ---------------------------------------------------------------------------

terraform {
  required_version = ">= 1.6"
  required_providers {
    aws = { source = "hashicorp/aws", version = ">= 5.40, < 7.0" }
  }
}

locals {
  name_tag_prefix = lookup(var.tags, "Name", "")
}

resource "aws_cloudwatch_metric_alarm" "dlq_not_empty" {
  alarm_name          = "${var.name_prefix}-dlq-not-empty"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  threshold           = 0
  period              = 300
  statistic           = "Maximum"
  namespace           = "AWS/SQS"
  metric_name         = "ApproximateNumberOfMessagesVisible"
  treat_missing_data  = "notBreaching"
  dimensions          = { QueueName = var.dead_letter_queue_name }
  alarm_description   = "Asynchronous work has failed all retries and is sitting in the dead-letter queue."
  alarm_actions       = var.alert_topic_arn == "" ? [] : [var.alert_topic_arn]
  tags = merge(
    var.tags,
    local.name_tag_prefix == "" ? {} : { Name = "${local.name_tag_prefix}-dlq-not-empty" },
  )
}

# --- log-derived metrics ---------------------------------------------------

# The authorizer denies for two very different reasons: a bad token (routine)
# and an unreachable database or IdP (an outage). The handler logs them under
# distinct messages precisely so they can be told apart here.
resource "aws_cloudwatch_log_metric_filter" "auth_dependency_failure" {
  for_each = var.authorizer_log_groups

  name           = "${var.name_prefix}-auth-dependency-failure"
  log_group_name = each.value
  pattern        = "{ $.msg = \"auth.dependency_failure\" }"

  metric_transformation {
    name          = "AuthorizerDependencyFailure"
    namespace     = var.metric_namespace
    value         = "1"
    default_value = "0"
    unit          = "Count"
  }
}

resource "aws_cloudwatch_metric_alarm" "auth_dependency_failure" {
  count = length(var.authorizer_log_groups) == 0 ? 0 : 1

  alarm_name          = "${var.name_prefix}-authorizer-dependency-failure"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  threshold           = 0
  period              = 300
  statistic           = "Sum"
  namespace           = var.metric_namespace
  metric_name         = "AuthorizerDependencyFailure"
  treat_missing_data  = "notBreaching"
  alarm_description   = "The authorizer is denying requests because the database or the identity provider is unreachable. Every authenticated route is down."
  alarm_actions       = var.alert_topic_arn == "" ? [] : [var.alert_topic_arn]
  tags = merge(
    var.tags,
    local.name_tag_prefix == "" ? {} : { Name = "${local.name_tag_prefix}-authorizer-dependency-failure" },
  )
}

resource "aws_cloudwatch_log_metric_filter" "unhandled" {
  for_each = var.handler_log_groups

  name           = "${var.name_prefix}-unhandled-${replace(each.value, "/", "-")}"
  log_group_name = each.value
  pattern        = "{ $.msg = \"request.unhandled\" }"

  metric_transformation {
    name          = "UnhandledExceptions"
    namespace     = var.metric_namespace
    value         = "1"
    default_value = "0"
    unit          = "Count"
  }
}

# shared.http converts an unhandled exception into a structured 500 response,
# so Lambda's native Errors metric remains zero. The log-derived metric is the
# only signal for that failure mode and therefore needs its own alarm.
resource "aws_cloudwatch_metric_alarm" "unhandled" {
  count = length(var.handler_log_groups) == 0 ? 0 : 1

  alarm_name          = "${var.name_prefix}-unhandled-exceptions"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  threshold           = 0
  period              = 300
  statistic           = "Sum"
  namespace           = var.metric_namespace
  metric_name         = "UnhandledExceptions"
  treat_missing_data  = "notBreaching"
  alarm_description   = "A handler caught an unhandled exception and returned a 500 response."
  alarm_actions       = var.alert_topic_arn == "" ? [] : [var.alert_topic_arn]
  tags = merge(
    var.tags,
    local.name_tag_prefix == "" ? {} : { Name = "${local.name_tag_prefix}-unhandled-exceptions" },
  )
}

# The report worker records a failed job in application state and returns a
# normal Lambda response. That is useful to its caller, but it means Lambda's
# native Errors metric and asynchronous DLQ never see this failure mode.
resource "aws_cloudwatch_log_metric_filter" "report_worker_failure" {
  for_each = var.report_worker_log_groups

  name           = "${var.name_prefix}-report-worker-failure-${replace(each.value, "/", "-")}"
  log_group_name = each.value
  pattern        = "{ ($.msg = \"report.worker.failed\") || ($.msg = \"report.worker.job_missing\") }"

  metric_transformation {
    name          = "ReportWorkerFailures"
    namespace     = var.metric_namespace
    value         = "1"
    default_value = "0"
    unit          = "Count"
  }
}

resource "aws_cloudwatch_metric_alarm" "report_worker_failure" {
  count = length(var.report_worker_log_groups) == 0 ? 0 : 1

  alarm_name          = "${var.name_prefix}-report-worker-failures"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  threshold           = 0
  period              = 300
  statistic           = "Sum"
  namespace           = var.metric_namespace
  metric_name         = "ReportWorkerFailures"
  treat_missing_data  = "notBreaching"
  alarm_description   = "A report worker caught a job failure that is invisible to Lambda Errors and the DLQ."
  alarm_actions       = var.alert_topic_arn == "" ? [] : [var.alert_topic_arn]
  tags = merge(
    var.tags,
    local.name_tag_prefix == "" ? {} : { Name = "${local.name_tag_prefix}-report-worker-failures" },
  )
}

# The notification job intentionally continues after one recipient fails so
# the remaining recipients still receive mail. Surface those partial failures
# even though the overall invocation succeeds.
resource "aws_cloudwatch_log_metric_filter" "notification_send_failure" {
  for_each = var.notification_log_groups

  name           = "${var.name_prefix}-notification-send-failure-${replace(each.value, "/", "-")}"
  log_group_name = each.value
  pattern        = "{ $.msg = \"sife.notify.send_failed\" }"

  metric_transformation {
    name          = "NotificationSendFailures"
    namespace     = var.metric_namespace
    value         = "1"
    default_value = "0"
    unit          = "Count"
  }
}

resource "aws_cloudwatch_metric_alarm" "notification_send_failure" {
  count = length(var.notification_log_groups) == 0 ? 0 : 1

  alarm_name          = "${var.name_prefix}-notification-send-failures"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  threshold           = 0
  period              = 300
  statistic           = "Sum"
  namespace           = var.metric_namespace
  metric_name         = "NotificationSendFailures"
  treat_missing_data  = "notBreaching"
  alarm_description   = "The SIFE notification job could not send to one or more recipients."
  alarm_actions       = var.alert_topic_arn == "" ? [] : [var.alert_topic_arn]
  tags = merge(
    var.tags,
    local.name_tag_prefix == "" ? {} : { Name = "${local.name_tag_prefix}-notification-send-failures" },
  )
}

# The fast-sync watchdog deliberately reports a degraded success when Oracle
# monitoring fails after the non-idempotent PostgreSQL sync is still safe to
# run. Lambda Errors therefore remains healthy; this log metric is the alerting
# path for the lost watchdog signal.
resource "aws_cloudwatch_log_metric_filter" "licensee_sync_watchdog_failure" {
  for_each = var.licensee_sync_log_groups

  name           = "${var.name_prefix}-licensee-sync-watchdog-failure-${replace(each.value, "/", "-")}"
  log_group_name = each.value
  pattern        = "{ $.msg = \"licensee.sync.watchdog_failed\" }"

  metric_transformation {
    name          = "LicenseeSyncWatchdogFailures"
    namespace     = var.metric_namespace
    value         = "1"
    default_value = "0"
    unit          = "Count"
  }
}

resource "aws_cloudwatch_metric_alarm" "licensee_sync_watchdog_failure" {
  count = length(var.licensee_sync_log_groups) == 0 ? 0 : 1

  alarm_name          = "${var.name_prefix}-licensee-sync-watchdog-failures"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  threshold           = 0
  period              = 300
  statistic           = "Sum"
  namespace           = var.metric_namespace
  metric_name         = "LicenseeSyncWatchdogFailures"
  treat_missing_data  = "notBreaching"
  alarm_description   = "The licensee fast sync completed without a working Oracle refresh watchdog."
  alarm_actions       = var.alert_topic_arn == "" ? [] : [var.alert_topic_arn]
  tags = merge(
    var.tags,
    local.name_tag_prefix == "" ? {} : { Name = "${local.name_tag_prefix}-licensee-sync-watchdog-failures" },
  )
}

# --- dashboard -------------------------------------------------------------

resource "aws_cloudwatch_dashboard" "this" {
  dashboard_name = var.name_prefix

  dashboard_body = jsonencode({
    widgets = [
      {
        type = "text", x = 0, y = 0, width = 24, height = 2,
        properties = {
          markdown = join("\n", [
            "# UID Portal API -- ${var.name_prefix}",
            "API Gateway HTTP APIs, Python 3.13 Lambdas, Aurora PostgreSQL via RDS Proxy.",
            "Runbook: `docs/apigw-migration/04-runbook.md` / Alerts: `${var.alert_topic_name}`",
          ])
        }
      },
      {
        type = "metric", x = 0, y = 2, width = 12, height = 6,
        properties = {
          title  = "Requests and errors by API"
          region = var.region
          view   = "timeSeries"
          stat   = "Sum"
          period = 300
          # concat with expansion removes only the per-API grouping. flatten()
          # would recursively turn each CloudWatch metric row into scalars.
          metrics = concat([], [
            for id in var.api_ids : [
              ["AWS/ApiGateway", "Count", "ApiId", id],
              [".", "4xx", ".", "."],
              [".", "5xx", ".", "."],
            ]
          ]...)
        }
      },
      {
        type = "metric", x = 12, y = 2, width = 12, height = 6,
        properties = {
          title  = "Latency (p50 / p95 / p99)"
          region = var.region
          view   = "timeSeries"
          period = 300
          metrics = concat([], [
            for id in var.api_ids : [
              ["AWS/ApiGateway", "Latency", "ApiId", id, { stat = "p50" }],
              ["...", { stat = "p95" }],
              ["...", { stat = "p99" }],
            ]
          ]...)
        }
      },
      {
        type = "metric", x = 0, y = 8, width = 12, height = 6,
        properties = {
          title  = "Authorizer -- the critical path for every protected route"
          region = var.region
          view   = "timeSeries"
          period = 300
          metrics = concat(
            [for fn in var.authorizer_function_names : ["AWS/Lambda", "Duration", "FunctionName", fn, { stat = "p95" }]],
            [for fn in var.authorizer_function_names : ["AWS/Lambda", "Errors", "FunctionName", fn, { stat = "Sum" }]],
            [[var.metric_namespace, "AuthorizerDependencyFailure", { stat = "Sum", label = "Dependency failures" }]],
          )
        }
      },
      {
        type = "metric", x = 12, y = 8, width = 12, height = 6,
        properties = {
          title  = "Unhandled exceptions and concurrency"
          region = var.region
          view   = "timeSeries"
          period = 300
          metrics = [
            [var.metric_namespace, "UnhandledExceptions", { stat = "Sum" }],
            ["AWS/Lambda", "ConcurrentExecutions", { stat = "Maximum" }],
            ["AWS/Lambda", "Throttles", { stat = "Sum" }],
          ]
        }
      },
      {
        type = "log", x = 0, y = 14, width = 24, height = 6,
        properties = {
          title  = "Recent failures"
          region = var.region
          query = join(" ", [
            "SOURCE logGroups(namePrefix: ['/aws/lambda/${var.name_prefix}-'])",
            "| fields @timestamp, requestId, route, status, code, detail",
            "| filter level in ['ERROR','WARNING']",
            "| sort @timestamp desc",
            "| limit 50",
          ])
        }
      },
    ]
  })
}
