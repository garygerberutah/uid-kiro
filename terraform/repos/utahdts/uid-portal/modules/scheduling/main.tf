# ---------------------------------------------------------------------------
# EventBridge Scheduler targets for the jobs that were Spring @Scheduled
# methods inside the Elastic Beanstalk application.
#
# The bug this fixes is worth stating plainly: a @Scheduled method runs on
# every instance in the autoscaling group. EventBridge Scheduler gives the job
# one central trigger rather than one trigger per instance. Delivery remains
# at-least-once when Scheduler retries, so handlers must be idempotent.
#
# EventBridge Scheduler rather than a CloudWatch Events rule because it
# supports a real timezone. These jobs are described in Mountain Time and must
# not drift by an hour twice a year.
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

resource "aws_scheduler_schedule_group" "this" {
  name = var.name_prefix
  tags = merge(
    var.tags,
    local.name_tag_prefix == "" ? {} : { Name = "${local.name_tag_prefix}-scheduler-group" },
  )
}

resource "aws_scheduler_schedule" "this" {
  for_each = var.schedules

  name       = "${var.name_prefix}-${each.key}"
  group_name = aws_scheduler_schedule_group.this.name
  state      = each.value.enabled ? "ENABLED" : "DISABLED"

  schedule_expression          = each.value.schedule
  schedule_expression_timezone = each.value.timezone

  # These are maintenance jobs, not user-facing work: letting the scheduler
  # spread them over a window avoids a thundering herd against the database
  # when several fire on the hour.
  flexible_time_window {
    mode                      = "FLEXIBLE"
    maximum_window_in_minutes = 5
  }

  target {
    arn      = each.value.target_arn
    role_arn = aws_iam_role.scheduler.arn

    input = jsonencode({
      source = "eventbridge.scheduler"
      job    = each.key
    })

    retry_policy {
      maximum_retry_attempts       = 2
      maximum_event_age_in_seconds = 3600
    }

    dynamic "dead_letter_config" {
      # Keep block cardinality independent of the queue ARN, which is unknown
      # on a first plan because the queue is created by the same stack.
      for_each = var.dead_letter_enabled ? [1] : []
      content {
        arn = var.dead_letter_arn
      }
    }
  }

  lifecycle {
    precondition {
      condition     = !var.dead_letter_enabled || var.dead_letter_arn != null
      error_message = "dead_letter_arn is required when dead_letter_enabled is true."
    }
  }

  # Scheduler validates the role ARN, not that its policies have propagated.
  # Waiting prevents a newly created schedule from racing its invoke/DLQ grants.
  depends_on = [aws_iam_role_policy.scheduler_invoke]
}

resource "aws_iam_role" "scheduler" {
  name = "${var.name_prefix}-scheduler"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "scheduler.amazonaws.com" }
      Action    = "sts:AssumeRole"
      Condition = {
        # Without this a confused-deputy attack from another account's
        # scheduler could assume the role.
        StringEquals = { "aws:SourceAccount" = var.account_id }
        ArnLike      = { "aws:SourceArn" = aws_scheduler_schedule_group.this.arn }
      }
    }]
  })

  tags = merge(
    var.tags,
    local.name_tag_prefix == "" ? {} : { Name = "${local.name_tag_prefix}-scheduler-role" },
  )
}

resource "aws_iam_role_policy" "scheduler_invoke" {
  name = "invoke-targets"
  role = aws_iam_role.scheduler.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = concat(
      [{
        Sid      = "InvokeTargets"
        Effect   = "Allow"
        Action   = "lambda:InvokeFunction"
        Resource = [for s in var.schedules : s.target_arn]
      }],
      !var.dead_letter_enabled ? [] : [{
        Sid      = "WriteDeadLetterQueue"
        Effect   = "Allow"
        Action   = "sqs:SendMessage"
        Resource = var.dead_letter_arn
      }],
    )
  })
}

# A scheduled job that stops running is silent by nature: nothing fails, work
# simply does not happen. This alarm turns that silence into a page.
resource "aws_cloudwatch_metric_alarm" "not_invoked" {
  for_each = { for k, v in var.schedules : k => v if v.enabled && v.alarm_on_missing }

  alarm_name          = "${var.name_prefix}-${each.key}-not-running"
  comparison_operator = "LessThanThreshold"
  evaluation_periods  = 1
  threshold           = 1
  period              = each.value.expected_interval_seconds
  statistic           = "Sum"
  namespace           = "AWS/Lambda"
  metric_name         = "Invocations"
  treat_missing_data  = "breaching"
  dimensions          = { FunctionName = each.value.function_name }
  alarm_description   = "${each.key} has not run within its expected interval."
  alarm_actions       = var.alarm_topic_arn == "" ? [] : [var.alarm_topic_arn]
  tags = merge(
    var.tags,
    local.name_tag_prefix == "" ? {} : { Name = "${local.name_tag_prefix}-${each.key}-not-running" },
  )
}
