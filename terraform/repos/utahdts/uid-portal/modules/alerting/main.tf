# ---------------------------------------------------------------------------
# Alarm destinations and the shared dead-letter queue.
#
# This is deliberately separate from the observability module. API, Lambda and
# Scheduler alarms all need the topic ARN, while the observability dashboards
# and metric filters need the API and Lambda resources. Keeping the destination
# in a small foundation module makes that dependency one-way instead of forming
# an observability <-> workload cycle.
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

resource "aws_sns_topic" "alerts" {
  name = "${var.name_prefix}-alerts"
  # CloudWatch alarms are an AWS-service publisher. The AWS-managed SNS key
  # already permits that path; reusing an application CMK would require a key
  # policy this stack does not own and can silently break alarm delivery.
  kms_master_key_id = "alias/aws/sns"
  tags = merge(
    var.tags,
    local.name_tag_prefix == "" ? {} : { Name = "${local.name_tag_prefix}-alerts" },
  )
}

# An alarm without a subscriber still records useful history, so this remains
# a check warning rather than preventing the infrastructure from being built.
# The warning makes the missing last mile explicit at plan time.
check "alerts_reach_somebody" {
  assert {
    condition     = length(var.alert_emails) > 0
    error_message = "${var.name_prefix}: alarms publish to the ${var.name_prefix}-alerts topic and nothing subscribes to it, so no alarm will reach a person. Set alert_emails in this environment's tfvars. Recorded as D-008."
  }
}

resource "aws_sns_topic_subscription" "email" {
  for_each = toset(var.alert_emails)

  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = each.value
}

# Shared by Lambda's asynchronous failure handling and EventBridge Scheduler.
# Writers are granted explicitly in the IAM and scheduling modules; naming a
# queue in dead_letter_config does not grant sqs:SendMessage by itself.
resource "aws_sqs_queue" "dlq" {
  name                      = "${var.name_prefix}-dlq"
  message_retention_seconds = 1209600 # 14 days, the maximum
  sqs_managed_sse_enabled   = true
  tags = merge(
    var.tags,
    local.name_tag_prefix == "" ? {} : { Name = "${local.name_tag_prefix}-dlq" },
  )
}
