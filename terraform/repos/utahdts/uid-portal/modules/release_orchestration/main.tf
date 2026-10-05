terraform {
  required_version = ">= 1.6"
  required_providers {
    aws = { source = "hashicorp/aws", version = ">= 5.40, < 7.0" }
  }
}

locals {
  name    = "uid-portal-${var.environment}-release"
  account = var.environment == "prod" ? "281669077180" : "705157108110"
}

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

resource "aws_cloudwatch_log_group" "validator" {
  name              = "/aws/lambda/${local.name}-validator"
  retention_in_days = 30
}

resource "aws_lambda_function" "validator" {
  function_name                  = "${local.name}-validator"
  role                           = var.validator_role_arn
  handler                        = "scripts.release_controller.handler"
  runtime                        = "python3.13"
  architectures                  = ["arm64"]
  filename                       = "${var.artifact_directory}/validator.zip"
  source_code_hash               = filebase64sha256("${var.artifact_directory}/validator.zip")
  publish                        = true
  memory_size                    = 256
  timeout                        = 15
  reserved_concurrent_executions = 2
  environment {
    variables = {
      RELEASE_ENVIRONMENT = var.environment
      RELEASE_ACCOUNT     = local.account
    }
  }
  vpc_config {
    subnet_ids         = var.private_subnet_ids
    security_group_ids = var.security_group_ids
  }
  depends_on = [aws_cloudwatch_log_group.validator]
  lifecycle {
    precondition {
      condition     = data.aws_caller_identity.current.account_id == local.account && data.aws_region.current.name == "us-west-2"
      error_message = "The coordinator must use its reviewed environment account in us-west-2."
    }
    precondition {
      condition     = var.environment == "prod" || toset(var.private_subnet_ids) == toset(["subnet-0c6272b1eea00003c", "subnet-0a1e2c8e6751b6833"])
      error_message = "AT must use the two approved private subnet IDs."
    }
    precondition {
      condition = alltrue([
        for arn in [var.validator_role_arn, var.release_role_arn, var.health_role_arn] :
        can(regex("^arn:aws:iam::${local.account}:role/[A-Za-z0-9+=,.@_/-]+$", arn))
      ]) && length(toset([var.validator_role_arn, var.release_role_arn, var.health_role_arn])) == 3
      error_message = "Supply three distinct reviewed account-local roles."
    }
    precondition {
      condition     = can(regex("^arn:aws:lambda:us-west-2:${local.account}:function:uid-portal-${var.environment}-infrastructure_probe:[1-9][0-9]*$", var.probe_version_arn))
      error_message = "Health must invoke a numeric published version of the existing infrastructure probe."
    }
  }
}

resource "aws_sfn_activity" "evidence" {
  name = "${local.name}-evidence-v1"
}

resource "aws_sfn_state_machine" "release" {
  name     = local.name
  role_arn = var.release_role_arn
  type     = "STANDARD"
  definition = templatefile("${var.artifact_directory}/release.asl.json", {
    validator_arn = aws_lambda_function.validator.qualified_arn
    activity_arn  = aws_sfn_activity.evidence.id
  })
  logging_configuration {
    include_execution_data = false
    level                  = "OFF"
  }
}

resource "aws_sfn_state_machine" "health" {
  name     = "${local.name}-health"
  role_arn = var.health_role_arn
  type     = "STANDARD"
  definition = templatefile("${var.artifact_directory}/health.asl.json", {
    probe_arn = var.probe_version_arn
  })
  logging_configuration {
    include_execution_data = false
    level                  = "OFF"
  }
}
