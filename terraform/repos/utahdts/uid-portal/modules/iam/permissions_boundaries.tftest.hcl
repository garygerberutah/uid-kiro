mock_provider "aws" {
  override_during = plan
  mock_data "aws_iam_policy_document" {
    defaults = { json = "{\"Version\":\"2012-10-17\",\"Statement\":[]}" }
  }
}

variables {
  name_prefix           = "uid-portal-at"
  account_id            = "705157108110"
  region                = "us-west-2"
  dead_letter_queue_arn = "arn:aws:sqs:us-west-2:705157108110:test-dlq"
  role_profiles = {
    public = {
      secret_arns       = [], secret_kms_key_arns = [], data_kms_actions = [],
      data_kms_key_arns = [], s3_statements = [], invokable_function_arns = [],
      write_dead_letter = false, vpc_access = false
    }
    portal_database = {
      secret_arns         = ["arn:aws:secretsmanager:us-west-2:705157108110:secret:test-db-abcdef"],
      secret_kms_key_arns = [], data_kms_actions = [], data_kms_key_arns = [],
      s3_statements       = [], invokable_function_arns = [],
      write_dead_letter   = false, vpc_access = true
    }
  }
  permissions_boundary_arns = {
    public          = "arn:aws:iam::705157108110:policy/uid-insureu-at-runtime-public"
    portal_database = "arn:aws:iam::705157108110:policy/uid-insureu-at-runtime-portal_database"
  }
}

override_data {
  target = data.aws_iam_policy_document.secrets["portal_database"]
  values = {
    json = "{\"Statement\":[{\"Effect\":\"Allow\",\"Action\":[\"secretsmanager:GetSecretValue\"],\"Resource\":[\"arn:aws:secretsmanager:us-west-2:705157108110:secret:test-db-abcdef\"]}]}"
  }
}

run "attach_each_profile_boundary" {
  command = plan
  assert {
    condition = alltrue([
      for profile, role in aws_iam_role.this :
      role.permissions_boundary == var.permissions_boundary_arns[profile]
    ])
    error_message = "Each execution role must use its own independently owned cap."
  }
  assert {
    condition = (
      !strcontains(output.permissions_boundary_review["public"].document, "secretsmanager:") &&
      strcontains(output.permissions_boundary_review["portal_database"].document, "secretsmanager:GetSecretValue")
    )
    error_message = "The public cap must not inherit another profile's secret access."
  }
}

run "reject_missing_boundary" {
  command = plan
  variables { permissions_boundary_arns = {} }
  expect_failures = [aws_iam_role.this]
}

run "reject_cross_profile_boundary" {
  command = plan
  variables {
    permissions_boundary_arns = {
      public          = "arn:aws:iam::705157108110:policy/uid-insureu-at-runtime-portal_database"
      portal_database = "arn:aws:iam::705157108110:policy/uid-insureu-at-runtime-portal_database"
    }
  }
  expect_failures = [var.permissions_boundary_arns]
}

run "reject_cross_account_boundary" {
  command = plan
  variables {
    permissions_boundary_arns = {
      public          = "arn:aws:iam::000000000000:policy/uid-insureu-at-runtime-public"
      portal_database = "arn:aws:iam::705157108110:policy/uid-insureu-at-runtime-portal_database"
    }
  }
  expect_failures = [var.permissions_boundary_arns]
}

run "preserve_other_environments" {
  command = plan
  variables {
    name_prefix               = "uid-portal-prod"
    permissions_boundary_arns = {}
  }
  assert {
    condition     = alltrue([for role in aws_iam_role.this : role.permissions_boundary == null])
    error_message = "The AT-only change must not attach boundaries in other environments."
  }
}
