mock_provider "aws" {
  override_during = plan
  mock_resource "aws_scheduler_schedule_group" {
    defaults = { arn = "arn:aws:scheduler:us-west-2:705157108110:schedule-group/uid-portal-at" }
  }
}

variables {
  name_prefix              = "uid-portal-at"
  account_id               = "705157108110"
  permissions_boundary_arn = "arn:aws:iam::705157108110:policy/uid-insureu-at-runtime-scheduler"
  schedules                = {}
}

run "attach_scheduler_boundary" {
  command = plan
  assert {
    condition     = aws_iam_role.scheduler.permissions_boundary == var.permissions_boundary_arn
    error_message = "The scheduler must have its own bootstrap-owned boundary."
  }
  assert {
    condition     = output.permissions_boundary_review.document == aws_iam_role_policy.scheduler_invoke.policy
    error_message = "The review document must match the scheduler's existing capabilities."
  }
}

run "reject_missing_boundary" {
  command = plan
  variables { permissions_boundary_arn = null }
  expect_failures = [aws_iam_role.scheduler]
}

run "reject_wrong_boundary" {
  command = plan
  variables { permissions_boundary_arn = "arn:aws:iam::705157108110:policy/uid-insureu-at-runtime-public" }
  expect_failures = [var.permissions_boundary_arn]
}

run "reject_cross_account_boundary" {
  command = plan
  variables { permissions_boundary_arn = "arn:aws:iam::000000000000:policy/uid-insureu-at-runtime-scheduler" }
  expect_failures = [var.permissions_boundary_arn]
}

run "preserve_other_environments" {
  command = plan
  variables {
    name_prefix              = "uid-portal-prod"
    permissions_boundary_arn = null
  }
  assert {
    condition     = aws_iam_role.scheduler.permissions_boundary == null
    error_message = "The AT-only change must not attach boundaries in other environments."
  }
}
