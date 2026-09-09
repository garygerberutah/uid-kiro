output "schedule_group" {
  value = aws_scheduler_schedule_group.this.name
}

output "schedule_arns" {
  value = { for k, s in aws_scheduler_schedule.this : k => s.arn }
}

output "scheduler_role_arn" {
  value = aws_iam_role.scheduler.arn
}

output "permissions_boundary_review" {
  value = {
    role_name  = "${var.name_prefix}-scheduler"
    policy_arn = var.permissions_boundary_arn
    document   = aws_iam_role_policy.scheduler_invoke.policy
  }
}
