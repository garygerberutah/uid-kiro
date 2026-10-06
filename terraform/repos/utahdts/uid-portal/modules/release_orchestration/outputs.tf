output "release_state_machine_arn" {
  value = aws_sfn_state_machine.release.id
}
output "health_state_machine_arn" {
  value = aws_sfn_state_machine.health.id
}
output "evidence_activity_arn" {
  value = aws_sfn_activity.evidence.id
}
output "validator_version_arn" {
  value = aws_lambda_function.validator.qualified_arn
}
output "reviewed_invoke_policy_inputs" {
  description = "Inputs for State-reviewed managed policies; this module never creates IAM grants."
  value = {
    release = { Action = "lambda:InvokeFunction", Resource = aws_lambda_function.validator.qualified_arn }
    health  = { Action = "lambda:InvokeFunction", Resource = var.probe_version_arn }
  }
}

output "validator_ingress" {
  description = "Exact coordinator function version and reviewed role for the ingress audit."
  value = {
    version_arn = aws_lambda_function.validator.qualified_arn
    role_arn    = var.validator_role_arn
  }
}
