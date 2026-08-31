output "function_name" { value = aws_lambda_function.this.function_name }
output "function_arn" { value = aws_lambda_function.this.arn }
output "invoke_arn" { value = aws_lambda_alias.live.invoke_arn }
output "alias_arn" { value = aws_lambda_alias.live.arn }
output "alias_name" { value = aws_lambda_alias.live.name }
output "log_group" { value = aws_cloudwatch_log_group.this.name }
output "alarm_arns" {
  value = [
    aws_cloudwatch_metric_alarm.errors.arn,
    aws_cloudwatch_metric_alarm.throttles.arn,
    aws_cloudwatch_metric_alarm.duration.arn,
  ]
}
