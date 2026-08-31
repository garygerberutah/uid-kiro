output "api_id" { value = aws_apigatewayv2_api.this.id }
output "api_name" { value = aws_apigatewayv2_api.this.name }
output "custom_domain_url" {
  description = "Custom hostname only when Terraform actually publishes its API mapping."
  value       = local.publish_domain ? "https://${var.domain_name}" : null
}
output "custom_domain_target" {
  description = "Regional API Gateway target read from the managed or externally owned custom domain; it is not a browser URL."
  value = local.publish_domain ? (
    var.domain_ownership == "managed"
    ? aws_apigatewayv2_domain_name.this[0].domain_name_configuration[0].target_domain_name
    : data.aws_api_gateway_domain_name.external[0].regional_domain_name
  ) : null
}
output "execution_arn" { value = aws_apigatewayv2_api.this.execution_arn }
output "stage_arn" { value = aws_apigatewayv2_stage.default.arn }
output "authorizer_id" { value = aws_apigatewayv2_authorizer.this.id }
output "invoke_url" {
  value = local.publish_domain ? "https://${var.domain_name}" : null
}
output "routes" {
  description = "Route keys actually created, for the smoke test to iterate."
  value       = [for id, r in local.deployed_routes : "${r.method} ${r.path}"]
}
