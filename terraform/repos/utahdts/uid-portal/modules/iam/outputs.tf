output "role_arns" {
  value = { for k, r in aws_iam_role.this : k => r.arn }
}

# Review material only. Application Terraform must never own these policies.
# Build each cap from that profile's existing policy documents, not a union of
# all profiles: the public execution role must not gain database or S3 access.
output "permissions_boundary_review" {
  value = {
    for profile in local.roles : profile => {
      role_name  = "${var.name_prefix}-${profile}"
      policy_arn = lookup(var.permissions_boundary_arns, profile, null)
      document = jsonencode({
        Version = "2012-10-17"
        Statement = concat(
          jsondecode(data.aws_iam_policy_document.logs.json).Statement,
          var.role_profiles[profile].vpc_access ? jsondecode(data.aws_iam_policy_document.vpc.json).Statement : [],
          [{
            Sid    = "RuntimeXray"
            Effect = "Allow"
            # Matches AWSXRayDaemonWriteAccess v2. Do not inherit future
            # managed-policy expansion without a new bootstrap policy review.
            Action = [
              "xray:PutTraceSegments", "xray:PutTelemetryRecords",
              "xray:GetSamplingRules", "xray:GetSamplingTargets",
              "xray:GetSamplingStatisticSummaries",
            ]
            Resource = ["*"]
          }],
          try(jsondecode(data.aws_iam_policy_document.secrets[profile].json).Statement, []),
          try(jsondecode(data.aws_iam_policy_document.secret_kms[profile].json).Statement, []),
          try(jsondecode(data.aws_iam_policy_document.encrypted_data[profile].json).Statement, []),
          try(jsondecode(data.aws_iam_policy_document.buckets[profile].json).Statement, []),
          try(jsondecode(data.aws_iam_policy_document.invoke[profile].json).Statement, []),
          try(jsondecode(data.aws_iam_policy_document.dead_letter[profile].json).Statement, []),
        )
      })
    }
  }
}
