# Read from the merged maps rather than the resource, so a bucket that moves
# between created and adopted does not change what any consumer sees.

output "upload_bucket" {
  value = local.bucket_ids["uploads"]
}

output "download_bucket" {
  value = local.bucket_ids["downloads"]
}

output "artifact_bucket" {
  value = local.bucket_ids["artifacts"]
}

output "bucket_arns" {
  value = local.bucket_arns
}

output "all_object_arns" {
  description = "Convenience for IAM policy documents."
  value       = [for arn in values(local.bucket_arns) : "${arn}/*"]
}

output "adopted_buckets" {
  description = "Buckets used but not managed here. Their settings are somebody else's."
  value       = keys(local.adopted)
}
