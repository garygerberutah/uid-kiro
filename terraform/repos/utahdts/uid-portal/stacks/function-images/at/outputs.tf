output "repository_url" {
  description = "Push images here, then record repository_url@sha256:<digest> in envs/at function_image_uris."
  value       = aws_ecr_repository.functions.repository_url
}

output "image_function_ids" {
  description = "Manifest functions allowed to pull from this repository."
  value       = local.image_function_ids
}
