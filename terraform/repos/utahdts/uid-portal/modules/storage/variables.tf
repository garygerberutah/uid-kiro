variable "upload_bucket_name" {
  type = string
}

variable "download_bucket_name" {
  type = string
}

variable "artifact_bucket_name" {
  type = string
}

variable "browser_origins" {
  description = "Origins allowed to PUT directly to the uploads bucket. Must include the portal UI origin for this environment."
  type        = list(string)
}

variable "kms_key_arn" {
  description = "Customer-managed key. Null uses SSE-S3, which is adequate for dev and free."
  type        = string
  default     = null
}

variable "noncurrent_version_days" {
  description = "How long a superseded version of an uploaded file stays recoverable."
  type        = number
  default     = 30
}

variable "generated_object_days" {
  description = "Lifetime of generated bundles and report artifacts."
  type        = number
  default     = 7
}

variable "tags" {
  type    = map(string)
  default = {}
}

variable "existing_bucket_names" {
  description = <<-EOT
    Buckets that already exist and must be used rather than created, keyed by
    role: uploads, downloads, artifacts. A key that is absent or empty means
    this module creates and owns that bucket.

    SIFE's uploads and downloads buckets predate this migration -- the Elastic
    Beanstalk app reads their names from AWS_S3_FILE_UPLOAD_BUCKET and
    AWS_S3_FILE_DOWNLOAD_BUCKET, which are set on the environment and are not in
    this repository. Creating fresh buckets at cutover would leave every file
    currently in the exchange behind, with no error to show for it.
  EOT
  type        = map(string)
  default     = {}

  validation {
    condition     = alltrue([for k in keys(var.existing_bucket_names) : contains(["uploads", "downloads", "artifacts"], k)])
    error_message = "Keys must be uploads, downloads or artifacts."
  }
}
