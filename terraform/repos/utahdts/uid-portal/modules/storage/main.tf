# ---------------------------------------------------------------------------
# S3 buckets for the SIFE file exchange and async job artifacts.
#
# Three buckets rather than three prefixes in one, because they have genuinely
# different lifecycles and different readers:
#
#   uploads    files entering the exchange. Written by conditional presigned
#              PUT from the browser, read by the zip Lambda. Retention follows the SIFE
#              rules already encoded in sife_file_details.sch_delete_date.
#   downloads  generated zip bundles. Disposable; expire quickly.
#   artifacts  async job output (reports). Disposable; expire with the job.
#
# All three are private, encrypted, versioned and TLS-only. The uploads bucket
# additionally needs CORS, because the browser PUTs to it directly -- that is
# the whole point of the presigned upload flow.
#
# Adopting buckets that already exist
# -----------------------------------
# SIFE has been running on Elastic Beanstalk for years, so its uploads and
# downloads buckets already exist and already hold files. Creating new ones at
# cutover would strand every file the exchange is currently carrying: the new
# API would look in an empty bucket and report nothing waiting, without erroring.
#
# So any bucket named in var.existing_bucket_names is looked up instead of
# created. An adopted bucket's configuration is deliberately left alone --
# versioning, encryption, lifecycle and the TLS-only policy are applied only to
# buckets this module owns. Rewriting the settings on a bucket another team
# manages is not this module's business, and a lifecycle rule applied by
# surprise to live SIFE files would delete them.
# ---------------------------------------------------------------------------

terraform {
  required_version = ">= 1.6"
  required_providers {
    aws = { source = "hashicorp/aws", version = ">= 5.40, < 7.0" }
  }
}

locals {
  buckets = {
    uploads   = var.upload_bucket_name
    downloads = var.download_bucket_name
    artifacts = var.artifact_bucket_name
  }

  adopted = { for k, v in var.existing_bucket_names : k => v if v != "" }
  created = { for k, v in local.buckets : k => v if !contains(keys(local.adopted), k) }

  # Everything downstream reads these rather than the resource directly, so a
  # bucket can move between created and adopted without touching a policy.
  bucket_ids = merge(
    { for k, b in aws_s3_bucket.this : k => b.id },
    { for k, b in data.aws_s3_bucket.adopted : k => b.id },
  )

  bucket_arns = merge(
    { for k, b in aws_s3_bucket.this : k => b.arn },
    { for k, b in data.aws_s3_bucket.adopted : k => b.arn },
  )
}

resource "aws_s3_bucket" "this" {
  for_each = local.created
  bucket   = each.value
  tags = merge(
    var.tags,
    { Purpose = each.key },
    lookup(var.tags, "Name", "") == "" ? {} : { Name = "${var.tags["Name"]}-${each.key}" },
  )
}

data "aws_s3_bucket" "adopted" {
  for_each = local.adopted
  bucket   = each.value
}

# Older revisions optionally placed an adopted uploads bucket's CORS document
# under this state address. Relinquish that ownership without calling S3. The
# State resource owner must preserve or add the browser CORS rule out of band.
removed {
  from = aws_s3_bucket_cors_configuration.uploads

  lifecycle {
    destroy = false
  }
}

resource "aws_s3_bucket_public_access_block" "this" {
  for_each = aws_s3_bucket.this

  bucket                  = each.value.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "this" {
  for_each = aws_s3_bucket.this

  bucket = each.value.id
  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "this" {
  for_each = aws_s3_bucket.this

  bucket = each.value.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = var.kms_key_arn == null ? "AES256" : "aws:kms"
      kms_master_key_id = var.kms_key_arn
    }
    # Without this, a KMS-encrypted bucket makes one KMS call per object
    # operation. SIFE moves many objects; the cost difference is real.
    bucket_key_enabled = var.kms_key_arn != null
  }
}

# Versioning is what makes an accidental overwrite or delete recoverable. It is
# on for uploads in particular because those are the files the exchange exists
# to carry, and there is no other copy.
resource "aws_s3_bucket_versioning" "this" {
  for_each = aws_s3_bucket.this

  bucket = each.value.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "uploads" {
  # Never applied to an adopted bucket: SIFE retention is governed by
  # sife_file_details.sch_delete_date, and an expiry rule imposed here would
  # delete live files on a schedule nobody agreed to.
  count = contains(keys(local.created), "uploads") ? 1 : 0

  bucket     = aws_s3_bucket.this["uploads"].id
  depends_on = [aws_s3_bucket_versioning.this]

  rule {
    id     = "expire-noncurrent"
    status = "Enabled"
    filter {}
    noncurrent_version_expiration {
      noncurrent_days = var.noncurrent_version_days
    }
  }

  rule {
    id     = "abort-incomplete-multipart"
    status = "Enabled"
    filter {}
    abort_incomplete_multipart_upload {
      # A browser that abandons a large upload leaves parts that are billed
      # but invisible in the console. Nothing else cleans these up.
      days_after_initiation = 7
    }
  }
}

# Bundles and reports are derived data: both can be regenerated, so neither
# needs to outlive the link that points at it.
resource "aws_s3_bucket_lifecycle_configuration" "ephemeral" {
  for_each   = setintersection(toset(["downloads", "artifacts"]), toset(keys(local.created)))
  bucket     = aws_s3_bucket.this[each.value].id
  depends_on = [aws_s3_bucket_versioning.this]

  rule {
    id     = "expire-generated-objects"
    status = "Enabled"
    filter {}
    expiration {
      days = var.generated_object_days
    }
    noncurrent_version_expiration {
      noncurrent_days = 1
    }
    abort_incomplete_multipart_upload {
      days_after_initiation = 1
    }
  }
}

# The browser sends a conditional PUT directly here using the presigned URL from
# /portal/sife/upload/init, so the bucket needs its own CORS rules; the ones on
# API Gateway do not apply to a request that never reaches the API.
resource "aws_s3_bucket_cors_configuration" "owned_uploads" {
  # Never apply configuration to an adopted bucket. CORS is a single replace-
  # all document, so even an apparently additive change would overwrite State-
  # owned policy. A missing rule is an owner prerequisite, not an exception.
  count  = contains(keys(local.created), "uploads") ? 1 : 0
  bucket = aws_s3_bucket.this["uploads"].id

  cors_rule {
    allowed_headers = ["*"]
    allowed_methods = ["PUT", "POST", "GET", "HEAD"]
    allowed_origins = var.browser_origins
    expose_headers  = ["ETag", "x-amz-request-id"]
    max_age_seconds = 3000
  }
}

# Deny anything that is not TLS. S3 accepts plaintext HTTP by default, and a
# presigned URL works just as well over it.
resource "aws_s3_bucket_policy" "tls_only" {
  # Created buckets only. A bucket policy is a single document, so writing one
  # onto an adopted bucket would silently discard whatever policy it already
  # carries -- possibly the grant that lets Beanstalk read it.
  for_each = aws_s3_bucket.this
  bucket   = each.value.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "DenyInsecureTransport"
      Effect    = "Deny"
      Principal = "*"
      Action    = "s3:*"
      Resource = [
        each.value.arn,
        "${each.value.arn}/*",
      ]
      Condition = {
        Bool = { "aws:SecureTransport" = "false" }
      }
    }]
  })
}
