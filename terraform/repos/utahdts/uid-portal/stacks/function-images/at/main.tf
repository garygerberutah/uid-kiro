# ---------------------------------------------------------------------------
# AT function images.
#
# The ECR repository for manifest `package: image` functions. It has its own
# state because it must exist, and hold a pushed image, before envs/at can
# create an image function. envs/at consumes only the digest-pinned image URI
# through function_image_uris.
#
# Images are immutable and scanned on push. Only the exact image functions in
# services/api/routes/routes.yaml may pull, and only through the Lambda
# service. This root creates no network or KMS resource.
# ---------------------------------------------------------------------------

terraform {
  required_version = ">= 1.10, < 2.0"
  required_providers {
    aws = { source = "hashicorp/aws", version = ">= 5.40, < 7.0" }
  }

  backend "s3" {
    bucket       = "uid-portal-tfstate"
    key          = "apigw/at/function-images/terraform.tfstate"
    region       = "us-west-2"
    encrypt      = true
    use_lockfile = true
  }
}

provider "aws" {
  region = "us-west-2"

  allowed_account_ids         = var.offline_provider_validation ? null : ["705157108110"]
  skip_credentials_validation = var.offline_provider_validation
  skip_requesting_account_id  = var.offline_provider_validation
  skip_metadata_api_check     = var.offline_provider_validation

  default_tags {
    tags = local.tags
  }
}

variable "offline_provider_validation" {
  description = "Disable AWS identity and metadata checks only for credential-free terraform init/validate. Never enable for plan or apply."
  type        = bool
  default     = false
}

resource "terraform_data" "reject_offline_provider_validation_in_plans" {
  lifecycle {
    precondition {
      condition     = !var.offline_provider_validation
      error_message = "offline_provider_validation is only for credential-free terraform init/validate; disable it before plan or apply."
    }
  }
}

locals {
  account_id  = "705157108110"
  region      = "us-west-2"
  name_prefix = "uid-portal-at"

  tags = {
    Owner      = "uid-portal"
    CostCenter = "uid"
    app        = "uid-dev-portal-api"
    contact    = "gary gerber"
    dept       = "uid"
    division   = "dts"
    elcid      = "id6901alaa"
    env        = "dev"
    Name       = "uid-dev-function-images"
    security   = "0"
  }

  manifest = yamldecode(file("${path.module}/../../../../../../../../services/api/routes/routes.yaml"))
  image_function_ids = sort(flatten([
    for api in values(local.manifest.apis) : [
      for route in api.routes : route.id if try(route.package, "zip") == "image"
    ]
  ]))
  image_function_arns = [
    for id in local.image_function_ids :
    "arn:aws:lambda:${local.region}:${local.account_id}:function:${local.name_prefix}-${id}"
  ]
}

resource "aws_ecr_repository" "functions" {
  name                 = "${local.name_prefix}-functions"
  image_tag_mutability = "IMMUTABLE"

  image_scanning_configuration {
    scan_on_push = true
  }

  # AWS-managed AES-256. This root never creates or changes a KMS key.
  encryption_configuration {
    encryption_type = "AES256"
  }

  lifecycle {
    # Published Lambda versions pin image digests. Deleting the repository
    # would strand every rollback target.
    prevent_destroy = true

    precondition {
      condition     = length(local.image_function_ids) > 0
      error_message = "The route manifest has no package: image function, so this repository has no consumer."
    }
  }
}

# Lambda pulls a same-account image through the service principal. Scope the
# grant to the exact manifest image functions, not every function in the
# account.
data "aws_iam_policy_document" "lambda_pull" {
  statement {
    sid    = "LambdaPullManifestImageFunctions"
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
    actions = [
      "ecr:BatchGetImage",
      "ecr:GetDownloadUrlForLayer",
    ]
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [local.account_id]
    }
    condition {
      test     = "ArnLike"
      variable = "aws:SourceArn"
      values   = local.image_function_arns
    }
  }
}

resource "aws_ecr_repository_policy" "lambda_pull" {
  repository = aws_ecr_repository.functions.name
  policy     = data.aws_iam_policy_document.lambda_pull.json
}

# Keep enough history to roll back several releases. Published Lambda
# versions reference digests, so expire only well beyond that window.
resource "aws_ecr_lifecycle_policy" "functions" {
  repository = aws_ecr_repository.functions.name
  policy = jsonencode({
    rules = [
      {
        rulePriority = 1
        description  = "Keep the 20 most recent images."
        selection = {
          tagStatus   = "any"
          countType   = "imageCountMoreThan"
          countNumber = 20
        }
        action = { type = "expire" }
      },
    ]
  })
}
