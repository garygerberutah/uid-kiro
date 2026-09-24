# ---------------------------------------------------------------------------
# The SPA rewrite function for the portal's multi-tenant CloudFront
# distribution.
#
# **This stack creates a function; it does not attach one.** The distributions
# are not managed by this repository -- neither the one serving
# insureu.uid-dev.utah.gov today nor the multi-tenant one that will replace it
# -- so attaching this is a change to infrastructure this Terraform does not
# own. Same arrangement as the neighbouring cdn-headers stack, and the same
# reason. See D-018.
#
# A CloudFront function is inert until a cache behaviour references it, so
# creating one changes nothing that is serving traffic. After this is applied,
# give the output ARN to the CloudFront owner, who attaches it to the default
# cache behaviour through the distribution's own workflow. Never import or
# update a distribution from this repository.
#
# Why a second function rather than importing `uid-portal-at-spa-rewrite`:
# that one exists, was created outside Terraform, and is attached to the live
# distribution. Adopting it would put a resource serving production-adjacent
# traffic into this state as the first act of owning it. A separate function
# for the new distribution leaves the live path untouched until DNS moves, and
# leaves a working rollback in place after it does.
#
# The two are deliberately identical in behaviour. Cutover should change where
# traffic goes and nothing about what it gets back.
# ---------------------------------------------------------------------------

terraform {
  required_version = ">= 1.6"
  required_providers {
    aws = { source = "hashicorp/aws", version = ">= 5.40, < 7.0" }
  }
}

provider "aws" {
  region = var.region

  skip_credentials_validation = var.offline_provider_validation
  skip_requesting_account_id  = var.offline_provider_validation
  skip_metadata_api_check     = var.offline_provider_validation
}

variable "region" {
  description = "AWS region used when this independently applied configuration is run as a root."
  type        = string
  default     = "us-west-2"
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

variable "name" {
  description = <<-EOT
    Function name, e.g. uid-portal-at-tenant-spa-rewrite. It must not be the
    name of a function that already exists: this stack creates, and a collision
    fails the apply rather than adopting whatever is there.
  EOT
  type        = string

  validation {
    condition     = var.name != "uid-portal-at-spa-rewrite"
    error_message = "That function already exists and is attached to the live distribution; choose a name this stack can create."
  }
}

variable "publish" {
  description = "Publish to the LIVE stage. A cache behaviour can only reference a published function."
  type        = bool
  default     = true
}

resource "aws_cloudfront_function" "spa_rewrite" {
  name    = var.name
  runtime = "cloudfront-js-2.0"
  publish = var.publish
  comment = "Rewrite extensionless UID Portal SPA routes to index.html. Default cache behaviour only."

  # Read from a file rather than inlined, so it can be reviewed and tested as
  # source. `ui/test/cloudfront/spaRewrite.test.js` executes this exact file.
  code = file("${path.module}/spa-rewrite.js")
}

output "function_arn" {
  description = "Give this to the CloudFront owner to attach as a viewer-request function on the default cache behaviour."
  value       = aws_cloudfront_function.spa_rewrite.arn
}

output "function_name" {
  value = aws_cloudfront_function.spa_rewrite.name
}
