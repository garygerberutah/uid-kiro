# ---------------------------------------------------------------------------
# Security response headers for the portal's CloudFront distribution.
#
# The application already ships a Content-Security-Policy as a <meta> tag,
# generated at build time from the same environment variables it uses. That one
# is real and it applies today. This exists for the two things a meta tag cannot
# do:
#
#   * `frame-ancestors`, which a meta CSP is specified to ignore. Clickjacking
#     protection has to arrive as a header.
#   * Strict-Transport-Security, nosniff and referrer policy, which are not CSP
#     at all.
#
# **This module creates a policy; it does not attach one.** The distribution
# serving insureu.uid.utah.gov is not managed by this repository -- the UI deploy
# workflow syncs to a pre-existing bucket and invalidates a hardcoded id -- so
# attaching it is a change to infrastructure this Terraform does not own. See
# D-018.
#
# After this application-owned policy is separately reviewed and created, give
# its output id and reviewed settings to the State CloudFront owner. Only that
# owner may attach it through the distribution's controlled workflow; never
# import or update the distribution from this repository.
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
  description = "Policy name, e.g. portal-uid-prod-security-headers."
  type        = string
}

variable "content_security_policy" {
  description = <<-EOT
    The policy string. Keep it identical to what src/csp.js generates for this
    environment, plus frame-ancestors. Two policies that disagree do not
    negotiate -- the browser enforces both, so the effective policy is the
    intersection, and a directive present in one and absent from the other
    silently becomes the strictest of the two.
  EOT
  type        = string
}

variable "include_subdomains" {
  description = "HSTS includeSubDomains. False until every subdomain is HTTPS."
  type        = bool
  default     = false
}

resource "aws_cloudfront_response_headers_policy" "security" {
  name    = var.name
  comment = "Security headers for the UID portal UI. Managed by the unassigned cdn-headers stack."

  security_headers_config {
    content_security_policy {
      content_security_policy = var.content_security_policy
      override                = true
    }

    # The reason this module exists: a <meta> CSP cannot set frame-ancestors,
    # so without a header the portal can be framed by anybody.
    frame_options {
      frame_option = "DENY"
      override     = true
    }

    content_type_options {
      override = true
    }

    referrer_policy {
      referrer_policy = "strict-origin-when-cross-origin"
      override        = true
    }

    strict_transport_security {
      access_control_max_age_sec = 31536000
      include_subdomains         = var.include_subdomains
      preload                    = false
      override                   = true
    }
  }
}

output "response_headers_policy_id" {
  description = "Attach to a cache behaviour with response_headers_policy_id."
  value       = aws_cloudfront_response_headers_policy.security.id
}

output "response_headers_policy_name" {
  value = aws_cloudfront_response_headers_policy.security.name
}
