# ---------------------------------------------------------------------------
# dev RDS Proxy.
#
# Separate state from envs/dev on purpose: the proxy outlives the API stack and
# is slow to modify, so it should not be in the blast radius of a routine
# Lambda apply. envs/dev consumes its endpoint through db_proxy_host.
#
# Network values below were read from the account, not guessed, and remain
# owned by the State of Utah network team:
#   uid-dev-postgresqlv2  aurora-postgresql 16.11, port 5432
#   sg-0637efea445216701  the cluster's own group, which already permits 5432
#                         from both private-app CIDRs
# ---------------------------------------------------------------------------

terraform {
  required_version = ">= 1.10, < 2.0"
  required_providers {
    aws = { source = "hashicorp/aws", version = ">= 5.40, < 7.0" }
  }

  backend "s3" {
    bucket       = "uid-portal-tfstate"
    key          = "apigw/dev/db-proxy/terraform.tfstate"
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
  tags = {
    Owner       = "uid-portal"
    CostCenter  = "uid"
    app         = "uid-portal-api"
    contact     = "Gary Gerber"
    dept        = "uid"
    elcid       = "ID6903ALAA"
    env         = "dev"
    managedby   = "Terraform - State in S3 Bucket"
    security    = "0"
    supportcode = "hstsahsy"
  }
}

module "proxy" {
  source = "../../../modules/db_proxy"

  name = "uid-dev-portal-proxy"

  # UID-Dev-SUBNET-PRIVATE-1-A (us-west-2a) and -1-B (us-west-2b).
  subnet_ids = [
    "subnet-0c6272b1eea00003c",
    "subnet-0a1e2c8e6751b6833",
  ]

  # Attach the existing cluster group rather than creating or maintaining a
  # proxy group. Its owner is responsible for ingress and egress rules.
  proxy_security_group_ids = ["sg-0637efea445216701"]
  db_cluster_identifier    = "uid-dev-postgresqlv2"

  # The managed-rotation secret. The bare "dev/postgres/portal" name the Java
  # used does not exist in this account.
  secret_arn = "arn:aws:secretsmanager:us-west-2:705157108110:secret:dev/postgres/portal/rotate-w0w68d"

  tags = local.tags
}
