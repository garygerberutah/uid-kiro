# Remote state. S3 with native locking (use_lockfile) rather than a DynamoDB
# table -- S3 has supported conditional writes since 2024 and the extra table
# is no longer worth managing.
#
# The State-owned bucket must already exist with versioning enabled. Application
# Terraform may use it as a backend but must never create or reconfigure it.
terraform {
  required_version = ">= 1.10, < 2.0"

  # Transitional state compatibility: the historical dev state may still
  # reference retired data.archive_file instances. Declare archive here so
  # backend-free CI and backend-backed readonly init resolve the same provider
  # set. Remove this declaration and its lock entry together only after a
  # reviewed state reconciliation proves those references are gone.
  required_providers {
    archive = {
      source  = "hashicorp/archive"
      version = "2.8.0"
    }
  }

  backend "s3" {
    bucket       = "uid-portal-tfstate"
    key          = "apigw/dev/terraform.tfstate"
    region       = "us-west-2"
    encrypt      = true
    use_lockfile = true
  }
}
