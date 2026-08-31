# Remote state. S3 with native locking (use_lockfile) rather than a DynamoDB
# table -- S3 has supported conditional writes since 2024 and the extra table
# is no longer worth managing.
#
# The State-owned bucket must already exist with versioning enabled. Application
# Terraform may use it as a backend but must never create or reconfigure it.
terraform {
  required_version = ">= 1.10, < 2.0"

  backend "s3" {
    bucket       = "uid-portal-tfstate"
    key          = "apigw/at/terraform.tfstate"
    region       = "us-west-2"
    encrypt      = true
    use_lockfile = true
  }
}
